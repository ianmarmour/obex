//! ## Server
//!
//! [`Server`] answers OBEX requests arriving over any [`Read`] + [`Write`] transport
//! and hands complete operations to a [`Handler`]. It takes care of:
//!
//! * packet size negotiation during CONNECT,
//! * reassembling multi-packet requests and splitting GET responses into packets,
//! * assigning Connection Ids to directed connections and rejecting unknown ones,
//! * Single Response Mode, both per operation (GOEP 2.0) and per connection,
//! * challenging clients during CONNECT and answering their challenges,
//! * ABORT requests in the middle of an operation.
//!
//! Profiles where the local device is the OBEX server, such as the MAP Message
//! Notification Server, OPP or the FTP server role, implement [`Handler`].
//!
//! The server is blocking and reads only when it expects a packet. While it streams a
//! GET response under Single Response Mode it therefore sees an ABORT only after the
//! object has been sent, which the specification allows (the GET completes, then the
//! ABORT is answered) but delays cancellation of large objects. Authentication is
//! performed during CONNECT; per operation challenges are only answered by the
//! client, not issued by the server.
//!
//! # Examples
//!
//! A minimal MAP Message Notification Server that accepts event reports:
//! ```no_run
//! # fn example(socket: std::net::TcpStream) -> obex::Result<()> {
//! use obex::header::Header;
//! use obex::packet::{Request, Response};
//! use obex::response::ResponseCode;
//! use obex::server::{Handler, Server};
//!
//! struct Notifications;
//!
//! impl Handler for Notifications {
//!     fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
//!         if request.headers.content_type() == Some("x-bt/MAP-event-report") {
//!             println!("{}", String::from_utf8_lossy(&body.unwrap_or_default()));
//!             Response::new(ResponseCode::Success)
//!         } else {
//!             Response::new(ResponseCode::BadRequest)
//!         }
//!     }
//! }
//!
//! Server::new(socket, Notifications).run()
//! # }
//! ```
//!
use std::future::{ready, Future};
use std::io::{self, Read, Write};

use crate::auth::{Credentials, DigestChallenge, Realm};
use crate::engine::io::{block_on, Blocking};
use crate::engine::server::{EngineHandler, ServerEngine};
use crate::error::Result;
use crate::header::Headers;
use crate::packet::{Request, Response, MINIMUM_PACKET_LENGTH};
use crate::response::ResponseCode;

/// The body of an object returned from [`Handler::get`].
pub enum Body {
    /// A body held in memory.
    Bytes(Vec<u8>),
    /// A body streamed from a reader, packet by packet.
    Reader(Box<dyn Read>),
}

impl Body {
    fn into_reader(self) -> Box<dyn Read> {
        match self {
            Body::Bytes(bytes) => Box::new(io::Cursor::new(bytes)),
            Body::Reader(reader) => reader,
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Body {
        Body::Bytes(bytes)
    }
}

impl From<&[u8]> for Body {
    fn from(bytes: &[u8]) -> Body {
        Body::Bytes(bytes.to_vec())
    }
}

/// An object returned from [`Handler::get`].
pub struct Object {
    /// Headers describing the object, sent before the body.
    pub headers: Headers,
    /// The object body; `None` sends no Body or End-of-Body headers at all.
    pub body: Option<Body>,
}

impl Object {
    /// Creates an object with a body.
    pub fn new(headers: impl Into<Headers>, body: impl Into<Body>) -> Object {
        Object {
            headers: headers.into(),
            body: Some(body.into()),
        }
    }

    /// Creates an object whose body is streamed from `reader`.
    pub fn from_reader(headers: impl Into<Headers>, reader: impl Read + 'static) -> Object {
        Object {
            headers: headers.into(),
            body: Some(Body::Reader(Box::new(reader))),
        }
    }

    /// Creates a response carrying only headers, for example Application Parameters.
    pub fn headers_only(headers: impl Into<Headers>) -> Object {
        Object {
            headers: headers.into(),
            body: None,
        }
    }
}

/// Application logic of an OBEX server.
///
/// Every method receives the complete request, with the non-body headers of every
/// packet of the operation in order. Single Response Mode headers are consumed by the
/// server and removed. Unimplemented operations answer `Not Implemented`.
pub trait Handler {
    /// Accepts or refuses a CONNECT. The server adds the connection parameters.
    ///
    /// For a directed connection (the request has a Target header) the server adds a
    /// fresh Connection Id and a Who header echoing the Target to a successful
    /// response, unless the handler already added them.
    fn connect(&mut self, request: &Request) -> Response {
        let _ = request;
        Response::new(ResponseCode::Success)
    }

    /// Acknowledges a DISCONNECT, which cannot be refused.
    fn disconnect(&mut self, request: &Request) -> Response {
        let _ = request;
        Response::new(ResponseCode::Success)
    }

    /// Receives an object. `body` is `None` when the request carried no Body or
    /// End-of-Body header, which by convention requests deletion of the named object.
    fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
        let _ = (request, body);
        Response::new(ResponseCode::NotImplemented)
    }

    /// Returns the requested object, or the response to refuse the request with.
    fn get(&mut self, request: &Request) -> std::result::Result<Object, Response> {
        let _ = request;
        Err(Response::new(ResponseCode::NotImplemented))
    }

    /// Changes the current folder. The flags are in `request.set_path`.
    fn set_path(&mut self, request: &Request) -> Response {
        let _ = request;
        Response::new(ResponseCode::NotImplemented)
    }

    /// Performs an ACTION operation.
    fn action(&mut self, request: &Request) -> Response {
        let _ = request;
        Response::new(ResponseCode::NotImplemented)
    }

    /// Handles a reliable session command.
    fn session(&mut self, request: &Request) -> Response {
        let _ = request;
        Response::new(ResponseCode::NotImplemented)
    }

    /// Handles a user defined opcode.
    fn user_defined(&mut self, request: &Request) -> Response {
        let _ = request;
        Response::new(ResponseCode::NotImplemented)
    }

    /// Notifies that the client aborted the operation in progress.
    fn abort(&mut self, request: &Request) {
        let _ = request;
    }

    /// The password a client must prove it knows when the server requires
    /// authentication. `user_id` is the User Id sent by the client, if any.
    fn password(&mut self, user_id: Option<&[u8]>) -> Option<Vec<u8>> {
        let _ = user_id;
        None
    }

    /// Credentials used to answer a client's challenge during CONNECT.
    fn credentials(&mut self, challenge: &DigestChallenge) -> Option<Credentials> {
        let _ = challenge;
        None
    }
}

impl<H: Handler + ?Sized> Handler for &mut H {
    fn connect(&mut self, request: &Request) -> Response {
        (**self).connect(request)
    }

    fn disconnect(&mut self, request: &Request) -> Response {
        (**self).disconnect(request)
    }

    fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
        (**self).put(request, body)
    }

    fn get(&mut self, request: &Request) -> std::result::Result<Object, Response> {
        (**self).get(request)
    }

    fn set_path(&mut self, request: &Request) -> Response {
        (**self).set_path(request)
    }

    fn action(&mut self, request: &Request) -> Response {
        (**self).action(request)
    }

    fn session(&mut self, request: &Request) -> Response {
        (**self).session(request)
    }

    fn user_defined(&mut self, request: &Request) -> Response {
        (**self).user_defined(request)
    }

    fn abort(&mut self, request: &Request) {
        (**self).abort(request)
    }

    fn password(&mut self, user_id: Option<&[u8]>) -> Option<Vec<u8>> {
        (**self).password(user_id)
    }

    fn credentials(&mut self, challenge: &DigestChallenge) -> Option<Credentials> {
        (**self).credentials(challenge)
    }
}

/// Requirements for clients connecting to a [`Server`] that requires authentication.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Authentication {
    /// Displayed to the user to tell them which password to use.
    pub realm: Option<Realm>,
    /// Clients must send a User Id, passed to [`Handler::password`].
    pub user_id_required: bool,
    /// Advertise that the access offered is read only.
    pub read_only: bool,
}

/// The `Server` type. See [the module level documentation](index.html) for more.
pub struct Server<T, H> {
    engine: ServerEngine<Blocking<T>, SyncHandler<H>>,
}

impl<T: Read + Write, H: Handler> Server<T, H> {
    /// Creates a server over a connected transport.
    pub fn new(transport: T, handler: H) -> Server<T, H> {
        Server {
            engine: ServerEngine::new(Blocking(transport), SyncHandler(handler)),
        }
    }

    /// Sets the largest packet this server can receive, at least 255 bytes.
    ///
    /// Over L2CAP this must not exceed the channel MTU.
    pub fn with_max_packet_length(mut self, max_packet_length: u16) -> Server<T, H> {
        self.engine.max_packet_length = max_packet_length.max(MINIMUM_PACKET_LENGTH);
        self
    }

    /// Accepts Single Response Mode when clients request it.
    ///
    /// Only enable this when the transport provides its own flow control, such as
    /// L2CAP in Enhanced Retransmission Mode.
    pub fn with_single_response_mode(mut self, enabled: bool) -> Server<T, H> {
        self.engine.srm_supported = enabled;
        self
    }

    /// Requires clients to authenticate during CONNECT, checking them against
    /// [`Handler::password`]. Other operations are refused until they have.
    pub fn with_authentication(mut self, authentication: Authentication) -> Server<T, H> {
        self.engine.authentication = Some(authentication);
        self
    }

    /// Sets the largest PUT body accepted in memory, 64 MiB by default.
    pub fn with_max_object_size(mut self, max_object_size: usize) -> Server<T, H> {
        self.engine.max_object_size = max_object_size;
        self
    }

    /// A reference to the handler.
    pub fn handler(&self) -> &H {
        &self.engine.handler.0
    }

    /// A mutable reference to the handler.
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.engine.handler.0
    }

    /// A reference to the underlying transport.
    pub fn get_ref(&self) -> &T {
        &self.engine.stream.get_ref().0
    }

    /// Unwraps the handler and the underlying transport.
    pub fn into_parts(self) -> (T, H) {
        (self.engine.stream.into_inner().0, self.engine.handler.0)
    }

    /// Serves requests until the client closes the transport.
    pub fn run(&mut self) -> Result<()> {
        block_on(self.engine.run())
    }

    /// Reads one request and serves the operation it starts.
    pub fn handle_next(&mut self) -> Result<()> {
        block_on(self.engine.handle_next())
    }
}

/// Adapts a blocking [`Handler`] to the engine.
struct SyncHandler<H>(H);

impl<H: Handler> EngineHandler for SyncHandler<H> {
    type Body = Blocking<Box<dyn Read>>;

    fn connect(&mut self, request: &Request) -> impl Future<Output = Response> {
        ready(self.0.connect(request))
    }

    fn disconnect(&mut self, request: &Request) -> impl Future<Output = Response> {
        ready(self.0.disconnect(request))
    }

    fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> impl Future<Output = Response> {
        ready(self.0.put(request, body))
    }

    fn get(
        &mut self,
        request: &Request,
    ) -> impl Future<Output = std::result::Result<(Headers, Option<Self::Body>), Response>> {
        ready(self.0.get(request).map(|object| {
            let body = object.body.map(|body| Blocking(body.into_reader()));
            (object.headers, body)
        }))
    }

    fn set_path(&mut self, request: &Request) -> impl Future<Output = Response> {
        ready(self.0.set_path(request))
    }

    fn action(&mut self, request: &Request) -> impl Future<Output = Response> {
        ready(self.0.action(request))
    }

    fn session(&mut self, request: &Request) -> impl Future<Output = Response> {
        ready(self.0.session(request))
    }

    fn user_defined(&mut self, request: &Request) -> impl Future<Output = Response> {
        ready(self.0.user_defined(request))
    }

    fn abort(&mut self, request: &Request) -> impl Future<Output = ()> {
        self.0.abort(request);
        ready(())
    }

    fn password(&mut self, user_id: Option<&[u8]>) -> impl Future<Output = Option<Vec<u8>>> {
        ready(self.0.password(user_id))
    }

    fn credentials(
        &mut self,
        challenge: &DigestChallenge,
    ) -> impl Future<Output = Option<Credentials>> {
        ready(self.0.credentials(challenge))
    }
}
