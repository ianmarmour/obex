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
use std::collections::HashSet;
use std::io::{self, Read, Write};

use crate::auth::{Credentials, DigestChallenge, DigestResponse, Realm};
use crate::body::Outgoing;
use crate::error::{Error, Result};
use crate::header::{Header, HeaderID, Headers};
use crate::opcode::Opcode;
use crate::packet::{
    ConnectParameters, Request, Response, MAXIMUM_PACKET_LENGTH, MINIMUM_PACKET_LENGTH,
    PACKET_PREFIX_LENGTH,
};
use crate::response::ResponseCode;
use crate::srm::SingleResponseMode;
use crate::transport::PacketStream;

/// The body of an object returned from [`Handler::get`].
pub enum Body {
    Bytes(Vec<u8>),
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
    stream: PacketStream<T>,
    handler: H,
    max_packet_length: u16,
    remote_max_packet_length: u16,
    srm_supported: bool,
    srm_enabled: bool,
    connections: HashSet<u32>,
    next_connection_id: u32,
    authentication: Option<Authentication>,
    authenticated: bool,
    challenge: Option<DigestChallenge>,
    max_object_size: usize,
}

impl<T: Read + Write, H: Handler> Server<T, H> {
    /// Creates a server over a connected transport.
    pub fn new(transport: T, handler: H) -> Server<T, H> {
        Server {
            stream: PacketStream::new(transport),
            handler,
            max_packet_length: MAXIMUM_PACKET_LENGTH,
            remote_max_packet_length: MINIMUM_PACKET_LENGTH,
            srm_supported: false,
            srm_enabled: false,
            connections: HashSet::new(),
            next_connection_id: 1,
            authentication: None,
            authenticated: false,
            challenge: None,
            max_object_size: 64 * 1024 * 1024,
        }
    }

    /// Sets the largest packet this server can receive, at least 255 bytes.
    ///
    /// Over L2CAP this must not exceed the channel MTU.
    pub fn with_max_packet_length(mut self, max_packet_length: u16) -> Server<T, H> {
        self.max_packet_length = max_packet_length.max(MINIMUM_PACKET_LENGTH);
        self
    }

    /// Accepts Single Response Mode when clients request it.
    ///
    /// Only enable this when the transport provides its own flow control, such as
    /// L2CAP in Enhanced Retransmission Mode.
    pub fn with_single_response_mode(mut self, enabled: bool) -> Server<T, H> {
        self.srm_supported = enabled;
        self
    }

    /// Requires clients to authenticate during CONNECT, checking them against
    /// [`Handler::password`]. Other operations are refused until they have.
    pub fn with_authentication(mut self, authentication: Authentication) -> Server<T, H> {
        self.authentication = Some(authentication);
        self
    }

    /// Sets the largest PUT body accepted in memory, 64 MiB by default.
    pub fn with_max_object_size(mut self, max_object_size: usize) -> Server<T, H> {
        self.max_object_size = max_object_size;
        self
    }

    /// A reference to the handler.
    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// A mutable reference to the handler.
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    /// A reference to the underlying transport.
    pub fn get_ref(&self) -> &T {
        self.stream.get_ref()
    }

    /// Unwraps the handler and the underlying transport.
    pub fn into_parts(self) -> (T, H) {
        (self.stream.into_inner(), self.handler)
    }

    /// Serves requests until the client closes the transport.
    pub fn run(&mut self) -> Result<()> {
        loop {
            match self.handle_next() {
                Ok(()) => {}
                Err(Error::Disconnected) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    /// Reads one request and serves the operation it starts.
    pub fn handle_next(&mut self) -> Result<()> {
        let packet = self.stream.read_packet()?;

        let request = match Request::parse(&packet) {
            Ok((_, request)) => request,
            Err(_) => {
                let code = match Opcode::from_byte(packet[0]) {
                    Ok(_) => ResponseCode::BadRequest,
                    Err(_) => ResponseCode::NotImplemented,
                };
                return self.send(Response::new(code));
            }
        };

        self.dispatch(request)
    }

    fn dispatch(&mut self, request: Request) -> Result<()> {
        match request.opcode {
            Opcode::Connect => return self.handle_connect(request),
            Opcode::Abort => {
                // Nothing is in progress between operations.
                self.handler.abort(&request);
                return self.send(Response::new(ResponseCode::Success));
            }
            _ => {}
        }

        if let Some(rejection) = self.rejection(&request) {
            return self.reject(request, rejection);
        }

        match request.opcode {
            Opcode::Disconnect => self.handle_disconnect(request),
            Opcode::Put => self.handle_put(request),
            Opcode::Get => self.handle_get(request),
            Opcode::SetPath => {
                let response = self.handler.set_path(&request);
                self.send(response)
            }
            _ => self.handle_headers_only(request),
        }
    }

    /// The response refusing `request` before it reaches the handler, if any.
    fn rejection(&self, request: &Request) -> Option<Response> {
        // A DISCONNECT may not be refused (OBEX section 3.4.2).
        let refusable = request.opcode != Opcode::Disconnect;

        if refusable && self.authentication.is_some() && !self.authenticated {
            return Some(Response::new(ResponseCode::Unauthorized));
        }

        match request.headers.connection_id() {
            Some(id) if !self.connections.contains(&id) => {
                Some(Response::new(ResponseCode::ServiceUnavailable))
            }
            _ => None,
        }
    }

    /// Refuses an operation. With SRM enabled the client keeps sending the request
    /// without waiting, so its remaining packets are consumed first.
    fn reject(&mut self, mut request: Request, rejection: Response) -> Result<()> {
        if self.srm_enabled && matches!(request.opcode, Opcode::Put | Opcode::Get) {
            while !request.is_final {
                request = self.stream.read_request()?;

                if request.opcode == Opcode::Abort {
                    self.handler.abort(&request);
                    return self.send(Response::new(ResponseCode::Success));
                }
            }
        }

        self.send(rejection)
    }

    fn handle_connect(&mut self, request: Request) -> Result<()> {
        let parameters = request.connect.unwrap_or_default();
        self.remote_max_packet_length = parameters.max_packet_length.max(MINIMUM_PACKET_LENGTH);

        if let Some(authentication) = self.authentication.clone() {
            if !self.verify_client(&request) {
                let challenge = DigestChallenge {
                    realm: authentication.realm,
                    user_id_required: authentication.user_id_required,
                    read_only: authentication.read_only,
                    ..DigestChallenge::new()
                };
                self.challenge = Some(challenge.clone());
                self.authenticated = false;

                let response =
                    Response::with_headers(ResponseCode::Unauthorized, [challenge.into()]);
                return self.send_connect(response);
            }

            self.authenticated = true;
            self.challenge = None;
        }

        let mut response = self.handler.connect(&request);

        if response.code.is_success() {
            if let Some(target) = request.headers.target() {
                if !response.headers.contains(HeaderID::ConnectionID) {
                    let id = self.allocate_connection_id();
                    response.headers.insert(0, Header::ConnectionID(id));
                }

                if !response.headers.contains(HeaderID::Who) {
                    response.headers.insert(1, Header::Who(target.to_vec()));
                }
            }

            if let Some(id) = response.headers.connection_id() {
                self.connections.insert(id);
            }

            let challenges = DigestChallenge::find_all(&request.headers).unwrap_or_default();
            if let Some(challenge) = challenges.into_iter().next() {
                if let Some(credentials) = self.handler.credentials(&challenge) {
                    response
                        .headers
                        .push(challenge.respond(&credentials).into());
                }
            }

            if self.srm_supported
                && request.headers.single_response_mode() == Some(SingleResponseMode::Enable)
            {
                response
                    .headers
                    .push(Header::SingleResponseMode(SingleResponseMode::Enable));
                self.srm_enabled = true;
            }
        }

        self.send_connect(response)
    }

    fn verify_client(&mut self, request: &Request) -> bool {
        let Some(challenge) = self.challenge.clone() else {
            return false;
        };

        let Some(Ok(digest)) = DigestResponse::find(&request.headers) else {
            return false;
        };

        match self.handler.password(digest.user_id.as_deref()) {
            Some(password) => digest.verify(&challenge, &password),
            None => false,
        }
    }

    fn allocate_connection_id(&mut self) -> u32 {
        loop {
            let id = self.next_connection_id;
            self.next_connection_id = self.next_connection_id.wrapping_add(1);

            // 0xFFFFFFFF is reserved as an invalid Connection Id.
            if id != u32::MAX && !self.connections.contains(&id) {
                return id;
            }
        }
    }

    fn handle_disconnect(&mut self, request: Request) -> Result<()> {
        let response = self.handler.disconnect(&request);

        if let Some(id) = request.headers.connection_id() {
            self.connections.remove(&id);
        }

        if request.headers.connection_id().is_none() || self.connections.is_empty() {
            self.connections.clear();
            self.srm_enabled = false;
            self.authenticated = false;
            self.remote_max_packet_length = MINIMUM_PACKET_LENGTH;
        }

        self.send(response)
    }

    fn handle_put(&mut self, mut request: Request) -> Result<()> {
        let mut srm = self.srm_enabled;
        let mut confirm_srm = !srm
            && self.srm_supported
            && request.headers.single_response_mode() == Some(SingleResponseMode::Enable);

        let mut headers = Headers::new();
        let mut body: Option<Vec<u8>> = None;
        let mut rejection: Option<Response> = None;

        loop {
            let additional = request
                .headers
                .single_response_mode_parameter()
                .is_some_and(|parameter| parameter.requests_additional_packet());
            let is_final = request.is_final;

            for header in request.headers {
                match header {
                    Header::Body(data) | Header::EndOfBody(data) => {
                        let body = body.get_or_insert_with(Vec::new);

                        if body.len() + data.len() > self.max_object_size {
                            rejection.get_or_insert(Response::new(
                                ResponseCode::RequestedEntityTooLarge,
                            ));
                        } else {
                            body.extend_from_slice(&data);
                        }
                    }
                    Header::SingleResponseMode(_) | Header::SingleResponseModeParameters(_) => {}
                    header => headers.push(header),
                }
            }

            if is_final {
                break;
            }

            if !srm || additional {
                // Without SRM the client waits for this response, so refuse right away.
                if !srm {
                    if let Some(rejection) = rejection.take() {
                        return self.send(rejection);
                    }
                }

                let mut response = Response::new(ResponseCode::Continue);

                if confirm_srm {
                    response
                        .headers
                        .push(Header::SingleResponseMode(SingleResponseMode::Enable));
                    confirm_srm = false;
                    srm = true;
                }

                self.send(response)?;
            }

            request = match self.next_request(Opcode::Put)? {
                Some(request) => request,
                None => return Ok(()),
            };
        }

        let request = Request::new(Opcode::Put, true, headers);
        let response = match rejection {
            Some(rejection) => rejection,
            None => self.handler.put(&request, body),
        };

        self.send(response)
    }

    fn handle_get(&mut self, mut request: Request) -> Result<()> {
        let mut srm = self.srm_enabled;
        let mut confirm_srm = !srm
            && self.srm_supported
            && request.headers.single_response_mode() == Some(SingleResponseMode::Enable);

        let mut headers = Headers::new();
        let mut wait;

        // Request phase: collect the request headers until the Final bit.
        loop {
            wait = request
                .headers
                .single_response_mode_parameter()
                .is_some_and(|parameter| parameter.requests_wait());
            let is_final = request.is_final;

            headers.extend(request.headers.into_iter().filter(|header| {
                !matches!(
                    header,
                    Header::SingleResponseMode(_) | Header::SingleResponseModeParameters(_)
                )
            }));

            if is_final {
                break;
            }

            if !srm {
                let mut response = Response::new(ResponseCode::Continue);

                if confirm_srm {
                    response
                        .headers
                        .push(Header::SingleResponseMode(SingleResponseMode::Enable));
                    confirm_srm = false;
                    srm = true;
                }

                self.send(response)?;
            }

            request = match self.next_request(Opcode::Get)? {
                Some(request) => request,
                None => return Ok(()),
            };
        }

        let request = Request::new(Opcode::Get, true, headers);
        let object = match self.handler.get(&request) {
            Ok(object) => object,
            Err(response) => return self.send(response),
        };

        let mut headers = object.headers.into_vec();
        if confirm_srm {
            headers.insert(0, Header::SingleResponseMode(SingleResponseMode::Enable));
            srm = true;
        }

        let mut outgoing = Outgoing::new(headers, object.body.map(Body::into_reader));

        // Response phase: send the object, waiting for continuation requests unless SRM is on.
        loop {
            let (packet, last) = match outgoing.next_packet(
                usize::from(self.remote_max_packet_length),
                PACKET_PREFIX_LENGTH,
            ) {
                Ok(packet) => packet,
                Err(_) => return self.send(Response::new(ResponseCode::InternalServerError)),
            };

            let code = if last {
                ResponseCode::Success
            } else {
                ResponseCode::Continue
            };
            self.send(Response::with_headers(code, packet))?;

            if last {
                return Ok(());
            }

            if !srm || wait {
                match self.next_request(Opcode::Get)? {
                    Some(request) => {
                        wait = request
                            .headers
                            .single_response_mode_parameter()
                            .is_some_and(|parameter| parameter.requests_wait());
                    }
                    None => return Ok(()),
                }
            }
        }
    }

    /// Serves ACTION, SESSION and user defined operations, which carry no body.
    fn handle_headers_only(&mut self, mut request: Request) -> Result<()> {
        let opcode = request.opcode;
        let mut headers = Headers::new();

        loop {
            let is_final = request.is_final;
            headers.extend(request.headers);

            if is_final {
                break;
            }

            self.send(Response::new(ResponseCode::Continue))?;

            request = match self.next_request(opcode)? {
                Some(request) => request,
                None => return Ok(()),
            };
        }

        let request = Request::new(opcode, true, headers);
        let response = match opcode {
            Opcode::Action => self.handler.action(&request),
            Opcode::Session => self.handler.session(&request),
            _ => self.handler.user_defined(&request),
        };

        self.send(response)
    }

    /// Reads the next packet of an operation. Returns `None` once an ABORT has been
    /// answered, which ends the operation.
    fn next_request(&mut self, opcode: Opcode) -> Result<Option<Request>> {
        let request = self.stream.read_request()?;

        if request.opcode == Opcode::Abort {
            self.handler.abort(&request);
            self.send(Response::new(ResponseCode::Success))?;
            return Ok(None);
        }

        if request.opcode != opcode {
            self.send(Response::new(ResponseCode::BadRequest))?;
            return Err(Error::Protocol(
                "a new operation started before the last one ended",
            ));
        }

        Ok(Some(request))
    }

    fn send_connect(&mut self, mut response: Response) -> Result<()> {
        response.connect = Some(ConnectParameters::new(self.max_packet_length));
        self.send(response)
    }

    fn send(&mut self, response: Response) -> Result<()> {
        let bytes = response.to_bytes()?;

        if bytes.len() > usize::from(self.remote_max_packet_length) {
            // The handler produced headers the client cannot receive.
            let mut fallback = Response::new(ResponseCode::InternalServerError);
            fallback.connect = response.connect;
            return self.stream.write_response(&fallback);
        }

        self.stream.write_packet(&bytes)
    }
}
