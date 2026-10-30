//! ## Tokio
//!
//! Async versions of [`Client`], [`Server`] and [`PacketStream`] for transports that
//! implement tokio's [`AsyncRead`] and [`AsyncWrite`], available with the `tokio`
//! feature:
//!
//! ```toml
//! [dependencies]
//! obex = { version = "0.0.1", features = ["tokio"] }
//! ```
//!
//! They run the same protocol engine as the blocking types in [`crate::client`],
//! [`crate::server`] and [`crate::transport`], so behavior is identical; only I/O
//! is awaited instead of blocking. This fits Bluetooth stacks with async sockets, such
//! as BlueZ through the `bluer` crate, whose RFCOMM and L2CAP streams implement these
//! traits.
//!
//! Futures returned by the client, the server and [`Handler`] implementations are
//! `Send` when the transport is, so they can be spawned on a multi-threaded runtime.
//!
//! # Examples
//!
//! A MAP client listing the inbox, and a Message Notification Server spawned next to it:
//! ```no_run
//! # async fn example(
//! #     mas_socket: tokio::net::TcpStream,
//! #     mns_socket: tokio::net::TcpStream,
//! # ) -> obex::Result<()> {
//! use obex::header::Header;
//! use obex::packet::{Request, Response};
//! use obex::response::ResponseCode;
//! use obex::target::MESSAGE_ACCESS;
//! use obex::tokio::{Client, Handler, Server};
//!
//! struct Notifications;
//!
//! impl Handler for Notifications {
//!     async fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
//!         println!("event: {}", String::from_utf8_lossy(&body.unwrap_or_default()));
//!         Response::new(ResponseCode::Success)
//!     }
//! }
//!
//! tokio::spawn(async move { Server::new(mns_socket, Notifications).run().await });
//!
//! let mut client = Client::new(mas_socket).with_single_response_mode(true);
//! client.connect([Header::Target(MESSAGE_ACCESS.to_vec())]).await?;
//! client.set_path_child("telecom", false).await?;
//! client.set_path_child("msg", false).await?;
//!
//! let listing = client
//!     .get([
//!         Header::Name("inbox".to_string()),
//!         Header::Type("x-bt/MAP-msg-listing".to_string()),
//!     ])
//!     .await?;
//! println!("{}", String::from_utf8_lossy(&listing.body));
//! # Ok(())
//! # }
//! ```
//!
use std::future::Future;

use ::tokio::io::{AsyncRead, AsyncWrite};

use crate::action::{ActionID, Permissions};
use crate::auth::{Credentials, DigestChallenge};
use crate::engine::client::ClientEngine;
use crate::engine::io::{Framed, Tokio};
use crate::engine::server::{EngineHandler, ServerEngine};
use crate::error::Result;
use crate::header::{Header, Headers};
use crate::packet::{Request, Response, SetPathFlags, MINIMUM_PACKET_LENGTH};
use crate::response::ResponseCode;
use crate::session::SessionParameters;

pub use crate::client::GetResponse;
pub use crate::server::Authentication;

/// The async OBEX client. See [`crate::client`] for what it takes care of.
pub struct Client<T> {
    engine: ClientEngine<Tokio<T>>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Client<T> {
    /// Creates a client over a connected transport.
    ///
    /// The client advertises a maximum packet length of 65535 bytes and does not use
    /// Single Response Mode until configured to.
    pub fn new(transport: T) -> Client<T> {
        Client {
            engine: ClientEngine::new(Tokio(transport)),
        }
    }

    /// Sets the largest packet this client can receive, at least 255 bytes.
    ///
    /// Over L2CAP this must not exceed the channel MTU.
    pub fn with_max_packet_length(mut self, max_packet_length: u16) -> Client<T> {
        self.engine.max_packet_length = max_packet_length.max(MINIMUM_PACKET_LENGTH);
        self
    }

    /// Enables Single Response Mode for PUT and GET operations.
    ///
    /// SRM is requested in the first packet of every PUT and GET, as GOEP 2.0 requires,
    /// and is used whenever the server confirms it. Only enable this when the transport
    /// provides its own flow control, such as L2CAP in Enhanced Retransmission Mode.
    pub fn with_single_response_mode(mut self, enabled: bool) -> Client<T> {
        self.engine.srm_supported = enabled;
        self
    }

    /// Answers every authentication challenge from the server with `credentials`.
    pub fn with_credentials(self, credentials: Credentials) -> Client<T> {
        self.with_credentials_provider(move |_| Some(credentials.clone()))
    }

    /// Answers authentication challenges with credentials chosen per challenge, for
    /// example by its realm. Returning `None` leaves the challenge unanswered.
    pub fn with_credentials_provider<F>(mut self, provider: F) -> Client<T>
    where
        F: FnMut(&DigestChallenge) -> Option<Credentials> + Send + 'static,
    {
        self.engine.credentials = Some(Box::new(provider));
        self
    }

    /// Challenges the server during CONNECT and requires it to prove it knows `password`.
    pub fn with_server_authentication(mut self, password: impl Into<Vec<u8>>) -> Client<T> {
        self.engine.server_password = Some(password.into());
        self
    }

    /// The Connection Id assigned by the server for a directed connection.
    pub fn connection_id(&self) -> Option<u32> {
        self.engine.connection_id
    }

    /// The largest packet this client can receive.
    pub fn max_packet_length(&self) -> u16 {
        self.engine.max_packet_length
    }

    /// The largest packet the server can receive, as negotiated during CONNECT.
    pub fn remote_max_packet_length(&self) -> u16 {
        self.engine.remote_max_packet_length
    }

    /// Returns `true` if Single Response Mode is enabled for the whole connection.
    pub fn single_response_mode_enabled(&self) -> bool {
        self.engine.single_response_mode_enabled()
    }

    /// A reference to the underlying transport.
    pub fn get_ref(&self) -> &T {
        &self.engine.stream.get_ref().0
    }

    /// A mutable reference to the underlying transport.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.engine.stream.get_mut().0
    }

    /// Unwraps the underlying transport.
    pub fn into_inner(self) -> T {
        self.engine.stream.into_inner().0
    }

    /// Opens an OBEX connection. See [`crate::client::Client::connect`].
    pub async fn connect(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<Response> {
        self.engine.connect(headers.into_iter().collect()).await
    }

    /// Closes the OBEX connection. The transport stays open.
    pub async fn disconnect(&mut self) -> Result<Response> {
        self.engine.disconnect().await
    }

    /// Sends an object to the server.
    ///
    /// An empty `body` creates an empty object; use [`Client::delete`] to send a PUT
    /// without any body headers.
    pub async fn put(
        &mut self,
        headers: impl IntoIterator<Item = Header>,
        body: &[u8],
    ) -> Result<Response> {
        let headers = headers.into_iter().collect();

        self.engine.put(headers, Some(Tokio(body))).await
    }

    /// Sends an object read from `body` to the server, streaming it packet by packet.
    ///
    /// If `body` returns an error the operation is aborted and the error is returned.
    pub async fn put_from<R: AsyncRead + Unpin>(
        &mut self,
        headers: impl IntoIterator<Item = Header>,
        body: R,
    ) -> Result<Response> {
        let headers = headers.into_iter().collect();

        self.engine.put(headers, Some(Tokio(body))).await
    }

    /// Sends a PUT without Body or End-of-Body headers, which requests deletion of the
    /// named object.
    pub async fn delete(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<Response> {
        let headers = headers.into_iter().collect();

        self.engine.put(headers, None::<Tokio<&[u8]>>).await
    }

    /// Requests an object from the server, collecting its body in memory.
    pub async fn get(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<GetResponse> {
        let mut body = Vec::new();
        let headers = self.get_into(headers, &mut body).await?;

        Ok(GetResponse { headers, body })
    }

    /// Requests an object from the server, streaming its body into `sink`.
    ///
    /// Returns every non-body response header. If `sink` returns an error the
    /// operation is aborted and the error is returned.
    pub async fn get_into<W: AsyncWrite + Unpin>(
        &mut self,
        headers: impl IntoIterator<Item = Header>,
        sink: W,
    ) -> Result<Headers> {
        let headers = headers.into_iter().collect();

        self.engine.get_into(headers, Tokio(sink)).await
    }

    /// Changes the current folder on the server. See [`crate::client::Client::set_path`].
    pub async fn set_path(&mut self, flags: SetPathFlags, name: Option<&str>) -> Result<Response> {
        self.engine.set_path(flags, name).await
    }

    /// Changes the current folder to the root folder.
    pub async fn set_path_root(&mut self) -> Result<Response> {
        self.engine.set_path_root().await
    }

    /// Changes the current folder to the parent folder.
    pub async fn set_path_parent(&mut self) -> Result<Response> {
        self.engine.set_path_parent().await
    }

    /// Enters the child folder `name`, optionally creating it if it does not exist.
    pub async fn set_path_child(&mut self, name: &str, create: bool) -> Result<Response> {
        self.engine.set_path_child(name, create).await
    }

    /// Performs an ACTION operation. The Action Id header is added automatically.
    pub async fn action(
        &mut self,
        action: ActionID,
        headers: impl IntoIterator<Item = Header>,
    ) -> Result<Response> {
        let headers = headers.into_iter().collect();

        self.engine.action(action, headers).await
    }

    /// Copies the object `source` to `destination` on the server.
    pub async fn copy(&mut self, source: &str, destination: &str) -> Result<Response> {
        self.engine.copy(source, destination).await
    }

    /// Moves or renames the object `source` to `destination` on the server.
    pub async fn move_object(&mut self, source: &str, destination: &str) -> Result<Response> {
        self.engine.move_object(source, destination).await
    }

    /// Sets the permissions of the object `name` on the server.
    pub async fn set_permissions(
        &mut self,
        name: &str,
        permissions: Permissions,
    ) -> Result<Response> {
        self.engine.set_permissions(name, permissions).await
    }

    /// Sends a reliable session command.
    ///
    /// The Session-Parameters header is sent first, as the specification requires.
    pub async fn session(
        &mut self,
        parameters: SessionParameters,
        headers: impl IntoIterator<Item = Header>,
    ) -> Result<Response> {
        let headers = headers.into_iter().collect();

        self.engine.session(parameters, headers).await
    }

    /// Sends an ABORT request outside of an operation and returns its response.
    pub async fn abort(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<Response> {
        let headers = headers.into_iter().collect();

        self.engine.abort(headers).await
    }

    /// Sends a single request packet and returns the response, whatever its code.
    ///
    /// No headers are added and the request must fit in one packet.
    pub async fn request(&mut self, request: Request) -> Result<Response> {
        self.engine.exchange(request).await
    }
}

/// The body of an object returned from [`Handler::get`].
pub enum Body {
    /// A body held in memory.
    Bytes(Vec<u8>),
    /// A body streamed from a reader, packet by packet.
    Reader(Box<dyn AsyncRead + Unpin + Send>),
}

impl Body {
    fn into_reader(self) -> Box<dyn AsyncRead + Unpin + Send> {
        match self {
            Body::Bytes(bytes) => Box::new(std::io::Cursor::new(bytes)),
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
    pub fn from_reader(
        headers: impl Into<Headers>,
        reader: impl AsyncRead + Unpin + Send + 'static,
    ) -> Object {
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

/// Application logic of an async OBEX server.
///
/// The async counterpart of [`crate::server::Handler`], with the same semantics.
/// Implement the methods with `async fn`; their futures must be `Send`.
pub trait Handler {
    /// Accepts or refuses a CONNECT. See [`crate::server::Handler::connect`].
    fn connect(&mut self, request: &Request) -> impl Future<Output = Response> + Send {
        let _ = request;
        async { Response::new(ResponseCode::Success) }
    }

    /// Acknowledges a DISCONNECT, which cannot be refused.
    fn disconnect(&mut self, request: &Request) -> impl Future<Output = Response> + Send {
        let _ = request;
        async { Response::new(ResponseCode::Success) }
    }

    /// Receives an object. `body` is `None` when the request carried no Body or
    /// End-of-Body header, which by convention requests deletion of the named object.
    fn put(
        &mut self,
        request: &Request,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = Response> + Send {
        let _ = (request, body);
        async { Response::new(ResponseCode::NotImplemented) }
    }

    /// Returns the requested object, or the response to refuse the request with.
    fn get(
        &mut self,
        request: &Request,
    ) -> impl Future<Output = std::result::Result<Object, Response>> + Send {
        let _ = request;
        async { Err(Response::new(ResponseCode::NotImplemented)) }
    }

    /// Changes the current folder. The flags are in `request.set_path`.
    fn set_path(&mut self, request: &Request) -> impl Future<Output = Response> + Send {
        let _ = request;
        async { Response::new(ResponseCode::NotImplemented) }
    }

    /// Performs an ACTION operation.
    fn action(&mut self, request: &Request) -> impl Future<Output = Response> + Send {
        let _ = request;
        async { Response::new(ResponseCode::NotImplemented) }
    }

    /// Handles a reliable session command.
    fn session(&mut self, request: &Request) -> impl Future<Output = Response> + Send {
        let _ = request;
        async { Response::new(ResponseCode::NotImplemented) }
    }

    /// Handles a user defined opcode.
    fn user_defined(&mut self, request: &Request) -> impl Future<Output = Response> + Send {
        let _ = request;
        async { Response::new(ResponseCode::NotImplemented) }
    }

    /// Notifies that the client aborted the operation in progress.
    fn abort(&mut self, request: &Request) -> impl Future<Output = ()> + Send {
        let _ = request;
        async {}
    }

    /// The password a client must prove it knows when the server requires
    /// authentication. `user_id` is the User Id sent by the client, if any.
    fn password(&mut self, user_id: Option<&[u8]>) -> impl Future<Output = Option<Vec<u8>>> + Send {
        let _ = user_id;
        async { None }
    }

    /// Credentials used to answer a client's challenge during CONNECT.
    fn credentials(
        &mut self,
        challenge: &DigestChallenge,
    ) -> impl Future<Output = Option<Credentials>> + Send {
        let _ = challenge;
        async { None }
    }
}

/// The async OBEX server. See [`crate::server`] for what it takes care of.
pub struct Server<T, H> {
    engine: ServerEngine<Tokio<T>, AsyncHandler<H>>,
}

impl<T: AsyncRead + AsyncWrite + Unpin, H: Handler> Server<T, H> {
    /// Creates a server over a connected transport.
    pub fn new(transport: T, handler: H) -> Server<T, H> {
        Server {
            engine: ServerEngine::new(Tokio(transport), AsyncHandler(handler)),
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
    pub async fn run(&mut self) -> Result<()> {
        self.engine.run().await
    }

    /// Reads one request and serves the operation it starts.
    pub async fn handle_next(&mut self) -> Result<()> {
        self.engine.handle_next().await
    }
}

/// Adapts an async [`Handler`] to the engine.
struct AsyncHandler<H>(H);

impl<H: Handler> EngineHandler for AsyncHandler<H> {
    type Body = Tokio<Box<dyn AsyncRead + Unpin + Send>>;

    async fn connect(&mut self, request: &Request) -> Response {
        self.0.connect(request).await
    }

    async fn disconnect(&mut self, request: &Request) -> Response {
        self.0.disconnect(request).await
    }

    async fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
        self.0.put(request, body).await
    }

    async fn get(
        &mut self,
        request: &Request,
    ) -> std::result::Result<(Headers, Option<Self::Body>), Response> {
        let object = self.0.get(request).await?;
        let body = object.body.map(|body| Tokio(body.into_reader()));

        Ok((object.headers, body))
    }

    async fn set_path(&mut self, request: &Request) -> Response {
        self.0.set_path(request).await
    }

    async fn action(&mut self, request: &Request) -> Response {
        self.0.action(request).await
    }

    async fn session(&mut self, request: &Request) -> Response {
        self.0.session(request).await
    }

    async fn user_defined(&mut self, request: &Request) -> Response {
        self.0.user_defined(request).await
    }

    async fn abort(&mut self, request: &Request) {
        self.0.abort(request).await
    }

    async fn password(&mut self, user_id: Option<&[u8]>) -> Option<Vec<u8>> {
        self.0.password(user_id).await
    }

    async fn credentials(&mut self, challenge: &DigestChallenge) -> Option<Credentials> {
        self.0.credentials(challenge).await
    }
}

/// Splits an async byte stream into OBEX packets. See [`crate::transport`].
pub struct PacketStream<T> {
    inner: Framed<Tokio<T>>,
}

impl<T> PacketStream<T> {
    /// Wraps a transport.
    pub fn new(inner: T) -> PacketStream<T> {
        PacketStream {
            inner: Framed::new(Tokio(inner)),
        }
    }

    /// A reference to the underlying transport.
    pub fn get_ref(&self) -> &T {
        &self.inner.get_ref().0
    }

    /// A mutable reference to the underlying transport.
    ///
    /// Reading from it directly will desynchronize the packet stream.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner.get_mut().0
    }

    /// Unwraps the underlying transport, discarding any buffered bytes.
    pub fn into_inner(self) -> T {
        self.inner.into_inner().0
    }
}

impl<T: AsyncRead + Unpin> PacketStream<T> {
    /// Reads one complete packet.
    ///
    /// Returns [`Error::Disconnected`](crate::Error::Disconnected) if the transport is
    /// closed between packets.
    pub async fn read_packet(&mut self) -> Result<Vec<u8>> {
        self.inner.read_packet().await
    }

    /// Reads and parses a request packet.
    pub async fn read_request(&mut self) -> Result<Request> {
        self.inner.read_request().await
    }

    /// Reads and parses a response to any request other than CONNECT.
    pub async fn read_response(&mut self) -> Result<Response> {
        self.inner.read_response().await
    }

    /// Reads and parses a response to a CONNECT request.
    pub async fn read_connect_response(&mut self) -> Result<Response> {
        self.inner.read_connect_response().await
    }
}

impl<T: AsyncWrite + Unpin> PacketStream<T> {
    /// Writes one complete packet in a single `write_all` and flushes it.
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.inner.write_packet(packet).await
    }

    /// Encodes and writes a request.
    pub async fn write_request(&mut self, request: &Request) -> Result<()> {
        self.inner.write_request(request).await
    }

    /// Encodes and writes a response.
    pub async fn write_response(&mut self, response: &Response) -> Result<()> {
        self.inner.write_response(response).await
    }
}
