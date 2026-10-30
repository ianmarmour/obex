//! ## Embedded
//!
//! An async [`Client`] and [`Server`] for transports implementing the
//! [`embedded-io-async`](embedded_io_async) traits, the I/O abstraction of embedded
//! Rust, such as the Bluetooth channels of Embassy based firmware. Available with the
//! `embedded-io-async` feature, with or without `std`:
//!
//! ```toml
//! [dependencies]
//! obex-protocol = { version = "0.2", default-features = false, features = ["embedded-io-async"] }
//! ```
//!
//! They run the same protocol engine as the blocking types in `crate::client` and
//! `crate::server` and the tokio types in `crate::tokio`, so behavior is identical and
//! they interoperate. Unlike the tokio API, handlers and their futures need not be
//! `Send`, so they may hold peripherals and run on single threaded executors.
//!
//! Two things differ from the `std` APIs:
//!
//! * Objects returned from [`Handler::get`] are held in memory.
//! * Without `std` there is no source of randomness for authentication nonces, so
//!   [`Server::with_authentication`] and [`Client::with_server_authentication`] take a
//!   nonce generator, typically backed by the hardware random number generator.
//!
//! # Examples
//!
//! A client listing a folder:
//! ```no_run
//! # async fn example<T: embedded_io_async::Read + embedded_io_async::Write>(
//! #     channel: T,
//! # ) -> obex_protocol::Result<()> {
//! use obex_protocol::embedded::Client;
//! use obex_protocol::header::Header;
//! use obex_protocol::target::FOLDER_BROWSING;
//!
//! let mut client = Client::new(channel);
//! client.connect([Header::Target(FOLDER_BROWSING.to_vec())]).await?;
//!
//! let listing = client
//!     .get([Header::Type("x-obex/folder-listing".into())])
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
use core::future::Future;

use embedded_io_async::{Read, Write};

use crate::action::{ActionID, Permissions};
use crate::auth::{Credentials, DigestChallenge};
use crate::engine::client::ClientEngine;
use crate::engine::io::{Bytes, Collect, Embedded, Framed};
use crate::engine::server::{EngineHandler, ServerEngine};
use crate::error::Result;
use crate::header::{Header, Headers};
use crate::packet::{Request, Response, SetPathFlags, MINIMUM_PACKET_LENGTH};
use crate::prelude::*;
use crate::response::ResponseCode;
use crate::session::SessionParameters;

pub use crate::auth::Authentication;
pub use crate::packet::GetResponse;

/// The embedded OBEX client. See [the module level documentation](index.html).
pub struct Client<T> {
    engine: ClientEngine<Embedded<T>>,
}

impl<T: Read + Write> Client<T> {
    /// Creates a client over a connected transport.
    ///
    /// The client advertises a maximum packet length of 65535 bytes and does not use
    /// Single Response Mode until configured to. Lower the packet length with
    /// [`with_max_packet_length`](Self::with_max_packet_length) on devices with
    /// little memory.
    pub fn new(transport: T) -> Client<T> {
        Client {
            engine: ClientEngine::new(Embedded(transport)),
        }
    }

    /// Sets the largest packet this client can receive, at least 255 bytes.
    ///
    /// Over L2CAP this must not exceed the channel MTU.
    pub fn with_max_packet_length(mut self, max_packet_length: u16) -> Client<T> {
        self.engine.max_packet_length = max_packet_length.max(MINIMUM_PACKET_LENGTH);
        self
    }

    /// Enables Single Response Mode for PUT and GET operations, for transports with
    /// their own flow control such as L2CAP in Enhanced Retransmission Mode.
    pub fn with_single_response_mode(mut self, enabled: bool) -> Client<T> {
        self.engine.srm_supported = enabled;
        self
    }

    /// Answers every authentication challenge from the server with `credentials`.
    pub fn with_credentials(self, credentials: Credentials) -> Client<T> {
        self.with_credentials_provider(move |_| Some(credentials.clone()))
    }

    /// Answers authentication challenges with credentials chosen per challenge.
    /// Returning `None` leaves the challenge unanswered.
    pub fn with_credentials_provider<F>(mut self, provider: F) -> Client<T>
    where
        F: FnMut(&DigestChallenge) -> Option<Credentials> + Send + 'static,
    {
        self.engine.credentials = Some(Box::new(provider));
        self
    }

    /// Challenges the server during CONNECT and requires it to prove it knows
    /// `password`, using `nonce` to generate the challenge.
    pub fn with_server_authentication<N>(
        mut self,
        password: impl Into<Vec<u8>>,
        nonce: N,
    ) -> Client<T>
    where
        N: FnMut() -> [u8; 16] + Send + 'static,
    {
        self.engine.server_password = Some(password.into());
        self.engine.nonce = Some(Box::new(nonce));
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

    /// Opens an OBEX connection, sending `headers` (such as a Target) with CONNECT.
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

        self.engine.put(headers, Some(Embedded(body))).await
    }

    /// Sends an object read from `body` to the server, streaming it packet by packet.
    ///
    /// If `body` returns an error the operation is aborted and the error is returned.
    pub async fn put_from<R: Read>(
        &mut self,
        headers: impl IntoIterator<Item = Header>,
        body: R,
    ) -> Result<Response> {
        let headers = headers.into_iter().collect();

        self.engine.put(headers, Some(Embedded(body))).await
    }

    /// Sends a PUT without Body or End-of-Body headers, which requests deletion of the
    /// named object.
    pub async fn delete(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<Response> {
        let headers = headers.into_iter().collect();

        self.engine.put(headers, None::<Embedded<&[u8]>>).await
    }

    /// Requests an object from the server, collecting its body in memory.
    pub async fn get(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<GetResponse> {
        let mut body = Vec::new();
        let headers = headers.into_iter().collect();
        let headers = self.engine.get_into(headers, Collect(&mut body)).await?;

        Ok(GetResponse { headers, body })
    }

    /// Requests an object from the server, streaming its body into `sink`.
    ///
    /// Returns every non-body response header. If `sink` returns an error the
    /// operation is aborted and the error is returned.
    pub async fn get_into<W: Write>(
        &mut self,
        headers: impl IntoIterator<Item = Header>,
        sink: W,
    ) -> Result<Headers> {
        let headers = headers.into_iter().collect();

        self.engine.get_into(headers, Embedded(sink)).await
    }

    /// Changes the current folder on the server.
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

/// An object returned from [`Handler::get`].
pub struct Object {
    /// Headers describing the object, sent before the body.
    pub headers: Headers,
    /// The object body; `None` sends no Body or End-of-Body headers at all.
    pub body: Option<Vec<u8>>,
}

impl Object {
    /// Creates an object with a body.
    pub fn new(headers: impl Into<Headers>, body: impl Into<Vec<u8>>) -> Object {
        Object {
            headers: headers.into(),
            body: Some(body.into()),
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

/// Application logic of an embedded OBEX server.
///
/// The counterpart of the blocking and tokio `Handler` traits, with the same
/// semantics. Implement the methods with `async fn`; the futures need not be `Send`.
pub trait Handler {
    /// Accepts or refuses a CONNECT. For a directed connection the server adds a
    /// Connection Id and a Who header to a successful response.
    fn connect(&mut self, request: &Request) -> impl Future<Output = Response> {
        let _ = request;
        async { Response::new(ResponseCode::Success) }
    }

    /// Acknowledges a DISCONNECT, which cannot be refused.
    fn disconnect(&mut self, request: &Request) -> impl Future<Output = Response> {
        let _ = request;
        async { Response::new(ResponseCode::Success) }
    }

    /// Receives an object. `body` is `None` when the request carried no Body or
    /// End-of-Body header, which by convention requests deletion of the named object.
    fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> impl Future<Output = Response> {
        let _ = (request, body);
        async { Response::new(ResponseCode::NotImplemented) }
    }

    /// Returns the requested object, or the response to refuse the request with.
    fn get(
        &mut self,
        request: &Request,
    ) -> impl Future<Output = core::result::Result<Object, Response>> {
        let _ = request;
        async { Err(Response::new(ResponseCode::NotImplemented)) }
    }

    /// Changes the current folder. The flags are in `request.set_path`.
    fn set_path(&mut self, request: &Request) -> impl Future<Output = Response> {
        let _ = request;
        async { Response::new(ResponseCode::NotImplemented) }
    }

    /// Performs an ACTION operation.
    fn action(&mut self, request: &Request) -> impl Future<Output = Response> {
        let _ = request;
        async { Response::new(ResponseCode::NotImplemented) }
    }

    /// Handles a reliable session command.
    fn session(&mut self, request: &Request) -> impl Future<Output = Response> {
        let _ = request;
        async { Response::new(ResponseCode::NotImplemented) }
    }

    /// Handles a user defined opcode.
    fn user_defined(&mut self, request: &Request) -> impl Future<Output = Response> {
        let _ = request;
        async { Response::new(ResponseCode::NotImplemented) }
    }

    /// Notifies that the client aborted the operation in progress.
    fn abort(&mut self, request: &Request) -> impl Future<Output = ()> {
        let _ = request;
        async {}
    }

    /// The password a client must prove it knows when the server requires
    /// authentication. `user_id` is the User Id sent by the client, if any.
    fn password(&mut self, user_id: Option<&[u8]>) -> impl Future<Output = Option<Vec<u8>>> {
        let _ = user_id;
        async { None }
    }

    /// Credentials used to answer a client's challenge during CONNECT.
    fn credentials(
        &mut self,
        challenge: &DigestChallenge,
    ) -> impl Future<Output = Option<Credentials>> {
        let _ = challenge;
        async { None }
    }
}

/// The embedded OBEX server. See [the module level documentation](index.html).
pub struct Server<T, H> {
    engine: ServerEngine<Embedded<T>, EmbeddedHandler<H>>,
}

impl<T: Read + Write, H: Handler> Server<T, H> {
    /// Creates a server over a connected transport.
    pub fn new(transport: T, handler: H) -> Server<T, H> {
        Server {
            engine: ServerEngine::new(Embedded(transport), EmbeddedHandler(handler)),
        }
    }

    /// Sets the largest packet this server can receive, at least 255 bytes.
    ///
    /// Over L2CAP this must not exceed the channel MTU.
    pub fn with_max_packet_length(mut self, max_packet_length: u16) -> Server<T, H> {
        self.engine.max_packet_length = max_packet_length.max(MINIMUM_PACKET_LENGTH);
        self
    }

    /// Accepts Single Response Mode when clients request it, for transports with
    /// their own flow control such as L2CAP in Enhanced Retransmission Mode.
    pub fn with_single_response_mode(mut self, enabled: bool) -> Server<T, H> {
        self.engine.srm_supported = enabled;
        self
    }

    /// Requires clients to authenticate during CONNECT, checking them against
    /// [`Handler::password`] with challenges whose nonces come from `nonce`. Other
    /// operations are refused until they have.
    pub fn with_authentication<N>(
        mut self,
        authentication: Authentication,
        nonce: N,
    ) -> Server<T, H>
    where
        N: FnMut() -> [u8; 16] + Send + 'static,
    {
        self.engine.authentication = Some(authentication);
        self.engine.nonce = Some(Box::new(nonce));
        self
    }

    /// Sets the largest PUT body accepted in memory, 64 MiB by default; lower it to
    /// fit the device's memory.
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

/// Adapts an embedded [`Handler`] to the engine.
struct EmbeddedHandler<H>(H);

impl<H: Handler> EngineHandler for EmbeddedHandler<H> {
    type Body = Bytes;

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
    ) -> core::result::Result<(Headers, Option<Self::Body>), Response> {
        let object = self.0.get(request).await?;

        Ok((object.headers, object.body.map(Bytes::new)))
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

/// Splits an `embedded-io-async` byte stream into OBEX packets, for implementations
/// that drive the protocol themselves.
pub struct PacketStream<T> {
    inner: Framed<Embedded<T>>,
}

impl<T> PacketStream<T> {
    /// Wraps a transport.
    pub fn new(inner: T) -> PacketStream<T> {
        PacketStream {
            inner: Framed::new(Embedded(inner)),
        }
    }

    /// A reference to the underlying transport.
    pub fn get_ref(&self) -> &T {
        &self.inner.get_ref().0
    }

    /// Unwraps the underlying transport, discarding any buffered bytes.
    pub fn into_inner(self) -> T {
        self.inner.into_inner().0
    }
}

impl<T: Read> PacketStream<T> {
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

impl<T: Write> PacketStream<T> {
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
