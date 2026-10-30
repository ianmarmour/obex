//! ## Client
//!
//! [`Client`] drives OBEX operations over any [`Read`] + [`Write`] transport. It takes
//! care of everything below the profile layer:
//!
//! * packet size negotiation during CONNECT,
//! * splitting headers and bodies into packets, and reassembling GET responses,
//! * sending the Connection Id of a directed connection with every operation,
//! * Single Response Mode negotiation for PUT and GET (GOEP 2.0),
//! * answering authentication challenges, and challenging the server,
//! * aborting an operation when the body source or sink fails.
//!
//! A profile such as MAP or PBAP is then a thin layer that picks the Target, Type,
//! Name and Application Parameters of each request.
//!
//! # Examples
//!
//! A PBAP style phone book download over an already connected RFCOMM or L2CAP socket:
//! ```no_run
//! # fn example(socket: std::net::TcpStream) -> obex_protocol::Result<()> {
//! use obex_protocol::client::Client;
//! use obex_protocol::header::Header;
//! use obex_protocol::target::PHONE_BOOK_ACCESS;
//! use obex_protocol::tlv::ApplicationParameters;
//!
//! let mut client = Client::new(socket).with_single_response_mode(true);
//! client.connect([Header::Target(PHONE_BOOK_ACCESS.to_vec())])?;
//!
//! let phone_book = client.get([
//!     Header::Name("telecom/pb.vcf".to_string()),
//!     Header::Type("x-bt/phonebook".to_string()),
//!     Header::ApplicationParameters(ApplicationParameters::new().with_u16(0x04, 100)),
//! ])?;
//!
//! println!("{}", String::from_utf8_lossy(&phone_book.body));
//! client.disconnect()?;
//! # Ok(())
//! # }
//! ```
//!
use std::io::{Read, Write};

use crate::action::{ActionID, Permissions};
use crate::auth::{Credentials, DigestChallenge};
use crate::engine::client::ClientEngine;
use crate::engine::io::{block_on, Blocking};
use crate::error::Result;
use crate::header::{Header, Headers};
use crate::packet::{Request, Response, SetPathFlags, MINIMUM_PACKET_LENGTH};
use crate::session::SessionParameters;

/// The result of a GET operation.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct GetResponse {
    /// Every non-body header of every response packet, in order.
    pub headers: Headers,
    /// The reassembled object body.
    pub body: Vec<u8>,
}

/// The `Client` type. See [the module level documentation](index.html) for more.
pub struct Client<T> {
    engine: ClientEngine<Blocking<T>>,
}

impl<T: Read + Write> Client<T> {
    /// Creates a client over a connected transport.
    ///
    /// The client advertises a maximum packet length of 65535 bytes and does not use
    /// Single Response Mode until configured to.
    pub fn new(transport: T) -> Client<T> {
        Client {
            engine: ClientEngine::new(Blocking(transport)),
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

    /// Opens an OBEX connection.
    ///
    /// Send a Target header to open a directed connection to a specific service; the
    /// Connection Id the server returns is then sent with every later operation. If the
    /// response carries no Who header matching the Target, the server connected to its
    /// default (inbox) service instead, and it is up to the caller whether to continue.
    pub fn connect(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<Response> {
        block_on(self.engine.connect(headers.into_iter().collect()))
    }

    /// Closes the OBEX connection. The transport stays open.
    pub fn disconnect(&mut self) -> Result<Response> {
        block_on(self.engine.disconnect())
    }

    /// Sends an object to the server.
    ///
    /// An empty `body` creates an empty object; use [`Client::delete`] to send a PUT
    /// without any body headers.
    pub fn put(
        &mut self,
        headers: impl IntoIterator<Item = Header>,
        body: &[u8],
    ) -> Result<Response> {
        block_on(
            self.engine
                .put(headers.into_iter().collect(), Some(Blocking(body))),
        )
    }

    /// Sends an object read from `body` to the server, streaming it packet by packet.
    ///
    /// If `body` returns an error the operation is aborted and the error is returned.
    pub fn put_from<R: Read>(
        &mut self,
        headers: impl IntoIterator<Item = Header>,
        body: R,
    ) -> Result<Response> {
        block_on(
            self.engine
                .put(headers.into_iter().collect(), Some(Blocking(body))),
        )
    }

    /// Sends a PUT without Body or End-of-Body headers, which requests deletion of the
    /// named object.
    pub fn delete(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<Response> {
        block_on(
            self.engine
                .put(headers.into_iter().collect(), None::<Blocking<&[u8]>>),
        )
    }

    /// Requests an object from the server, collecting its body in memory.
    pub fn get(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<GetResponse> {
        let mut body = Vec::new();
        let headers = self.get_into(headers, &mut body)?;

        Ok(GetResponse { headers, body })
    }

    /// Requests an object from the server, streaming its body into `sink`.
    ///
    /// Returns every non-body response header. If `sink` returns an error the
    /// operation is aborted and the error is returned.
    pub fn get_into<W: Write>(
        &mut self,
        headers: impl IntoIterator<Item = Header>,
        sink: W,
    ) -> Result<Headers> {
        block_on(
            self.engine
                .get_into(headers.into_iter().collect(), Blocking(sink)),
        )
    }

    /// Changes the current folder on the server.
    ///
    /// `name` is the folder to enter, relative to the current one. `None` sends no
    /// Name header, which combined with `backup` moves to the parent folder, and an
    /// empty name resets to the root folder.
    pub fn set_path(&mut self, flags: SetPathFlags, name: Option<&str>) -> Result<Response> {
        block_on(self.engine.set_path(flags, name))
    }

    /// Changes the current folder to the root folder.
    pub fn set_path_root(&mut self) -> Result<Response> {
        block_on(self.engine.set_path_root())
    }

    /// Changes the current folder to the parent folder.
    pub fn set_path_parent(&mut self) -> Result<Response> {
        block_on(self.engine.set_path_parent())
    }

    /// Enters the child folder `name`, optionally creating it if it does not exist.
    pub fn set_path_child(&mut self, name: &str, create: bool) -> Result<Response> {
        block_on(self.engine.set_path_child(name, create))
    }

    /// Performs an ACTION operation. The Action Id header is added automatically.
    pub fn action(
        &mut self,
        action: ActionID,
        headers: impl IntoIterator<Item = Header>,
    ) -> Result<Response> {
        block_on(self.engine.action(action, headers.into_iter().collect()))
    }

    /// Copies the object `source` to `destination` on the server.
    pub fn copy(&mut self, source: &str, destination: &str) -> Result<Response> {
        block_on(self.engine.copy(source, destination))
    }

    /// Moves or renames the object `source` to `destination` on the server.
    pub fn move_object(&mut self, source: &str, destination: &str) -> Result<Response> {
        block_on(self.engine.move_object(source, destination))
    }

    /// Sets the permissions of the object `name` on the server.
    pub fn set_permissions(&mut self, name: &str, permissions: Permissions) -> Result<Response> {
        block_on(self.engine.set_permissions(name, permissions))
    }

    /// Sends a reliable session command.
    ///
    /// The Session-Parameters header is sent first, as the specification requires.
    pub fn session(
        &mut self,
        parameters: SessionParameters,
        headers: impl IntoIterator<Item = Header>,
    ) -> Result<Response> {
        block_on(
            self.engine
                .session(parameters, headers.into_iter().collect()),
        )
    }

    /// Sends an ABORT request outside of an operation and returns its response.
    ///
    /// Operations started by this client abort themselves when their body source or
    /// sink fails; this is for protocols layered on raw [`Client::request`] calls.
    pub fn abort(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<Response> {
        block_on(self.engine.abort(headers.into_iter().collect()))
    }

    /// Sends a single request packet and returns the response, whatever its code.
    ///
    /// No headers are added and the request must fit in one packet. This is the
    /// building block for user defined opcodes and unusual exchanges.
    pub fn request(&mut self, request: Request) -> Result<Response> {
        block_on(self.engine.exchange(request))
    }
}
