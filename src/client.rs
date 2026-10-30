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
//! # fn example(socket: std::net::TcpStream) -> obex::Result<()> {
//! use obex::client::Client;
//! use obex::header::Header;
//! use obex::target::PHONE_BOOK_ACCESS;
//! use obex::tlv::ApplicationParameters;
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
use std::io::{self, Read, Write};

use crate::action::{ActionID, Permissions};
use crate::auth::{Credentials, DigestChallenge, DigestResponse};
use crate::body::{must_lead, Outgoing};
use crate::error::{Error, Result};
use crate::header::{Header, HeaderID, Headers};
use crate::opcode::Opcode;
use crate::packet::{
    ConnectParameters, Request, Response, SetPathFlags, MAXIMUM_PACKET_LENGTH,
    MINIMUM_PACKET_LENGTH, PACKET_PREFIX_LENGTH,
};
use crate::response::ResponseCode;
use crate::session::SessionParameters;
use crate::srm::SingleResponseMode;
use crate::transport::PacketStream;

type CredentialProvider = Box<dyn FnMut(&DigestChallenge) -> Option<Credentials> + Send>;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum SrmState {
    Disabled,
    /// The server asked to enable SRM; the next PUT or GET confirms it.
    Pending,
    /// SRM is enabled for every operation on this connection.
    Enabled,
}

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
    stream: PacketStream<T>,
    max_packet_length: u16,
    remote_max_packet_length: u16,
    connection_id: Option<u32>,
    srm_supported: bool,
    srm: SrmState,
    srm_wait: bool,
    credentials: Option<CredentialProvider>,
    server_password: Option<Vec<u8>>,
}

impl<T: Read + Write> Client<T> {
    /// Creates a client over a connected transport.
    ///
    /// The client advertises a maximum packet length of 65535 bytes and does not use
    /// Single Response Mode until configured to.
    pub fn new(transport: T) -> Client<T> {
        Client {
            stream: PacketStream::new(transport),
            max_packet_length: MAXIMUM_PACKET_LENGTH,
            remote_max_packet_length: MINIMUM_PACKET_LENGTH,
            connection_id: None,
            srm_supported: false,
            srm: SrmState::Disabled,
            srm_wait: false,
            credentials: None,
            server_password: None,
        }
    }

    /// Sets the largest packet this client can receive, at least 255 bytes.
    ///
    /// Over L2CAP this must not exceed the channel MTU.
    pub fn with_max_packet_length(mut self, max_packet_length: u16) -> Client<T> {
        self.max_packet_length = max_packet_length.max(MINIMUM_PACKET_LENGTH);
        self
    }

    /// Enables Single Response Mode for PUT and GET operations.
    ///
    /// SRM is requested in the first packet of every PUT and GET, as GOEP 2.0 requires,
    /// and is used whenever the server confirms it. Only enable this when the transport
    /// provides its own flow control, such as L2CAP in Enhanced Retransmission Mode.
    pub fn with_single_response_mode(mut self, enabled: bool) -> Client<T> {
        self.srm_supported = enabled;
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
        self.credentials = Some(Box::new(provider));
        self
    }

    /// Challenges the server during CONNECT and requires it to prove it knows `password`.
    pub fn with_server_authentication(mut self, password: impl Into<Vec<u8>>) -> Client<T> {
        self.server_password = Some(password.into());
        self
    }

    /// The Connection Id assigned by the server for a directed connection.
    pub fn connection_id(&self) -> Option<u32> {
        self.connection_id
    }

    /// The largest packet this client can receive.
    pub fn max_packet_length(&self) -> u16 {
        self.max_packet_length
    }

    /// The largest packet the server can receive, as negotiated during CONNECT.
    pub fn remote_max_packet_length(&self) -> u16 {
        self.remote_max_packet_length
    }

    /// Returns `true` if Single Response Mode is enabled for the whole connection.
    pub fn single_response_mode_enabled(&self) -> bool {
        self.srm == SrmState::Enabled
    }

    /// A reference to the underlying transport.
    pub fn get_ref(&self) -> &T {
        self.stream.get_ref()
    }

    /// A mutable reference to the underlying transport.
    pub fn get_mut(&mut self) -> &mut T {
        self.stream.get_mut()
    }

    /// Unwraps the underlying transport.
    pub fn into_inner(self) -> T {
        self.stream.into_inner()
    }

    /// Opens an OBEX connection.
    ///
    /// Send a Target header to open a directed connection to a specific service; the
    /// Connection Id the server returns is then sent with every later operation. If the
    /// response carries no Who header matching the Target, the server connected to its
    /// default (inbox) service instead, and it is up to the caller whether to continue.
    pub fn connect(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<Response> {
        let mut headers: Headers = headers.into_iter().collect();

        let challenge = self
            .server_password
            .as_ref()
            .map(|_| DigestChallenge::new());
        if let Some(challenge) = &challenge {
            headers.push(challenge.clone().into());
        }

        let requested_srm = headers.single_response_mode() == Some(SingleResponseMode::Enable);
        let request = Request::connect(ConnectParameters::new(self.max_packet_length), headers);
        let response = self.exchange(request)?;

        if !response.code.is_success() {
            return Err(Error::Response(Box::new(response)));
        }

        if let (Some(challenge), Some(password)) = (&challenge, &self.server_password) {
            match DigestResponse::find(&response.headers) {
                Some(Ok(digest)) if digest.verify(challenge, password) => {}
                _ => return Err(Error::AuthenticationFailed),
            }
        }

        let parameters = response.connect.unwrap_or_default();
        self.remote_max_packet_length = parameters.max_packet_length.max(MINIMUM_PACKET_LENGTH);
        self.connection_id = response.headers.connection_id();
        self.srm_wait = response
            .headers
            .single_response_mode_parameter()
            .is_some_and(|parameter| parameter.requests_wait());
        self.srm = match response.headers.single_response_mode() {
            Some(SingleResponseMode::Enable) if requested_srm => SrmState::Enabled,
            Some(SingleResponseMode::Enable) if self.srm_supported => SrmState::Pending,
            _ => SrmState::Disabled,
        };

        Ok(response)
    }

    /// Closes the OBEX connection. The transport stays open.
    pub fn disconnect(&mut self) -> Result<Response> {
        let headers = self.with_connection_id(Vec::new());
        let response = self.exchange(Request::new(Opcode::Disconnect, true, headers));

        self.connection_id = None;
        self.remote_max_packet_length = MINIMUM_PACKET_LENGTH;
        self.srm = SrmState::Disabled;
        self.srm_wait = false;

        expect_success(response?)
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
        self.put_inner(headers.into_iter().collect(), Some(body))
    }

    /// Sends an object read from `body` to the server, streaming it packet by packet.
    ///
    /// If `body` returns an error the operation is aborted and the error is returned.
    pub fn put_from<R: Read>(
        &mut self,
        headers: impl IntoIterator<Item = Header>,
        body: R,
    ) -> Result<Response> {
        self.put_inner(headers.into_iter().collect(), Some(body))
    }

    /// Sends a PUT without Body or End-of-Body headers, which requests deletion of the
    /// named object.
    pub fn delete(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<Response> {
        self.put_inner::<io::Empty>(headers.into_iter().collect(), None)
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
        mut sink: W,
    ) -> Result<Headers> {
        let mut headers = self.with_connection_id(headers.into_iter().collect());
        let (srm_header, mut srm) = self.srm_header();
        let requested_srm = srm_header.is_some() && !srm;
        insert_early(&mut headers, srm_header);

        let mut outgoing: Outgoing<io::Empty> = Outgoing::new(headers, None);
        let mut collected = Headers::new();
        let mut first = true;
        let mut can_retry = self.credentials.is_some();

        // Request phase: send every request header, the last packet with the Final bit.
        let mut response = loop {
            let (packet, last) = outgoing.next_packet(self.remote_max(), PACKET_PREFIX_LENGTH)?;
            let sent = (first && can_retry).then(|| packet.clone());
            self.write_request(&Request::new(Opcode::Get, last, packet))?;

            if !last && srm {
                first = false;
                continue;
            }

            let response = self.read_response()?;

            if let Some(sent) = sent {
                if let Some(answer) = self.answer_challenge(&response)? {
                    outgoing.rewind(sent);
                    outgoing.insert_early(answer);
                    can_retry = false;
                    continue;
                }
            }
            can_retry = false;

            if requested_srm && confirms_srm(&response) {
                srm = true;
            }

            if last {
                break response;
            }

            if response.code != ResponseCode::Continue {
                return Err(Error::Response(Box::new(response)));
            }

            collect(response.headers, &mut collected, &mut io::sink())?;
            first = false;
        };

        // Response phase: keep asking for the object until the server reports success.
        loop {
            let code = response.code;

            if code != ResponseCode::Continue && !code.is_success() {
                return Err(Error::Response(Box::new(response)));
            }

            if requested_srm && confirms_srm(&response) {
                srm = true;
            }

            let additional = response
                .headers
                .single_response_mode_parameter()
                .is_some_and(|parameter| parameter.requests_additional_packet());

            let delivered = collect(response.headers, &mut collected, &mut sink);

            if code.is_success() {
                delivered?;
                sink.flush()?;
                return Ok(collected);
            }

            if let Err(error) = delivered {
                let _ = self.abort_get(srm);
                return Err(error.into());
            }

            if !srm || additional {
                self.write_request(&Request::new(Opcode::Get, true, Headers::new()))?;
            }

            response = self.read_response()?;
        }
    }

    /// Changes the current folder on the server.
    ///
    /// `name` is the folder to enter, relative to the current one. `None` sends no
    /// Name header, which combined with `backup` moves to the parent folder, and an
    /// empty name resets to the root folder.
    pub fn set_path(&mut self, flags: SetPathFlags, name: Option<&str>) -> Result<Response> {
        let mut headers = self.with_connection_id(Vec::new());
        if let Some(name) = name {
            headers.push(Header::Name(name.to_string()));
        }

        expect_success(self.exchange(Request::set_path(flags, headers))?)
    }

    /// Changes the current folder to the root folder.
    pub fn set_path_root(&mut self) -> Result<Response> {
        let flags = SetPathFlags {
            backup: false,
            no_create: true,
        };

        self.set_path(flags, Some(""))
    }

    /// Changes the current folder to the parent folder.
    pub fn set_path_parent(&mut self) -> Result<Response> {
        let flags = SetPathFlags {
            backup: true,
            no_create: true,
        };

        self.set_path(flags, None)
    }

    /// Enters the child folder `name`, optionally creating it if it does not exist.
    pub fn set_path_child(&mut self, name: &str, create: bool) -> Result<Response> {
        let flags = SetPathFlags {
            backup: false,
            no_create: !create,
        };

        self.set_path(flags, Some(name))
    }

    /// Performs an ACTION operation. The Action Id header is added automatically.
    pub fn action(
        &mut self,
        action: ActionID,
        headers: impl IntoIterator<Item = Header>,
    ) -> Result<Response> {
        let mut all = vec![Header::ActionID(action)];
        all.extend(headers);
        let headers = self.with_connection_id(all);

        expect_success(self.exchange(Request::new(Opcode::Action, true, headers))?)
    }

    /// Copies the object `source` to `destination` on the server.
    pub fn copy(&mut self, source: &str, destination: &str) -> Result<Response> {
        self.action(
            ActionID::Copy,
            [
                Header::Name(source.to_string()),
                Header::DestName(destination.to_string()),
            ],
        )
    }

    /// Moves or renames the object `source` to `destination` on the server.
    pub fn move_object(&mut self, source: &str, destination: &str) -> Result<Response> {
        self.action(
            ActionID::MoveRename,
            [
                Header::Name(source.to_string()),
                Header::DestName(destination.to_string()),
            ],
        )
    }

    /// Sets the permissions of the object `name` on the server.
    pub fn set_permissions(&mut self, name: &str, permissions: Permissions) -> Result<Response> {
        self.action(
            ActionID::SetPermissions,
            [
                Header::Name(name.to_string()),
                Header::Permissions(permissions),
            ],
        )
    }

    /// Sends a reliable session command.
    ///
    /// The Session-Parameters header is sent first, as the specification requires.
    pub fn session(
        &mut self,
        parameters: SessionParameters,
        headers: impl IntoIterator<Item = Header>,
    ) -> Result<Response> {
        let mut all = vec![parameters.into()];
        all.extend(headers);

        expect_success(self.exchange(Request::new(Opcode::Session, true, all))?)
    }

    /// Sends an ABORT request outside of an operation and returns its response.
    ///
    /// Operations started by this client abort themselves when their body source or
    /// sink fails; this is for protocols layered on raw [`Client::request`] calls.
    pub fn abort(&mut self, headers: impl IntoIterator<Item = Header>) -> Result<Response> {
        let headers = self.with_connection_id(headers.into_iter().collect());

        self.exchange(Request::new(Opcode::Abort, true, headers))
    }

    /// Sends a single request packet and returns the response, whatever its code.
    ///
    /// No headers are added and the request must fit in one packet. This is the
    /// building block for user defined opcodes and unusual exchanges.
    pub fn request(&mut self, request: Request) -> Result<Response> {
        self.exchange(request)
    }

    fn remote_max(&self) -> usize {
        usize::from(self.remote_max_packet_length)
    }

    /// Prepends the Connection Id unless the headers already identify the service.
    fn with_connection_id(&self, mut headers: Vec<Header>) -> Headers {
        let identified = headers
            .iter()
            .any(|header| matches!(header, Header::ConnectionID(_) | Header::Target(_)));

        if let (Some(id), false) = (self.connection_id, identified) {
            headers.insert(0, Header::ConnectionID(id));
        }

        headers.into()
    }

    /// The SRM header to send with the next PUT or GET, and whether SRM is active
    /// from the first packet on.
    fn srm_header(&mut self) -> (Option<Header>, bool) {
        let enable = Some(Header::SingleResponseMode(SingleResponseMode::Enable));

        match self.srm {
            SrmState::Enabled => (None, true),
            SrmState::Pending => {
                // Confirming the server's request enables SRM as soon as it arrives.
                self.srm = SrmState::Enabled;
                (enable, true)
            }
            SrmState::Disabled if self.srm_supported => (enable, false),
            SrmState::Disabled => (None, false),
        }
    }

    fn put_inner<R: Read>(&mut self, headers: Vec<Header>, body: Option<R>) -> Result<Response> {
        let mut headers = self.with_connection_id(headers);
        let (srm_header, mut srm) = self.srm_header();
        let requested_srm = srm_header.is_some() && !srm;
        insert_early(&mut headers, srm_header);

        let mut outgoing = Outgoing::new(headers, body);
        let mut wait = std::mem::take(&mut self.srm_wait);
        let mut first = true;
        let mut can_retry = self.credentials.is_some();

        loop {
            let (packet, last) = match outgoing.next_packet(self.remote_max(), PACKET_PREFIX_LENGTH)
            {
                Ok(packet) => packet,
                Err(error) => {
                    if !first {
                        let _ = self.abort_put();
                    }
                    return Err(error);
                }
            };

            let sent = (first && can_retry).then(|| packet.clone());
            self.write_request(&Request::new(Opcode::Put, last, packet))?;

            if !last && srm && !wait {
                first = false;
                continue;
            }

            let response = self.read_response()?;

            if let Some(sent) = sent {
                if let Some(answer) = self.answer_challenge(&response)? {
                    outgoing.rewind(sent);
                    outgoing.insert_early(answer);
                    can_retry = false;
                    continue;
                }
            }
            can_retry = false;

            if last {
                return expect_success(response);
            }

            if response.code != ResponseCode::Continue {
                return Err(Error::Response(Box::new(response)));
            }

            if requested_srm && confirms_srm(&response) {
                srm = true;
            }

            wait = srm
                && response
                    .headers
                    .single_response_mode_parameter()
                    .is_some_and(|parameter| parameter.requests_wait());
            first = false;
        }
    }

    /// Aborts a PUT; the server sends exactly one response, to the ABORT.
    fn abort_put(&mut self) -> Result<Response> {
        let headers = self.with_connection_id(Vec::new());
        self.write_request(&Request::new(Opcode::Abort, true, headers))?;

        self.read_response()
    }

    /// Aborts a GET. Under SRM the server may still be streaming the object, so
    /// responses are skipped until the one answering the ABORT arrives.
    fn abort_get(&mut self, srm: bool) -> Result<Response> {
        let headers = self.with_connection_id(Vec::new());
        self.write_request(&Request::new(Opcode::Abort, true, headers))?;

        loop {
            let response = self.read_response()?;
            let object_data = response.code == ResponseCode::Continue
                || response.headers.contains(HeaderID::EndOfBody);

            if !(srm && object_data) {
                return Ok(response);
            }
        }
    }

    /// Sends a single packet request, answering one authentication challenge.
    fn exchange(&mut self, mut request: Request) -> Result<Response> {
        let mut retried = false;

        loop {
            self.write_request(&request)?;

            let response = if request.opcode == Opcode::Connect {
                self.stream.read_connect_response()?
            } else {
                self.read_response()?
            };

            if !retried {
                if let Some(answer) = self.answer_challenge(&response)? {
                    insert_early(&mut request.headers, Some(answer));
                    retried = true;
                    continue;
                }
            }

            return Ok(response);
        }
    }

    /// Builds an Authenticate Response for an `Unauthorized` response, if possible.
    fn answer_challenge(&mut self, response: &Response) -> Result<Option<Header>> {
        if response.code != ResponseCode::Unauthorized {
            return Ok(None);
        }

        let Some(provider) = self.credentials.as_mut() else {
            return Ok(None);
        };

        // The first challenge is the most general one (OBEX section 3.6).
        let Some(challenge) = DigestChallenge::find_all(&response.headers)?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };

        Ok(provider(&challenge).map(|credentials| challenge.respond(&credentials).into()))
    }

    fn write_request(&mut self, request: &Request) -> Result<()> {
        let bytes = request.to_bytes()?;

        if request.opcode != Opcode::Connect && bytes.len() > self.remote_max() {
            return Err(Error::PacketTooLarge {
                length: bytes.len(),
                maximum: self.remote_max(),
            });
        }

        self.stream.write_packet(&bytes)
    }

    fn read_response(&mut self) -> Result<Response> {
        self.stream.read_response()
    }
}

fn expect_success(response: Response) -> Result<Response> {
    if response.code.is_success() {
        Ok(response)
    } else {
        Err(Error::Response(Box::new(response)))
    }
}

fn confirms_srm(response: &Response) -> bool {
    response.headers.single_response_mode() == Some(SingleResponseMode::Enable)
}

fn insert_early(headers: &mut Headers, header: Option<Header>) {
    if let Some(header) = header {
        let index = headers
            .iter()
            .take_while(|header| must_lead(header))
            .count();
        headers.insert(index, header);
    }
}

/// Moves non-body headers into `collected` and writes body data to `sink`.
fn collect<W: Write>(headers: Headers, collected: &mut Headers, sink: &mut W) -> io::Result<()> {
    for header in headers {
        match header {
            Header::Body(data) | Header::EndOfBody(data) => sink.write_all(&data)?,
            Header::SingleResponseMode(_) | Header::SingleResponseModeParameters(_) => {}
            header => collected.push(header),
        }
    }

    Ok(())
}
