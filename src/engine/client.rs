//! The OBEX client protocol, shared by the blocking and async clients.

use crate::action::{ActionID, Permissions};
use crate::auth::{Credentials, DigestChallenge, DigestResponse};
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

use super::body::{must_lead, Outgoing};
use super::io::{Discard, Framed, Sink, Source};

pub(crate) type CredentialProvider = Box<dyn FnMut(&DigestChallenge) -> Option<Credentials> + Send>;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum SrmState {
    Disabled,
    /// The server asked to enable SRM; the next PUT or GET confirms it.
    Pending,
    /// SRM is enabled for every operation on this connection.
    Enabled,
}

pub(crate) struct ClientEngine<T> {
    pub(crate) stream: Framed<T>,
    pub(crate) max_packet_length: u16,
    pub(crate) remote_max_packet_length: u16,
    pub(crate) connection_id: Option<u32>,
    pub(crate) srm_supported: bool,
    srm: SrmState,
    srm_wait: bool,
    pub(crate) credentials: Option<CredentialProvider>,
    pub(crate) server_password: Option<Vec<u8>>,
}

impl<T> ClientEngine<T> {
    pub(crate) fn new(transport: T) -> ClientEngine<T> {
        ClientEngine {
            stream: Framed::new(transport),
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

    pub(crate) fn single_response_mode_enabled(&self) -> bool {
        self.srm == SrmState::Enabled
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
}

impl<T: Source + Sink> ClientEngine<T> {
    pub(crate) async fn connect(&mut self, mut headers: Headers) -> Result<Response> {
        let challenge = self
            .server_password
            .as_ref()
            .map(|_| DigestChallenge::new());
        if let Some(challenge) = &challenge {
            headers.push(challenge.clone().into());
        }

        let requested_srm = headers.single_response_mode() == Some(SingleResponseMode::Enable);
        let request = Request::connect(ConnectParameters::new(self.max_packet_length), headers);
        let response = self.exchange(request).await?;

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

    pub(crate) async fn disconnect(&mut self) -> Result<Response> {
        let headers = self.with_connection_id(Vec::new());
        let response = self
            .exchange(Request::new(Opcode::Disconnect, true, headers))
            .await;

        self.connection_id = None;
        self.remote_max_packet_length = MINIMUM_PACKET_LENGTH;
        self.srm = SrmState::Disabled;
        self.srm_wait = false;

        expect_success(response?)
    }

    /// Runs a PUT. `body` is `None` when no body headers should be sent at all.
    pub(crate) async fn put<R: Source>(
        &mut self,
        headers: Vec<Header>,
        body: Option<R>,
    ) -> Result<Response> {
        let mut headers = self.with_connection_id(headers);
        let (srm_header, mut srm) = self.srm_header();
        let requested_srm = srm_header.is_some() && !srm;
        insert_early(&mut headers, srm_header);

        let mut outgoing = Outgoing::new(headers, body);
        let mut wait = std::mem::take(&mut self.srm_wait);
        let mut first = true;
        let mut can_retry = self.credentials.is_some();

        loop {
            let (packet, last) = match outgoing
                .next_packet(self.remote_max(), PACKET_PREFIX_LENGTH)
                .await
            {
                Ok(packet) => packet,
                Err(error) => {
                    if !first {
                        let _ = self.abort_put().await;
                    }
                    return Err(error);
                }
            };

            let sent = (first && can_retry).then(|| packet.clone());
            self.write_request(&Request::new(Opcode::Put, last, packet))
                .await?;

            if !last && srm && !wait {
                first = false;
                continue;
            }

            let response = self.stream.read_response().await?;

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

    /// Runs a GET, writing the body to `sink` and returning the other headers.
    pub(crate) async fn get_into<W: Sink>(
        &mut self,
        headers: Vec<Header>,
        mut sink: W,
    ) -> Result<Headers> {
        let mut headers = self.with_connection_id(headers);
        let (srm_header, mut srm) = self.srm_header();
        let requested_srm = srm_header.is_some() && !srm;
        insert_early(&mut headers, srm_header);

        let mut outgoing: Outgoing<Discard> = Outgoing::new(headers, None);
        let mut collected = Headers::new();
        let mut first = true;
        let mut can_retry = self.credentials.is_some();

        // Request phase: send every request header, the last packet with the Final bit.
        let mut response = loop {
            let (packet, last) = outgoing
                .next_packet(self.remote_max(), PACKET_PREFIX_LENGTH)
                .await?;
            let sent = (first && can_retry).then(|| packet.clone());
            self.write_request(&Request::new(Opcode::Get, last, packet))
                .await?;

            if !last && srm {
                first = false;
                continue;
            }

            let response = self.stream.read_response().await?;

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

            collect(response.headers, &mut collected, &mut Discard).await?;
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

            let delivered = collect(response.headers, &mut collected, &mut sink).await;

            if code.is_success() {
                delivered?;
                sink.flush().await?;
                return Ok(collected);
            }

            if let Err(error) = delivered {
                let _ = self.abort_get(srm).await;
                return Err(error.into());
            }

            if !srm || additional {
                self.write_request(&Request::new(Opcode::Get, true, Headers::new()))
                    .await?;
            }

            response = self.stream.read_response().await?;
        }
    }

    pub(crate) async fn set_path(
        &mut self,
        flags: SetPathFlags,
        name: Option<&str>,
    ) -> Result<Response> {
        let mut headers = self.with_connection_id(Vec::new());
        if let Some(name) = name {
            headers.push(Header::Name(name.to_string()));
        }

        expect_success(self.exchange(Request::set_path(flags, headers)).await?)
    }

    pub(crate) async fn set_path_root(&mut self) -> Result<Response> {
        let flags = SetPathFlags {
            backup: false,
            no_create: true,
        };

        self.set_path(flags, Some("")).await
    }

    pub(crate) async fn set_path_parent(&mut self) -> Result<Response> {
        let flags = SetPathFlags {
            backup: true,
            no_create: true,
        };

        self.set_path(flags, None).await
    }

    pub(crate) async fn set_path_child(&mut self, name: &str, create: bool) -> Result<Response> {
        let flags = SetPathFlags {
            backup: false,
            no_create: !create,
        };

        self.set_path(flags, Some(name)).await
    }

    pub(crate) async fn action(
        &mut self,
        action: ActionID,
        headers: Vec<Header>,
    ) -> Result<Response> {
        let mut all = vec![Header::ActionID(action)];
        all.extend(headers);
        let headers = self.with_connection_id(all);

        expect_success(
            self.exchange(Request::new(Opcode::Action, true, headers))
                .await?,
        )
    }

    pub(crate) async fn copy(&mut self, source: &str, destination: &str) -> Result<Response> {
        let headers = vec![
            Header::Name(source.to_string()),
            Header::DestName(destination.to_string()),
        ];

        self.action(ActionID::Copy, headers).await
    }

    pub(crate) async fn move_object(
        &mut self,
        source: &str,
        destination: &str,
    ) -> Result<Response> {
        let headers = vec![
            Header::Name(source.to_string()),
            Header::DestName(destination.to_string()),
        ];

        self.action(ActionID::MoveRename, headers).await
    }

    pub(crate) async fn set_permissions(
        &mut self,
        name: &str,
        permissions: Permissions,
    ) -> Result<Response> {
        let headers = vec![
            Header::Name(name.to_string()),
            Header::Permissions(permissions),
        ];

        self.action(ActionID::SetPermissions, headers).await
    }

    pub(crate) async fn session(
        &mut self,
        parameters: SessionParameters,
        headers: Vec<Header>,
    ) -> Result<Response> {
        let mut all = vec![parameters.into()];
        all.extend(headers);

        expect_success(
            self.exchange(Request::new(Opcode::Session, true, all))
                .await?,
        )
    }

    pub(crate) async fn abort(&mut self, headers: Vec<Header>) -> Result<Response> {
        let headers = self.with_connection_id(headers);

        self.exchange(Request::new(Opcode::Abort, true, headers))
            .await
    }

    /// Aborts a PUT; the server sends exactly one response, to the ABORT.
    async fn abort_put(&mut self) -> Result<Response> {
        let headers = self.with_connection_id(Vec::new());
        self.write_request(&Request::new(Opcode::Abort, true, headers))
            .await?;

        self.stream.read_response().await
    }

    /// Aborts a GET. Under SRM the server may still be streaming the object, so
    /// responses are skipped until the one answering the ABORT arrives.
    async fn abort_get(&mut self, srm: bool) -> Result<Response> {
        let headers = self.with_connection_id(Vec::new());
        self.write_request(&Request::new(Opcode::Abort, true, headers))
            .await?;

        loop {
            let response = self.stream.read_response().await?;
            let object_data = response.code == ResponseCode::Continue
                || response.headers.contains(HeaderID::EndOfBody);

            if !(srm && object_data) {
                return Ok(response);
            }
        }
    }

    /// Sends a single packet request, answering one authentication challenge.
    pub(crate) async fn exchange(&mut self, mut request: Request) -> Result<Response> {
        let mut retried = false;

        loop {
            self.write_request(&request).await?;

            let response = if request.opcode == Opcode::Connect {
                self.stream.read_connect_response().await?
            } else {
                self.stream.read_response().await?
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

    async fn write_request(&mut self, request: &Request) -> Result<()> {
        let bytes = request.to_bytes()?;

        if request.opcode != Opcode::Connect && bytes.len() > self.remote_max() {
            return Err(Error::PacketTooLarge {
                length: bytes.len(),
                maximum: self.remote_max(),
            });
        }

        self.stream.write_packet(&bytes).await
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
async fn collect<W: Sink>(
    headers: Headers,
    collected: &mut Headers,
    sink: &mut W,
) -> std::io::Result<()> {
    for header in headers {
        match header {
            Header::Body(data) | Header::EndOfBody(data) => sink.write_all(&data).await?,
            Header::SingleResponseMode(_) | Header::SingleResponseModeParameters(_) => {}
            header => collected.push(header),
        }
    }

    Ok(())
}
