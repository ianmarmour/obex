//! The OBEX server protocol, shared by the blocking and async servers.

use std::collections::HashSet;
use std::future::Future;

use crate::auth::{Credentials, DigestChallenge, DigestResponse};
use crate::error::{Error, Result};
use crate::header::{Header, HeaderID, Headers};
use crate::opcode::Opcode;
use crate::packet::{
    ConnectParameters, Request, Response, MAXIMUM_PACKET_LENGTH, MINIMUM_PACKET_LENGTH,
    PACKET_PREFIX_LENGTH,
};
use crate::response::ResponseCode;
use crate::server::Authentication;
use crate::srm::SingleResponseMode;

use super::body::Outgoing;
use super::io::{Framed, Sink, Source};

/// The application logic as seen by the engine. The public blocking and async
/// `Handler` traits are adapted to this.
pub(crate) trait EngineHandler {
    /// The reader of a GET response body.
    type Body: Source;

    fn connect(&mut self, request: &Request) -> impl Future<Output = Response>;

    fn disconnect(&mut self, request: &Request) -> impl Future<Output = Response>;

    fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> impl Future<Output = Response>;

    fn get(
        &mut self,
        request: &Request,
    ) -> impl Future<Output = std::result::Result<(Headers, Option<Self::Body>), Response>>;

    fn set_path(&mut self, request: &Request) -> impl Future<Output = Response>;

    fn action(&mut self, request: &Request) -> impl Future<Output = Response>;

    fn session(&mut self, request: &Request) -> impl Future<Output = Response>;

    fn user_defined(&mut self, request: &Request) -> impl Future<Output = Response>;

    fn abort(&mut self, request: &Request) -> impl Future<Output = ()>;

    fn password(&mut self, user_id: Option<&[u8]>) -> impl Future<Output = Option<Vec<u8>>>;

    fn credentials(
        &mut self,
        challenge: &DigestChallenge,
    ) -> impl Future<Output = Option<Credentials>>;
}

pub(crate) struct ServerEngine<T, H> {
    pub(crate) stream: Framed<T>,
    pub(crate) handler: H,
    pub(crate) max_packet_length: u16,
    remote_max_packet_length: u16,
    pub(crate) srm_supported: bool,
    srm_enabled: bool,
    connections: HashSet<u32>,
    next_connection_id: u32,
    pub(crate) authentication: Option<Authentication>,
    authenticated: bool,
    challenge: Option<DigestChallenge>,
    pub(crate) max_object_size: usize,
}

impl<T, H> ServerEngine<T, H> {
    pub(crate) fn new(transport: T, handler: H) -> ServerEngine<T, H> {
        ServerEngine {
            stream: Framed::new(transport),
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
}

impl<T: Source + Sink, H: EngineHandler> ServerEngine<T, H> {
    pub(crate) async fn run(&mut self) -> Result<()> {
        loop {
            match self.handle_next().await {
                Ok(()) => {}
                Err(Error::Disconnected) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) async fn handle_next(&mut self) -> Result<()> {
        let packet = self.stream.read_packet().await?;

        let request = match Request::parse(&packet) {
            Ok((_, request)) => request,
            Err(_) => {
                let code = match Opcode::from_byte(packet[0]) {
                    Ok(_) => ResponseCode::BadRequest,
                    Err(_) => ResponseCode::NotImplemented,
                };
                return self.send(Response::new(code)).await;
            }
        };

        self.dispatch(request).await
    }

    async fn dispatch(&mut self, request: Request) -> Result<()> {
        match request.opcode {
            Opcode::Connect => return self.handle_connect(request).await,
            Opcode::Abort => {
                // Nothing is in progress between operations.
                self.handler.abort(&request).await;
                return self.send(Response::new(ResponseCode::Success)).await;
            }
            _ => {}
        }

        if let Some(rejection) = self.rejection(&request) {
            return self.reject(request, rejection).await;
        }

        match request.opcode {
            Opcode::Disconnect => self.handle_disconnect(request).await,
            Opcode::Put => self.handle_put(request).await,
            Opcode::Get => self.handle_get(request).await,
            Opcode::SetPath => {
                let response = self.handler.set_path(&request).await;
                self.send(response).await
            }
            _ => self.handle_headers_only(request).await,
        }
    }

    /// Refuses an operation. With SRM enabled the client keeps sending the request
    /// without waiting, so its remaining packets are consumed first.
    async fn reject(&mut self, mut request: Request, rejection: Response) -> Result<()> {
        if self.srm_enabled && matches!(request.opcode, Opcode::Put | Opcode::Get) {
            while !request.is_final {
                request = self.stream.read_request().await?;

                if request.opcode == Opcode::Abort {
                    self.handler.abort(&request).await;
                    return self.send(Response::new(ResponseCode::Success)).await;
                }
            }
        }

        self.send(rejection).await
    }

    async fn handle_connect(&mut self, request: Request) -> Result<()> {
        let parameters = request.connect.unwrap_or_default();
        self.remote_max_packet_length = parameters.max_packet_length.max(MINIMUM_PACKET_LENGTH);

        if let Some(authentication) = self.authentication.clone() {
            if !self.verify_client(&request).await {
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
                return self.send_connect(response).await;
            }

            self.authenticated = true;
            self.challenge = None;
        }

        let mut response = self.handler.connect(&request).await;

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
                if let Some(credentials) = self.handler.credentials(&challenge).await {
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

        self.send_connect(response).await
    }

    async fn verify_client(&mut self, request: &Request) -> bool {
        let Some(challenge) = self.challenge.clone() else {
            return false;
        };

        let Some(Ok(digest)) = DigestResponse::find(&request.headers) else {
            return false;
        };

        match self.handler.password(digest.user_id.as_deref()).await {
            Some(password) => digest.verify(&challenge, &password),
            None => false,
        }
    }

    async fn handle_disconnect(&mut self, request: Request) -> Result<()> {
        let response = self.handler.disconnect(&request).await;

        if let Some(id) = request.headers.connection_id() {
            self.connections.remove(&id);
        }

        if request.headers.connection_id().is_none() || self.connections.is_empty() {
            self.connections.clear();
            self.srm_enabled = false;
            self.authenticated = false;
            self.remote_max_packet_length = MINIMUM_PACKET_LENGTH;
        }

        self.send(response).await
    }

    async fn handle_put(&mut self, mut request: Request) -> Result<()> {
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
                        return self.send(rejection).await;
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

                self.send(response).await?;
            }

            request = match self.next_request(Opcode::Put).await? {
                Some(request) => request,
                None => return Ok(()),
            };
        }

        let request = Request::new(Opcode::Put, true, headers);
        let response = match rejection {
            Some(rejection) => rejection,
            None => self.handler.put(&request, body).await,
        };

        self.send(response).await
    }

    async fn handle_get(&mut self, mut request: Request) -> Result<()> {
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

                self.send(response).await?;
            }

            request = match self.next_request(Opcode::Get).await? {
                Some(request) => request,
                None => return Ok(()),
            };
        }

        let request = Request::new(Opcode::Get, true, headers);
        let (headers, body) = match self.handler.get(&request).await {
            Ok(object) => object,
            Err(response) => return self.send(response).await,
        };

        let mut headers = headers.into_vec();
        if confirm_srm {
            headers.insert(0, Header::SingleResponseMode(SingleResponseMode::Enable));
            srm = true;
        }

        let mut outgoing = Outgoing::new(headers, body);

        // Response phase: send the object, waiting for continuation requests unless SRM is on.
        loop {
            let (packet, last) = match outgoing
                .next_packet(
                    usize::from(self.remote_max_packet_length),
                    PACKET_PREFIX_LENGTH,
                )
                .await
            {
                Ok(packet) => packet,
                Err(_) => {
                    return self
                        .send(Response::new(ResponseCode::InternalServerError))
                        .await
                }
            };

            let code = if last {
                ResponseCode::Success
            } else {
                ResponseCode::Continue
            };
            self.send(Response::with_headers(code, packet)).await?;

            if last {
                return Ok(());
            }

            if !srm || wait {
                match self.next_request(Opcode::Get).await? {
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
    async fn handle_headers_only(&mut self, mut request: Request) -> Result<()> {
        let opcode = request.opcode;
        let mut headers = Headers::new();

        loop {
            let is_final = request.is_final;
            headers.extend(request.headers);

            if is_final {
                break;
            }

            self.send(Response::new(ResponseCode::Continue)).await?;

            request = match self.next_request(opcode).await? {
                Some(request) => request,
                None => return Ok(()),
            };
        }

        let request = Request::new(opcode, true, headers);
        let response = match opcode {
            Opcode::Action => self.handler.action(&request).await,
            Opcode::Session => self.handler.session(&request).await,
            _ => self.handler.user_defined(&request).await,
        };

        self.send(response).await
    }

    /// Reads the next packet of an operation. Returns `None` once an ABORT has been
    /// answered, which ends the operation.
    async fn next_request(&mut self, opcode: Opcode) -> Result<Option<Request>> {
        let request = self.stream.read_request().await?;

        if request.opcode == Opcode::Abort {
            self.handler.abort(&request).await;
            self.send(Response::new(ResponseCode::Success)).await?;
            return Ok(None);
        }

        if request.opcode != opcode {
            self.send(Response::new(ResponseCode::BadRequest)).await?;
            return Err(Error::Protocol(
                "a new operation started before the last one ended",
            ));
        }

        Ok(Some(request))
    }

    async fn send_connect(&mut self, mut response: Response) -> Result<()> {
        response.connect = Some(ConnectParameters::new(self.max_packet_length));
        self.send(response).await
    }

    async fn send(&mut self, response: Response) -> Result<()> {
        let bytes = response.to_bytes()?;

        if bytes.len() > usize::from(self.remote_max_packet_length) {
            // The handler produced headers the client cannot receive.
            let mut fallback = Response::new(ResponseCode::InternalServerError);
            fallback.connect = response.connect;
            return self.stream.write_response(&fallback).await;
        }

        self.stream.write_packet(&bytes).await
    }
}
