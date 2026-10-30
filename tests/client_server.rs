//! End to end tests running the `Client` against the `Server` over socket pairs.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

use obex::action::{ActionID, Permissions};
use obex::auth::{Credentials, DigestChallenge};
use obex::client::Client;
use obex::header::{Header, HeaderValue};
use obex::opcode::Opcode;
use obex::packet::{Request, Response};
use obex::response::ResponseCode;
use obex::server::{Authentication, Handler, Object, Server};
use obex::target::{FOLDER_BROWSING, MESSAGE_ACCESS};
use obex::tlv::ApplicationParameters;
use obex::Error;

/// An in-memory folder tree served over OBEX.
#[derive(Default)]
struct Store {
    files: HashMap<String, Vec<u8>>,
    path: Vec<String>,
    aborts: usize,
    password: Option<Vec<u8>>,
    connect_targets: Vec<Vec<u8>>,
}

impl Store {
    fn key(&self, name: &str) -> String {
        let mut parts = self.path.clone();
        parts.push(name.to_string());
        parts.join("/")
    }
}

impl Handler for Store {
    fn connect(&mut self, request: &Request) -> Response {
        if let Some(target) = request.headers.target() {
            self.connect_targets.push(target.to_vec());
        }
        Response::new(ResponseCode::Success)
    }

    fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
        let Some(name) = request.headers.name() else {
            return Response::new(ResponseCode::BadRequest);
        };
        let key = self.key(name);

        match body {
            Some(body) => {
                self.files.insert(key, body);
                Response::new(ResponseCode::Success)
            }
            None => match self.files.remove(&key) {
                Some(_) => Response::new(ResponseCode::Success),
                None => Response::new(ResponseCode::NotFound),
            },
        }
    }

    fn get(&mut self, request: &Request) -> Result<Object, Response> {
        if request.headers.content_type() == Some("x-test/parameters-only") {
            let parameters = ApplicationParameters::new().with_u16(0x12, 42);
            return Ok(Object::headers_only([Header::ApplicationParameters(
                parameters,
            )]));
        }

        if request.headers.content_type() == Some("x-test/echo-description") {
            let description: String = request
                .headers
                .iter()
                .filter_map(|header| match header {
                    Header::Description(text) => Some(text.as_str()),
                    _ => None,
                })
                .collect();
            return Ok(Object::new(Vec::<Header>::new(), description.into_bytes()));
        }

        let name = request.headers.name().unwrap_or_default();
        match self.files.get(&self.key(name)) {
            Some(body) => Ok(Object::new(
                [Header::Length(body.len() as u32)],
                body.clone(),
            )),
            None => Err(Response::new(ResponseCode::NotFound)),
        }
    }

    fn set_path(&mut self, request: &Request) -> Response {
        let flags = request.set_path.unwrap_or_default();

        if flags.backup && self.path.pop().is_none() {
            return Response::new(ResponseCode::NotFound);
        }

        match request.headers.name() {
            Some("") => self.path.clear(),
            Some(name) => self.path.push(name.to_string()),
            None => {}
        }

        Response::new(ResponseCode::Success)
    }

    fn action(&mut self, request: &Request) -> Response {
        let (Some(name), action) = (request.headers.name(), request.headers.action_id()) else {
            return Response::new(ResponseCode::BadRequest);
        };
        let source = self.key(name);

        match action {
            Some(ActionID::Copy) | Some(ActionID::MoveRename) => {
                let destination = self.key(request.headers.dest_name().unwrap_or_default());
                let Some(body) = self.files.get(&source).cloned() else {
                    return Response::new(ResponseCode::NotFound);
                };
                if action == Some(ActionID::MoveRename) {
                    self.files.remove(&source);
                }
                self.files.insert(destination, body);
                Response::new(ResponseCode::Success)
            }
            Some(ActionID::SetPermissions) if request.headers.permissions().is_some() => {
                Response::new(ResponseCode::Success)
            }
            _ => Response::new(ResponseCode::NotImplemented),
        }
    }

    fn user_defined(&mut self, request: &Request) -> Response {
        Response::with_headers(ResponseCode::Success, request.headers.clone())
    }

    fn abort(&mut self, _request: &Request) {
        self.aborts += 1;
    }

    fn password(&mut self, user_id: Option<&[u8]>) -> Option<Vec<u8>> {
        match user_id {
            Some(b"admin") | None => self.password.clone(),
            Some(_) => None,
        }
    }

    fn credentials(&mut self, _challenge: &DigestChallenge) -> Option<Credentials> {
        self.password.clone().map(Credentials::new)
    }
}

/// Counts the packets the server writes.
struct Counted<T> {
    inner: T,
    writes: Arc<AtomicUsize>,
}

impl<T: Read> Read for Counted<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<T: Write> Write for Counted<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

type TestServer<T> = Server<T, Store>;

fn start_on<T, F>(transport: T, store: Store, configure: F) -> thread::JoinHandle<Store>
where
    T: Read + Write + Send + 'static,
    F: FnOnce(TestServer<T>) -> TestServer<T> + Send + 'static,
{
    thread::spawn(move || {
        let mut server = configure(Server::new(transport, store));
        server.run().expect("server failed");
        server.into_parts().1
    })
}

fn start<F>(configure: F) -> (UnixStream, thread::JoinHandle<Store>)
where
    F: FnOnce(TestServer<UnixStream>) -> TestServer<UnixStream> + Send + 'static,
{
    let (client, server) = UnixStream::pair().unwrap();
    (client, start_on(server, Store::default(), configure))
}

fn object(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 7 % 251) as u8).collect()
}

#[test]
fn directed_connection_put_and_get() {
    let (socket, server) = start(|server| server.with_max_packet_length(512));
    let mut client = Client::new(socket).with_max_packet_length(300);

    let response = client
        .connect([Header::Target(FOLDER_BROWSING.to_vec())])
        .unwrap();

    assert_eq!(Some(FOLDER_BROWSING.as_slice()), response.headers.who());
    assert!(client.connection_id().is_some());
    assert_eq!(512, client.remote_max_packet_length());

    let body = object(100_000);
    client
        .put(
            [
                Header::Name("big.bin".to_string()),
                Header::Length(body.len() as u32),
            ],
            &body,
        )
        .unwrap();

    let fetched = client.get([Header::Name("big.bin".to_string())]).unwrap();
    assert_eq!(body, fetched.body);
    assert_eq!(Some(body.len() as u32), fetched.headers.length());

    client.disconnect().unwrap();
    assert_eq!(None, client.connection_id());
    drop(client);

    let store = server.join().unwrap();
    assert_eq!(vec![FOLDER_BROWSING.to_vec()], store.connect_targets);
}

#[test]
fn delete_and_create_empty() {
    let (socket, _server) = start(|server| server);
    let mut client = Client::new(socket);
    client.connect([]).unwrap();

    client
        .put([Header::Name("empty.txt".to_string())], &[])
        .unwrap();
    assert_eq!(
        Vec::<u8>::new(),
        client
            .get([Header::Name("empty.txt".to_string())])
            .unwrap()
            .body
    );

    client
        .delete([Header::Name("empty.txt".to_string())])
        .unwrap();

    let error = client
        .get([Header::Name("empty.txt".to_string())])
        .unwrap_err();
    assert_eq!(Some(ResponseCode::NotFound), error.response_code());

    let error = client
        .delete([Header::Name("missing.txt".to_string())])
        .unwrap_err();
    assert_eq!(Some(ResponseCode::NotFound), error.response_code());
}

#[test]
fn set_path_and_actions() {
    let (socket, server) = start(|server| server);
    let mut client = Client::new(socket);
    client
        .connect([Header::Target(FOLDER_BROWSING.to_vec())])
        .unwrap();

    client.set_path_child("docs", true).unwrap();
    client
        .put([Header::Name("a.txt".to_string())], b"hello")
        .unwrap();
    client.copy("a.txt", "b.txt").unwrap();
    client.move_object("b.txt", "c.txt").unwrap();
    client
        .set_permissions(
            "c.txt",
            Permissions {
                user: Permissions::READ | Permissions::WRITE,
                ..Permissions::default()
            },
        )
        .unwrap();

    let error = client.copy("missing.txt", "x.txt").unwrap_err();
    assert_eq!(Some(ResponseCode::NotFound), error.response_code());

    client.set_path_parent().unwrap();
    client
        .put([Header::Name("root.txt".to_string())], b"root")
        .unwrap();
    client.set_path_child("docs", false).unwrap();
    client.set_path_root().unwrap();

    let error = client.set_path_parent().unwrap_err();
    assert_eq!(Some(ResponseCode::NotFound), error.response_code());

    client.disconnect().unwrap();
    drop(client);

    let store = server.join().unwrap();
    let mut names: Vec<&str> = store.files.keys().map(String::as_str).collect();
    names.sort();
    assert_eq!(vec!["docs/a.txt", "docs/c.txt", "root.txt"], names);
}

#[test]
fn single_response_mode_per_operation() {
    let writes = Arc::new(AtomicUsize::new(0));
    let (socket, server_socket) = UnixStream::pair().unwrap();
    let counted = Counted {
        inner: server_socket,
        writes: writes.clone(),
    };
    let _server = start_on(counted, Store::default(), |server| {
        server
            .with_single_response_mode(true)
            .with_max_packet_length(1024)
    });

    let mut client = Client::new(socket)
        .with_single_response_mode(true)
        .with_max_packet_length(1024);
    client
        .connect([Header::Target(MESSAGE_ACCESS.to_vec())])
        .unwrap();
    assert!(!client.single_response_mode_enabled());

    let body = object(50_000);
    let before = writes.load(Ordering::SeqCst);
    client
        .put([Header::Name("srm.bin".to_string())], &body)
        .unwrap();
    // One response confirming SRM and one final response, instead of ~50.
    assert_eq!(2, writes.load(Ordering::SeqCst) - before);

    let fetched = client.get([Header::Name("srm.bin".to_string())]).unwrap();
    assert_eq!(body, fetched.body);

    // SRM ends with each operation, so the next one negotiates it again.
    client
        .put([Header::Name("again.bin".to_string())], &body)
        .unwrap();
    assert_eq!(
        body,
        client
            .get([Header::Name("again.bin".to_string())])
            .unwrap()
            .body
    );
}

#[test]
fn single_response_mode_per_connection() {
    let (socket, _server) = start(|server| server.with_single_response_mode(true));
    let mut client = Client::new(socket).with_single_response_mode(true);

    let response = client
        .connect([Header::SingleResponseMode(
            obex::srm::SingleResponseMode::Enable,
        )])
        .unwrap();
    assert_eq!(
        Some(obex::srm::SingleResponseMode::Enable),
        response.headers.single_response_mode()
    );
    assert!(client.single_response_mode_enabled());

    let body = object(20_000);
    client
        .put([Header::Name("c.bin".to_string())], &body)
        .unwrap();
    assert_eq!(
        body,
        client
            .get([Header::Name("c.bin".to_string())])
            .unwrap()
            .body
    );

    // A refused operation must not desynchronize the pipelined packets.
    let error = client
        .get([Header::Name("missing".to_string())])
        .unwrap_err();
    assert_eq!(Some(ResponseCode::NotFound), error.response_code());
    assert_eq!(
        body,
        client
            .get([Header::Name("c.bin".to_string())])
            .unwrap()
            .body
    );
}

#[test]
fn single_response_mode_falls_back_when_unsupported() {
    let (socket, _server) = start(|server| server);
    let mut client = Client::new(socket).with_single_response_mode(true);
    client.connect([]).unwrap();

    let body = object(10_000);
    client
        .put([Header::Name("f.bin".to_string())], &body)
        .unwrap();
    assert_eq!(
        body,
        client
            .get([Header::Name("f.bin".to_string())])
            .unwrap()
            .body
    );
}

#[test]
fn multi_packet_get_request_headers() {
    for srm in [false, true] {
        let (socket, _server) = start(move |server| {
            server
                .with_max_packet_length(255)
                .with_single_response_mode(srm)
        });
        let mut client = Client::new(socket).with_single_response_mode(srm);
        client.connect([]).unwrap();

        let parts: Vec<String> = (0..10).map(|i| format!("{:0>100}", i)).collect();
        let mut headers = vec![Header::Type("x-test/echo-description".to_string())];
        headers.extend(parts.iter().cloned().map(Header::Description));

        let response = client.get(headers).unwrap();
        assert_eq!(parts.concat().into_bytes(), response.body, "srm: {}", srm);
    }
}

#[test]
fn headers_only_get() {
    let (socket, _server) = start(|server| server);
    let mut client = Client::new(socket);
    client.connect([]).unwrap();

    let response = client
        .get([Header::Type("x-test/parameters-only".to_string())])
        .unwrap();

    assert!(response.body.is_empty());
    assert_eq!(
        Some(42),
        response
            .headers
            .application_parameters()
            .and_then(|parameters| parameters.get_u16(0x12))
    );
}

struct FailingReader {
    remaining: usize,
}

impl Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("disk on fire"));
        }
        let length = buf.len().min(self.remaining);
        buf[..length].fill(1);
        self.remaining -= length;
        Ok(length)
    }
}

struct FailingWriter {
    remaining: usize,
}

impl Write for FailingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.remaining < buf.len() {
            return Err(io::Error::other("disk full"));
        }
        self.remaining -= buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn failing_body_source_and_sink_abort() {
    for srm in [false, true] {
        // Small packets so both failures happen in the middle of an operation.
        let (socket, server) = start(move |server| {
            server
                .with_single_response_mode(srm)
                .with_max_packet_length(1024)
        });
        let mut client = Client::new(socket)
            .with_single_response_mode(srm)
            .with_max_packet_length(1024);
        client.connect([]).unwrap();

        let error = client
            .put_from(
                [Header::Name("broken.bin".to_string())],
                FailingReader { remaining: 5_000 },
            )
            .unwrap_err();
        assert!(matches!(error, Error::Io(_)), "srm: {} {:?}", srm, error);

        let body = object(30_000);
        client
            .put([Header::Name("ok.bin".to_string())], &body)
            .unwrap();

        let error = client
            .get_into(
                [Header::Name("ok.bin".to_string())],
                FailingWriter { remaining: 1_000 },
            )
            .unwrap_err();
        assert!(matches!(error, Error::Io(_)), "srm: {} {:?}", srm, error);

        // The connection is still in sync after both aborts.
        assert_eq!(
            body,
            client
                .get([Header::Name("ok.bin".to_string())])
                .unwrap()
                .body
        );

        client.disconnect().unwrap();
        drop(client);

        let store = server.join().unwrap();
        assert!(!store.files.contains_key("broken.bin"));
        assert_eq!(2, store.aborts, "srm: {}", srm);
    }
}

#[test]
fn server_authenticates_client() {
    let (client_socket, server_socket) = UnixStream::pair().unwrap();
    let store = Store {
        password: Some(b"1234".to_vec()),
        ..Store::default()
    };
    let _server = start_on(server_socket, store, |server| {
        server.with_authentication(Authentication {
            user_id_required: true,
            ..Authentication::default()
        })
    });

    let mut client = Client::new(client_socket).with_credentials_provider(|challenge| {
        assert!(challenge.user_id_required);
        Some(Credentials::with_user_id("admin", "1234"))
    });
    client
        .connect([Header::Target(FOLDER_BROWSING.to_vec())])
        .unwrap();
    client
        .put([Header::Name("secret.txt".to_string())], b"s3cr3t")
        .unwrap();
}

#[test]
fn server_rejects_wrong_password() {
    let (client_socket, server_socket) = UnixStream::pair().unwrap();
    let store = Store {
        password: Some(b"1234".to_vec()),
        ..Store::default()
    };
    let _server = start_on(server_socket, store, |server| {
        server.with_authentication(Authentication::default())
    });

    let mut client = Client::new(client_socket).with_credentials(Credentials::new("0000"));
    let error = client.connect([]).unwrap_err();
    assert_eq!(Some(ResponseCode::Unauthorized), error.response_code());

    // Operations are refused until the client authenticates.
    let error = client
        .put([Header::Name("x".to_string())], b"x")
        .unwrap_err();
    assert_eq!(Some(ResponseCode::Unauthorized), error.response_code());

    // A DISCONNECT may not be refused, even by an unauthenticated client.
    client.disconnect().unwrap();

    let mut client = Client::new(client.into_inner());
    let error = client.connect([]).unwrap_err();
    assert_eq!(Some(ResponseCode::Unauthorized), error.response_code());
}

#[test]
fn client_authenticates_server() {
    let (client_socket, server_socket) = UnixStream::pair().unwrap();
    let store = Store {
        password: Some(b"pin".to_vec()),
        ..Store::default()
    };
    let _server = start_on(server_socket, store, |server| server);

    let mut client = Client::new(client_socket).with_server_authentication("pin");
    client.connect([]).unwrap();
    client.disconnect().unwrap();

    let mut client = Client::new(client.into_inner()).with_server_authentication("nip");
    assert!(matches!(
        client.connect([]),
        Err(Error::AuthenticationFailed)
    ));
}

#[test]
fn unknown_connection_ids_and_opcodes() {
    let (socket, _server) = start(|server| server);
    let mut client = Client::new(socket);
    client
        .connect([Header::Target(FOLDER_BROWSING.to_vec())])
        .unwrap();

    let response = client
        .request(Request::new(
            Opcode::Get,
            true,
            [Header::ConnectionID(0xDEAD), Header::Name("x".to_string())],
        ))
        .unwrap();
    assert_eq!(ResponseCode::ServiceUnavailable, response.code);

    let custom = Header::Other {
        id: 0x30,
        value: HeaderValue::Unicode("ping".to_string()),
    };
    let response = client
        .request(Request::new(
            Opcode::UserDefined(0x10),
            true,
            [custom.clone()],
        ))
        .unwrap();
    assert_eq!(ResponseCode::Success, response.code);
    assert_eq!(Some(&custom), response.headers.iter().next());

    // A reserved opcode is answered with Not Implemented and the server keeps serving.
    client.get_mut().write_all(&[0x84, 0x00, 0x03]).unwrap();
    let mut answer = [0u8; 3];
    client.get_mut().read_exact(&mut answer).unwrap();
    assert_eq!([0xD1, 0x00, 0x03], answer);

    client.disconnect().unwrap();
}

/// A sequenced packet socket: every write is one message, and a read returns at most
/// one message, discarding whatever does not fit, like L2CAP `SOCK_SEQPACKET`.
struct SeqPacket {
    sender: mpsc::Sender<Vec<u8>>,
    receiver: mpsc::Receiver<Vec<u8>>,
    mtu: usize,
}

fn seqpacket_pair(mtu: usize) -> (SeqPacket, SeqPacket) {
    let (a_sender, a_receiver) = mpsc::channel();
    let (b_sender, b_receiver) = mpsc::channel();

    (
        SeqPacket {
            sender: a_sender,
            receiver: b_receiver,
            mtu,
        },
        SeqPacket {
            sender: b_sender,
            receiver: a_receiver,
            mtu,
        },
    )
}

impl Read for SeqPacket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.receiver.recv() {
            Ok(message) => {
                let length = message.len().min(buf.len());
                buf[..length].copy_from_slice(&message[..length]);
                Ok(length)
            }
            Err(_) => Ok(0),
        }
    }
}

impl Write for SeqPacket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.mtu {
            return Err(io::Error::other("message larger than the MTU"));
        }
        self.sender
            .send(buf.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn l2cap_style_sequenced_packets_with_srm() {
    const MTU: u16 = 672;

    let (client_socket, server_socket) = seqpacket_pair(usize::from(MTU));
    let server = start_on(server_socket, Store::default(), |server| {
        server
            .with_max_packet_length(MTU)
            .with_single_response_mode(true)
    });

    let mut client = Client::new(client_socket)
        .with_max_packet_length(MTU)
        .with_single_response_mode(true);
    client
        .connect([Header::Target(MESSAGE_ACCESS.to_vec())])
        .unwrap();

    let body = object(40_000);
    client
        .put([Header::Name("l2cap.bin".to_string())], &body)
        .unwrap();
    assert_eq!(
        body,
        client
            .get([Header::Name("l2cap.bin".to_string())])
            .unwrap()
            .body
    );

    client.disconnect().unwrap();
    drop(client);
    server.join().unwrap();
}

/// Runs a scripted server on the other end of a socket pair.
fn scripted<F>(script: F) -> (UnixStream, thread::JoinHandle<()>)
where
    F: FnOnce(&mut obex::transport::PacketStream<UnixStream>) + Send + 'static,
{
    let (client, server) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || {
        let mut stream = obex::transport::PacketStream::new(server);
        script(&mut stream);
    });

    (client, handle)
}

fn connect_response(headers: Vec<Header>) -> Response {
    Response {
        connect: Some(obex::packet::ConnectParameters::new(4096)),
        ..Response::with_headers(ResponseCode::Success, headers)
    }
}

#[test]
fn client_answers_challenge_on_an_operation() {
    let (socket, script) = scripted(|stream| {
        stream.read_request().unwrap();
        stream.write_response(&connect_response(vec![])).unwrap();

        // Refuse the first PUT packet with a challenge.
        let challenge = DigestChallenge::new();
        let first = stream.read_request().unwrap();
        assert!(first.is_final);
        stream
            .write_response(&Response::with_headers(
                ResponseCode::Unauthorized,
                [challenge.clone().into()],
            ))
            .unwrap();

        // The retry carries the same object and a valid digest.
        let retry = stream.read_request().unwrap();
        let digest = obex::auth::DigestResponse::find(&retry.headers)
            .unwrap()
            .unwrap();
        assert!(digest.verify(&challenge, b"pw"));
        assert_eq!(first.headers.name(), retry.headers.name());
        assert_eq!(Some(b"payload".to_vec()), retry.headers.body());

        stream
            .write_response(&Response::new(ResponseCode::Success))
            .unwrap();
    });

    let mut client = Client::new(socket).with_credentials(Credentials::new("pw"));
    client.connect([]).unwrap();
    client
        .put([Header::Name("guarded".to_string())], b"payload")
        .unwrap();
    script.join().unwrap();
}

#[test]
fn client_confirms_server_initiated_srm() {
    let (socket, script) = scripted(|stream| {
        stream.read_request().unwrap();
        stream
            .write_response(&connect_response(vec![Header::SingleResponseMode(
                obex::srm::SingleResponseMode::Enable,
            )]))
            .unwrap();

        // Every PUT packet arrives without waiting for a response.
        let first = stream.read_request().unwrap();
        assert_eq!(
            Some(obex::srm::SingleResponseMode::Enable),
            first.headers.single_response_mode()
        );
        let mut packets = 1;
        let mut request = first;
        while !request.is_final {
            request = stream.read_request().unwrap();
            packets += 1;
        }
        assert!(packets > 2);

        stream
            .write_response(&Response::new(ResponseCode::Success))
            .unwrap();
    });

    let mut client = Client::new(socket).with_single_response_mode(true);
    client.connect([]).unwrap();
    client
        .put([Header::Name("fast".to_string())], &object(20_000))
        .unwrap();
    assert!(client.single_response_mode_enabled());
    script.join().unwrap();
}

#[test]
fn client_honors_srm_wait() {
    let (socket, script) = scripted(|stream| {
        stream.read_request().unwrap();
        stream.write_response(&connect_response(vec![])).unwrap();

        // Confirm SRM but ask the client to wait after its next packet.
        stream.read_request().unwrap();
        stream
            .write_response(&Response::with_headers(
                ResponseCode::Continue,
                [
                    Header::SingleResponseMode(obex::srm::SingleResponseMode::Enable),
                    Header::SingleResponseModeParameters(
                        obex::srm::SingleResponseModeParameter::Wait,
                    ),
                ],
            ))
            .unwrap();

        // The client waits for this response before streaming the rest.
        stream.read_request().unwrap();
        stream
            .write_response(&Response::new(ResponseCode::Continue))
            .unwrap();

        let mut request = stream.read_request().unwrap();
        while !request.is_final {
            request = stream.read_request().unwrap();
        }
        stream
            .write_response(&Response::new(ResponseCode::Success))
            .unwrap();
    });

    let mut client = Client::new(socket).with_single_response_mode(true);
    client.connect([]).unwrap();
    client
        .put([Header::Name("paced".to_string())], &object(20_000))
        .unwrap();
    script.join().unwrap();
}

#[test]
fn oversized_objects_are_refused() {
    for srm in [false, true] {
        let (socket, server) = start(move |server| {
            server
                .with_max_object_size(10_000)
                .with_max_packet_length(1024)
                .with_single_response_mode(srm)
        });
        let mut client = Client::new(socket).with_single_response_mode(srm);
        client.connect([]).unwrap();

        let error = client
            .put([Header::Name("huge.bin".to_string())], &object(50_000))
            .unwrap_err();
        assert_eq!(
            Some(ResponseCode::RequestedEntityTooLarge),
            error.response_code(),
            "srm: {}",
            srm
        );

        // The connection is still usable afterwards.
        client
            .put([Header::Name("small.bin".to_string())], &object(5_000))
            .unwrap();
        client.disconnect().unwrap();
        drop(client);

        let store = server.join().unwrap();
        assert!(!store.files.contains_key("huge.bin"), "srm: {}", srm);
        assert!(store.files.contains_key("small.bin"), "srm: {}", srm);
    }
}
