//! End to end tests of the async API, run with `cargo test --features tokio`.
#![cfg(feature = "tokio")]

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use obex::auth::{Credentials, DigestChallenge};
use obex::header::Header;
use obex::packet::{Request, Response};
use obex::response::ResponseCode;
use obex::target::{FOLDER_BROWSING, MESSAGE_ACCESS};
use obex::tokio::{Authentication, Client, Handler, Object, PacketStream, Server};
use obex::Error;
use tokio::io::{duplex, AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

#[derive(Default)]
struct Store {
    files: HashMap<String, Vec<u8>>,
    path: Vec<String>,
    aborts: usize,
    password: Option<Vec<u8>>,
}

impl Store {
    fn key(&self, name: &str) -> String {
        let mut parts = self.path.clone();
        parts.push(name.to_string());
        parts.join("/")
    }
}

impl Handler for Store {
    async fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
        // Yield to prove handlers may genuinely suspend.
        tokio::task::yield_now().await;

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

    async fn get(&mut self, request: &Request) -> Result<Object, Response> {
        let name = request.headers.name().unwrap_or_default();

        if name == "streamed" {
            // Stream the body from an async reader rather than memory.
            let (mut writer, reader) = duplex(1024);
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                for chunk in 0..100u8 {
                    writer.write_all(&[chunk; 1000]).await.unwrap();
                }
            });
            return Ok(Object::from_reader([Header::Length(100_000)], reader));
        }

        match self.files.get(&self.key(name)) {
            Some(body) => Ok(Object::new(
                [Header::Length(body.len() as u32)],
                body.clone(),
            )),
            None => Err(Response::new(ResponseCode::NotFound)),
        }
    }

    async fn set_path(&mut self, request: &Request) -> Response {
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

    async fn abort(&mut self, _request: &Request) {
        self.aborts += 1;
    }

    async fn password(&mut self, _user_id: Option<&[u8]>) -> Option<Vec<u8>> {
        self.password.clone()
    }

    async fn credentials(&mut self, _challenge: &DigestChallenge) -> Option<Credentials> {
        self.password.clone().map(Credentials::new)
    }
}

type TestServer = Server<DuplexStream, Store>;

/// Spawns a server on its own task, which also proves its future is `Send`.
fn start(
    store: Store,
    configure: impl FnOnce(TestServer) -> TestServer,
) -> (DuplexStream, tokio::task::JoinHandle<Store>) {
    let (client, server) = duplex(64 * 1024);
    let mut server = configure(Server::new(server, store));

    let handle = tokio::spawn(async move {
        server.run().await.expect("server failed");
        server.into_parts().1
    });

    (client, handle)
}

fn object(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 7 % 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawned_client_and_server() {
    let (socket, server) = start(Store::default(), |server| {
        server.with_max_packet_length(512)
    });

    let client = tokio::spawn(async move {
        let mut client = Client::new(socket).with_max_packet_length(300);
        let response = client
            .connect([Header::Target(FOLDER_BROWSING.to_vec())])
            .await
            .unwrap();
        assert_eq!(Some(FOLDER_BROWSING.as_slice()), response.headers.who());
        assert!(client.connection_id().is_some());

        let body = object(100_000);
        client.set_path_child("docs", true).await.unwrap();
        client
            .put([Header::Name("big.bin".to_string())], &body)
            .await
            .unwrap();

        let fetched = client
            .get([Header::Name("big.bin".to_string())])
            .await
            .unwrap();
        assert_eq!(body, fetched.body);
        assert_eq!(Some(body.len() as u32), fetched.headers.length());

        client
            .delete([Header::Name("big.bin".to_string())])
            .await
            .unwrap();
        let error = client
            .get([Header::Name("big.bin".to_string())])
            .await
            .unwrap_err();
        assert_eq!(Some(ResponseCode::NotFound), error.response_code());

        client.set_path_parent().await.unwrap();
        client.disconnect().await.unwrap();
    });

    client.await.unwrap();
    let store = server.await.unwrap();
    assert!(store.files.is_empty());
}

#[tokio::test]
async fn single_response_mode_and_streamed_bodies() {
    let (socket, _server) = start(Store::default(), |server| {
        server
            .with_single_response_mode(true)
            .with_max_packet_length(1024)
    });

    let mut client = Client::new(socket)
        .with_single_response_mode(true)
        .with_max_packet_length(1024);
    client
        .connect([Header::Target(MESSAGE_ACCESS.to_vec())])
        .await
        .unwrap();

    let body = object(50_000);
    client
        .put_from([Header::Name("srm.bin".to_string())], &body[..])
        .await
        .unwrap();

    let mut sink = Vec::new();
    client
        .get_into([Header::Name("srm.bin".to_string())], &mut sink)
        .await
        .unwrap();
    assert_eq!(body, sink);

    let streamed = client
        .get([Header::Name("streamed".to_string())])
        .await
        .unwrap();
    let expected: Vec<u8> = (0..100u8).flat_map(|chunk| [chunk; 1000]).collect();
    assert_eq!(expected, streamed.body);
}

/// An async reader or writer that fails after `remaining` bytes.
struct Failing {
    remaining: usize,
}

impl AsyncRead for Failing {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.remaining == 0 {
            return Poll::Ready(Err(io::Error::other("disk on fire")));
        }
        let length = buf.remaining().min(self.remaining);
        buf.put_slice(&vec![1; length]);
        self.remaining -= length;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Failing {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.remaining < buf.len() {
            return Poll::Ready(Err(io::Error::other("disk full")));
        }
        self.remaining -= buf.len();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn failing_body_source_and_sink_abort() {
    for srm in [false, true] {
        let (socket, server) = start(Store::default(), move |server| {
            server
                .with_single_response_mode(srm)
                .with_max_packet_length(1024)
        });
        let mut client = Client::new(socket)
            .with_single_response_mode(srm)
            .with_max_packet_length(1024);
        client.connect([]).await.unwrap();

        let error = client
            .put_from(
                [Header::Name("broken".to_string())],
                Failing { remaining: 5_000 },
            )
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Io(_)), "srm: {}", srm);

        let body = object(30_000);
        client
            .put([Header::Name("ok".to_string())], &body)
            .await
            .unwrap();
        let error = client
            .get_into(
                [Header::Name("ok".to_string())],
                Failing { remaining: 1_000 },
            )
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Io(_)), "srm: {}", srm);

        assert_eq!(
            body,
            client
                .get([Header::Name("ok".to_string())])
                .await
                .unwrap()
                .body
        );
        client.disconnect().await.unwrap();
        drop(client);

        let store = server.await.unwrap();
        assert_eq!(2, store.aborts, "srm: {}", srm);
    }
}

#[tokio::test]
async fn authentication_in_both_directions() {
    let store = Store {
        password: Some(b"1234".to_vec()),
        ..Store::default()
    };
    let (socket, _server) = start(store, |server| {
        server.with_authentication(Authentication::default())
    });

    let mut client = Client::new(socket)
        .with_credentials(Credentials::new("1234"))
        .with_server_authentication("1234");
    client.connect([]).await.unwrap();
    client
        .put([Header::Name("secret".to_string())], b"s3cr3t")
        .await
        .unwrap();

    let store = Store {
        password: Some(b"1234".to_vec()),
        ..Store::default()
    };
    let (socket, _server) = start(store, |server| {
        server.with_authentication(Authentication::default())
    });

    let mut client = Client::new(socket).with_credentials(Credentials::new("0000"));
    let error = client.connect([]).await.unwrap_err();
    assert_eq!(Some(ResponseCode::Unauthorized), error.response_code());
}

#[tokio::test]
async fn async_client_with_blocking_server() {
    let (client_socket, server_socket) = std::os::unix::net::UnixStream::pair().unwrap();

    struct Echo;
    impl obex::server::Handler for Echo {
        fn get(&mut self, request: &Request) -> Result<obex::server::Object, Response> {
            let name = request.headers.name().unwrap_or_default().to_string();
            Ok(obex::server::Object::new(
                [],
                name.repeat(1000).into_bytes(),
            ))
        }
    }

    let server = std::thread::spawn(move || {
        obex::server::Server::new(server_socket, Echo)
            .with_single_response_mode(true)
            .run()
            .unwrap();
    });

    client_socket.set_nonblocking(true).unwrap();
    let socket = tokio::net::UnixStream::from_std(client_socket).unwrap();
    let mut client = Client::new(socket).with_single_response_mode(true);
    client.connect([]).await.unwrap();

    let response = client
        .get([Header::Name("ping".to_string())])
        .await
        .unwrap();
    assert_eq!("ping".repeat(1000).into_bytes(), response.body);

    client.disconnect().await.unwrap();
    drop(client);
    tokio::task::spawn_blocking(move || server.join().unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn blocking_client_with_async_server_over_tcp() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut server = Server::new(socket, Store::default());
        server.run().await.unwrap();
        server.into_parts().1
    });

    let body = object(20_000);
    let uploaded = body.clone();
    tokio::task::spawn_blocking(move || {
        let socket = std::net::TcpStream::connect(address).unwrap();
        let mut client = obex::client::Client::new(socket);
        client.connect([]).unwrap();
        client
            .put([Header::Name("tcp.bin".to_string())], &uploaded)
            .unwrap();
        client.disconnect().unwrap();
    })
    .await
    .unwrap();

    let store = server.await.unwrap();
    assert_eq!(Some(&body), store.files.get("tcp.bin"));
}

#[tokio::test]
async fn scripted_exchange_with_packet_stream() {
    let (client_socket, server_socket) = duplex(4096);

    let script = tokio::spawn(async move {
        let mut stream = PacketStream::new(server_socket);
        let connect = stream.read_request().await.unwrap();
        assert!(connect.connect.is_some());

        let response = Response {
            connect: Some(obex::packet::ConnectParameters::new(4096)),
            ..Response::with_headers(ResponseCode::Success, [Header::ConnectionID(7)])
        };
        stream.write_response(&response).await.unwrap();

        let request = stream.read_request().await.unwrap();
        assert_eq!(Some(7), request.headers.connection_id());
        stream
            .write_response(&Response::with_headers(
                ResponseCode::Success,
                [Header::EndOfBody(b"hello".to_vec())],
            ))
            .await
            .unwrap();
    });

    let mut client = Client::new(client_socket);
    client.connect([]).await.unwrap();
    assert_eq!(Some(7), client.connection_id());
    assert_eq!(b"hello".to_vec(), client.get([]).await.unwrap().body);
    script.await.unwrap();
}
