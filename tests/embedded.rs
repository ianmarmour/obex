//! End to end tests of the `embedded-io-async` API, run on the host with
//! `cargo test --all-features`. Transports are tokio duplex streams adapted with
//! `embedded-io-adapters`, and client and server run concurrently on one task, so
//! nothing here needs to be `Send`.
#![cfg(all(feature = "embedded-io-async", feature = "tokio"))]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use embedded_io_adapters::tokio_1::FromTokio;
use obex_protocol::auth::{Credentials, DigestChallenge};
use obex_protocol::embedded::{Authentication, Client, Handler, Object, PacketStream, Server};
use obex_protocol::header::Header;
use obex_protocol::packet::{Request, Response};
use obex_protocol::response::ResponseCode;
use obex_protocol::target::{FOLDER_BROWSING, MESSAGE_ACCESS};
use obex_protocol::Error;
use tokio::io::{duplex, DuplexStream};

type Channel = FromTokio<DuplexStream>;

/// A handler sharing its state through an `Rc`, which a tokio handler could not.
#[derive(Default, Clone)]
struct Store {
    files: Rc<RefCell<HashMap<String, Vec<u8>>>>,
    path: Vec<String>,
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
        let mut files = self.files.borrow_mut();

        match body {
            Some(body) => {
                files.insert(key, body);
                Response::new(ResponseCode::Success)
            }
            None => match files.remove(&key) {
                Some(_) => Response::new(ResponseCode::Success),
                None => Response::new(ResponseCode::NotFound),
            },
        }
    }

    async fn get(&mut self, request: &Request) -> Result<Object, Response> {
        let name = request.headers.name().unwrap_or_default();

        match self.files.borrow().get(&self.key(name)) {
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

    async fn password(&mut self, _user_id: Option<&[u8]>) -> Option<Vec<u8>> {
        self.password.clone()
    }

    async fn credentials(&mut self, _challenge: &DigestChallenge) -> Option<Credentials> {
        self.password.clone().map(Credentials::new)
    }
}

fn channels() -> (Channel, Channel) {
    let (client, server) = duplex(64 * 1024);
    (FromTokio::new(client), FromTokio::new(server))
}

fn object(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 7 % 251) as u8).collect()
}

/// A deterministic stand-in for a hardware random number generator.
fn counter_nonces() -> impl FnMut() -> [u8; 16] + Send + 'static {
    let mut counter = 0u8;
    move || {
        counter = counter.wrapping_add(1);
        [counter; 16]
    }
}

/// Serves `server` until the client closes its end of the transport.
async fn serve(mut server: Server<Channel, Store>) -> Store {
    server.run().await.expect("server failed");
    server.into_parts().1
}

#[tokio::test]
async fn client_and_server() {
    let (client_channel, server_channel) = channels();
    let store = Store::default();
    let files = store.files.clone();
    let server = Server::new(server_channel, store).with_max_packet_length(512);

    let client = async move {
        let mut client = Client::new(client_channel).with_max_packet_length(300);
        let response = client
            .connect([Header::Target(FOLDER_BROWSING.to_vec())])
            .await
            .unwrap();
        assert_eq!(Some(FOLDER_BROWSING.as_slice()), response.headers.who());
        assert!(client.connection_id().is_some());
        assert_eq!(512, client.remote_max_packet_length());

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

        client
            .put([Header::Name("kept.txt".to_string())], b"kept")
            .await
            .unwrap();
        client.set_path_parent().await.unwrap();
        client.disconnect().await.unwrap();
    };

    let ((), _) = tokio::join!(client, serve(server));
    assert_eq!(Some(&b"kept".to_vec()), files.borrow().get("docs/kept.txt"));
}

#[tokio::test]
async fn single_response_mode_and_streamed_bodies() {
    let (client_channel, server_channel) = channels();
    let server = Server::new(server_channel, Store::default())
        .with_single_response_mode(true)
        .with_max_packet_length(1024);

    let client = async move {
        let mut client = Client::new(client_channel)
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

        let mut sink = [0u8; 50_000];
        client
            .get_into([Header::Name("srm.bin".to_string())], &mut sink[..])
            .await
            .unwrap();
        assert_eq!(body, sink);

        // A sink that is too small fails the operation with its error.
        let mut small = [0u8; 10];
        let error = client
            .get_into([Header::Name("srm.bin".to_string())], &mut small[..])
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Transport(_)), "{:?}", error);

        client.disconnect().await.unwrap();
    };

    tokio::join!(client, serve(server));
}

#[tokio::test]
async fn authentication_in_both_directions() {
    let (client_channel, server_channel) = channels();
    let store = Store {
        password: Some(b"1234".to_vec()),
        ..Store::default()
    };
    let server = Server::new(server_channel, store)
        .with_authentication(Authentication::default(), counter_nonces());

    let client = async move {
        let mut client = Client::new(client_channel)
            .with_credentials(Credentials::new("1234"))
            .with_server_authentication("1234", counter_nonces());
        client.connect([]).await.unwrap();
        client
            .put([Header::Name("secret".to_string())], b"s3cr3t")
            .await
            .unwrap();
        client.disconnect().await.unwrap();
    };

    tokio::join!(client, serve(server));

    let (client_channel, server_channel) = channels();
    let store = Store {
        password: Some(b"1234".to_vec()),
        ..Store::default()
    };
    let mut server = Server::new(server_channel, store)
        .with_authentication(Authentication::default(), counter_nonces());

    let client = async move {
        let mut client = Client::new(client_channel).with_credentials(Credentials::new("0000"));
        let error = client.connect([]).await.unwrap_err();
        assert_eq!(Some(ResponseCode::Unauthorized), error.response_code());
    };

    let ((), _) = tokio::join!(client, server.run());
}

#[tokio::test]
async fn interoperates_with_the_tokio_api() {
    // An embedded client against a tokio server.
    let (client_socket, server_socket) = duplex(64 * 1024);
    let server = tokio::spawn(async move {
        struct Echo;
        impl obex_protocol::tokio::Handler for Echo {
            async fn get(
                &mut self,
                request: &Request,
            ) -> Result<obex_protocol::tokio::Object, Response> {
                let name = request.headers.name().unwrap_or_default().to_string();
                Ok(obex_protocol::tokio::Object::new(
                    [],
                    name.repeat(1000).into_bytes(),
                ))
            }
        }

        obex_protocol::tokio::Server::new(server_socket, Echo)
            .with_single_response_mode(true)
            .run()
            .await
            .unwrap();
    });

    let mut client = Client::new(FromTokio::new(client_socket)).with_single_response_mode(true);
    client.connect([]).await.unwrap();
    let response = client
        .get([Header::Name("ping".to_string())])
        .await
        .unwrap();
    assert_eq!("ping".repeat(1000).into_bytes(), response.body);
    client.disconnect().await.unwrap();
    drop(client);
    server.await.unwrap();

    // A tokio client against an embedded server.
    let (client_socket, server_socket) = duplex(64 * 1024);
    let store = Store::default();
    let files = store.files.clone();
    let server = Server::new(FromTokio::new(server_socket), store);

    let client = async move {
        let mut client = obex_protocol::tokio::Client::new(client_socket);
        client.connect([]).await.unwrap();
        client
            .put([Header::Name("tokio.bin".to_string())], &object(20_000))
            .await
            .unwrap();
        client.disconnect().await.unwrap();
    };

    tokio::join!(client, serve(server));
    assert_eq!(Some(&object(20_000)), files.borrow().get("tokio.bin"));
}

#[tokio::test]
async fn packet_stream_and_transport_errors() {
    use tokio::io::AsyncWriteExt;

    let (client_channel, server_channel) = channels();

    let script = async move {
        let mut stream = PacketStream::new(server_channel);
        let connect = stream.read_request().await.unwrap();
        assert!(connect.connect.is_some());

        let response = Response {
            connect: Some(obex_protocol::packet::ConnectParameters::new(4096)),
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

        // Closing between packets is a clean disconnect.
        let error = stream.read_request().await.unwrap_err();
        assert!(matches!(error, Error::Disconnected), "{:?}", error);
    };

    let client = async move {
        let mut client = Client::new(client_channel);
        client.connect([]).await.unwrap();
        assert_eq!(Some(7), client.connection_id());
        assert_eq!(b"hello".to_vec(), client.get([]).await.unwrap().body);
    };

    tokio::join!(script, client);

    // Closing in the middle of a packet is a transport error.
    let (mut writer, reader) = duplex(64);
    writer.write_all(&[0x83, 0x00, 0x10, 0x00]).await.unwrap();
    drop(writer);

    let mut stream = PacketStream::new(FromTokio::new(reader));
    let error = stream.read_response().await.unwrap_err();
    assert!(
        matches!(
            error,
            Error::Transport(embedded_io_async::ErrorKind::ConnectionAborted)
        ),
        "{:?}",
        error
    );
}
