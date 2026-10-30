//! Runs an async OBEX server and client against each other over TCP on localhost.
//!
//! ```text
//! cargo run --example tokio_loopback --features tokio
//! ```

use std::collections::HashMap;

use obex::header::Header;
use obex::packet::{Request, Response};
use obex::response::ResponseCode;
use obex::target::FOLDER_BROWSING;
use obex::tokio::{Client, Handler, Object, Server};
use tokio::net::{TcpListener, TcpStream};

#[derive(Default)]
struct Folder {
    files: HashMap<String, Vec<u8>>,
}

impl Handler for Folder {
    async fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
        let (Some(name), Some(body)) = (request.headers.name(), body) else {
            return Response::new(ResponseCode::BadRequest);
        };

        println!("server: stored {} ({} bytes)", name, body.len());
        self.files.insert(name.to_string(), body);

        Response::new(ResponseCode::Success)
    }

    async fn get(&mut self, request: &Request) -> Result<Object, Response> {
        let name = request.headers.name().unwrap_or_default();

        match self.files.get(name) {
            Some(body) => Ok(Object::new(
                [Header::Length(body.len() as u32)],
                body.clone(),
            )),
            None => Err(Response::new(ResponseCode::NotFound)),
        }
    }
}

#[tokio::main]
async fn main() -> obex::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (socket, peer) = listener.accept().await?;
        println!("server: connection from {}", peer);
        Server::new(socket, Folder::default()).run().await
    });

    let mut client = Client::new(TcpStream::connect(address).await?).with_max_packet_length(4096);
    let response = client
        .connect([Header::Target(FOLDER_BROWSING.to_vec())])
        .await?;
    println!(
        "client: connected with connection id {:?}",
        response.headers.connection_id()
    );

    let notes: Vec<u8> = b"Async OBEX over tokio.\n".repeat(1000);
    client
        .put([Header::Name("notes.txt".to_string())], &notes)
        .await?;

    let fetched = client.get([Header::Name("notes.txt".to_string())]).await?;
    println!(
        "client: fetched notes.txt, {} bytes, intact: {}",
        fetched.body.len(),
        fetched.body == notes
    );

    client.disconnect().await?;
    drop(client);

    server.await.expect("server task panicked")
}
