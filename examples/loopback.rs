//! Runs an OBEX folder server and a client against it over TCP on localhost.
//!
//! ```text
//! cargo run --example loopback
//! ```
//!
//! OBEX over TCP normally uses port 650; an ephemeral port is used here so the
//! example runs without privileges.

use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::thread;

use obex::client::Client;
use obex::header::Header;
use obex::packet::{Request, Response};
use obex::response::ResponseCode;
use obex::server::{Handler, Object, Server};
use obex::target::FOLDER_BROWSING;

#[derive(Default)]
struct Folder {
    files: HashMap<String, Vec<u8>>,
}

impl Handler for Folder {
    fn connect(&mut self, request: &Request) -> Response {
        match request.headers.target() {
            Some(target) if target == FOLDER_BROWSING => Response::new(ResponseCode::Success),
            _ => Response::new(ResponseCode::ServiceUnavailable),
        }
    }

    fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
        let Some(name) = request.headers.name() else {
            return Response::new(ResponseCode::BadRequest);
        };

        match body {
            Some(body) => {
                println!("server: stored {} ({} bytes)", name, body.len());
                self.files.insert(name.to_string(), body);
            }
            None => {
                println!("server: deleted {}", name);
                self.files.remove(name);
            }
        }

        Response::new(ResponseCode::Success)
    }

    fn get(&mut self, request: &Request) -> Result<Object, Response> {
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

fn main() -> obex::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;

    let server = thread::spawn(move || -> obex::Result<()> {
        let (socket, peer) = listener.accept()?;
        println!("server: connection from {}", peer);
        Server::new(socket, Folder::default()).run()
    });

    let mut client = Client::new(TcpStream::connect(address)?).with_max_packet_length(4096);

    let response = client.connect([Header::Target(FOLDER_BROWSING.to_vec())])?;
    println!(
        "client: connected with connection id {:?}, server accepts {} byte packets",
        response.headers.connection_id(),
        client.remote_max_packet_length()
    );

    let notes: Vec<u8> = b"OBEX is HTTP for small devices.\n".repeat(1000);
    client.put([Header::Name("notes.txt".to_string())], &notes)?;

    let fetched = client.get([Header::Name("notes.txt".to_string())])?;
    println!(
        "client: fetched notes.txt, Length header {:?}, {} bytes, intact: {}",
        fetched.headers.length(),
        fetched.body.len(),
        fetched.body == notes
    );

    client.delete([Header::Name("notes.txt".to_string())])?;

    match client.get([Header::Name("notes.txt".to_string())]) {
        Err(error) => println!("client: get after delete failed as expected: {}", error),
        Ok(_) => println!("client: unexpectedly fetched a deleted file"),
    }

    client.disconnect()?;
    drop(client);

    server.join().expect("server thread panicked")
}
