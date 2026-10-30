# obex-protocol
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![CI](https://github.com/ianmarmour/obex-protocol/workflows/CI/badge.svg)](https://github.com/ianmarmour/obex-protocol/actions/workflows/ci.yml)

A native IrDA Object Exchange (OBEX 1.5) protocol library for Rust, with minimal dependencies.

## What is OBEX

> OBEX is a compact, efficient, binary protocol that enables a wide range of devices to exchange data in a simple and spontaneous manner.

OBEX is to small devices what HTTP is to the web: a request/response protocol for putting and getting objects. It runs over Bluetooth (RFCOMM and L2CAP), IrDA and TCP. On Bluetooth it underpins the Generic Object Exchange Profile (GOEP), and through it the Message Access (MAP), Phone Book Access (PBAP), File Transfer (FTP), Object Push (OPP), Basic Imaging (BIP) and Synchronization profiles.

## What is This Library

This library is a building block. It implements OBEX itself, complete and transport independent, and stays out of profile specifics so that profile crates can be thin layers on top of it:

```text
+-----------------------------------------------------------+
|  Profiles: MAP, PBAP, FTP, OPP, BIP, SYNC ...             |  your crates
+-----------------------------------------------------------+
|  client / server                 (blocking)               |  protocol engines
|  tokio::{Client, Server}         (async, `tokio` feature) |
|  header  packet  auth  srm  ...                           |  codec (no I/O)
+-----------------------------------------------------------+
|  RFCOMM (GOEP 1.x)   L2CAP ERTM (GOEP 2.x)   TCP :650     |  any Read + Write
+-----------------------------------------------------------+
```

* **Codec** (`header`, `packet`, `opcode`, `response`, `tlv`, `auth`, `srm`, `session`, `action`, `target`): every header, opcode and response code in the specification, plus user defined headers. These types only convert between packets and bytes, so they work with blocking, async or embedded I/O.
* **Client**: CONNECT, DISCONNECT, PUT (streaming), GET (streaming), SETPATH, ACTION (copy, move, permissions), SESSION and ABORT.
* **Server**: a `Handler` trait receives complete operations; the server does the packet work. You need this for the profile roles where your device is the one being connected to, such as the MAP Message Notification Server.
* **Transport framing** for both stream sockets (RFCOMM, TCP) and sequenced packet sockets (L2CAP `SOCK_SEQPACKET`).
* **Async** (optional `tokio` feature): `obex_protocol::tokio` has async versions of the client, server, handler and packet stream. The blocking and async APIs run the same protocol engine, so they behave identically and can talk to each other.

Both engines handle packet size negotiation, multi-packet requests and responses, directed connections (Target, Who and Connection Id), Single Response Mode, digest authentication and ABORT.

## How Do I Use This Library

The crate is published as `obex-protocol` (the `obex` name was taken) and imported as `obex_protocol`:

```toml
[dependencies]
obex-protocol = "0.1"
```

Open a socket with your Bluetooth stack (BlueZ, `bluer`, or the platform APIs; find the RFCOMM channel or L2CAP PSM through SDP) and hand it to a `Client` or `Server`. Anything implementing `std::io::Read + std::io::Write` works.

### Client

```rust
use obex_protocol::client::Client;
use obex_protocol::header::Header;
use obex_protocol::target::FOLDER_BROWSING;

let mut client = Client::new(socket);
client.connect([Header::Target(FOLDER_BROWSING.to_vec())])?;

client.set_path_child("Documents", false)?;
client.put([Header::Name("notes.txt".to_string())], b"Hello over OBEX")?;

let listing = client.get([Header::Type("x-obex/folder-listing".to_string())])?;
println!("{}", String::from_utf8_lossy(&listing.body));

client.disconnect()?;
```

Large objects can be streamed with `Client::put_from` (any `Read`) and `Client::get_into` (any `Write`). If the reader or writer fails, the operation is aborted on the wire.

### Server

```rust
use obex_protocol::packet::{Request, Response};
use obex_protocol::response::ResponseCode;
use obex_protocol::server::{Handler, Object, Server};

struct Inbox;

impl Handler for Inbox {
    fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
        println!("received {:?}", request.headers.name());
        Response::new(ResponseCode::Success)
    }

    fn get(&mut self, _request: &Request) -> Result<Object, Response> {
        Ok(Object::new([], b"BEGIN:VCARD\r\nEND:VCARD\r\n".to_vec()))
    }
}

Server::new(socket, Inbox).run()?;
```

### Codec only

```rust
use obex_protocol::header::Header;
use obex_protocol::opcode::Opcode;
use obex_protocol::packet::{Request, Response};

let bytes = Request::new(Opcode::Get, true, [Header::Name("pb.vcf".to_string())]).to_bytes()?;
let (_, response) = Response::parse(&incoming)?;
```

### Async (tokio)

Enable the `tokio` feature:

```toml
[dependencies]
obex-protocol = { version = "0.1", features = ["tokio"] }
```

The API mirrors the blocking one, with `.await` and `async fn` handlers. It works with any `AsyncRead + AsyncWrite` transport, such as `bluer`'s RFCOMM and L2CAP streams. Client, server and handler futures are `Send`, so they can be spawned on a multi-threaded runtime.

```rust
use obex_protocol::header::Header;
use obex_protocol::packet::{Request, Response};
use obex_protocol::response::ResponseCode;
use obex_protocol::tokio::{Client, Handler, Server};

struct Notifications;

impl Handler for Notifications {
    async fn put(&mut self, request: &Request, body: Option<Vec<u8>>) -> Response {
        Response::new(ResponseCode::Success)
    }
}

tokio::spawn(async move { Server::new(server_socket, Notifications).run().await });

let mut client = Client::new(client_socket).with_single_response_mode(true);
client.connect([]).await?;
let object = client.get([Header::Name("inbox".to_string())]).await?;
```

## Building a Profile on Top

Profile crates built on this one form a family named `obex-protocol-<profile>`. For example, [`obex-protocol-map`](https://github.com/ianmarmour/map) implements the Bluetooth Message Access Profile and is imported as `obex_protocol_map`.

Profiles choose a Target, then send Names, Types and Application Parameters. A Message Access Profile client, for example, is mostly constants:

```rust
use obex_protocol::client::Client;
use obex_protocol::header::Header;
use obex_protocol::target::MESSAGE_ACCESS;
use obex_protocol::tlv::ApplicationParameters;

const MAX_LIST_COUNT: u8 = 0x01;
const LISTING_SIZE: u8 = 0x12;

let mut mas = Client::new(l2cap_socket)
    .with_max_packet_length(l2cap_mtu)
    .with_single_response_mode(true);

mas.connect([Header::Target(MESSAGE_ACCESS.to_vec())])?;
mas.set_path_child("telecom", false)?;
mas.set_path_child("msg", false)?;

let listing = mas.get([
    Header::Name("inbox".to_string()),
    Header::Type("x-bt/MAP-msg-listing".to_string()),
    Header::ApplicationParameters(ApplicationParameters::new().with_u16(MAX_LIST_COUNT, 20)),
])?;

let size = listing.headers.application_parameters().and_then(|p| p.get_u16(LISTING_SIZE));
```

The other half of MAP, the Message Notification Server, is a `Handler` that accepts `x-bt/MAP-event-report` PUTs. The server answers its directed CONNECT (Target `MESSAGE_NOTIFICATION`) with a Who header and Connection Id automatically. `obex_protocol::target` has the Target UUIDs for FTP, PBAP, MAP MAS and MAP MNS.

## Bluetooth Notes

* **RFCOMM (GOEP 1.x)** is a stream socket. Leave Single Response Mode off.
* **L2CAP (GOEP 2.x)** is a sequenced packet socket in Enhanced Retransmission Mode. Set `with_max_packet_length` to at most the L2CAP MTU so every OBEX packet fits in one SDU, and enable `with_single_response_mode(true)` on the client and server to get SRM. It is negotiated per PUT and GET, as GOEP 2.0 requires.
* SDP discovery, pairing and opening sockets belong to the Bluetooth stack, not this crate.

`examples/bluetooth_push.rs` pushes a file over a raw BlueZ RFCOMM socket on Linux, and `examples/loopback.rs` runs a server and a client over TCP:

```bash
cargo run --example loopback
```

```bash
cargo run --example tokio_loopback --features tokio
```

## Specification Coverage

| OBEX 1.5 section                          | Status |
|-------------------------------------------|--------|
| 2. Headers (all, plus user defined)       | Implemented |
| 3.1-3.2 Request and response format       | Implemented |
| 3.3 Single Response Mode                  | Implemented (per operation and per connection, SRMP wait and additional packet) |
| 3.4.1-3.4.6 CONNECT, DISCONNECT, PUT, GET, ABORT, SETPATH | Implemented |
| 3.4.7 SESSION                             | Commands and parameters; sequence numbers and resume retransmission are left to the caller |
| 3.4.8 ACTION                              | Implemented |
| 3.6 Authentication                        | Implemented; servers challenge during CONNECT, clients answer challenges on any operation |
| 3.7 Multiplexing with Connection Ids      | Implemented |
| 9. Folder listing, capability and object profile objects | Type constants only; XML parsing is left to profile crates |

The specification is in [`docs/OBEX15.pdf`](docs/OBEX15.pdf).

## Minimum Supported Rust Version

Rust 1.85, checked in CI.
