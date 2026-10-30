//! Pushes a file to a Bluetooth device with the Object Push Profile, over RFCOMM.
//!
//! ```text
//! cargo run --example bluetooth_push -- <address> <rfcomm channel> <file>
//! cargo run --example bluetooth_push -- 00:11:22:33:44:55 12 contact.vcf
//! ```
//!
//! This uses a raw BlueZ RFCOMM socket, so it only runs on Linux, and the device must
//! already be paired. The RFCOMM channel of the Object Push service is published in
//! the device's SDP record (`sdptool browse <address>` lists it). Any Bluetooth stack
//! that hands out a socket implementing `Read + Write` works the same way.

#[cfg(target_os = "linux")]
mod rfcomm {
    use std::fs::File;
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};

    const BTPROTO_RFCOMM: libc::c_int = 3;

    #[repr(C)]
    struct SockaddrRc {
        rc_family: libc::sa_family_t,
        rc_bdaddr: [u8; 6],
        rc_channel: u8,
    }

    /// Parses `AA:BB:CC:DD:EE:FF` into the little-endian `bdaddr_t` layout.
    pub fn parse_address(text: &str) -> Option<[u8; 6]> {
        let bytes: Vec<u8> = text
            .split(':')
            .map(|part| u8::from_str_radix(part, 16).ok())
            .collect::<Option<_>>()?;
        let mut address: [u8; 6] = bytes.try_into().ok()?;
        address.reverse();

        Some(address)
    }

    /// Opens an RFCOMM connection. Sockets support `read(2)` and `write(2)`, so the
    /// descriptor is wrapped in a `File` to get `Read + Write`.
    pub fn connect(address: [u8; 6], channel: u8) -> io::Result<File> {
        // SAFETY: socket(2) has no memory safety preconditions.
        let fd = unsafe { libc::socket(libc::AF_BLUETOOTH, libc::SOCK_STREAM, BTPROTO_RFCOMM) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `fd` is a freshly created descriptor owned by nothing else.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };

        let sockaddr = SockaddrRc {
            rc_family: libc::AF_BLUETOOTH as libc::sa_family_t,
            rc_bdaddr: address,
            rc_channel: channel,
        };

        // SAFETY: `sockaddr` is a valid `sockaddr_rc` and the length matches it.
        let result = unsafe {
            libc::connect(
                fd,
                &sockaddr as *const SockaddrRc as *const libc::sockaddr,
                std::mem::size_of::<SockaddrRc>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(File::from(socket))
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use obex_protocol::client::Client;
    use obex_protocol::header::Header;
    use std::path::Path;

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: {} <address> <rfcomm channel> <file>", args[0]);
        std::process::exit(2);
    }

    let address = rfcomm::parse_address(&args[1]).ok_or("invalid Bluetooth address")?;
    let channel: u8 = args[2].parse()?;
    let path = Path::new(&args[3]);
    let body = std::fs::read(path)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid file name")?;

    let mut client = Client::new(rfcomm::connect(address, channel)?);

    // Object Push connects to the default (inbox) service, without a Target header.
    client.connect([])?;
    println!(
        "connected, remote accepts {} byte packets",
        client.remote_max_packet_length()
    );

    let mut headers = vec![
        Header::Name(name.to_string()),
        Header::Length(body.len() as u32),
    ];
    if name.ends_with(".vcf") {
        headers.push(Header::Type("text/x-vcard".to_string()));
    }

    client.put(headers, &body)?;
    println!("pushed {} ({} bytes)", name, body.len());

    client.disconnect()?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example uses BlueZ RFCOMM sockets and only runs on Linux.");
}
