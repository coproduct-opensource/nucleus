//! Real local TCP round trip for workload HTTP adapters. No external route.
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;

pub(crate) fn round_trip() -> std::io::Result<()> {
    let timeout = Duration::from_secs(2);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut client = TcpStream::connect_timeout(&listener.local_addr()?, timeout)?;
    // Connect has completed the handshake, so accept must have a queued peer.
    listener.set_nonblocking(true)?;
    let (mut server, _) = listener.accept()?;
    for stream in [&client, &server] {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
    }
    const MESSAGE: &[u8] = b"nucleus-loopback";
    let mut received = [0u8; MESSAGE.len()];
    client.write_all(MESSAGE)?;
    server.read_exact(&mut received)?;
    server.write_all(&received)?;
    client.read_exact(&mut received)?;
    if received != MESSAGE {
        return Err(std::io::Error::other("loopback payload changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_real_local_connection_round_trips_the_payload() {
        super::round_trip().unwrap();
    }
}
