//! Real local TCP round trip for workload HTTP adapters. No external route.
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn accept_until(listener: &TcpListener, deadline: Instant) -> std::io::Result<TcpStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "loopback accept timed out",
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn round_trip() -> std::io::Result<()> {
    let timeout = Duration::from_secs(2);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut client = TcpStream::connect_timeout(&listener.local_addr()?, timeout)?;
    // connect can return before the listener exposes its queued peer (measured
    // as EWOULDBLOCK on macOS). Readiness must be awaited within the same bound.
    listener.set_nonblocking(true)?;
    let mut server = accept_until(&listener, Instant::now() + timeout)?;
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
    fn an_absent_peer_times_out_instead_of_becoming_a_success() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let error = super::accept_until(&listener, std::time::Instant::now()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn a_peer_that_is_not_ready_yet_can_still_connect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            std::net::TcpStream::connect(address).unwrap()
        });
        super::accept_until(
            &listener,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .unwrap();
        peer.join().unwrap();
    }
    #[test]
    fn a_real_local_connection_round_trips_the_payload() {
        super::round_trip().unwrap();
    }
}
