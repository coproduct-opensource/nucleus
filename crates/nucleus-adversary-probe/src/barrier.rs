//! `nucleus-adversary-probe barrier` — the guest half of `nucleus-perf
//! teardown-barrier`.
//!
//! Holds a workload-API connection open and sends `FETCH_SVID` on it as fast as
//! the host answers, for as long as the guest lives. When the host closes the
//! connection it reconnects, so a host that closes the connection but keeps
//! serving new ones is still exercised. It never exits on its own: the host's
//! cancel ends it.
//!
//! It prints nothing and decides nothing. The verdict is the node's own log,
//! read by the harness: how many commands the node served for this pod after its
//! workload-API bridge began shutting down. A guest that reports on itself is a
//! guest being believed, and this one is killed before it could report anyway.

#[cfg(target_os = "linux")]
pub fn run() -> i32 {
    use std::io::{BufRead, BufReader, Write};
    // `FETCH_SVID` rather than `PING` because it is the one that did damage: served
    // during teardown, it minted a certificate for an identity the node had just
    // released (#2930).
    const COMMAND: &[u8] = b"FETCH_SVID\n";
    use std::time::Duration;
    const VMADDR_CID_HOST: u32 = 2;
    let port = std::env::var("NUCLEUS_TRANSCRIPT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(15012);
    loop {
        let Ok(stream) = vsock::VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port) else {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let Ok(mut writer) = stream.try_clone() else {
            continue;
        };
        let mut reader = BufReader::new(stream);
        loop {
            if writer
                .write_all(COMMAND)
                .and_then(|()| writer.flush())
                .is_err()
            {
                break;
            }
            let mut reply = String::new();
            match reader.read_line(&mut reply) {
                Ok(n) if n > 0 => {}
                // EOF, error or timeout: the host stopped answering on this one.
                Ok(_) | Err(_) => break,
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run() -> i32 {
    eprintln!("barrier: needs a Linux guest with vsock");
    2
}
