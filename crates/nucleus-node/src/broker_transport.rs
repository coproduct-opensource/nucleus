//! Where the guest reaches the broker, and how much it may say.
//!
//! # The socket the guest connects to
//!
//! Firecracker's vsock is asymmetric. Host-initiated connections go to the
//! single AF_UNIX socket at `uds_path`; **guest-initiated** connections arrive
//! at a *different* path — `{uds_path}_{PORT}` — and the host must be listening
//! there before the guest connects, or the connection is refused.
//!
//! Getting that path wrong does not fail loudly: the guest simply cannot reach
//! the broker, and every credential request quietly falls back to whatever the
//! old path was. [`broker_socket_path`] exists so the derivation is written once
//! and tested, rather than formatted inline at a call site.
//!
//! # Why the reader is bounded separately from the parser
//!
//! `envelope_frame::check_frame` bounds what is *parsed*. It cannot bound what
//! is *accumulated*, because by the time it sees a string the reading is already
//! done. A guest that opens a connection and sends bytes without ever sending a
//! newline would make the host buffer forever — the size check never runs,
//! because the line never ends.
//!
//! So [`read_frame_bounded`] enforces the ceiling **while reading**, and stops
//! at the limit rather than after it. The two bounds are not redundant: one
//! protects the parser, the other protects the reader that feeds it.

use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::envelope_frame::MAX_FRAME_BYTES;

/// The vsock port the guest connects to for credential brokering.
///
/// Distinct from the tool-proxy's control-plane port: that one is
/// host-initiated and carries host→guest requests, this one is guest-initiated
/// and carries envelopes the other way. Sharing a port would mix a trusted
/// direction with an untrusted one on the same listener.
pub const BROKER_VSOCK_PORT: u32 = 1027;

/// Where the host must listen for guest-initiated broker connections.
///
/// Firecracker appends `_{port}` to the configured `uds_path` for
/// guest-initiated connections; see the vsock documentation.
pub fn broker_socket_path(uds_path: &Path, port: u32) -> PathBuf {
    let mut s = uds_path.as_os_str().to_os_string();
    s.push(format!("_{port}"));
    PathBuf::from(s)
}

/// Why a frame could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The peer sent more than the ceiling without terminating the frame.
    ///
    /// Reported when the limit is reached, not after it — the whole point is
    /// that the host stops accumulating.
    Unterminated {
        /// How much was accumulated before giving up.
        bytes: usize,
    },
    /// The connection ended before a frame was complete.
    Eof,
    /// Underlying I/O failure.
    Io,
}

/// Read one newline-terminated frame, refusing to accumulate past `max`.
///
/// Returns the frame WITHOUT its trailing newline. Reads byte-at-a-time rather
/// than with `read_line`, because `read_line` will happily grow its buffer to
/// whatever the peer sends — which is exactly the behaviour being prevented.
pub fn read_frame_bounded(mut reader: impl BufRead, max: usize) -> Result<String, ReadError> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => return Err(ReadError::Eof),
            Ok(_) => {
                if byte[0] == b'\n' {
                    return String::from_utf8(buf).map_err(|_| ReadError::Io);
                }
                if buf.len() >= max {
                    return Err(ReadError::Unterminated { bytes: buf.len() });
                }
                buf.push(byte[0]);
            }
            Err(_) => return Err(ReadError::Io),
        }
    }
}

/// Read a frame using the module's default ceiling.
pub fn read_frame(reader: impl BufRead) -> Result<String, ReadError> {
    read_frame_bounded(reader, MAX_FRAME_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The guest-initiated path is `{uds_path}_{port}`, not `uds_path`. Getting
    /// this wrong makes the broker silently unreachable.
    #[test]
    fn the_guest_initiated_socket_has_the_port_suffix() {
        let base = Path::new("/srv/jailer/pod-1/root/vsock.sock");
        let p = broker_socket_path(base, BROKER_VSOCK_PORT);
        assert_eq!(
            p,
            PathBuf::from("/srv/jailer/pod-1/root/vsock.sock_1027"),
            "Firecracker appends _PORT for guest-initiated connections"
        );
        assert_ne!(
            p,
            base.to_path_buf(),
            "it must NOT be the host-initiated path"
        );
    }

    /// The broker port must not collide with the control-plane port, or an
    /// untrusted guest-initiated direction shares a listener with a trusted
    /// host-initiated one.
    #[test]
    fn the_broker_port_is_distinct_from_the_control_plane() {
        // The tool-proxy's control plane is configured per-pod via the spec;
        // 1024 is the conventional default in this repo's fixtures.
        assert_ne!(BROKER_VSOCK_PORT, 1024);
    }

    #[test]
    fn a_terminated_frame_reads_back_without_its_newline() {
        let input = Cursor::new(b"{\"a\":1}\nleftover".to_vec());
        assert_eq!(read_frame(input).unwrap(), "{\"a\":1}");
    }

    /// **THE BOUND THE PARSER CANNOT PROVIDE.** A guest that never sends a
    /// newline must not make the host accumulate without limit. `check_frame`
    /// cannot help: it never runs, because the line never ends.
    #[test]
    fn an_endless_frame_is_cut_off_at_the_ceiling() {
        // 10x the ceiling, no newline anywhere.
        let flood = vec![b'x'; MAX_FRAME_BYTES * 10];
        match read_frame(Cursor::new(flood)) {
            Err(ReadError::Unterminated { bytes }) => assert_eq!(
                bytes, MAX_FRAME_BYTES,
                "reading must stop AT the ceiling, not after it"
            ),
            other => panic!("an unterminated flood must be refused, got {other:?}"),
        }
    }

    /// A frame exactly at the ceiling is still accepted — the bound is on
    /// accumulation, not an off-by-one that rejects legitimate maximum frames.
    #[test]
    fn a_frame_exactly_at_the_ceiling_is_accepted() {
        let mut data = vec![b'x'; MAX_FRAME_BYTES];
        data.push(b'\n');
        let got = read_frame(Cursor::new(data)).expect("a maximal frame is legal");
        assert_eq!(got.len(), MAX_FRAME_BYTES);
    }

    /// A closed connection is an error, not an empty frame that would then be
    /// parsed as malformed and handled as a request.
    #[test]
    fn a_closed_connection_is_eof_not_an_empty_frame() {
        assert_eq!(read_frame(Cursor::new(Vec::new())), Err(ReadError::Eof));
    }

    /// Invalid UTF-8 is refused rather than lossily converted — a lossy
    /// conversion would let a guest smuggle bytes past the parser's expectations.
    #[test]
    fn invalid_utf8_is_refused() {
        let bad = vec![0xff, 0xfe, b'\n'];
        assert_eq!(read_frame(Cursor::new(bad)), Err(ReadError::Io));
    }
}
