//! Framing for a streamed host-performed call (#2696 P4).
//!
//! # The shape on the wire
//!
//! One connection per call, guest-initiated, on the broker's port:
//!
//! ```text
//! guest -> host   <hex-hmac> <StreamRequest json>\n      (signed, as every broker frame)
//! guest -> host   chunk* END                             (the request body)
//! host  -> guest  <StreamHead json>\n
//! host  -> guest  chunk* END <StreamEnd json>\n          (only after a granted head)
//! ```
//!
//! A chunk is a 4-byte big-endian length and that many bytes. A length of zero
//! is [`END_OF_BODY`], so an empty chunk cannot be written by accident: there is
//! no such chunk, only the end. A length above [`MAX_STREAM_CHUNK_BYTES`] is a
//! protocol violation, refused when its header is read, before any of its bytes
//! are buffered. So neither side ever holds more than one chunk of the other's
//! traffic, whatever the size of the call.
//!
//! # Why the chunks are not signed
//!
//! The open frame is, under the pod's broker capability, and it is what tells
//! the host the mediating proxy composed this call. The chunks travel on the
//! connection that frame opened, and no other process can write into a
//! connection it did not open. Signing each chunk would add a MAC per 64 KiB
//! and prove nothing the connection does not.
//!
//! # One implementation
//!
//! The guest that relays and the host that performs both call [`io`], so the
//! framing is defined once, in the crate both link, for the reason
//! [`crate::frame`] gives: two codecs that agree today are one edit from
//! disagreeing, and the disagreement looks like a policy refusal.

/// Largest chunk either side writes or accepts: 64 KiB.
///
/// Small enough that the host's per-chunk egress charge is fine-grained (a
/// pod's ceiling is passed by at most one chunk's worth of reservation, which
/// is then refused rather than sent) and that one chunk is cheap to hold;
/// large enough that a 1 MiB prompt is sixteen frames rather than thousands.
pub const MAX_STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Largest head or end line either side reads. Both are a few short fields.
pub const MAX_STREAM_LINE_BYTES: usize = 16 * 1024;

/// The chunk header that ends a body.
pub const END_OF_BODY: [u8; 4] = [0; 4];

/// How long the host lets the guest go quiet while it uploads a body.
pub const UPLOAD_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// How long the host waits for the upstream to answer, and between parts of
/// its answer. Generous because a model may think for minutes before the
/// first token and between tokens.
pub const UPSTREAM_IDLE: std::time::Duration = std::time::Duration::from_secs(300);

/// How long the guest waits for each part of the host's reply after the head:
/// longer than [`UPSTREAM_IDLE`], so a stalled upstream is reported by the
/// host, which knows why, rather than guessed at by the guest.
///
/// Here rather than on either side so the ordering is a fact of one file, not
/// a coupling two crates restate.
pub const GUEST_REPLY_WAIT: std::time::Duration =
    std::time::Duration::from_secs(UPSTREAM_IDLE.as_secs() + 30);

/// How long the guest waits for the head, from the open frame: the upload and
/// the upstream's first answer together. Finite, so a host that never answers
/// cannot hold a workload's call forever.
pub const GUEST_HEAD_WAIT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// What a chunk header announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkLen {
    /// This many bytes follow, between 1 and [`MAX_STREAM_CHUNK_BYTES`].
    Data(usize),
    /// The body is over.
    End,
}

/// Why a stream frame could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamFrameError {
    /// A chunk header announced more than [`MAX_STREAM_CHUNK_BYTES`]. Refused
    /// at the header, before any of its bytes are read.
    ChunkTooLarge {
        /// What the header announced.
        announced: u32,
    },
    /// A line ran past its bound without a newline. Reported at the bound.
    LineTooLong {
        /// How much was read before giving up.
        bytes: usize,
    },
    /// The connection ended before the frame did.
    Eof,
    /// A line was not UTF-8.
    NotUtf8,
    /// The transport failed.
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for StreamFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChunkTooLarge { announced } => write!(
                f,
                "a stream chunk announced {announced} bytes, above the {MAX_STREAM_CHUNK_BYTES}-byte \
                 chunk bound"
            ),
            Self::LineTooLong { bytes } => {
                write!(f, "a stream line ran past {bytes} bytes without ending")
            }
            Self::Eof => write!(f, "the stream ended before its frame did"),
            Self::NotUtf8 => write!(f, "a stream line was not UTF-8"),
            Self::Io(kind) => write!(f, "the stream's transport failed: {kind}"),
        }
    }
}

impl std::error::Error for StreamFrameError {}

/// Read a chunk header.
///
/// # Errors
/// [`StreamFrameError::ChunkTooLarge`] for a length above the bound.
pub fn decode_header(header: [u8; 4]) -> Result<ChunkLen, StreamFrameError> {
    let announced = u32::from_be_bytes(header);
    match usize::try_from(announced) {
        Ok(0) => Ok(ChunkLen::End),
        Ok(n) if n <= MAX_STREAM_CHUNK_BYTES => Ok(ChunkLen::Data(n)),
        _ => Err(StreamFrameError::ChunkTooLarge { announced }),
    }
}

/// The header for a chunk of `len` bytes, or `None` when `len` is zero (that
/// header is [`END_OF_BODY`]) or above the bound (split it first).
#[must_use]
pub fn encode_header(len: usize) -> Option<[u8; 4]> {
    if len == 0 || len > MAX_STREAM_CHUNK_BYTES {
        return None;
    }
    u32::try_from(len).ok().map(u32::to_be_bytes)
}

/// The async half: reading and writing frames over a connection.
#[cfg(feature = "io")]
pub mod io {
    use super::{ChunkLen, MAX_STREAM_CHUNK_BYTES, StreamFrameError, decode_header, encode_header};
    use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    /// One frame of a body.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Chunk {
        /// Between 1 and [`MAX_STREAM_CHUNK_BYTES`] bytes.
        Data(Vec<u8>),
        /// The body is over.
        End,
    }

    fn io_error(e: &std::io::Error) -> StreamFrameError {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            StreamFrameError::Eof
        } else {
            StreamFrameError::Io(e.kind())
        }
    }

    /// Write `bytes` as one or more chunks. Writes nothing for an empty slice,
    /// because an empty chunk would read as the end of the body.
    ///
    /// # Errors
    /// The transport's.
    pub async fn write_chunks<W: AsyncWrite + Unpin>(
        writer: &mut W,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        for piece in bytes.chunks(MAX_STREAM_CHUNK_BYTES) {
            let Some(header) = encode_header(piece.len()) else {
                // `chunks` never yields an empty or oversized piece.
                continue;
            };
            writer.write_all(&header).await?;
            writer.write_all(piece).await?;
        }
        Ok(())
    }

    /// End the body.
    ///
    /// # Errors
    /// The transport's.
    pub async fn write_end<W: AsyncWrite + Unpin>(writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&super::END_OF_BODY).await?;
        writer.flush().await
    }

    /// Write `line` and its newline, and flush.
    ///
    /// # Errors
    /// The transport's.
    pub async fn write_line<W: AsyncWrite + Unpin>(
        writer: &mut W,
        line: &str,
    ) -> std::io::Result<()> {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    }

    /// Read one chunk, refusing an oversized one at its header.
    ///
    /// # Errors
    /// [`StreamFrameError`] naming why.
    pub async fn read_chunk<R: AsyncRead + Unpin>(
        reader: &mut R,
    ) -> Result<Chunk, StreamFrameError> {
        let mut header = [0u8; 4];
        reader
            .read_exact(&mut header)
            .await
            .map_err(|e| io_error(&e))?;
        match decode_header(header)? {
            ChunkLen::End => Ok(Chunk::End),
            ChunkLen::Data(len) => {
                let mut data = vec![0u8; len];
                reader
                    .read_exact(&mut data)
                    .await
                    .map_err(|e| io_error(&e))?;
                Ok(Chunk::Data(data))
            }
        }
    }

    /// Read one newline-terminated line, refusing to accumulate past `max`.
    ///
    /// From a BUFFERED reader the caller keeps, because the bytes after the
    /// newline are the next frame: a reader that buffered internally and was
    /// then dropped would lose them.
    ///
    /// # Errors
    /// [`StreamFrameError`] naming why.
    pub async fn read_line<R: AsyncBufRead + Unpin>(
        reader: &mut R,
        max: usize,
    ) -> Result<String, StreamFrameError> {
        let mut buf = Vec::new();
        loop {
            let byte = reader.read_u8().await.map_err(|e| io_error(&e))?;
            if byte == b'\n' {
                return String::from_utf8(buf).map_err(|_| StreamFrameError::NotUtf8);
            }
            if buf.len() >= max {
                return Err(StreamFrameError::LineTooLong { bytes: buf.len() });
            }
            buf.push(byte);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::BufReader;

        /// What one side writes, the other reads: a body larger than one
        /// chunk arrives as bounded chunks and then the end.
        #[tokio::test]
        async fn a_body_round_trips_as_bounded_chunks() {
            let body: Vec<u8> = (0..(MAX_STREAM_CHUNK_BYTES * 2 + 7))
                .map(|i| i.to_le_bytes()[0])
                .collect();
            let mut wire = Vec::new();
            write_chunks(&mut wire, &body).await.expect("write");
            write_end(&mut wire).await.expect("end");

            let mut reader = wire.as_slice();
            let mut got = Vec::new();
            let mut frames = 0;
            while let Chunk::Data(d) = read_chunk(&mut reader).await.expect("a frame") {
                assert!(d.len() <= MAX_STREAM_CHUNK_BYTES);
                frames += 1;
                got.extend(d);
            }
            assert_eq!(got, body);
            assert_eq!(frames, 3);
        }

        /// An empty write writes nothing: an empty chunk would be the end.
        #[tokio::test]
        async fn an_empty_write_is_not_an_end() {
            let mut wire = Vec::new();
            write_chunks(&mut wire, &[]).await.expect("write");
            assert!(wire.is_empty());
        }

        /// An oversized header is refused before any of its bytes are read.
        #[tokio::test]
        async fn an_oversized_chunk_is_refused_at_its_header() {
            let announced = u32::try_from(MAX_STREAM_CHUNK_BYTES + 1).expect("fits");
            let wire = announced.to_be_bytes();
            let mut reader = wire.as_slice();
            assert_eq!(
                read_chunk(&mut reader).await,
                Err(StreamFrameError::ChunkTooLarge { announced })
            );
        }

        /// A connection that ends mid-chunk is an EOF, never a short chunk.
        #[tokio::test]
        async fn a_truncated_chunk_is_eof() {
            let mut wire = encode_header(10).expect("header").to_vec();
            wire.extend_from_slice(b"short");
            let mut reader = wire.as_slice();
            assert_eq!(read_chunk(&mut reader).await, Err(StreamFrameError::Eof));
        }

        /// Lines stop at the bound, and leave the next frame's bytes in the
        /// caller's reader.
        #[tokio::test]
        async fn a_line_is_bounded_and_leaves_what_follows() {
            let mut wire = b"{\"granted\":true}\n".to_vec();
            wire.extend_from_slice(&encode_header(3).expect("header"));
            wire.extend_from_slice(b"abc");
            let mut reader = BufReader::new(wire.as_slice());
            assert_eq!(
                read_line(&mut reader, 64).await.expect("line"),
                "{\"granted\":true}"
            );
            assert_eq!(
                read_chunk(&mut reader).await.expect("chunk"),
                Chunk::Data(b"abc".to_vec())
            );

            let long = vec![b'x'; 100];
            let mut reader = BufReader::new(long.as_slice());
            assert_eq!(
                read_line(&mut reader, 64).await,
                Err(StreamFrameError::LineTooLong { bytes: 64 })
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_encode_only_real_chunks() {
        assert_eq!(encode_header(0), None, "zero is the end, not a chunk");
        assert_eq!(encode_header(MAX_STREAM_CHUNK_BYTES + 1), None);
        let h = encode_header(MAX_STREAM_CHUNK_BYTES).expect("the bound itself is legal");
        assert_eq!(decode_header(h), Ok(ChunkLen::Data(MAX_STREAM_CHUNK_BYTES)));
        assert_eq!(decode_header(END_OF_BODY), Ok(ChunkLen::End));
    }

    #[test]
    fn an_oversized_header_is_refused() {
        assert!(matches!(
            decode_header(u32::MAX.to_be_bytes()),
            Err(StreamFrameError::ChunkTooLarge { .. })
        ));
    }
}
