//! Own the complete bounded upload before granting authority to send it.
//! The anonymous file is never named in the guest namespace and is removed
//! on close, including cancellation. Only fixed-size chunks occupy memory.
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::{Refusal, STREAM_IDLE_TIMEOUT};
use nucleus_cred_protocol::stream::io::{Chunk, read_chunk};

pub(super) struct StagedBody {
    file: tokio::fs::File,
    len: u64,
    digest: [u8; 32],
}

impl StagedBody {
    pub(super) async fn read<R: AsyncRead + Unpin>(
        reader: &mut R,
        max: u64,
    ) -> Result<Self, Refusal> {
        let file = tokio::task::spawn_blocking(tempfile::tempfile)
            .await
            .map_err(|_| storage_error())?
            .map_err(|_| storage_error())?;
        let mut file = tokio::fs::File::from_std(file);
        let mut hash = Sha256::new();
        let mut len = 0u64;
        loop {
            let chunk = tokio::time::timeout(STREAM_IDLE_TIMEOUT, read_chunk(reader))
                .await
                .map_err(|_| Refusal::Malformed)?
                .map_err(|_| Refusal::Malformed)?;
            let data = match chunk {
                Chunk::Data(data) => data,
                Chunk::End => break,
            };
            if data.len() as u64 > max.saturating_sub(len) {
                return Err(Refusal::Named(format!(
                    "the request body exceeds this node's per-call maximum of {max} bytes (--egress-stream-max-request-bytes)"
                )));
            }
            file.write_all(&data).await.map_err(|_| storage_error())?;
            hash.update(&data);
            len += data.len() as u64;
        }
        file.flush().await.map_err(|_| storage_error())?;
        file.rewind().await.map_err(|_| storage_error())?;
        Ok(Self {
            file,
            len,
            digest: hash.finalize().into(),
        })
    }

    pub(super) fn len(&self) -> u64 {
        self.len
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Replay only the owned file. Guest bytes can no longer change the effect.
    pub(super) async fn send(
        mut self,
        tx: mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
    ) -> Result<(), std::io::Error> {
        let mut remaining = self.len;
        while remaining != 0 {
            let mut bytes = vec![0; remaining.min(64 * 1024) as usize];
            if let Err(error) = self.file.read_exact(&mut bytes).await {
                let _ = tx
                    .send(Err(std::io::Error::other("staged upload unreadable")))
                    .await;
                return Err(error);
            }
            remaining -= bytes.len() as u64;
            if tx.send(Ok(bytes)).await.is_err() {
                // An upstream may answer before reading the entire request.
                return Ok(());
            }
        }
        Ok(())
    }
}

fn storage_error() -> Refusal {
    Refusal::Named("host upload staging unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_cred_protocol::stream::io::{write_chunks, write_end};

    #[tokio::test]
    async fn replay_and_hash_are_the_complete_payload_independent_of_chunking() {
        let payload: Vec<u8> = (0..170_000).map(|i| (i % 251) as u8).collect();
        let mut encoded = Vec::new();
        for piece in payload.chunks(7919) {
            write_chunks(&mut encoded, piece).await.unwrap();
        }
        write_end(&mut encoded).await.unwrap();
        let body = StagedBody::read(&mut encoded.as_slice(), payload.len() as u64)
            .await
            .unwrap();
        assert_eq!(body.len(), payload.len() as u64);
        assert_eq!(body.digest(), <[u8; 32]>::from(Sha256::digest(&payload)));
        let (tx, mut rx) = mpsc::channel::<Result<Vec<u8>, std::io::Error>>(1);
        let consume = async {
            let mut bytes = Vec::new();
            while let Some(chunk) = rx.recv().await {
                bytes.extend(chunk.unwrap());
            }
            bytes
        };
        let (sent, replay) = tokio::join!(body.send(tx), consume);
        sent.unwrap();
        assert_eq!(replay, payload);
    }

    #[tokio::test]
    async fn an_unterminated_or_oversized_body_never_becomes_a_staged_effect() {
        let mut encoded = Vec::new();
        write_chunks(&mut encoded, b"unapproved partial body")
            .await
            .unwrap();
        assert!(matches!(
            StagedBody::read(&mut encoded.as_slice(), 100).await,
            Err(Refusal::Malformed)
        ));
        write_end(&mut encoded).await.unwrap();
        assert!(matches!(
            StagedBody::read(&mut encoded.as_slice(), 4).await,
            Err(Refusal::Named(_))
        ));
    }
}
