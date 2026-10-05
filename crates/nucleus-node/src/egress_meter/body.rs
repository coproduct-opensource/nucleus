//! Pace at HTTP body consumption, not at the buffered file producer.
use crate::egress_meter::UploadCharge;
use portcullis::UploadPace;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::mpsc,
    time::{Instant, Sleep},
};
use tokio_stream::Stream;
#[cfg(test)]
use tokio_stream::StreamExt;

pub struct UploadBody {
    receiver: mpsc::Receiver<Result<Vec<u8>, io::Error>>,
    charge: UploadCharge,
    pending: Vec<u8>,
    offset: usize,
    sleep: Option<Pin<Box<Sleep>>>,
    start: Instant,
    now: u64,
    ended: bool,
}

impl std::fmt::Debug for UploadBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadBody").finish_non_exhaustive()
    }
}

impl UploadBody {
    /// A bounded PERFORM body, already owned and hashed by the host.
    pub fn from_bytes(bytes: Vec<u8>, charge: UploadCharge, now: u64) -> Self {
        let (sender, receiver) = mpsc::channel(1);
        drop(sender);
        let mut body = Self::new(receiver, charge, now);
        body.pending = bytes;
        body
    }

    #[cfg(test)]
    pub async fn collect_bytes(mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Some(chunk) = self.recv().await {
            bytes.extend(chunk.expect("test caller consumes an admitted body"));
        }
        bytes
    }
    pub fn new(
        receiver: mpsc::Receiver<Result<Vec<u8>, io::Error>>,
        charge: UploadCharge,
        now: u64,
    ) -> Self {
        Self {
            receiver,
            charge,
            pending: Vec::new(),
            offset: 0,
            sleep: None,
            start: Instant::now(),
            now,
            ended: false,
        }
    }

    #[cfg(test)]
    pub async fn recv(&mut self) -> Option<Result<Vec<u8>, io::Error>> {
        self.next().await
    }
}

impl Stream for UploadBody {
    type Item = Result<Vec<u8>, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        loop {
            if let Some(sleep) = &mut this.sleep {
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                this.sleep = None;
            }
            if this.offset == this.pending.len() {
                match this.receiver.poll_recv(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(None) => {
                        this.ended = true;
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Some(Err(error))) => {
                        this.ended = true;
                        return Poll::Ready(Some(Err(error)));
                    }
                    Poll::Ready(Some(Ok(bytes))) => {
                        this.pending = bytes;
                        this.offset = 0;
                        if this.pending.is_empty() {
                            continue;
                        }
                    }
                }
            }
            let now = this.now.saturating_add(this.start.elapsed().as_secs());
            match this
                .charge
                .pace((this.pending.len() - this.offset) as u64, now)
            {
                Ok(UploadPace::Ready(bytes)) if bytes > 0 => {
                    let end = this.offset + bytes as usize;
                    let bytes = this.pending[this.offset..end].to_vec();
                    this.offset = end;
                    return Poll::Ready(Some(Ok(bytes)));
                }
                Ok(UploadPace::Wait { seconds }) => {
                    this.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_secs(seconds))));
                }
                result => {
                    this.ended = true;
                    return Poll::Ready(Some(Err(io::Error::other(format!(
                        "upload pace unavailable: {result:?}"
                    )))));
                }
            }
        }
    }
}

/// Header metadata is counted before handing the request to HTTP. The caller
/// bounds this wait and refreshes credential authorization after it completes.
pub async fn pace_open(
    charge: &mut UploadCharge,
    mut bytes: u64,
    now: u64,
) -> Result<(), io::Error> {
    let start = Instant::now();
    while bytes > 0 {
        match charge.pace(bytes, now.saturating_add(start.elapsed().as_secs())) {
            Ok(UploadPace::Ready(n)) if n > 0 => bytes -= n,
            Ok(UploadPace::Wait { seconds }) => {
                tokio::time::sleep(Duration::from_secs(seconds)).await
            }
            result => {
                return Err(io::Error::other(format!(
                    "upload open pace unavailable: {result:?}"
                )));
            }
        }
    }
    Ok(())
}
