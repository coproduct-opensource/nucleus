use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info};

pub struct VsockBridge {
    listen_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl VsockBridge {
    pub async fn start(uds_path: PathBuf, guest_port: u32) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listen_addr = listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        info!("vsock bridge shutting down");
                        break;
                    }
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, _)) => {
                                let uds = uds_path.clone();
                                tokio::spawn(async move {
                                    if let Err(err) = handle_connection(stream, &uds, guest_port).await {
                                        error!("vsock bridge connection error: {err}");
                                    }
                                });
                            }
                            Err(err) => {
                                error!("vsock bridge accept error: {err}");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            listen_addr,
            shutdown: Some(shutdown_tx),
            task,
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

async fn handle_connection(
    mut inbound: TcpStream,
    uds_path: &Path,
    guest_port: u32,
) -> std::io::Result<()> {
    let mut vsock = UnixStream::connect(uds_path).await?;
    let connect_line = format!("CONNECT {guest_port}\n");
    vsock.write_all(connect_line.as_bytes()).await?;
    vsock.flush().await?;

    let mut response = Vec::new();
    loop {
        let mut buf = [0u8; 1];
        let read = vsock.read(&mut buf).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "vsock handshake EOF",
            ));
        }
        response.push(buf[0]);
        if buf[0] == b'\n' {
            break;
        }
        if response.len() > 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "vsock handshake too long",
            ));
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    if !response_str.starts_with("OK ") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("vsock handshake failed: {response_str}"),
        ));
    }

    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut vsock).await?;
    Ok(())
}
