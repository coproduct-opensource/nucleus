//! Host-only adapter to an operator's provider-specific scoped credential service.
use super::{MintFuture, MintedCredential, ScopedCredentialMinter, WriteScope};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

const RESPONSE_LIMIT: u64 = 16 * 1024;
const MINT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn connect_config(path: &Path) -> Result<Arc<dyn ScopedCredentialMinter>, String> {
    if !path.is_absolute() {
        return Err("audit minter socket must be an absolute host path".into());
    }
    Ok(Arc::new(SocketMinter {
        path: path.to_owned(),
    }))
}

struct SocketMinter {
    path: PathBuf,
}

#[derive(Serialize)]
struct MintRequest<'a> {
    schema: &'static str,
    scope: &'a WriteScope,
    ttl_seconds: u64,
}

// No Debug: a response contains secrets, including on malformed provider replies.
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum MintResponse {
    Granted {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        expires_at_unix: u64,
    },
    Refused,
}

impl ScopedCredentialMinter for SocketMinter {
    fn mint<'a>(&'a self, scope: &'a WriteScope, ttl: Duration) -> MintFuture<'a> {
        Box::pin(async move {
            tokio::time::timeout(MINT_TIMEOUT, self.exchange(scope, ttl))
                .await
                .map_err(|_| "audit credential service timed out".to_string())?
        })
    }
}

impl SocketMinter {
    async fn exchange(
        &self,
        scope: &WriteScope,
        ttl: Duration,
    ) -> Result<MintedCredential, String> {
        let mut stream = UnixStream::connect(&self.path)
            .await
            .map_err(|_| "audit credential service connection failed")?;
        let mut request = serde_json::to_vec(&MintRequest {
            schema: "nucleus.audit-mint.v1",
            scope,
            ttl_seconds: ttl.as_secs(),
        })
        .map_err(|_| "audit credential request encoding failed")?;
        request.push(b'\n');
        stream
            .write_all(&request)
            .await
            .map_err(|_| "audit credential request write failed")?;
        let mut response = Vec::new();
        BufReader::new(stream.take(RESPONSE_LIMIT + 1))
            .read_until(b'\n', &mut response)
            .await
            .map_err(|_| "audit credential response read failed")?;
        if response.len() as u64 > RESPONSE_LIMIT || response.last() != Some(&b'\n') {
            return Err("audit credential response exceeds limit or is incomplete".into());
        }
        // Do not propagate parser errors: diagnostics can include credential bytes.
        match serde_json::from_slice::<MintResponse>(&response)
            .map_err(|_| "invalid audit credential service response")?
        {
            MintResponse::Refused => Err("audit credential service refused scope".into()),
            MintResponse::Granted {
                access_key_id,
                secret_access_key,
                session_token,
                expires_at_unix,
            } => {
                let expires_at = SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(expires_at_unix))
                    .ok_or("audit credential expiry is unrepresentable")?;
                Ok(MintedCredential {
                    access_key_id,
                    secret_access_key,
                    session_token,
                    expires_at,
                })
            }
        }
    }
}

#[cfg(test)]
#[path = "audit_credential_socket_tests.rs"]
mod tests;
