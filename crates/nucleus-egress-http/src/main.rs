//! Unprivileged HTTP compatibility adapter for a single broker upstream.
//! Only the Unix workload door is reachable; this process never holds credentials.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use clap::Parser;

mod managed;

#[derive(Parser)]
#[command(about = "Expose one credentialed broker upstream to local HTTP clients")]
struct Args {
    /// Unix workload door supplied by the runtime. TCP destinations are refused.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_URL")]
    door: String,
    /// Registered upstream name; cannot be overridden by a request.
    #[arg(long)]
    upstream: String,
    /// Local listener, never a wildcard or external interface.
    #[arg(long, default_value = "127.0.0.1:18081")]
    listen: Loopback,
    /// Total request deadline, including operator approval and streamed response.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=3600))]
    timeout_seconds: u64,
    /// Optional workload to run once the listener is bound: -- command args...
    #[arg(last = true)]
    command: Vec<std::ffi::OsString>,
}

/// A listener address checked before it can be bound by this adapter.
#[derive(Clone, Debug)]
struct Loopback(SocketAddrV4);
impl std::str::FromStr for Loopback {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let address: SocketAddrV4 = value
            .parse()
            .map_err(|e| format!("invalid IPv4 listener: {e}"))?;
        if !address.ip().is_loopback() {
            return Err("listen address must be IPv4 loopback".into());
        }
        Ok(Self(address))
    }
}
impl Loopback {
    async fn bind(self) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(self.0).await
    }
}

#[derive(Clone)]
struct Adapter {
    #[expect(
        clippy::disallowed_types,
        reason = "Unix-only transport to the enforcing workload door, not external egress"
    )]
    client: reqwest::Client,
    upstream: String,
}

impl Adapter {
    #[expect(
        clippy::disallowed_types,
        reason = "constructor fixes Unix transport and disables proxies and redirects before any request"
    )]
    fn new(door: &str, upstream: String, timeout: Duration) -> Result<Self, String> {
        let socket = door
            .strip_prefix("unix://")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && p.file_name().is_some())
            .ok_or("door must be unix:///absolute/socket/path")?;
        if !safe_segment(&upstream) {
            return Err("upstream must be a nonempty name without path syntax".into());
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .no_proxy()
            .unix_socket(socket)
            .redirect(reqwest::redirect::Policy::none())
            .http1_only()
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client, upstream })
    }

    fn destination(&self, uri: &axum::http::Uri) -> Result<String, &'static str> {
        // The broker protocol currently carries a relative path, not a query
        // or arbitrary method. Refuse unsupported syntax rather than change it.
        if uri.scheme().is_some() || uri.authority().is_some() || uri.query().is_some() {
            return Err("only origin-form paths without queries are supported");
        }
        let path = uri
            .path()
            .strip_prefix('/')
            .ok_or("absolute path required")?;
        if !path.split('/').all(safe_segment) {
            return Err("path must contain plain nonempty segments without traversal or escapes");
        }
        Ok(format!(
            "http://workload-door/v1/egress/{}/{path}",
            self.upstream
        ))
    }
}

fn safe_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

async fn forward(State(adapter): State<Adapter>, request: Request) -> Response {
    if request.method() != Method::POST {
        return (StatusCode::METHOD_NOT_ALLOWED, "broker supports POST only").into_response();
    }
    let destination = match adapter.destination(request.uri()) {
        Ok(url) => url,
        Err(reason) => return (StatusCode::BAD_REQUEST, reason).into_response(),
    };
    let (parts, body) = request.into_parts();
    let mut outgoing = adapter.client.post(destination);
    // No Authorization, Cookie, Host, identity or proxy-approval headers cross
    // this boundary. Credentials and authentication belong to the host/door.
    for name in [
        header::CONTENT_TYPE.as_str(),
        "x-nucleus-approval-wait-seconds",
    ] {
        if let Some(value) = parts.headers.get(name) {
            outgoing = outgoing.header(name, value);
        }
    }
    let response = match outgoing
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "workload broker transport failed").into_response();
        }
    };
    let mut outgoing_response = Response::new(Body::empty());
    *outgoing_response.status_mut() = response.status();
    for name in [header::CONTENT_TYPE, header::RETRY_AFTER] {
        if let Some(value) = response.headers().get(&name) {
            outgoing_response.headers_mut().insert(name, value.clone());
        }
    }
    *outgoing_response.body_mut() = Body::from_stream(response.bytes_stream());
    outgoing_response
}

fn router(adapter: Adapter) -> Router {
    Router::new().fallback(forward).with_state(adapter)
}

#[tokio::main]
async fn main() -> Result<std::process::ExitCode, Box<dyn std::error::Error>> {
    let args = Args::parse();
    let adapter = Adapter::new(
        &args.door,
        args.upstream,
        Duration::from_secs(args.timeout_seconds),
    )?;
    let listener = args.listen.bind().await?;
    let address = listener.local_addr()?;
    println!("NUCLEUS_EGRESS_HTTP_READY http://{}", address);
    managed::run(
        listener,
        router(adapter),
        args.command,
        managed::shutdown()?,
    )
    .await
}

#[cfg(test)]
mod tests;
