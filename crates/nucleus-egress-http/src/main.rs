//! Unprivileged HTTP compatibility adapter for the pod's declared broker
//! upstreams. Only the Unix workload door is reachable; this process never
//! holds credentials, and admits only callers running as its own uid.
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

use std::collections::BTreeMap;
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
mod peer;
mod plan;

#[derive(Parser)]
#[command(about = "Expose the pod's declared credentialed upstreams to local HTTP clients")]
struct Args {
    /// Unix workload door supplied by the runtime. TCP destinations are refused.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_URL")]
    door: String,
    /// An upstream the pod declared (the runtime set `NUCLEUS_EGRESS_<NAME>_URL`
    /// for it); repeat for several. Each gets its own loopback listener, and a
    /// request cannot name another.
    #[arg(long = "upstream", required = true)]
    upstreams: Vec<String>,
    /// Local listener for a single upstream, never a wildcard or external
    /// interface. Default: an ephemeral loopback port per upstream.
    #[arg(long)]
    listen: Option<Loopback>,
    /// Also give the command an upstream's URL under its own variable:
    /// `VAR=UPSTREAM`. Repeatable.
    #[arg(long = "export", value_name = "VAR=UPSTREAM")]
    exports: Vec<String>,
    /// Set `VAR` to a fixed non-secret placeholder, for a command that will not
    /// start without a credential variable. Never forwarded. Repeatable.
    #[arg(long = "placeholder", value_name = "VAR")]
    placeholders: Vec<String>,
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

    fn destination(&self, uri: &axum::http::Uri) -> Result<String, String> {
        if uri.scheme().is_some() || uri.authority().is_some() {
            return Err("only origin-form paths are supported".into());
        }
        let path = uri
            .path()
            .strip_prefix('/')
            .ok_or("absolute path required")?;
        if !path.split('/').all(safe_segment) {
            return Err(
                "path must contain plain nonempty segments without traversal or escapes".into(),
            );
        }
        // The query rule the tool-proxy and the host also apply, so a refusal
        // here is the refusal the host would give, made before anything leaves.
        let query = match uri.query() {
            None => String::new(),
            Some(query) => {
                nucleus_spec::workload_egress::check_query(query).map_err(|r| r.to_string())?;
                format!("?{query}")
            }
        };
        Ok(format!(
            "http://workload-door/v1/egress/{}/{path}{query}",
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
    // GET and POST: the closed set the host performs (smart-HTTP version
    // control needs the GET for its ref advertisement).
    let method = request.method().clone();
    if method != Method::POST && method != Method::GET {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            "broker supports GET and POST only",
        )
            .into_response();
    }
    let destination = match adapter.destination(request.uri()) {
        Ok(url) => url,
        Err(reason) => return (StatusCode::BAD_REQUEST, reason).into_response(),
    };
    let (parts, body) = request.into_parts();
    let mut outgoing = adapter.client.request(method.clone(), destination);
    // No Authorization, Cookie, Host, identity or forwarding headers cross this
    // boundary: `guest_may_propose_header` is the rule the door and the host
    // apply too, and the host then forwards only what the operator's registry
    // lists for this upstream. The approval wait is the door's own header.
    for (name, value) in &parts.headers {
        let name = name.as_str();
        let protocol = name == header::CONTENT_TYPE.as_str()
            || nucleus_spec::workload_egress::guest_may_propose_header(name);
        if protocol || name == "x-nucleus-approval-wait-seconds" {
            outgoing = outgoing.header(name, value);
        }
    }
    if method == Method::POST {
        outgoing = outgoing.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    }
    let response = match outgoing.send().await {
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
    // Only what is UTF-8 can declare an upstream; anything else is inherited
    // by the command untouched and read by nobody here.
    let env: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let plan = plan::Plan::new(
        &plan::Flags {
            door: &args.door,
            upstreams: &args.upstreams,
            listen: args.listen.map(|l| l.0),
            exports: &args.exports,
            placeholders: &args.placeholders,
        },
        &env,
    )?;
    let mut servers = Vec::new();
    let mut bound = BTreeMap::new();
    for upstream in plan.upstreams() {
        let adapter = Adapter::new(
            &args.door,
            upstream.clone(),
            Duration::from_secs(args.timeout_seconds),
        )?;
        let listener = peer::AdmittingListener::bind(plan.listen()).await?;
        let origin = format!("http://{}", listener.local());
        println!("NUCLEUS_EGRESS_HTTP_READY {upstream} {origin}");
        bound.insert(upstream.clone(), origin);
        servers.push((listener, router(adapter)));
    }
    managed::run(
        servers,
        plan.child_env(&bound),
        args.command,
        managed::shutdown()?,
    )
    .await
}

#[cfg(test)]
mod tests;
