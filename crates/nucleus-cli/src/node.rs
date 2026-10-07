//! Node command - interact with a running nucleus-node
//!
//! Test utilities for nucleus-node HTTP and gRPC APIs.

mod apple_host;
mod effect_approvals;
mod workload;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use std::fs;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::time::Duration;

/// Interact with a running nucleus-node
#[derive(Args, Debug)]
#[command(mut_args = |a| a.hide_env_values(true))]
pub struct NodeArgs {
    /// Start/check the selected Apple host and use its current URL and mTLS identity
    #[arg(long, conflicts_with_all = ["url", "tls_cert", "tls_key", "trust_bundle"])]
    pub apple_host_config: Option<PathBuf>,

    /// Node URL; defaults to config's node.url, then https://127.0.0.1:8080
    #[arg(long, env = "NUCLEUS_NODE_URL")]
    pub url: Option<String>,

    // === mTLS: the only way to the node since Move B ===
    //
    // There is no shared-secret alternative: the node stopped reading
    // `NUCLEUS_NODE_AUTH_SECRET` with Move B, and the CLI stopped offering
    // `--auth-secret`/`--secrets-file`/`sign` with #3294.
    /// Path to this CLI's client certificate (PEM). Defaults to the identity
    /// `nucleus setup` already provisioned (`~/.config/nucleus/identity/
    /// cli-cert.pem`) when all three of `--tls-cert`/`--tls-key`/
    /// `--trust-bundle` are unset and that identity exists — see
    /// `apply_provisioned_identity_defaults`. Requires `--tls-key`.
    #[arg(long, env = "NUCLEUS_NODE_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,
    /// Path to this CLI's client private key (PEM). Requires `--tls-cert`.
    #[arg(long, env = "NUCLEUS_NODE_TLS_KEY")]
    pub tls_key: Option<PathBuf>,
    /// Path to the trust bundle (PEM) that verifies the node's server
    /// certificate — the node's own CA root, not a public CA, since the
    /// node self-issues. Required alongside `--tls-cert`/`--tls-key`: without
    /// it the node's self-issued cert has no root to verify against.
    #[arg(long, env = "NUCLEUS_NODE_TRUST_BUNDLE")]
    pub trust_bundle: Option<PathBuf>,

    #[command(subcommand)]
    pub command: NodeCommand,
}

impl NodeArgs {
    fn url(&self) -> &str {
        self.url
            .as_deref()
            .unwrap_or(crate::config::DEFAULT_NODE_URL)
    }
}

#[derive(Subcommand, Debug)]
pub enum NodeCommand {
    /// Check nucleus-node health
    Health,

    /// List all pods
    Pods,

    /// Create a pod from a YAML spec
    Create {
        /// Path to pod spec YAML file
        spec_file: PathBuf,
        /// Record this pod as a child of the given parent pod id (sets the
        /// `x-nucleus-parent-pod-id` header). For orchestrator/test use — the
        /// header is unauthenticated, so a real pod's lineage is instead
        /// established by the node from the authenticated caller.
        #[arg(long)]
        parent_pod_id: Option<String>,
    },

    /// Cancel (stop) a pod
    Cancel {
        /// Pod ID
        pod_id: String,
    },

    /// Stream logs from a pod
    Logs {
        /// Pod ID
        pod_id: String,

        /// Follow logs (like tail -f)
        #[arg(short, long)]
        follow: bool,

        /// Byte offset to start from
        #[arg(long, default_value = "0")]
        offset: u64,
    },

    /// Review and settle host approvals using the operator's mTLS identity
    EffectApprovals {
        pod_id: uuid::Uuid,
        #[command(subcommand)]
        command: effect_approvals::Command,
    },

    /// Read workload results and logs, or collect a signed artifact bundle
    Workload {
        pod_id: uuid::Uuid,
        #[command(subcommand)]
        command: workload::Command,
    },
}

/// Fills in `--tls-cert`/`--tls-key`/`--trust-bundle` from the identity
/// `nucleus setup` already provisioned (Move A step 6:
/// `provision::mint_cli_identity`), when the caller passed none of the
/// three flags explicitly and all three provisioned files are present.
///
/// Move B made the node's HTTP listener mTLS-only, with no plaintext/HMAC
/// mode left to fall back to — before this, every default `nucleus node`
/// invocation on an otherwise fully set-up machine would silently attempt
/// (and fail) the now-nonexistent plaintext path, because nothing pointed
/// these flags at the identity `setup` already minted.
///
/// Only fills in the gap when ALL THREE flags are unset: a partial explicit
/// set must still hit `load_mtls_config`'s "must all be provided together"
/// error rather than being silently completed from defaults, and any flag
/// the caller DID set must never be overridden.
fn apply_provisioned_identity_defaults(args: &mut NodeArgs) {
    if args.tls_cert.is_some() || args.tls_key.is_some() || args.trust_bundle.is_some() {
        return;
    }
    let Ok(dir) = crate::config::Config::identity_dir() else {
        return;
    };
    if let Some((cert, key, bundle)) = provisioned_identity_paths_in(&dir) {
        args.tls_cert = Some(cert);
        args.tls_key = Some(key);
        args.trust_bundle = Some(bundle);
    }
}

/// The directory-parameterized half of [`apply_provisioned_identity_defaults`]
/// — split out so a test can point it at a tempdir instead of the real,
/// non-overridable `Config::identity_dir()`. `Some` only when all three
/// files `mint_cli_identity` writes are present; a partial set (e.g. a
/// half-written identity from an interrupted `setup`) is treated the same
/// as none, so `load_mtls_config`'s "must all be provided together" error
/// still fires rather than a silently completed partial default.
fn provisioned_identity_paths_in(dir: &std::path::Path) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let cert = dir.join("cli-cert.pem");
    let key = dir.join("cli-key.pem");
    let bundle = dir.join("trust-bundle.pem");
    (cert.is_file() && key.is_file() && bundle.is_file()).then_some((cert, key, bundle))
}

/// Execute the node command
pub async fn execute(mut args: NodeArgs, config_path: &str) -> Result<()> {
    let config = crate::config::Config::load(config_path)?;
    apple_host::apply_default(&mut args, &config);
    apple_host::apply(&mut args).await?;
    apply_provisioned_identity_defaults(&mut args);
    let agent = create_client(&args)?;

    let url = args.url().to_string();
    match args.command {
        NodeCommand::Workload { pod_id, command } => {
            workload::run(&agent, &url, pod_id, &command).await
        }
        NodeCommand::EffectApprovals { pod_id, command } => {
            println!(
                "{}",
                effect_approvals::run(&agent, &url, pod_id, &command).await?
            );
            Ok(())
        }
        NodeCommand::Health => health(&agent, &url).await,
        NodeCommand::Pods => list_pods(&agent, &url).await,
        NodeCommand::Create {
            spec_file,
            parent_pod_id,
        } => create_pod(&agent, &url, &spec_file, parent_pod_id.as_deref()).await,
        NodeCommand::Cancel { pod_id } => cancel_pod(&agent, &url, &pod_id).await,
        NodeCommand::Logs {
            pod_id,
            follow,
            offset,
        } => stream_logs(&agent, &url, &pod_id, follow, offset).await,
    }
}

/// `(client identity PEM bundle, trust bundle PEM)` read from
/// `--tls-cert`/`--tls-key`/`--trust-bundle`, or `None` when none of the
/// three is set — which [`create_client`] refuses, since the node has no
/// other way in.
///
/// A PARTIAL set is a hard error, the same discipline node/tool-proxy's own
/// `--tls-*` flags use: one misspelled flag must not read as "none given".
fn load_mtls_config(args: &NodeArgs) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    match (&args.tls_cert, &args.tls_key, &args.trust_bundle) {
        (None, None, None) => Ok(None),
        (Some(cert_path), Some(key_path), Some(bundle_path)) => {
            let mut identity_pem = fs::read(cert_path)
                .with_context(|| format!("failed to read {}", cert_path.display()))?;
            let key_pem = fs::read(key_path)
                .with_context(|| format!("failed to read {}", key_path.display()))?;
            // reqwest's `Identity::from_pem` wants cert and key concatenated
            // in one buffer, the same convention `nucleus-sdk::MtlsConfig`
            // already uses.
            identity_pem.push(b'\n');
            identity_pem.extend_from_slice(&key_pem);

            let bundle_pem = fs::read(bundle_path)
                .with_context(|| format!("failed to read {}", bundle_path.display()))?;
            if reqwest::Certificate::from_pem_bundle(&bundle_pem)
                .with_context(|| format!("invalid trust bundle {}", bundle_path.display()))?
                .is_empty()
            {
                bail!(
                    "trust bundle {} contains no certificates",
                    bundle_path.display()
                );
            }

            Ok(Some((identity_pem, bundle_pem)))
        }
        _ => bail!(
            "--tls-cert, --tls-key and --trust-bundle must all be provided together for mTLS \
             (or none, to use the identity `nucleus setup` provisioned)"
        ),
    }
}

/// How long an ordinary management request (health, list, cancel) may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The node's HTTP API over mTLS: the only transport it serves since Move B.
///
/// A type rather than an enum with a plaintext arm, so a command that needs
/// the operator's identity (host approvals, workload collection) cannot be
/// handed a client without one (#3294 removed the shared-secret arm).
pub(crate) struct HttpClient(reqwest::Client);

/// Builds the mTLS client from `--tls-cert`/`--tls-key`/`--trust-bundle`, which
/// default to the identity `nucleus setup` provisioned. Refused, by name, when
/// none is configured: there is no shared secret to fall back to.
fn create_client(args: &NodeArgs) -> Result<HttpClient> {
    let Some((identity_pem, bundle_pem)) = load_mtls_config(args)? else {
        bail!(
            "no client identity for the node: run `nucleus setup` to provision one, or pass \
             --tls-cert, --tls-key and --trust-bundle. The node's API is mTLS-only; it reads no \
             shared secret"
        );
    };
    // reqwest's `rustls-no-provider` feature needs a provider installed
    // before building a `Client` — `main.rs` does this at startup, but
    // defensively (and idempotently: `install_default` errors if one is
    // already installed, hence `let _ =`) doing it here too means this
    // function works correctly wherever it's called from, including tests.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // The node's certificate names it by SPIFFE ID, not by hostname, so
    // hostname verification cannot identify it; `node_tls` checks the chain
    // against `--trust-bundle` AND that the certificate names exactly the node
    // — in the trust domain `--tls-cert` itself belongs to. The same CA signs
    // federated tenants' SVIDs; those carry `ClientAuth` only
    // (`LeafRole::Foreign`), so the chain's server-usage check refuses one
    // before the name check.
    let tls = nucleus_identity::node_tls::node_client_config(&identity_pem, &bundle_pem).context(
        "failed to build the node TLS configuration from --tls-cert/--tls-key/--trust-bundle",
    )?;

    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .tls_backend_preconfigured(tls)
        .build()
        .context("failed to build mTLS client")?;
    Ok(HttpClient(client))
}

impl HttpClient {
    /// Sends a request and returns `(status, body)`. Not used for
    /// `stream_logs`, which needs a streaming read rather than a buffered
    /// body.
    ///
    /// `within` is required rather than defaulted because the right deadline
    /// is the operation's, not the client's: a pod create waits on a boot the
    /// node itself bounds, and cutting it off at the management default is
    /// what turned #2904's diagnosable failure into `timeout: global`.
    async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        within: Duration,
    ) -> Result<(u16, Vec<u8>)> {
        let mut req = self.0.request(method, url).timeout(within);
        for (key, value) in headers {
            req = req.header(key.as_str(), value.as_str());
        }
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await?.to_vec();
        Ok((status, bytes))
    }
}

/// The reason the node gave, out of a non-2xx body.
///
/// `nucleus-node` renders every `ApiError` as `{"error": "..."}`
/// (`nucleus-node/src/api_error.rs`), so the `error` field is the diagnosis and
/// the envelope is not. Three outcomes are kept apart rather than collapsed into
/// one string, because they call for different next steps (ADR 0007 A-3): an
/// empty body means the node said nothing, an unparseable body means it said
/// something we do not model, and a parsed body means we can name the reason.
fn node_error_detail(body: &[u8]) -> String {
    if body.is_empty() {
        return "<no body>".to_string();
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(value) => match value.get("error").and_then(serde_json::Value::as_str) {
            Some(reason) => reason.to_string(),
            // Valid JSON the node did not shape as an ApiError: show it whole
            // rather than reporting "<no body>" for a body that exists.
            None => String::from_utf8_lossy(body).trim().to_string(),
        },
        Err(_) => String::from_utf8_lossy(body).trim().to_string(),
    }
}

/// Fail on a non-2xx, naming the reason the node gave.
///
/// The body is the whole value here, and `verify.rs` already says why: the
/// node's 400s name the actual reason — `missing spec.image`, a policy it
/// cannot resolve, a rootfs it cannot open. Reporting only "status 400" turns a
/// precise diagnosis into a guess, which is #2902, measured at about an hour of
/// someone reading nucleus's source to find out what their spec was missing.
///
/// One function rather than a copy at each call site: five copies of a
/// formatting decision drift, and the drift is silent (ADR 0007 G-1).
pub(crate) fn ensure_ok(status: u16, body: &[u8], what: &str) -> Result<()> {
    if status < 300 {
        return Ok(());
    }
    bail!(
        "{what} failed with status {status}: {}",
        node_error_detail(body)
    );
}

async fn health(client: &HttpClient, url: &str) -> Result<()> {
    let endpoint = format!("{url}/v1/health");

    let (status, body) = client
        .send(reqwest::Method::GET, &endpoint, &[], b"", REQUEST_TIMEOUT)
        .await
        .context("Health check failed")?;
    ensure_ok(status, &body, "Health check")?;
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn list_pods(client: &HttpClient, url: &str) -> Result<()> {
    let endpoint = format!("{url}/v1/pods");

    let (status, body) = client
        .send(reqwest::Method::GET, &endpoint, &[], b"", REQUEST_TIMEOUT)
        .await
        .context("List pods failed")?;
    ensure_ok(status, &body, "List pods")?;
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn create_pod(
    client: &HttpClient,
    url: &str,
    spec_file: &PathBuf,
    parent_pod_id: Option<&str>,
) -> Result<()> {
    let endpoint = format!("{url}/v1/pods");

    // Read spec file
    let spec_content = fs::read_to_string(spec_file)
        .with_context(|| format!("Failed to read spec from {}", spec_file.display()))?;

    // Parse YAML to JSON
    let spec: serde_json::Value = serde_yaml::from_str(&spec_content)
        .with_context(|| format!("Invalid YAML in {}", spec_file.display()))?;

    let body = serde_json::to_string(&spec)?;

    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    if let Some(parent) = parent_pod_id {
        headers.push(("x-nucleus-parent-pod-id".to_string(), parent.to_string()));
    }

    let (status, resp_body) = client
        .send(
            reqwest::Method::POST,
            &endpoint,
            &headers,
            body.as_bytes(),
            nucleus_spec::boot_budget::POD_CREATE_CLIENT_TIMEOUT,
        )
        .await
        .context("Create pod failed")?;
    ensure_ok(status, &resp_body, "Create pod")?;
    let value: serde_json::Value = serde_json::from_slice(&resp_body)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn cancel_pod(client: &HttpClient, url: &str, pod_id: &str) -> Result<()> {
    let endpoint = format!("{url}/v1/pods/{pod_id}/cancel");

    let (status, resp_body) = client
        .send(reqwest::Method::POST, &endpoint, &[], b"", REQUEST_TIMEOUT)
        .await
        .context("Cancel pod failed")?;
    match status {
        s if s < 300 => {
            println!("Cancelled pod {pod_id}");
            Ok(())
        }
        // 404 keeps its own arm: "no such pod" is a complete diagnosis already,
        // and the node's body for it adds nothing the caller did not ask.
        404 => bail!("Pod {pod_id} not found"),
        s => ensure_ok(s, &resp_body, "Cancel pod"),
    }
}

async fn stream_logs(
    client: &HttpClient,
    url: &str,
    pod_id: &str,
    follow: bool,
    offset: u64,
) -> Result<()> {
    let endpoint = format!("{url}/v1/pods/{pod_id}/logs?follow={follow}&offset={offset}");

    // Not through `HttpClient::send`: a `--follow`ed stream can run
    // indefinitely, so it needs a real streaming read, not a buffered body.
    let mut resp = client
        .0
        .get(&endpoint)
        .send()
        .await
        .context("Stream logs failed")?;
    match resp.status().as_u16() {
        404 => bail!("Pod {pod_id} not found"),
        s if s >= 300 => bail!("Stream logs failed with status {s}"),
        _ => {}
    }
    // Lines are not guaranteed to align with chunk boundaries, so
    // buffer across chunks and only print complete lines.
    let mut pending = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        pending.extend_from_slice(&chunk);
        while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=pos).collect();
            let text = String::from_utf8_lossy(&line[..line.len() - 1]);
            println!("{text}");
            std::io::stdout().flush().ok();
        }
    }
    if !pending.is_empty() {
        println!("{}", String::from_utf8_lossy(&pending));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node that answers only after `delay`, with a 200 and an empty JSON body.
    fn slow_node(delay: Duration) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let _ = std::io::Read::read(&mut stream, &mut buf);
                    std::thread::sleep(delay);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-type: application/json\r\n\r\n{}",
                    );
                });
            }
        });
        format!("http://{addr}")
    }

    /// #2904, client side. The node's health budget and the CLI's request clock
    /// were both 30 s, so the CLI always gave up first and the node's diagnosis of
    /// a pod that would not boot was never read. The operation's deadline must win
    /// over the client's default on BOTH transports, or passing a longer one for
    /// `create` changes nothing.
    ///
    /// Driven red: dropping the per-request `timeout` in `send` fails it at the
    /// one-second client default.
    #[tokio::test]
    async fn an_operations_deadline_outlasts_the_clients_default() {
        let url = slow_node(Duration::from_millis(1500));
        let short = Duration::from_secs(1);
        let long = Duration::from_secs(10);

        // `rustls-no-provider`: the client refuses to build without one, whichever
        // test in this binary happens to run first.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = HttpClient(reqwest::Client::builder().timeout(short).build().unwrap());
        let (status, _) = client
            .send(reqwest::Method::POST, &url, &[], b"{}", long)
            .await
            .expect("the transport must honour the operation's deadline");
        assert_eq!(status, 200);

        // Non-vacuity: the server really is slower than the short deadline.
        assert!(
            client
                .send(reqwest::Method::GET, &url, &[], b"", short)
                .await
                .is_err(),
            "the stand-in node must be slow enough for the deadline to matter"
        );
    }

    /// Every CLI path that POSTs a pod names the node-derived deadline. A census,
    /// not a proof: it catches a new create site written with the client default,
    /// which is how the four existing ones came to share the node's 30 s.
    #[test]
    fn every_pod_create_site_waits_on_the_node_derived_deadline() {
        let sources = [
            ("node.rs", include_str!("node.rs")),
            ("verify.rs", include_str!("verify.rs")),
            ("twosafety_boot.rs", include_str!("twosafety_boot.rs")),
            ("run.rs", include_str!("run.rs")),
        ];
        for (name, src) in sources {
            assert!(
                src.contains("/v1/pods\""),
                "{name} no longer creates pods; update this census"
            );
            assert!(
                src.contains("POD_CREATE_CLIENT_TIMEOUT"),
                "{name} POSTs /v1/pods without POD_CREATE_CLIENT_TIMEOUT: its client would give \
                 up before the node reports why a pod did not boot (#2904)"
            );
        }
    }

    // ── mTLS (Move A step 5) ────────────────────────────────────────────────

    fn base_args() -> NodeArgs {
        NodeArgs {
            apple_host_config: None,
            url: Some("https://127.0.0.1:0".to_string()),
            tls_cert: None,
            tls_key: None,
            trust_bundle: None,
            command: NodeCommand::Health,
        }
    }

    // ── provisioned-identity defaults (Move B) ──────────────────────────────

    #[test]
    fn provisioned_identity_paths_are_found_when_all_three_files_exist() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cli-cert.pem"), "CERT").unwrap();
        fs::write(dir.path().join("cli-key.pem"), "KEY").unwrap();
        fs::write(dir.path().join("trust-bundle.pem"), "BUNDLE").unwrap();

        let found = provisioned_identity_paths_in(dir.path());
        assert_eq!(
            found,
            Some((
                dir.path().join("cli-cert.pem"),
                dir.path().join("cli-key.pem"),
                dir.path().join("trust-bundle.pem"),
            ))
        );
    }

    #[test]
    fn provisioned_identity_paths_are_none_when_nothing_was_provisioned() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(provisioned_identity_paths_in(dir.path()), None);
    }

    /// A half-written identity (an interrupted `setup`, say) must not be
    /// treated as usable — only ALL THREE files present counts.
    #[test]
    fn provisioned_identity_paths_are_none_when_only_some_files_exist() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cli-cert.pem"), "CERT").unwrap();
        fs::write(dir.path().join("cli-key.pem"), "KEY").unwrap();
        // trust-bundle.pem deliberately missing.
        assert_eq!(provisioned_identity_paths_in(dir.path()), None);
    }

    #[test]
    fn apply_provisioned_identity_defaults_never_overrides_an_explicit_flag() {
        // Even when the "provisioned" files would resolve to something else,
        // an explicitly-set flag (any one of the three) must survive
        // untouched — a partial explicit set is a configuration the caller
        // asked for, not a gap to fill in.
        let mut args = base_args();
        let explicit = PathBuf::from("/explicit/cert.pem");
        args.tls_cert = Some(explicit.clone());

        apply_provisioned_identity_defaults(&mut args);

        assert_eq!(args.tls_cert, Some(explicit));
        assert_eq!(args.tls_key, None);
        assert_eq!(args.trust_bundle, None);
    }

    #[test]
    fn load_mtls_config_is_none_when_no_flag_is_set() {
        let args = base_args();
        assert!(load_mtls_config(&args).unwrap().is_none());
    }

    /// #3294: with no identity, the CLI says so and stops. It used to fall
    /// back to an HMAC secret from `--auth-secret`, a secrets file or the
    /// Keychain, which the node had stopped reading.
    #[test]
    fn create_client_refuses_without_an_identity() {
        let Err(error) = create_client(&base_args()) else {
            panic!("a client with no identity must be refused");
        };
        let error = format!("{error:#}");
        assert!(error.contains("nucleus setup"), "{error}");
        assert!(error.contains("--tls-cert"), "{error}");
    }

    /// #3294: the shared-secret flags are gone, not ignored. An old script
    /// passing one fails at parse time instead of reaching the node unsigned.
    #[test]
    fn the_shared_secret_flags_and_sign_are_gone() {
        use clap::Parser;
        #[derive(Parser)]
        struct Parse {
            #[command(flatten)]
            args: NodeArgs,
        }
        for retired in [
            vec!["node", "--auth-secret", "deadbeef", "health"],
            vec!["node", "--secrets-file", "/tmp/secrets.env", "health"],
            vec!["node", "--actor", "someone", "health"],
            vec!["node", "sign"],
        ] {
            assert!(
                Parse::try_parse_from(retired.iter().copied()).is_err(),
                "{retired:?} still parses"
            );
        }
        assert!(Parse::try_parse_from(["node", "health"]).is_ok());
    }

    /// Each of the three flags alone -- and any two of three -- must be
    /// refused, not silently treated as "no mTLS" (which would hide what
    /// looks like a half-completed mTLS setup behind a generic "no identity")
    /// or as "mTLS enabled" (which would attempt to load files that were never
    /// fully specified).
    #[test]
    fn load_mtls_config_refuses_a_partial_flag_set() {
        let combos: &[(bool, bool, bool)] = &[
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, false, true),
            (false, true, true),
        ];
        for &(cert, key, bundle) in combos {
            let mut args = base_args();
            let p = Some(PathBuf::from("/nonexistent.pem"));
            if cert {
                args.tls_cert = p.clone();
            }
            if key {
                args.tls_key = p.clone();
            }
            if bundle {
                args.trust_bundle = p;
            }
            assert!(
                load_mtls_config(&args).is_err(),
                "combo cert={cert} key={key} bundle={bundle} should be refused"
            );
        }
    }

    /// The property `--tls-cert`/`--tls-key`/`--trust-bundle` exist for,
    /// proven with a REAL TLS handshake rather than by inspecting
    /// `load_mtls_config`'s return value: a server built with
    /// `nucleus_identity::mtls`'s own primitives (the same code the node
    /// uses) requires and verifies a client certificate, and this module's
    /// `create_agent` — driven by the CLI flags exactly as a real invocation
    /// would set them — completes the handshake and receives the response.
    // `ureq` is blocking, and `health()` calls it directly (matching how
    // production code calls it) rather than through `spawn_blocking`. On the
    // default single-threaded test runtime that starves `server_handle`'s
    // task on the same worker -- a test-harness deadlock, not a TLS finding.
    // Two worker threads let the client's blocking call and the server's
    // task run concurrently, the same way they would as separate processes
    // in reality.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_client_completes_a_real_mtls_handshake() {
        use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa, TlsServerConfig};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let trust_domain = "cli-mtls-test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();
        let trust_bundle = ca.trust_bundle().clone();

        let server_identity = Identity::new(trust_domain, "system", "node");
        let server_csr = CsrOptions::new(server_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let server_cert = ca
            .sign_csr(
                server_csr.csr(),
                server_csr.private_key(),
                &server_identity,
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let client_identity = Identity::new(trust_domain, "system", "cli");
        let client_csr = CsrOptions::new(client_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let client_cert = ca
            .sign_csr(
                client_csr.csr(),
                client_csr.private_key(),
                &client_identity,
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client-cert.pem");
        let key_path = dir.path().join("client-key.pem");
        let bundle_path = dir.path().join("trust-bundle.pem");
        fs::write(&cert_path, client_cert.chain_pem()).unwrap();
        fs::write(&key_path, client_cert.private_key_pem()).unwrap();
        fs::write(
            &bundle_path,
            trust_bundle
                .roots()
                .iter()
                .map(|c| c.to_pem())
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let server_trust_bundle = trust_bundle.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _peer) = tcp_listener.accept().await.unwrap();
            let acceptor = TlsServerConfig::new(server_cert, server_trust_bundle)
                .build_acceptor()
                .unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 1024];
            let n = tls.read(&mut buf).await.unwrap();
            assert!(
                String::from_utf8_lossy(&buf[..n]).starts_with("GET /v1/health"),
                "server should have received the real request the agent sent"
            );
            tls.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
            )
            .await
            .unwrap();
        });

        let mut args = base_args();
        args.url = Some(format!("https://{addr}"));
        args.tls_cert = Some(cert_path);
        args.tls_key = Some(key_path);
        args.trust_bundle = Some(bundle_path);

        let agent = create_client(&args).unwrap();
        health(&agent, args.url())
            .await
            .expect("a real mTLS handshake against the SAME CA must succeed");

        server_handle.await.unwrap();
    }

    /// The refute half: the client must actually be pinning to
    /// `--trust-bundle`'s roots, not accidentally falling back to a broader
    /// trust store. A server cert signed by an UNRELATED CA must be refused
    /// even though it names the node — the identity check replaces only the
    /// hostname check, not chain validation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_client_refuses_a_server_from_an_unrelated_ca() {
        use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa, TlsServerConfig};
        use tokio::net::TcpListener;

        let real_domain = "cli-mtls-refuse-test.nucleus.local";
        let real_ca = SelfSignedCa::new(real_domain).unwrap();

        let client_identity = Identity::new(real_domain, "system", "cli");
        let client_csr = CsrOptions::new(client_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let client_cert = real_ca
            .sign_csr(
                client_csr.csr(),
                client_csr.private_key(),
                &client_identity,
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // The server's cert and trust bundle come from a DIFFERENT CA than
        // the one the CLI is told to trust.
        let stranger_domain = "stranger.nucleus.local";
        let stranger_ca = SelfSignedCa::new(stranger_domain).unwrap();
        let server_identity = Identity::new(stranger_domain, "system", "node");
        let server_csr = CsrOptions::new(server_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let server_cert = stranger_ca
            .sign_csr(
                server_csr.csr(),
                server_csr.private_key(),
                &server_identity,
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let server_trust_bundle = stranger_ca.trust_bundle().clone();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client-cert.pem");
        let key_path = dir.path().join("client-key.pem");
        let bundle_path = dir.path().join("trust-bundle.pem");
        fs::write(&cert_path, client_cert.chain_pem()).unwrap();
        fs::write(&key_path, client_cert.private_key_pem()).unwrap();
        fs::write(
            // The REAL CA's bundle -- what the CLI is told to trust.
            &bundle_path,
            real_ca
                .trust_bundle()
                .roots()
                .iter()
                .map(|c| c.to_pem())
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            let (stream, _peer) = tcp_listener.accept().await.unwrap();
            let acceptor = TlsServerConfig::new(server_cert, server_trust_bundle)
                .build_acceptor()
                .unwrap();
            // The handshake itself may fail server-side too (the client's
            // cert isn't in the stranger CA's trust bundle either) -- either
            // side observing a failure is the property under test.
            let _ = acceptor.accept(stream).await;
        });

        let mut args = base_args();
        args.url = Some(format!("https://{addr}"));
        args.tls_cert = Some(cert_path);
        args.tls_key = Some(key_path);
        args.trust_bundle = Some(bundle_path);

        let agent = create_client(&args).unwrap();
        let result = health(&agent, args.url()).await;
        assert!(
            result.is_err(),
            "a server certificate from an unrelated CA must be refused, \
             even with hostname verification disabled"
        );

        server_handle.await.unwrap();
    }

    /// The other refute half: the node's CA certifies pods too, so a chain
    /// that verifies says only "certified by this CA". A server presenting a
    /// pod's certificate from the SAME CA the CLI trusts is not the node.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_client_accepts_only_the_node_from_its_own_ca() {
        use nucleus_identity::{
            CaClient, CsrOptions, Identity, SelfSignedCa, TlsServerConfig, WorkloadCertificate,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let trust_domain = "cli-mtls-peer-test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();
        async fn mint(ca: &SelfSignedCa, id: &Identity) -> WorkloadCertificate {
            let csr = CsrOptions::new(id.to_spiffe_uri()).generate().unwrap();
            ca.sign_csr(
                csr.csr(),
                csr.private_key(),
                id,
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap()
        }
        let client_cert = mint(&ca, &Identity::new(trust_domain, "system", "cli")).await;
        let pod = Identity::new(trust_domain, "pods", "550e8400-e29b-41d4-a716-446655440000");
        let server_cert = mint(&ca, &pod).await;
        let trust_bundle = ca.trust_bundle().clone();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client-cert.pem");
        let key_path = dir.path().join("client-key.pem");
        let bundle_path = dir.path().join("trust-bundle.pem");
        fs::write(&cert_path, client_cert.chain_pem()).unwrap();
        fs::write(&key_path, client_cert.private_key_pem()).unwrap();
        fs::write(&bundle_path, trust_bundle.roots()[0].to_pem()).unwrap();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            let (stream, _peer) = tcp_listener.accept().await.unwrap();
            let acceptor = TlsServerConfig::new(server_cert, trust_bundle)
                .build_acceptor()
                .unwrap();
            // Answers exactly as the node would, so the only way the client
            // can fail is by refusing the certificate.
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let mut buf = [0u8; 1024];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
                    )
                    .await;
            }
        });

        let mut args = base_args();
        args.url = Some(format!("https://{addr}"));
        args.tls_cert = Some(cert_path);
        args.tls_key = Some(key_path);
        args.trust_bundle = Some(bundle_path);

        let agent = create_client(&args).unwrap();
        let result = health(&agent, args.url()).await;
        assert!(
            result.is_err(),
            "a pod's certificate from the node's own CA must not be taken for the node"
        );

        server_handle.await.unwrap();
    }

    /// #2902: `Create pod failed with status 400` cost about an hour of reading
    /// nucleus's source to discover the spec was missing `image`. The node had
    /// already produced the reason; the CLI discarded it.
    #[test]
    fn a_node_error_body_is_reported_as_the_reason() {
        assert_eq!(
            node_error_detail(br#"{"error":"driver error: missing spec.image"}"#),
            "driver error: missing spec.image"
        );
    }

    /// The three non-2xx shapes stay apart (ADR 0007 A-3). Collapsing them is
    /// how "the node said nothing" becomes indistinguishable from "the node
    /// said something we could not parse", which is the same absence-of-
    /// evidence error one level up in the client.
    #[test]
    fn the_three_body_shapes_are_distinguishable() {
        assert_eq!(node_error_detail(b""), "<no body>");
        assert_eq!(
            node_error_detail(b"upstream proxy refused"),
            "upstream proxy refused"
        );
        // Valid JSON the node did not shape as an ApiError: shown whole, never
        // reported as "<no body>" for a body that plainly exists.
        assert_eq!(
            node_error_detail(br#"{"detail":"nope"}"#),
            r#"{"detail":"nope"}"#
        );
    }

    /// `ensure_ok` is the guard the five call sites share; a 2xx must pass and a
    /// non-2xx must carry the reason into the message the user sees.
    #[test]
    fn ensure_ok_passes_success_and_names_the_reason_on_failure() {
        assert!(ensure_ok(200, b"", "Create pod").is_ok());
        assert!(ensure_ok(299, b"", "Create pod").is_ok());

        let err = ensure_ok(400, br#"{"error":"missing spec.image"}"#, "Create pod")
            .expect_err("a 400 must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("missing spec.image"),
            "reason absent from: {msg}"
        );
        assert!(msg.contains("400"), "status absent from: {msg}");
    }
}
