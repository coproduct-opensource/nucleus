//! Inbound federation: an outside issuer's token becomes a pod principal,
//! within a ceiling the operator wrote (ADR 0010, the caller-issuer role of
//! `docs/federated-upstream-profile.md` §3).
//!
//! # The shape
//!
//! An agent runtime that holds an OIDC token from ITS OWN issuer presents it
//! once, at `POST /v1/federation/exchange`, together with a PKCS#10 CSR for a
//! key it keeps. The node answers with two short-lived things:
//!
//! 1. an X.509 SVID for the principal the operator's binding maps the token to,
//!    `spiffe://<binding.trust_domain>/ns/<binding.label>/sa/<encoded sub>`;
//! 2. a node-rooted delegation certificate whose root identity is that
//!    principal, whose permissions are the binding's ceiling (met with anything
//!    the caller asked to narrow it to), and whose `provenance` is
//!    `sha256(token)`.
//!
//! The caller then uses the node's EXISTING mTLS `POST /v1/pods` with that SVID
//! and the certificate in `x-nucleus-delegation-cert`: admission case 2
//! (`pod_authority`). There is no second way to create a pod and no bearer
//! token on `/v1/pods`, which would be replayable for the token's whole life.
//!
//! # Why a separate listener
//!
//! The node's API listener requires a client certificate, and the whole point
//! of this route is that the caller does not have one yet. That is also why
//! the old single-vendor exchange route was dead: it was mounted behind the
//! listener whose admission it existed to grant. This listener is
//! server-authenticated TLS only (the node's own certificate, rotated like the
//! API listener's) and serves nothing but the exchange.
//!
//! # Bindings (`[[caller]]`)
//!
//! Operator config, in the same TOML file as the `[[upstream]]` registry
//! (`--upstreams`), because a binding names the upstreams its callers may be
//! admitted to and one file is one atomic statement of what this node offers.
//! Unknown fields are refused and a bad binding stops the node from starting,
//! for the same reason `upstreams.rs` gives:
//!
//! ```toml
//! [[caller]]
//! label             = "example-runtime"
//! issuer            = "https://issuer.example.invalid/org/example-org-0001"
//! audience          = "https://federation.node.example.invalid"
//! algs              = ["ES256"]
//! jwks              = { discovery = true }   # or { uri = "https://…" } or { inline = '{"keys":[…]}' }
//! max_lifetime_secs = 900
//! leeway_secs       = 30                     # optional; default 30, at most 60
//! trust_domain      = "runtime.example.invalid"
//! required_claims   = { org = "example-org-0001" }   # optional
//! ceiling           = { profile = "codegen" }         # or { inline = { …lattice… } }
//! upstreams         = ["model-api"]                   # names from [[upstream]]; optional
//! svid_ttl_secs     = 600                             # optional; default 600, at most 3600
//! ```
//!
//! Load-time rules, each stopping the node:
//!
//! * `label` is `[a-z0-9-]`, 1–63 bytes, unique;
//! * `issuer` is unique across bindings — the exchange picks a binding by the
//!   token's exact `iss`, and two bindings for one issuer would make which
//!   ceiling applies depend on file order;
//! * `trust_domain` is lowercase `[a-z0-9.-]`, unique, and NOT the node's own:
//!   the tenant of a federated caller is its trust domain (ADR 0001), and a
//!   binding in the node's domain could map a `sub` onto an operator or pod
//!   identity. The CA refuses it independently (`sign_csr_for_foreign_trust_domain`);
//! * every name in `upstreams` is an `[[upstream]]` in the same file;
//! * `ceiling` resolves; the issuer settings pass `ExternalIssuerValidator::new`.
//!
//! # Mapping `sub` to a SPIFFE path segment
//!
//! SPIFFE path segments allow `[A-Za-z0-9._-]`; an outside `sub` may contain
//! anything. The encoding keeps `[A-Za-z0-9-]` as is and writes every other
//! byte of the UTF-8 `sub` — `.` and `_` included — as `_` followed by two
//! lowercase hex digits. Because `_` is ALWAYS an escape introducer and never a
//! literal, the encoding is injective (it decodes unambiguously), so two
//! distinct `sub`s can never become one principal. Nothing is truncated or
//! hashed: a `sub` whose encoding exceeds 200 bytes is refused rather than
//! shortened, since shortening is where collisions come from.
//!
//! The principal is per `sub`, but the tenant and the budget are per BINDING:
//! a runtime whose `sub` changes per invocation still authenticates, and all
//! its principals share one trust domain, one ledger and one pod view.
//!
//! # A token is spent by a successful validation
//!
//! Replay is keyed on `sha256(token)` and recorded when the token passes, not
//! when the exchange completes. A caller whose token passed and whose CSR was
//! then refused must fetch a new token. The alternative — record only on
//! success — leaves a window in which the same token is in flight twice.
//!
//! # The single-vendor route this replaces
//!
//! The old `POST /v1/oidc/<vendor>` route validated one CI provider's tokens against an issuer
//! URL compiled into the node and signed a CSR for a node-domain identity. It
//! was mounted behind the mTLS listener, so no caller without an SVID — i.e.
//! no caller it was for — could reach it. It is deleted, flags and all. The
//! same provider is one `[[caller]]` here: its issuer, audience and `RS256` in
//! operator config, its organisation allowlist a `required_claims` entry. Two
//! things differ, both deliberately: the principal is in the binding's own
//! trust domain rather than a CI namespace of the node's own (ADR 0001), and
//! it can create pods only within the binding's ceiling, not as a CI-prefixed
//! identity the node's policy trusted by name. A multi-valued allowlist (several
//! repositories under one issuer) is not expressible yet; `required_claims` is
//! exact-match, and one issuer has one binding.
//!
//! # What a caller learns when refused
//!
//! 401 for anything about the token, 403 for anything about what the token was
//! used to ask for, 400 for a body that does not parse, 503 when the node cannot
//! judge right now. The reason is logged, never returned (ADR 0004: a refusal
//! that says which check failed is an oracle for passing it).

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use nucleus_federation::{ExternalIssuerConfig, ExternalIssuerValidator, InboundError, JwksSource};
use nucleus_identity::Identity;
use nucleus_spec::{CredentialedEgressSpec, PolicySpec};
use portcullis::PermissionLattice;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::upstreams::UpstreamRegistry;

/// Largest request body. A CSR is well under 2 KiB; the bound is what an
/// unauthenticated caller can make the node buffer and parse.
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Largest bearer token looked at, matching the validator's own cap, so the
/// issuer peek below cannot be made to decode more than validation would.
const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Largest encoded `sub`. See the module docs: refused, never truncated.
const MAX_ENCODED_SUB: usize = 200;
const DEFAULT_SVID_TTL: Duration = Duration::from_secs(600);
const MAX_SVID_TTL: Duration = Duration::from_secs(3600);
/// An SVID shorter than this is not worth issuing; a token this close to
/// expiry is refused rather than answered with a certificate that is dead on
/// arrival.
const MIN_SVID_TTL_SECS: u64 = 5;
/// A TLS handshake that has not finished in this long is dropped. Handshakes
/// run off the accept loop, so a slow or silent client holds a task, never the
/// listener.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes in flight at once. Past it, new connections wait in the kernel's
/// backlog rather than as tasks here.
const MAX_HANDSHAKES: usize = 256;

/// Operator knobs, flattened into `pod_authority::AuthorityArgs` (and so into
/// the node's `Args`) rather than into `main.rs`.
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct FederationArgs {
    /// Address for the federation exchange listener (`POST
    /// /v1/federation/exchange`), served over server-authenticated TLS with the
    /// node's own certificate and NO client certificate. Unset, the exchange is
    /// not served. Requires at least one `[[caller]]` binding in `--upstreams`.
    #[arg(long = "federation-listen", env = "NUCLEUS_FEDERATION_LISTEN")]
    pub federation_listen: Option<String>,
    /// Exchanges in flight at once; a request beyond it is answered 503
    /// immediately. The bound is what one caller spraying tokens can cost the
    /// node's signer and the issuers' key endpoints.
    #[arg(
        long = "federation-max-concurrent",
        env = "NUCLEUS_FEDERATION_MAX_CONCURRENT",
        default_value_t = 16
    )]
    pub federation_max_concurrent: usize,
    /// PEM certificate chain the exchange listener presents instead of the
    /// node's own SVID. The node certificate names only a SPIFFE URI, which an
    /// ordinary HTTPS client cannot match to a hostname; a caller outside the
    /// node's trust domain usually needs a certificate for the DNS name it
    /// dials. Loaded once at start (restart to rotate). With
    /// `--federation-tls-key`, or neither.
    #[arg(long = "federation-tls-cert", env = "NUCLEUS_FEDERATION_TLS_CERT")]
    pub federation_tls_cert: Option<std::path::PathBuf>,
    /// PEM private key for `--federation-tls-cert`.
    #[arg(long = "federation-tls-key", env = "NUCLEUS_FEDERATION_TLS_KEY")]
    pub federation_tls_key: Option<std::path::PathBuf>,
}

impl Default for FederationArgs {
    fn default() -> Self {
        Self {
            federation_listen: None,
            federation_max_concurrent: 16,
            federation_tls_cert: None,
            federation_tls_key: None,
        }
    }
}

// ── Config file shape ───────────────────────────────────────────────────────

/// One `[[caller]]` table as written. Parsed by `upstreams.rs` (same file) and
/// validated by [`CallerBindings::from_files`].
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct CallerFile {
    label: String,
    issuer: String,
    audience: String,
    algs: Vec<String>,
    jwks: JwksFile,
    max_lifetime_secs: u64,
    #[serde(default)]
    leeway_secs: Option<u64>,
    trust_domain: String,
    #[serde(default)]
    required_claims: BTreeMap<String, String>,
    ceiling: CeilingSpec,
    #[serde(default)]
    upstreams: Vec<String>,
    #[serde(default)]
    svid_ttl_secs: Option<u64>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum JwksFile {
    /// Must be `true`; `false` is a config error rather than "no keys".
    Discovery(bool),
    Uri(String),
    /// A JWKS document, as JSON text.
    Inline(String),
}

/// A ceiling, in config or in an exchange request: a profile name, or an
/// inline lattice.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CeilingSpec {
    Profile(String),
    Inline(Box<PermissionLattice>),
}

impl CeilingSpec {
    fn resolve(&self) -> Result<PermissionLattice, String> {
        let spec = match self {
            Self::Profile(name) => PolicySpec::Profile { name: name.clone() },
            Self::Inline(lattice) => PolicySpec::Inline {
                lattice: lattice.clone(),
            },
        };
        spec.resolve().map_err(|e| e.to_string())
    }
}

// ── Validated bindings ──────────────────────────────────────────────────────

/// One operator binding, validated. See the module docs.
pub(crate) struct CallerBinding {
    label: String,
    trust_domain: String,
    issuer: String,
    validator: ExternalIssuerValidator,
    ceiling: PermissionLattice,
    upstreams: Vec<CredentialedEgressSpec>,
    svid_ttl: Duration,
}

impl std::fmt::Debug for CallerBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallerBinding")
            .field("label", &self.label)
            .field("trust_domain", &self.trust_domain)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl CallerBinding {
    /// The binding's tenant (ADR 0001).
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The most any caller admitted through this binding may hold.
    pub fn ceiling(&self) -> &PermissionLattice {
        &self.ceiling
    }

    /// The registry upstreams a pod created under this binding may be admitted.
    pub fn upstreams(&self) -> &[CredentialedEgressSpec] {
        &self.upstreams
    }

    /// The SPIFFE ID a validated `sub` maps to, or `None` when the `sub`
    /// cannot be mapped without truncation. See the module docs.
    pub fn principal(&self, sub: &str) -> Option<String> {
        let sa = encode_sub(sub)?;
        Identity::try_new(&self.trust_domain, &self.label, sa)
            .ok()
            .map(|id| id.to_spiffe_uri())
    }
}

/// The injective `sub` → path-segment encoding. See the module docs.
fn encode_sub(sub: &str) -> Option<String> {
    use std::fmt::Write as _;
    if sub.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(sub.len());
    for b in sub.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "_{b:02x}");
        }
        if out.len() > MAX_ENCODED_SUB {
            return None;
        }
    }
    Some(out)
}

/// Every binding this node serves. Empty when the file has no `[[caller]]`.
#[derive(Debug, Default)]
pub(crate) struct CallerBindings {
    bindings: Vec<CallerBinding>,
}

impl CallerBindings {
    /// Validate the `[[caller]]` tables of the operator file.
    ///
    /// # Errors
    /// Any rule in the module docs, naming the binding by `label`. The node
    /// refuses to start on it.
    pub fn from_files(
        files: &[CallerFile],
        registry: &UpstreamRegistry,
        node_trust_domain: &str,
    ) -> Result<Self, String> {
        if files.is_empty() {
            return Ok(Self::default());
        }
        // Same precondition `pod_authority::federation_source` states: reqwest
        // panics building a TLS client with no provider installed.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            return Err("[[caller]] bindings need a TLS crypto provider installed first".into());
        }
        let http = nucleus_federation::default_client()
            .map_err(|e| format!("federation HTTP client: {e}"))?;
        let (mut labels, mut issuers, mut domains) =
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        let mut bindings = Vec::with_capacity(files.len());
        for f in files {
            let at = |what: &str| format!("[[caller]] {:?}: {what}", f.label);
            let label_ok = (1..=63).contains(&f.label.len())
                && f.label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !label_ok {
                return Err(at("label must be 1-63 bytes of [a-z0-9-]"));
            }
            if !labels.insert(f.label.clone()) {
                return Err(at("label is defined twice"));
            }
            if !issuers.insert(f.issuer.clone()) {
                return Err(at(
                    "issuer is already bound by another [[caller]]; one issuer, one binding",
                ));
            }
            let td_ok = (1..=255).contains(&f.trust_domain.len())
                && f.trust_domain.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'
                });
            if !td_ok {
                return Err(at("trust_domain must be lowercase [a-z0-9.-]"));
            }
            if f.trust_domain == node_trust_domain {
                return Err(at(
                    "trust_domain must not be the node's own: a federated tenant is its own \
                     trust domain (ADR 0001)",
                ));
            }
            if !domains.insert(f.trust_domain.clone()) {
                return Err(at("trust_domain is bound by another [[caller]]"));
            }
            let mut algs = BTreeSet::new();
            for a in &f.algs {
                algs.insert(a.parse().map_err(|_| at("unknown algorithm in algs"))?);
            }
            let jwks = match &f.jwks {
                JwksFile::Discovery(true) => JwksSource::Discovery,
                JwksFile::Discovery(false) => {
                    return Err(at("jwks.discovery = false names no key source"));
                }
                JwksFile::Uri(u) => {
                    JwksSource::Uri(u.parse().map_err(|_| at("jwks.uri is not a URL"))?)
                }
                JwksFile::Inline(text) => JwksSource::Inline(
                    serde_json::from_str(text).map_err(|_| at("jwks.inline is not a JWKS"))?,
                ),
            };
            let mut cfg = ExternalIssuerConfig::new(&f.issuer, &f.audience, algs, jwks);
            cfg.max_lifetime = Duration::from_secs(f.max_lifetime_secs);
            if let Some(l) = f.leeway_secs {
                cfg.leeway = Duration::from_secs(l);
            }
            cfg.required_claims = f.required_claims.clone();
            let validator = ExternalIssuerValidator::new(cfg, http.clone())
                .map_err(|e| at(&format!("issuer settings: {e}")))?;
            let ceiling = f
                .ceiling
                .resolve()
                .map_err(|e| at(&format!("ceiling: {e}")))?;
            let mut upstreams = Vec::with_capacity(f.upstreams.len());
            for name in &f.upstreams {
                let entry = registry
                    .entries()
                    .iter()
                    .find(|e| &e.name == name)
                    .ok_or_else(|| at(&format!("upstream {name:?} is not in [[upstream]]")))?;
                upstreams.push(entry.clone());
            }
            let svid_ttl = f
                .svid_ttl_secs
                .map_or(DEFAULT_SVID_TTL, Duration::from_secs);
            if svid_ttl.as_secs() < MIN_SVID_TTL_SECS || svid_ttl > MAX_SVID_TTL {
                return Err(at("svid_ttl_secs must be between 5 and 3600"));
            }
            bindings.push(CallerBinding {
                label: f.label.clone(),
                trust_domain: f.trust_domain.clone(),
                issuer: f.issuer.clone(),
                validator,
                ceiling,
                upstreams,
                svid_ttl,
            });
        }
        Ok(Self { bindings })
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// The binding for an EXACT issuer. Nothing about an unbound issuer is
    /// fetched or looked at: dispatch happens before any key work, so a token
    /// naming an issuer nobody configured costs one map lookup.
    pub fn by_issuer(&self, iss: &str) -> Option<&CallerBinding> {
        self.bindings.iter().find(|b| b.issuer == iss)
    }

    /// The binding whose tenant is `trust_domain`.
    pub fn by_trust_domain(&self, trust_domain: &str) -> Option<&CallerBinding> {
        self.bindings
            .iter()
            .find(|b| b.trust_domain == trust_domain)
    }

    /// Every federated tenant, for `AuthorizationPolicy`.
    pub fn trust_domains(&self) -> impl Iterator<Item = &str> {
        self.bindings.iter().map(|b| b.trust_domain.as_str())
    }
}

/// The trust domain of a SPIFFE ID, or `None` for something that is not one.
pub(crate) fn trust_domain_of(spiffe_id: &str) -> Option<&str> {
    spiffe_id
        .strip_prefix("spiffe://")?
        .split('/')
        .next()
        .filter(|td| !td.is_empty())
}

// ── The exchange ────────────────────────────────────────────────────────────

/// `POST /v1/federation/exchange` body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExchangeRequest {
    /// PKCS#10, PEM or base64 DER. Must request exactly the mapped principal.
    csr: String,
    /// Narrow the binding's ceiling for this exchange. Met with it, so it can
    /// only narrow; asking for more yields the binding's ceiling.
    #[serde(default)]
    requested_ceiling: Option<CeilingSpec>,
}

/// `POST /v1/federation/exchange` answer.
#[derive(Serialize, Debug)]
pub(crate) struct ExchangeResponse {
    /// The principal both credentials name.
    pub spiffe_id: String,
    /// The SVID, leaf first, PEM.
    pub svid_chain_pem: String,
    /// The node CA's roots, PEM: what the caller verifies the node's API
    /// listener against when it uses the SVID.
    pub trust_bundle_pem: String,
    /// Base64 `AttenuationToken`, for `x-nucleus-delegation-cert`.
    pub delegation_cert: String,
    /// Unix seconds after which neither credential is valid.
    pub expires_at: u64,
}

/// Why an exchange was refused. The status is what the caller sees; the
/// reason is only logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    BadRequest(&'static str),
    Unauthorized(&'static str),
    Forbidden(&'static str),
    Unavailable(&'static str),
    Internal(&'static str),
}

impl Refusal {
    fn status(self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::BadRequest(r)
            | Self::Unauthorized(r)
            | Self::Forbidden(r)
            | Self::Unavailable(r)
            | Self::Internal(r) => r,
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let word = match self {
            Self::BadRequest(_) => "bad_request",
            Self::Unauthorized(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::Unavailable(_) => "unavailable",
            Self::Internal(_) => "internal_error",
        };
        (self.status(), Json(serde_json::json!({ "error": word }))).into_response()
    }
}

/// What the exchange needs: the authority (bindings, and the root key it mints
/// with), the CA that signs SVIDs, and the concurrency gate.
#[derive(Clone)]
pub(crate) struct IngressState {
    pub authority: Arc<crate::pod_authority::PodAuthority>,
    pub identity: crate::identity::IdentityManager,
    pub gate: Arc<Semaphore>,
}

/// The `iss` of a compact JWT, read WITHOUT verifying it — only to choose which
/// binding verifies it. Nothing else from the unverified payload is used.
fn peek_issuer(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    match serde_json::from_slice::<serde_json::Value>(&bytes).ok()? {
        serde_json::Value::Object(m) => m.get("iss")?.as_str().map(str::to_string),
        _ => None,
    }
}

/// A CSR as PEM, from PEM or base64 DER.
fn csr_pem(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.starts_with("-----BEGIN") {
        return Some(raw.to_string());
    }
    let der = base64::engine::general_purpose::STANDARD.decode(raw).ok()?;
    Some(pem_encode("CERTIFICATE REQUEST", &der))
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The exchange itself, transport-free so tests drive exactly what the route
/// runs. `now` is unix seconds.
pub(crate) async fn exchange(
    st: &IngressState,
    authorization: Option<&str>,
    body: &[u8],
    now: u64,
) -> Result<ExchangeResponse, Refusal> {
    let request: ExchangeRequest =
        serde_json::from_slice(body).map_err(|_| Refusal::BadRequest("body does not parse"))?;

    let token = authorization
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.len() <= MAX_TOKEN_BYTES)
        .ok_or(Refusal::Unauthorized("no bearer token"))?;

    // Dispatch by exact `iss` among CONFIGURED issuers, before any key work.
    let bindings = st.authority.caller_bindings();
    let binding = peek_issuer(token)
        .and_then(|iss| bindings.by_issuer(&iss))
        .ok_or(Refusal::Unauthorized("token names no configured issuer"))?;

    let caller = binding.validator.validate(token, now).await.map_err(|e| {
        // Which check failed is logged here, where it is still in hand, and
        // goes no further: the caller gets the status alone.
        tracing::warn!(binding = %binding.label, check = ?e.reason(), "federated token refused");
        match e {
            InboundError::Refused(_) => Refusal::Unauthorized("token refused by its binding"),
            InboundError::Unavailable(_) => Refusal::Unavailable("issuer keys unavailable"),
        }
    })?;

    let principal = binding
        .principal(&caller.sub)
        .ok_or(Refusal::Forbidden("sub does not map to a principal"))?;

    let ceiling = match &request.requested_ceiling {
        None => binding.ceiling.clone(),
        Some(req) => {
            let asked = req
                .resolve()
                .map_err(|_| Refusal::BadRequest("requested_ceiling does not resolve"))?;
            binding.ceiling.meet(&asked)
        }
    };

    // The SVID lives no longer than the token that vouched for it, nor the
    // binding's cap. One second is held back for the CA's clock running on
    // from ours.
    let remaining = caller.exp.saturating_sub(now.saturating_add(1));
    let ttl_secs = remaining.min(binding.svid_ttl.as_secs());
    if ttl_secs < MIN_SVID_TTL_SECS {
        return Err(Refusal::Unauthorized("token too close to expiry"));
    }
    let ttl = Duration::from_secs(ttl_secs);

    let csr = csr_pem(&request.csr).ok_or(Refusal::BadRequest("csr is not PEM or base64"))?;
    let identity = Identity::from_spiffe_uri(&principal)
        .map_err(|_| Refusal::Internal("principal does not parse"))?;
    // The CSR must ask for exactly this principal and nothing else; the CA
    // refuses otherwise (`spiffe_uri_from_csr_der`), and refuses any identity
    // in the node's own trust domain.
    let svid_chain_pem = st
        .identity
        .ca()
        .sign_csr_for_foreign_trust_domain(&csr, &identity, ttl)
        .await
        .map_err(|_| Refusal::Forbidden("csr refused"))?;
    let trust_bundle_pem = st
        .identity
        .ca()
        .trust_bundle()
        .roots()
        .iter()
        .map(|c| c.to_pem())
        .collect::<Vec<_>>()
        .join("\n");

    // Our `now` + ttl is no later than the CA's, so the certificate never
    // outlives the SVID.
    let not_after_unix = now.saturating_add(ttl_secs);
    let not_after = chrono::DateTime::from_timestamp(i64::try_from(not_after_unix).unwrap_or(0), 0)
        .ok_or(Refusal::Internal("expiry out of range"))?;
    let delegation_cert = st
        .authority
        .mint_federated_delegation(ceiling, principal.clone(), not_after, caller.token_hash)
        .map_err(|_| Refusal::Internal("delegation mint failed"))?;

    tracing::info!(
        binding = %binding.label,
        tenant = %binding.trust_domain,
        principal = %principal,
        expires_at = not_after_unix,
        "federated caller exchanged a token for an SVID and a delegation"
    );
    Ok(ExchangeResponse {
        spiffe_id: principal,
        svid_chain_pem,
        trust_bundle_pem,
        delegation_cert,
        expires_at: not_after_unix,
    })
}

async fn exchange_route(
    State(st): State<IngressState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Bounded concurrency: refuse immediately rather than queue, so a burst
    // costs the caller a retry and not the node a backlog of signer work.
    let Ok(_permit) = st.gate.clone().try_acquire_owned() else {
        tracing::warn!("federation exchange refused: at the concurrency bound");
        return Refusal::Unavailable("at the concurrency bound").into_response();
    };
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match exchange(&st, authorization, &body, now).await {
        Ok(resp) => Json(resp).into_response(),
        Err(refusal) => {
            tracing::warn!(
                status = refusal.status().as_u16(),
                reason = refusal.reason(),
                "federation exchange refused"
            );
            refusal.into_response()
        }
    }
}

/// The exchange listener's router: one route, a body cap.
pub(crate) fn router(st: IngressState) -> Router {
    Router::new()
        .route("/v1/federation/exchange", post(exchange_route))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(st)
}

// ── The listener ────────────────────────────────────────────────────────────

/// A server-authenticated TLS listener whose handshakes run off the accept
/// loop. See [`HANDSHAKE_TIMEOUT`].
struct TlsListener {
    rx: tokio::sync::mpsc::Receiver<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        SocketAddr,
    )>,
    addr: SocketAddr,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            // The acceptor task ended (its listener failed); serve nothing
            // further rather than spin.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.addr)
    }
}

fn spawn_acceptor(
    tcp: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) -> tokio::sync::mpsc::Receiver<(
    tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    SocketAddr,
)> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let slots = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    tokio::spawn(async move {
        loop {
            let Ok(permit) = slots.clone().acquire_owned().await else {
                return;
            };
            let (stream, addr) = match tcp.accept().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "federation listener accept failed");
                    continue;
                }
            };
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                let _permit = permit;
                if let Ok(Ok(tls)) =
                    tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                {
                    let _ = tx.send((tls, addr)).await;
                }
            });
        }
    });
    rx
}

/// A server-auth-only TLS config from an operator's PEM files.
fn operator_tls(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Result<rustls::ServerConfig, String> {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("--federation-tls-cert {}: {e}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| format!("--federation-tls-key {}: {e}", key.display()))?;
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("federation listener certificate: {e}"))
}

/// Serve `app` over server-authenticated TLS on `tcp`. No client certificate
/// is asked for: the bearer token is this route's authentication.
fn serve_tls(tcp: tokio::net::TcpListener, config: rustls::ServerConfig, app: Router) {
    let addr = tcp
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let listener = TlsListener {
        rx: spawn_acceptor(tcp, tokio_rustls::TlsAcceptor::from(Arc::new(config))),
        addr,
    };
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "federation listener stopped");
        }
    });
}

/// Serve the exchange, if `--federation-listen` is set. Returns once the
/// listener is bound; serving continues on a task.
///
/// # Errors
/// `--federation-listen` without any `[[caller]]` binding (a listener that
/// can only refuse is a misconfiguration, said at start), only one of the two
/// `--federation-tls-*` files, an unloadable certificate, or an address that
/// does not bind.
pub(crate) async fn spawn(
    state: &crate::NodeState,
    args: &FederationArgs,
) -> Result<(), crate::ApiError> {
    let Some(listen) = args.federation_listen.as_deref() else {
        return Ok(());
    };
    let err = crate::ApiError::Driver;
    if state.authority.caller_bindings().is_empty() {
        return Err(err(
            "--federation-listen is set but --upstreams has no [[caller]] binding".into(),
        ));
    }
    let identity = state
        .identity_manager
        .clone()
        .ok_or_else(|| err("the federation listener needs the node identity".into()))?;
    let config = match (&args.federation_tls_cert, &args.federation_tls_key) {
        (Some(cert), Some(key)) => operator_tls(cert, key).map_err(err)?,
        (None, None) => {
            // The node's own certificate, rotated like the API listener's.
            let node_cert = identity.node_certificate().await.map_err(err)?;
            let resolver = Arc::new(
                nucleus_identity::tls::RotatingServerCert::new(&node_cert)
                    .map_err(|e| err(format!("federation listener certificate: {e}")))?,
            );
            crate::http_serve::spawn_certificate_rotation(state, resolver.clone());
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver)
        }
        _ => {
            return Err(err(
                "--federation-tls-cert and --federation-tls-key go together".into(),
            ));
        }
    };
    let tcp = tokio::net::TcpListener::bind(listen).await?;
    let addr = tcp.local_addr()?;
    let app = router(IngressState {
        authority: state.authority.clone(),
        identity,
        gate: Arc::new(Semaphore::new(args.federation_max_concurrent.max(1))),
    });
    serve_tls(tcp, config, app);
    tracing::info!(%addr, "federation exchange listening (server-authenticated TLS, no client certificate)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pod_authority::{Admission, AuthorityArgs, PodAuthority};
    use portcullis::token::AttenuationToken;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use serde_json::{Value, json};

    const NODE_TD: &str = "node.local";
    const ISS_A: &str = "https://issuer-a.example.invalid";
    const ISS_B: &str = "https://issuer-b.example.invalid";
    const AUD: &str = "https://federation.node.example.invalid";
    const TD_A: &str = "tenant-a.example.invalid";
    const TD_B: &str = "tenant-b.example.invalid";

    fn b64u(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// An outside issuer: one P-256 key, signing whatever it is told to.
    struct Issuer {
        key: EcdsaKeyPair,
        kid: &'static str,
        iss: &'static str,
    }

    impl Issuer {
        fn new(iss: &'static str, kid: &'static str) -> Self {
            let rng = SystemRandom::new();
            let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let key =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der.as_ref(), &rng)
                    .unwrap();
            Self { key, kid, iss }
        }

        fn jwks(&self) -> String {
            let pk = self.key.public_key().as_ref();
            json!({"keys": [{
                "kty": "EC", "crv": "P-256", "use": "sig", "kid": self.kid,
                "x": b64u(&pk[1..33]), "y": b64u(&pk[33..65]),
            }]})
            .to_string()
        }

        fn sign(&self, header: Value, claims: Value) -> String {
            let input = format!(
                "{}.{}",
                b64u(header.to_string().as_bytes()),
                b64u(claims.to_string().as_bytes())
            );
            let sig = self
                .key
                .sign(&SystemRandom::new(), input.as_bytes())
                .unwrap();
            format!("{input}.{}", b64u(sig.as_ref()))
        }

        fn claims(&self, sub: &str, now: u64) -> Value {
            json!({
                "iss": self.iss, "aud": AUD, "sub": sub, "iat": now, "exp": now + 300,
                "org": "example-org-0001",
            })
        }

        fn header(&self) -> Value {
            json!({"alg": "ES256", "kid": self.kid, "typ": "JWT"})
        }

        fn token(&self, sub: &str, now: u64) -> String {
            self.sign(self.header(), self.claims(sub, now))
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    struct Fixture {
        st: IngressState,
        a: Issuer,
        /// Held so B's binding is loaded; its key signs nothing here.
        _b: Issuer,
        _dir: tempfile::TempDir,
    }

    /// Two bindings on one node. A may reach `model-api` only; B nothing. A's
    /// ceiling is `codegen` (budget 5); B's `read_only`.
    fn fixture_with(extra_caller: &str) -> Fixture {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (a, b) = (Issuer::new(ISS_A, "key-a"), Issuer::new(ISS_B, "key-b"));
        let dir = tempfile::tempdir().unwrap();
        let toml = format!(
            r#"
[[upstream]]
name = "model-api"
base_url = "https://model.example.invalid/v1"
header = "authorization"
value_prefix = "Bearer "
[upstream.credential.env]
var = "MODEL_TOKEN"

[[upstream]]
name = "search-api"
base_url = "https://search.example.invalid"
header = "x-api-key"
[upstream.credential.env]
var = "SEARCH_TOKEN"

[[caller]]
label = "runtime-a"
issuer = "{ISS_A}"
audience = "{AUD}"
algs = ["ES256"]
jwks = {{ inline = '{jwks_a}' }}
max_lifetime_secs = 900
trust_domain = "{TD_A}"
required_claims = {{ org = "example-org-0001" }}
ceiling = {{ profile = "codegen" }}
upstreams = ["model-api"]
svid_ttl_secs = 600

[[caller]]
label = "runtime-b"
issuer = "{ISS_B}"
audience = "{AUD}"
algs = ["ES256"]
jwks = {{ inline = '{jwks_b}' }}
max_lifetime_secs = 900
trust_domain = "{TD_B}"
ceiling = {{ profile = "read_only" }}
{extra_caller}
"#,
            jwks_a = a.jwks(),
            jwks_b = b.jwks(),
        );
        let path = dir.path().join("upstreams.toml");
        std::fs::write(&path, toml).unwrap();
        let args = AuthorityArgs {
            root_minter_spiffe_id: None,
            cert_trust_anchors: Vec::new(),
            max_children_per_pod: 8,
            upstreams: Some(path),
            federation_issuer: None,
            ingress: FederationArgs::default(),
        };
        let authority = Arc::new(PodAuthority::new(&args, NODE_TD, dir.path()).unwrap());
        let identity =
            crate::identity::IdentityManager::new(NODE_TD, Duration::from_secs(3600)).unwrap();
        Fixture {
            st: IngressState {
                authority,
                identity,
                gate: Arc::new(Semaphore::new(4)),
            },
            a,
            _b: b,
            _dir: dir,
        }
    }

    fn fixture() -> Fixture {
        fixture_with("")
    }

    fn csr_for(uri: &str) -> String {
        nucleus_identity::CsrOptions::new(uri)
            .generate()
            .unwrap()
            .csr()
            .to_string()
    }

    fn body(csr: &str, ceiling: Option<Value>) -> Vec<u8> {
        let mut b = json!({ "csr": csr });
        if let Some(c) = ceiling {
            b["requested_ceiling"] = c;
        }
        b.to_string().into_bytes()
    }

    async fn run(f: &Fixture, token: &str, body: &[u8]) -> Result<ExchangeResponse, Refusal> {
        exchange(&f.st, Some(&format!("Bearer {token}")), body, now()).await
    }

    fn principal_a(sub: &str) -> String {
        format!(
            "spiffe://{TD_A}/ns/runtime-a/sa/{}",
            encode_sub(sub).unwrap()
        )
    }

    fn cert_of(resp: &ExchangeResponse) -> AttenuationToken {
        AttenuationToken::from_base64(&resp.delegation_cert).unwrap()
    }

    #[tokio::test]
    async fn a_bound_token_becomes_an_svid_and_a_delegation_for_its_principal() {
        let f = fixture();
        let token = f.a.token("alice", now());
        let resp = run(&f, &token, &body(&csr_for(&principal_a("alice")), None))
            .await
            .expect("exchanged");
        assert_eq!(resp.spiffe_id, principal_a("alice"));
        let leaf =
            nucleus_identity::certificate::Certificate::from_pem(&resp.svid_chain_pem).unwrap();
        assert_eq!(
            nucleus_identity::spiffe_uri_from_svid(leaf.der()).unwrap(),
            resp.spiffe_id
        );
        let cert = cert_of(&resp);
        assert_eq!(cert.certificate().root_identity(), resp.spiffe_id);
        use sha2::Digest as _;
        let hash: [u8; 32] = sha2::Sha256::digest(token.as_bytes()).into();
        assert_eq!(cert.certificate().authority().provenance, Some(hash));
    }

    #[tokio::test]
    async fn a_token_the_binding_does_not_accept_is_401() {
        let f = fixture();
        let t = now();
        let csr = csr_for(&principal_a("alice"));
        let mut wrong_aud = f.a.claims("alice", t);
        wrong_aud["aud"] = json!("https://someone-else.example.invalid");
        let mut wrong_alg = f.a.header();
        wrong_alg["alg"] = json!("ES384");
        let mut wrong_kid = f.a.header();
        wrong_kid["kid"] = json!("key-nobody-published");
        // The shape a CI provider's binding takes: the organisation allowlist
        // the removed single-vendor route hard-coded is a required claim.
        let mut other_org = f.a.claims("alice", t);
        other_org["org"] = json!("example-org-0002");
        let mut over_lifetime = f.a.claims("alice", t);
        over_lifetime["exp"] = json!(t + 901);
        let cases = [
            ("aud", f.a.sign(f.a.header(), wrong_aud)),
            ("alg", f.a.sign(wrong_alg, f.a.claims("alice", t))),
            ("kid", f.a.sign(wrong_kid, f.a.claims("alice", t))),
            ("lifetime", f.a.sign(f.a.header(), over_lifetime)),
            ("required claim", f.a.sign(f.a.header(), other_org)),
            // B's issuer, but signed by A's key: B's binding checks B's keys.
            ("key", {
                let mut c = f.a.claims("alice", t);
                c["iss"] = json!(ISS_B);
                let mut h = f.a.header();
                h["kid"] = json!("key-b");
                f.a.sign(h, c)
            }),
        ];
        for (what, token) in cases {
            assert!(
                matches!(
                    run(&f, &token, &body(&csr, None)).await,
                    Err(Refusal::Unauthorized(_))
                ),
                "{what}"
            );
        }
    }

    #[tokio::test]
    async fn an_unconfigured_issuer_is_refused_without_fetching_anything() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;
        // A third binding whose keys live at the mock: the positive control
        // that this binding DOES fetch, so zero requests below means something.
        let extra = format!(
            r#"
[[caller]]
label = "runtime-c"
issuer = "{uri}/c"
audience = "{AUD}"
algs = ["ES256"]
jwks = {{ uri = "{uri}/c/jwks" }}
max_lifetime_secs = 900
trust_domain = "tenant-c.example.invalid"
ceiling = {{ profile = "read_only" }}
"#,
            uri = server.uri()
        );
        let f = fixture_with(&extra);
        let csr = csr_for(&principal_a("alice"));

        // The token names the mock's address as its issuer, but no binding
        // has that EXACT issuer.
        let mut c = f.a.claims("alice", now());
        c["iss"] = json!(format!("{}/unbound", server.uri()));
        let token = f.a.sign(f.a.header(), c);
        assert!(matches!(
            run(&f, &token, &body(&csr, None)).await,
            Err(Refusal::Unauthorized(_))
        ));
        assert!(server.received_requests().await.unwrap().is_empty());

        let mut c = f.a.claims("alice", now());
        c["iss"] = json!(format!("{}/c", server.uri()));
        let token = f.a.sign(f.a.header(), c);
        assert!(run(&f, &token, &body(&csr, None)).await.is_err());
        assert!(
            !server.received_requests().await.unwrap().is_empty(),
            "control: the bound issuer's keys are fetched"
        );
    }

    #[tokio::test]
    async fn a_token_is_exchanged_once() {
        let f = fixture();
        let token = f.a.token("alice", now());
        let csr = csr_for(&principal_a("alice"));
        assert!(run(&f, &token, &body(&csr, None)).await.is_ok());
        assert!(matches!(
            run(&f, &token, &body(&csr, None)).await,
            Err(Refusal::Unauthorized(_))
        ));
    }

    #[tokio::test]
    async fn a_csr_for_anyone_but_the_mapped_principal_is_403() {
        let f = fixture();
        let t = now();
        let wrong = csr_for(&principal_a("mallory"));
        assert!(matches!(
            run(&f, &f.a.token("alice", t), &body(&wrong, None)).await,
            Err(Refusal::Forbidden(_))
        ));
        // Exactly the principal, plus a DNS name: refused, not trimmed.
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.subject_alt_names = vec![
            rcgen::SanType::URI(principal_a("alice").try_into().unwrap()),
            rcgen::SanType::DnsName("node.example.invalid".try_into().unwrap()),
        ];
        let extra = params.serialize_request(&key).unwrap().pem().unwrap();
        assert!(matches!(
            run(&f, &f.a.token("alice", t + 1), &body(&extra, None)).await,
            Err(Refusal::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn the_svid_does_not_outlive_the_token() {
        let f = fixture();
        let t = now();
        let mut c = f.a.claims("alice", t);
        c["exp"] = json!(t + 60);
        let token = f.a.sign(f.a.header(), c);
        let resp = run(&f, &token, &body(&csr_for(&principal_a("alice")), None))
            .await
            .unwrap();
        let leaf =
            nucleus_identity::certificate::Certificate::from_pem(&resp.svid_chain_pem).unwrap();
        let svid_not_after = u64::try_from(leaf.not_after().unwrap().timestamp()).unwrap();
        assert!(svid_not_after <= t + 60, "{svid_not_after} > {}", t + 60);
        assert!(resp.expires_at <= svid_not_after);
        let cert_not_after = cert_of(&resp)
            .certificate()
            .authority()
            .not_after
            .timestamp();
        assert!(u64::try_from(cert_not_after).unwrap() <= svid_not_after);
    }

    #[tokio::test]
    async fn asking_for_more_than_the_ceiling_gets_the_ceiling() {
        let f = fixture();
        let t = now();
        let csr = || csr_for(&principal_a("alice"));
        let exchanged =
            |resp: ExchangeResponse| cert_of(&resp).certificate().effective_permissions().clone();
        let unasked = exchanged(
            run(&f, &f.a.token("alice", t), &body(&csr(), None))
                .await
                .unwrap(),
        );
        let wider = exchanged(
            run(
                &f,
                &f.a.token("alice", t + 1),
                &body(&csr(), Some(json!({"profile": "permissive"}))),
            )
            .await
            .unwrap(),
        );
        let narrower = exchanged(
            run(
                &f,
                &f.a.token("alice", t + 2),
                &body(&csr(), Some(json!({"profile": "read_only"}))),
            )
            .await
            .unwrap(),
        );
        let ceiling =
            f.st.authority
                .caller_bindings()
                .by_trust_domain(TD_A)
                .unwrap()
                .ceiling();
        assert!(
            !ceiling.leq(&PermissionLattice::read_only()),
            "fixture: narrowing is visible"
        );
        assert!(
            wider.leq(ceiling) && unasked.leq(ceiling),
            "never above the ceiling"
        );
        // Not `wider == unasked`: the lattice's meet is not idempotent against
        // a wider operand (it can add obligations), so the property is the
        // bound, not the bytes.
        // Capabilities and budget, not `leq` of the whole lattice: its time
        // component compares validity windows, and a profile resolved here is
        // stamped later than the one resolved inside the exchange.
        let read_only = PermissionLattice::read_only();
        assert!(
            narrower.capabilities.leq(&read_only.capabilities)
                && narrower.budget.leq(&read_only.budget),
            "asking for less gets less"
        );
        assert_ne!(narrower, unasked);
    }

    fn pod_spec(upstreams: Vec<CredentialedEgressSpec>, budget: u32) -> nucleus_spec::PodSpec {
        let mut lattice = PermissionLattice::permissive();
        lattice.budget.max_cost_usd = rust_decimal::Decimal::from(budget);
        nucleus_spec::PodSpec::new(nucleus_spec::PodSpecInner {
            work_dir: "/work".into(),
            timeout_seconds: 60,
            policy: PolicySpec::Inline {
                lattice: Box::new(lattice),
            },
            budget_model: None,
            resources: None,
            network: None,
            credentialed_egress: upstreams,
            workload: None,
            image: None,
            vsock: None,
            seccomp: None,
            cgroup: None,
            audit_sink: None,
            credentials: None,
        })
    }

    /// What `POST /v1/pods` does with the exchange's output: the SVID's
    /// identity is the mTLS peer, the certificate is the header.
    fn admission(resp: &ExchangeResponse) -> Admission {
        let leaf =
            nucleus_identity::certificate::Certificate::from_pem(&resp.svid_chain_pem).unwrap();
        Admission {
            caller_spiffe_id: nucleus_identity::spiffe_uri_from_svid(leaf.der()).unwrap(),
            caller_pod: None,
            header_cert: Some(resp.delegation_cert.clone()),
        }
    }

    #[tokio::test]
    async fn an_exchanged_caller_creates_a_pod_within_its_binding() {
        let f = fixture();
        let resp = run(
            &f,
            &f.a.token("alice", now()),
            &body(&csr_for(&principal_a("alice")), None),
        )
        .await
        .unwrap();
        let registry =
            f.st.authority
                .upstream_registry()
                .unwrap()
                .entries()
                .to_vec();
        assert_eq!(registry.len(), 2);
        let pod = uuid::Uuid::new_v4();
        let issued =
            f.st.authority
                .admit(&admission(&resp), &pod_spec(registry.clone(), 1), pod)
                .await
                .expect("admitted through case 2");
        let binding =
            f.st.authority
                .caller_bindings()
                .by_trust_domain(TD_A)
                .unwrap();
        assert!(
            issued.effective.leq(binding.ceiling()),
            "clamped to the ceiling"
        );
        let names: Vec<_> = issued.upstreams.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["model-api"], "only the binding's upstreams");
        assert_eq!(issued.root_identity, principal_a("alice"));
    }

    #[tokio::test]
    async fn every_exchange_under_a_binding_draws_on_one_budget() {
        let f = fixture();
        let ceiling_budget =
            f.st.authority
                .caller_bindings()
                .by_trust_domain(TD_A)
                .unwrap()
                .ceiling()
                .budget
                .max_cost_usd;
        assert!(
            ceiling_budget >= rust_decimal::Decimal::from(2),
            "fixture needs budget"
        );
        let whole = u32::try_from(ceiling_budget.trunc().mantissa()).unwrap();

        let t = now();
        let first = run(
            &f,
            &f.a.token("alice", t),
            &body(&csr_for(&principal_a("alice")), None),
        )
        .await
        .unwrap();
        // A different principal under the same binding, from a fresh token.
        let second = run(
            &f,
            &f.a.token("bob", t),
            &body(&csr_for(&principal_a("bob")), None),
        )
        .await
        .unwrap();
        assert_ne!(
            cert_of(&first).fingerprint(),
            cert_of(&second).fingerprint()
        );

        f.st.authority
            .admit(
                &admission(&first),
                &pod_spec(Vec::new(), whole),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("the first pod takes the whole binding budget");
        let refused =
            f.st.authority
                .admit(
                    &admission(&second),
                    &pod_spec(Vec::new(), 1),
                    uuid::Uuid::new_v4(),
                )
                .await;
        assert!(
            matches!(refused, Err(crate::ApiError::Authority(ref m)) if m.contains("budget")),
            "a second exchange is not a second budget: {refused:?}"
        );
    }

    #[tokio::test]
    async fn a_federated_tenant_is_held_to_the_nodes_own_root() {
        // A certificate for A's principal minted under ANOTHER anchor the
        // operator trusts is refused for a federated tenant.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let f = fixture();
        let other = ring::signature::Ed25519KeyPair::from_pkcs8(
            ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let holder = ring::signature::Ed25519KeyPair::from_pkcs8(
            ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let forged = portcullis::certificate::LatticeCertificate::mint_with_holder_key(
            PermissionLattice::permissive(),
            principal_a("alice"),
            chrono::Utc::now() + chrono::Duration::seconds(300),
            None,
            &other,
            &holder,
        );
        let header = AttenuationToken::seal(forged, other.public_key().as_ref().to_vec())
            .to_base64()
            .unwrap();
        let admission = Admission {
            caller_spiffe_id: principal_a("alice"),
            caller_pod: None,
            header_cert: Some(header),
        };
        assert!(
            f.st.authority
                .admit(&admission, &pod_spec(Vec::new(), 1), uuid::Uuid::new_v4())
                .await
                .is_err()
        );
    }

    #[test]
    fn the_sub_encoding_is_injective_and_bounded() {
        assert_eq!(encode_sub("alice-01").unwrap(), "alice-01");
        assert_eq!(encode_sub("a.b").unwrap(), "a_2eb");
        assert_ne!(
            encode_sub("a.b"),
            encode_sub("a_2eb"),
            "`_` is always escaped"
        );
        assert_eq!(encode_sub("a_2eb").unwrap(), "a_5f2eb");
        assert_eq!(encode_sub("repo:org/x").unwrap(), "repo_3aorg_2fx");
        assert!(encode_sub("").is_none());
        assert!(encode_sub(&"x".repeat(MAX_ENCODED_SUB)).is_some());
        assert!(
            encode_sub(&"x".repeat(MAX_ENCODED_SUB + 1)).is_none(),
            "refused, not cut"
        );
        assert!(
            encode_sub(&".".repeat(80)).is_none(),
            "the bound is on the ENCODED length"
        );
    }

    #[test]
    fn a_binding_in_the_nodes_own_trust_domain_does_not_load() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let a = Issuer::new(ISS_A, "key-a");
        let bad = |extra: &str| {
            format!(
                "[[caller]]\nlabel = \"x\"\nissuer = \"{ISS_A}\"\naudience = \"{AUD}\"\n\
                 algs = [\"ES256\"]\njwks = {{ inline = '{}' }}\nmax_lifetime_secs = 900\n\
                 ceiling = {{ profile = \"read_only\" }}\n{extra}\n",
                a.jwks()
            )
        };
        for (what, toml) in [
            ("own domain", bad(&format!("trust_domain = \"{NODE_TD}\""))),
            (
                "unknown upstream",
                bad("trust_domain = \"t.example.invalid\"\nupstreams = [\"nope\"]"),
            ),
            (
                "uppercase domain",
                bad("trust_domain = \"T.example.invalid\""),
            ),
            (
                "typo'd field",
                bad("trust_domain = \"t.example.invalid\"\nsvid_ttl = 5"),
            ),
        ] {
            let loaded = UpstreamRegistry::from_toml_str(&toml).and_then(|reg| {
                CallerBindings::from_files(reg.callers(), &reg, NODE_TD).map(|_| ())
            });
            assert!(loaded.is_err(), "{what}");
        }
        let twice = format!(
            "{}{}",
            bad("trust_domain = \"t.example.invalid\""),
            bad("trust_domain = \"u.example.invalid\"").replace("label = \"x\"", "label = \"y\"")
        );
        let reg = UpstreamRegistry::from_toml_str(&twice).unwrap();
        assert!(
            CallerBindings::from_files(reg.callers(), &reg, NODE_TD).is_err(),
            "one issuer, one binding"
        );
    }

    #[tokio::test]
    async fn the_listener_serves_the_exchange_over_tls_without_a_client_certificate() {
        // The real transport: an operator certificate for a DNS name, a plain
        // HTTPS client that trusts it and presents NO certificate, and the
        // route answering 401 with nothing more than the status word.
        let f = fixture();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        serve_tls(
            tcp,
            operator_tls(&cert_path, &key_path).unwrap(),
            router(f.st.clone()),
        );

        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
            .resolve("localhost", SocketAddr::from(([127, 0, 0, 1], port)))
            .build()
            .unwrap();
        let resp = client
            .post(format!("https://localhost:{port}/v1/federation/exchange"))
            .body(body("x", None))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(resp.text().await.unwrap(), r#"{"error":"unauthorized"}"#);

        // And an exchange that works, over the same connection type.
        let token = f.a.token("alice", now());
        let resp = client
            .post(format!("https://localhost:{port}/v1/federation/exchange"))
            .bearer_auth(token)
            .body(body(&csr_for(&principal_a("alice")), None))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["spiffe_id"], json!(principal_a("alice")));
        for field in [
            "svid_chain_pem",
            "trust_bundle_pem",
            "delegation_cert",
            "expires_at",
        ] {
            assert!(!v[field].is_null(), "{field}");
        }
    }
}
