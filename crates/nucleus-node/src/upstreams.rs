//! The operator's upstream registry: which credentialed upstreams exist on this
//! node at all, and where each one's credential comes from.
//!
//! # The hole this closes
//!
//! A `CredentialedEgressSpec` names a destination (`upstream`) and **which of the
//! node's environment variables** is attached to it (`credential_env`), and the
//! broker's store was built by reading exactly that variable
//! (`broker_launch::store_from_node_environment`). Until this module existed the
//! node took both from the pod spec, verbatim, from any caller of
//! `POST /v1/pods`. The only clamp was the in-guest tool-proxy's, on the
//! sub-pod path — so a caller that reached the node directly (an external
//! mTLS caller, or a guest workload holding its own pod's SVID key, #2724) could
//! name any node variable and any URL: "read any node secret and post it where
//! I like".
//!
//! # The model
//!
//! The pod spec SELECTS; the operator DEFINES. An entry here is a name, a base
//! URL, a header, a prefix or an encoding of the header value (host-only, see
//! [`ValueEncoding`]), and a **credential source**:
//!
//! * `env { var }` — a static value from the node's environment, chosen by the
//!   operator rather than the spec author;
//! * `federated { … }` — a token minted per exchange (ADR 0010): the node signs
//!   an assertion for the calling pod and trades it at the upstream's token
//!   endpoint. See `federated_credential.rs`.
//!
//! # What the pod spec sees of an entry, and what admission compares
//!
//! Admission compares a requested `CredentialedEgressSpec` against each entry's
//! **projection** into that type, field for field
//! (`CredentialedEgressSpec::admitted_by`, the same comparison the tool-proxy's
//! sub-pod clamp uses). The projection carries exactly what the spec type can
//! carry: name, base URL, header, prefix, and `credential_env` — the variable's
//! name for an `env` entry, the empty string for a `federated` one.
//!
//! The federation config itself — token endpoint, grant, audience, parameters —
//! is deliberately NOT part of the projection and cannot be written in a spec.
//! On Firecracker the pod spec is baked into the guest rootfs, so anything it
//! carried would be readable by the guest, and a spec able to carry it would
//! let the spec's author choose where the node's assertions are sent. Equality
//! therefore decides WHICH entry a pod may hold; the source is then read out of
//! this file by that entry ([`UpstreamRegistry::resolve`]), never out of the
//! spec. Two entries whose projections were equal would make that lookup
//! ambiguous, and names are unique, so they cannot be.
//!
//! # No registry means no credentialed egress
//!
//! Fail-closed, deliberately. Without `--upstreams`, admission drops every
//! requested entry for every caller, the root minter included. The alternative —
//! trusting the root minter's spec verbatim when no registry is configured —
//! would keep a node with no registry working exactly as before, but it would
//! keep a pod spec, rather than the operator's file, as the author of which node
//! variable is read, on the one path where the spec's author is least checked.
//!
//! # File format
//!
//! TOML, one `[[upstream]]` table per entry. Unknown fields are refused at every
//! level, so a typo cannot silently become a default:
//!
//! ```toml
//! [[upstream]]
//! name         = "model-api"
//! base_url     = "https://model-api.example/v1"
//! header       = "authorization"
//! value_prefix = "Bearer "
//! call_charge_micro_usd = 1000 # operator tariff per authorized dispatch attempt
//!
//! [upstream.credential.federated]
//! token_endpoint     = "https://auth.model-api.example/oauth/token"
//! grant              = "token-exchange"   # or "jwt-bearer"
//! encoding           = "form"             # or "json"
//! audience           = "https://auth.model-api.example"
//! scope              = "inference"        # optional
//! request_audience   = "model-api"        # optional: RFC 8693 `audience` body parameter
//! assertion_ttl_secs = 300                # optional; default 300, cap 3600
//!
//! [upstream.credential.federated.params]  # optional, opaque, sent verbatim
//! policy_id = "example-policy-0001"
//!
//! [[upstream]]
//! name         = "search-api"
//! base_url     = "https://search.example"
//! header       = "x-api-key"
//! call_charge_micro_usd = 1000
//!
//! [upstream.credential.env]
//! var = "SEARCH_API_TOKEN"
//!
//! [[upstream]]
//! name         = "git-remote"
//! base_url     = "https://forge.example/"
//! header       = "authorization"
//! call_charge_micro_usd = 0
//! # Guest-proposed headers forwarded to this upstream (default: none beyond
//! # content-type). Never authorization, cookie, proxy-* or this entry's own
//! # `header`: the node refuses to start on one.
//! request_headers = ["accept", "git-protocol", "content-encoding"]
//! # The host sends `Basic base64("token-user:" + credential)` (#3252). The
//! # credential is held bare, so a minted one works too. Default "raw":
//! # `value_prefix + credential`. `value_prefix` is refused beside `basic`; a
//! # username that is empty or contains ':' refuses the registry.
//! value_encoding = { basic = { username = "token-user" } }
//!
//! [upstream.credential.env]
//! var = "GIT_REMOTE_TOKEN"
//!
//! [[upstream]]
//! name         = "forge-api"
//! base_url     = "https://api.forge.example/"
//! header       = "authorization"
//! value_prefix = "Bearer "
//! call_charge_micro_usd = 0
//! request_headers = ["accept"]
//! # Names only the host may set (#3213): a guest proposal is dropped, and the
//! # node refuses to start if `request_headers` or `fixed_headers` lists one.
//! # The entry's own `header` is always one.
//! secret_headers = ["x-account-binding"]
//! # What its requests ARE (#3229). `kind = "forge"` refuses any write
//! # (a POST) that no effect below classifies; `kind = "api"` (the default)
//! # decides such a call as `web_fetch`. A push is `git_push` whatever is
//! # declared. Operations: web_fetch, git_push, create_pr. Path segments are
//! # literals or `*` (exactly one segment).
//! kind    = "forge"
//! effects = [
//!   { method = "POST", path = "/repos/*/*/pulls", operation = "create_pr" },
//! ]
//!
//! [upstream.fixed_headers]   # added by the host to every call, never guest-set
//! x-api-version = "2026-01-01"
//!
//! [upstream.credential.federated]       # an operator-run RFC 8693 minter
//! token_endpoint = "https://minter.example/token"
//! grant          = "token-exchange"
//! encoding       = "form"
//! audience       = "https://minter.example"
//! ```
//!
//! The effect table is part of the entry's projection: a pod spec carries it,
//! the guest classifies by it, and admission compares it like every other
//! field (`nucleus_cred_protocol::egress::EffectTable`).
//!
//! # Reserved: a client certificate as the subject
//!
//! Some token endpoints accept the caller's X.509 certificate, presented in
//! the TLS handshake, as the RFC 8693 subject (`subject_token_type` …`:mtls`,
//! the subject token being the certificate chain) instead of a signed
//! assertion. That form is **parsed and validated, and then refused** with
//! "not supported yet": the node has no client for it. It is in the format now
//! so that a registry written for it loads unchanged once it is served, and so
//! that the meaning of the fields above cannot drift to accommodate it later:
//!
//! ```toml
//! [upstream.credential.federated]
//! subject            = "client-certificate"   # default: "assertion"
//! client_certificate = "pod-svid"             # or "node-svid": whose certificate the node presents
//! token_endpoint     = "https://sts.example/v1/token"   # https only: it must be an mTLS endpoint
//! grant              = "token-exchange"       # the only grant this subject has
//! encoding           = "json"                 # or "form"
//! request_audience   = "example-provider-0001"  # required: RFC 8693 `audience`
//! # `audience` and `assertion_ttl_secs` describe an assertion and are refused here.
//!
//! [upstream.credential.federated.params]
//! requested_token_type = "urn:ietf:params:oauth:token-type:access_token"
//! ```
//!
//! The node refuses to START on such an entry, rather than load the rest and
//! leave that upstream unusable: an operator who wrote it expects it to work.
//!
//! The first version of this file (P0, never released) used the spec's own
//! field names flat — `upstream` for the base URL and `credential_env` beside
//! it. That shape is not read any more: with a second source kind, a flat
//! `credential_env` would be one source spelled differently from the other,
//! and nothing outside this branch ever wrote one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use nucleus_federation::{CompactJwt, DEFAULT_TTL, Encoding, Grant, MAX_TTL, TokenRequest};
use nucleus_spec::CredentialedEgressSpec;
use reqwest::Url;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    #[serde(default)]
    upstream: Vec<EntryFile>,
    /// Inbound bindings (`federation_ingress.rs`). Same file, because a binding
    /// names the upstreams its callers may hold, and one file is one atomic
    /// statement of what this node offers in both directions.
    #[serde(default)]
    caller: Vec<crate::federation_ingress::CallerFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryFile {
    name: String,
    base_url: String,
    header: String,
    #[serde(default)]
    value_prefix: String,
    /// How the credential becomes the header value (#3252). Absent is `raw`.
    #[serde(default)]
    value_encoding: Option<ValueEncodingFile>,
    credential: CredentialFile,
    /// Missing prices never imply free calls. The broker refuses unpriced entries.
    call_charge_micro_usd: Option<u64>,
    /// Request header names a guest may set on calls to this upstream (#3210,
    /// #3213). Default empty: only `content-type` is forwarded.
    #[serde(default)]
    request_headers: Vec<String>,
    /// Headers the host adds to every call to this upstream, name to value
    /// (#3213). Not secret: the values are in the effect an operator reviews.
    #[serde(default)]
    fixed_headers: BTreeMap<String, String>,
    /// Header names only the host may set on calls to this upstream (#3213).
    #[serde(default)]
    secret_headers: Vec<String>,
    /// `api` or `forge` (#3229). Absent is read by `EffectTable::from_parts`,
    /// the one place that decides what absence means.
    #[serde(default)]
    kind: Option<nucleus_spec::UpstreamKind>,
    /// The operator's effect classification (#3229).
    #[serde(default)]
    effects: Vec<nucleus_spec::DeclaredEffect>,
}

/// `value_encoding = "raw"` or `value_encoding = { basic = { username = "…" } }`.
/// An unknown variant, or an unknown field in `basic`, refuses the registry.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ValueEncodingFile {
    Raw,
    Basic(BasicFile),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BasicFile {
    username: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum CredentialFile {
    Env { var: String },
    Federated(Box<FederatedFile>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FederatedFile {
    /// `"assertion"` (the default) or `"client-certificate"` (reserved).
    #[serde(default)]
    subject: Option<String>,
    /// For `subject = "client-certificate"`: `"pod-svid"` or `"node-svid"`.
    #[serde(default)]
    client_certificate: Option<String>,
    token_endpoint: String,
    grant: String,
    encoding: String,
    /// The assertion's `aud`: required for an assertion, refused without one.
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    request_audience: Option<String>,
    #[serde(default)]
    params: BTreeMap<String, String>,
    #[serde(default)]
    assertion_ttl_secs: Option<u64>,
}

/// Where an entry's credential comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CredentialSource {
    /// A static value in the node's environment, under this variable.
    Env {
        /// The variable's NAME. Never its value.
        var: String,
    },
    /// Minted per exchange. Shared behind an `Arc` because every pod admitted
    /// the entry holds the same configuration.
    Federated(Arc<FederatedUpstream>),
}

/// A federated upstream's exchange configuration, validated at load.
///
/// Only constructible by [`UpstreamRegistry::from_toml_str`] (and tests): the
/// endpoint was checked by the same `TokenRequest::new` the exchange uses, and
/// the parameters by the same `with_params`, so an entry that loaded is one the
/// token client will accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FederatedUpstream {
    /// The registry name — `nucleus_upstream` in the assertion, and the store
    /// key.
    pub name: String,
    pub token_endpoint: Url,
    pub grant: Grant,
    pub encoding: Encoding,
    /// The assertion's `aud`, exactly.
    pub audience: String,
    pub scope: Option<String>,
    /// RFC 8693's `audience` request parameter, which names the resource the
    /// token is for. Distinct from [`Self::audience`], which names the token
    /// endpoint the assertion is for, and reserved in `params` by the token
    /// client (a duplicated standard key is a parser-differential), so it has
    /// its own field.
    pub request_audience: Option<String>,
    pub params: BTreeMap<String, String>,
    pub assertion_ttl: Duration,
}

/// How the host renders a credential into its header value (#3252).
///
/// # Host-only, applied at injection
///
/// The credential is stored and minted bare; the encoding is applied by
/// [`RegistryEntry::header_value`] at the moment the header is built, on the
/// one path both the buffered and the streamed call take
/// (`broker_perform::credential_header`, ADR 0007 G-1). So a federated token
/// never exists pre-encoded at rest, and a static one need not either.
///
/// It is not part of the spec projection: the guest never sees it, cannot
/// choose it, and needs no capability to parse it. A pod selects an entry by
/// its projection and names are unique, so the encoding a pod gets is the one
/// the operator wrote for that name: [`UpstreamRegistry::resolve`] copies it
/// out of the registry, never out of a spec.
///
/// # Closed
///
/// Two variants and no catch-all (ADR 0007 A-1, B-3). A third scheme is a
/// new variant every `match` on this must answer, not a string that falls
/// through to one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueEncoding {
    /// `value_prefix` followed by the credential, verbatim.
    Raw,
    /// `Basic ` followed by base64(`username` `:` credential), RFC 7617. The
    /// scheme is the encoding's, so the entry's `value_prefix` is refused at
    /// load rather than prepended to it.
    Basic(BasicUsername),
}

/// An RFC 7617 user-id: non-empty, no `:` (the first colon ends it, so one
/// inside would move part of the username into the password the upstream
/// reads), and no control character. Constructed only by
/// [`BasicUsername::new`] (ADR 0007 C-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BasicUsername(String);

/// The longest username accepted: generous for any account name, and a bound
/// on what one registry line makes the host encode per call.
const MAX_BASIC_USERNAME: usize = 256;

impl BasicUsername {
    /// # Errors
    /// Empty, longer than [`MAX_BASIC_USERNAME`] bytes, or containing `:` or
    /// a control character; the message names which.
    pub(crate) fn new(username: &str) -> Result<Self, &'static str> {
        if username.is_empty() {
            return Err("username must be non-empty");
        }
        if username.len() > MAX_BASIC_USERNAME {
            return Err("username is longer than 256 bytes");
        }
        if username.contains(':') {
            return Err("username may not contain ':', which ends a Basic user-id");
        }
        if username.chars().any(char::is_control) {
            return Err("username may not contain a control character");
        }
        Ok(Self(username.to_string()))
    }
}

/// One operator-defined upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegistryEntry {
    /// What a pod spec sees and admission compares. See the module docs.
    spec: CredentialedEgressSpec,
    /// How the credential becomes the header value. Host-only; see
    /// [`ValueEncoding`].
    value_encoding: ValueEncoding,
    credential: CredentialSource,
    call_charge: Option<CallCharge>,
    /// Lower-case header names the guest may propose for this upstream,
    /// validated at load. See [`RegistryEntry::forwards_header`].
    request_headers: BTreeSet<String>,
    /// The operator's fixed headers and secret names, validated at load.
    header_policy: HeaderPolicy,
}

/// What the operator fixed about an upstream's request headers beyond the
/// guest's allowlist (#3213).
///
/// # Two kinds of header no guest sets
///
/// * **Fixed**: a name and value the host adds to every call, such as an API
///   version an upstream requires. Not secret: the value is in the effect the
///   operator reviews and the digest an approval binds. A guest proposal of
///   the same name is dropped, so the guest cannot choose the version the
///   operator pinned.
/// * **Secret**: a name only the host may inject. A guest proposal is dropped
///   whatever else is configured, and the node refuses to start on a registry
///   that lists one in `request_headers` or `fixed_headers`. The entry's
///   credential `header` is always secret without being listed. A value the
///   host injects never reaches a record: the call's record carries forwarded
///   header NAMES, and the effect binds the credential header by name only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeaderPolicy {
    fixed: BTreeMap<String, String>,
    secret: BTreeSet<String>,
}

impl HeaderPolicy {
    /// No fixed headers and no secret names beyond the credential header.
    #[cfg(test)]
    pub(crate) fn none() -> Self {
        Self {
            fixed: BTreeMap::new(),
            secret: BTreeSet::new(),
        }
    }
}

/// A fixed operator tariff for one authorized dispatch attempt, never guest usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallCharge(u64);

impl CallCharge {
    pub(crate) fn micro_usd(self) -> u64 {
        self.0
    }
    pub(crate) fn usd(self) -> rust_decimal::Decimal {
        rust_decimal::Decimal::from_i128_with_scale(i128::from(self.0), 6)
    }
    #[cfg(test)]
    pub(crate) fn free() -> Self {
        Self(0)
    }
    /// What an approval held for a guest-performed call shows the operator
    /// (ADR 0014 S4): nothing, because the host dispatches nothing for it.
    pub(crate) fn guest_call() -> Self {
        Self(0)
    }
}

impl RegistryEntry {
    #[cfg(test)]
    pub(crate) fn with_call_charge(mut self, micro_usd: u64) -> Self {
        self.call_charge = Some(CallCharge(micro_usd));
        self
    }
    pub(crate) fn call_charge(&self) -> Result<CallCharge, &'static str> {
        self.call_charge
            .ok_or("upstream has no operator call charge")
    }
    /// The projection a pod spec selects this entry by: name, base, header,
    /// prefix, and the env variable's name (empty for a federated entry).
    pub fn spec(&self) -> &CredentialedEgressSpec {
        &self.spec
    }

    /// The credential header's value for `credential`: the entry's
    /// [`ValueEncoding`] applied to it. The only place a credential header
    /// value is built, so the buffered and streamed paths cannot disagree
    /// about it (ADR 0007 G-1). Never logged.
    pub(crate) fn header_value(&self, credential: &str) -> String {
        use base64::Engine as _;
        match &self.value_encoding {
            ValueEncoding::Raw => format!("{}{credential}", self.spec.value_prefix),
            ValueEncoding::Basic(BasicUsername(username)) => format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{credential}"))
            ),
        }
    }

    /// Where the credential comes from.
    pub fn credential(&self) -> &CredentialSource {
        &self.credential
    }

    /// Whether this entry mints its credential per exchange.
    pub fn is_federated(&self) -> bool {
        matches!(self.credential, CredentialSource::Federated(_))
    }

    /// Whether a guest-proposed request header `name` is forwarded to this
    /// upstream: the operator listed it, the shared rule lets a guest propose
    /// it at all, and it is not the header this entry injects the credential
    /// in. All three, every call: the load-time check is not relied on alone,
    /// so a rule tightened later applies to a registry loaded earlier.
    pub fn forwards_header(&self, name: &str) -> bool {
        self.request_headers.contains(name)
            && nucleus_spec::workload_egress::guest_may_propose_header(name)
            && !name.eq_ignore_ascii_case(&self.spec.header)
            && !self.header_policy.secret.contains(name)
            && !self.header_policy.fixed.contains_key(name)
    }

    /// The headers the host adds to every call to this upstream, lower-case
    /// name to value. Never a guest's: [`Self::forwards_header`] drops a
    /// proposal of any of these names.
    pub fn fixed_headers(&self) -> &BTreeMap<String, String> {
        &self.header_policy.fixed
    }

    /// This entry with `fixed` and `secret` as its header policy,
    /// unvalidated: for tests of the per-call checks on their own.
    #[cfg(test)]
    pub(crate) fn with_header_policy(mut self, fixed: &[(&str, &str)], secret: &[&str]) -> Self {
        self.header_policy = HeaderPolicy {
            fixed: fixed
                .iter()
                .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                .collect(),
            secret: secret.iter().map(|n| (*n).to_string()).collect(),
        };
        self
    }

    /// This entry with `names` as its request-header allowlist, unvalidated:
    /// for tests that need to show the per-call check holds on its own.
    #[cfg(test)]
    pub(crate) fn with_request_headers(mut self, names: &[&str]) -> Self {
        self.request_headers = names.iter().map(|n| (*n).to_string()).collect();
        self
    }

    /// An `env` entry whose projection is `spec`. The registry's own loader
    /// builds entries from TOML; this is for tests that start from a spec.
    #[cfg(test)]
    pub fn env(spec: CredentialedEgressSpec) -> Self {
        let credential = CredentialSource::Env {
            var: spec.credential_env.clone(),
        };
        Self {
            spec,
            value_encoding: ValueEncoding::Raw,
            credential,
            call_charge: Some(CallCharge::free()),
            request_headers: BTreeSet::new(),
            header_policy: HeaderPolicy::none(),
        }
    }
}

/// The upstreams an operator has defined for this node. See the module docs.
#[derive(Debug, Clone, Default)]
pub(crate) struct UpstreamRegistry {
    entries: Vec<RegistryEntry>,
    /// Each entry's projection, in the same order: the admission ceiling.
    specs: Vec<CredentialedEgressSpec>,
    /// The file's `[[caller]]` tables, as written. Validated (against this
    /// registry) by `federation_ingress::CallerBindings::from_files`.
    callers: Vec<crate::federation_ingress::CallerFile>,
}

impl UpstreamRegistry {
    /// Load and validate the registry at `path`.
    ///
    /// # Errors
    /// An unreadable file, malformed TOML, or an entry [`Self::from_toml_str`]
    /// refuses. The node refuses to START on any of these: a registry that
    /// half-loaded would be a smaller ceiling than the operator wrote, which is
    /// safe, but silently so, and "my upstream is refused" is a worse way to
    /// learn about a typo than "the node will not start".
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("upstream registry {}: {e}", path.display()))?;
        Self::from_toml_str(&text).map_err(|e| format!("upstream registry {}: {e}", path.display()))
    }

    /// Parse and validate a registry.
    ///
    /// Names must be unique, because the broker's store and `PerformRequest.target`
    /// are keyed by name: two entries sharing one would make which credential a
    /// request gets depend on iteration order. The base URL must be an absolute
    /// `http(s)` URL with a host, and the header must be non-empty, so an entry
    /// cannot be valid-looking and unusable. An `env` variable must be named; a
    /// `federated` entry must be one the token client will accept (see
    /// [`FederatedUpstream`]).
    ///
    /// # Errors
    /// Names the offending entry by `name`, never by a variable's value (this
    /// never reads a variable at all).
    pub fn from_toml_str(text: &str) -> Result<Self, String> {
        let file: RegistryFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut seen = BTreeSet::new();
        let mut entries = Vec::with_capacity(file.upstream.len());
        for up in file.upstream {
            if up.name.trim().is_empty() {
                return Err("an [[upstream]] entry has an empty name".into());
            }
            if !seen.insert(up.name.clone()) {
                return Err(format!("upstream {:?} is defined twice", up.name));
            }
            let url = Url::parse(&up.base_url)
                .map_err(|e| format!("upstream {:?}: base_url: {e}", up.name))?;
            if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
                return Err(format!(
                    "upstream {:?}: base_url must be absolute http(s) with a host",
                    up.name
                ));
            }
            if up.header.trim().is_empty() {
                return Err(format!("upstream {:?}: header must be set", up.name));
            }
            let (credential, env_var) = match up.credential {
                CredentialFile::Env { var } => {
                    if var.trim().is_empty() {
                        return Err(format!(
                            "upstream {:?}: credential.env.var must be set",
                            up.name
                        ));
                    }
                    (CredentialSource::Env { var: var.clone() }, Some(var))
                }
                CredentialFile::Federated(fed) => (
                    CredentialSource::Federated(Arc::new(federated(&up.name, *fed)?)),
                    None,
                ),
            };
            let value_encoding = value_encoding(&up.name, &up.value_prefix, up.value_encoding)?;
            let header_policy =
                header_policy(&up.name, &up.header, up.fixed_headers, up.secret_headers)?;
            let request_headers =
                request_headers(&up.name, &up.header, up.request_headers, &header_policy)?;
            let effects = nucleus_spec::EffectTable::from_parts(up.kind, up.effects)
                .map_err(|e| format!("upstream {:?}: {e}", up.name))?;
            entries.push(RegistryEntry {
                value_encoding,
                request_headers,
                header_policy,
                call_charge: up.call_charge_micro_usd.map(CallCharge),
                spec: CredentialedEgressSpec::registry_projection(
                    up.name,
                    up.base_url,
                    up.header,
                    up.value_prefix,
                    env_var,
                    effects,
                ),
                credential,
            });
        }
        let specs = entries.iter().map(|e| e.spec.clone()).collect();
        Ok(Self {
            entries,
            specs,
            callers: file.caller,
        })
    }

    /// The `[[caller]]` tables of this file, unvalidated.
    pub fn callers(&self) -> &[crate::federation_ingress::CallerFile] {
        &self.callers
    }

    /// Every entry's projection, for admission to clamp against.
    pub fn entries(&self) -> &[CredentialedEgressSpec] {
        &self.specs
    }

    /// Whether any entry mints its credential per exchange — in which case the
    /// node needs a federation issuer to start.
    pub fn has_federated(&self) -> bool {
        self.entries.iter().any(RegistryEntry::is_federated)
    }

    /// The registry's OWN entries for an admitted set: each entry whose
    /// projection equals an admitted one, as this registry holds it.
    ///
    /// Admission has already clamped the set to equality with these entries, so
    /// on the ordinary path this selects exactly the admitted entries. It
    /// exists so the broker does not rely on that: what reaches the store and
    /// the federation path is copied out of the operator's file, and a pod whose
    /// admitted set somehow disagrees with the registry (a node restarted onto a
    /// narrower file, say) loses the entry rather than keeping a definition the
    /// operator no longer has.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn resolve(&self, admitted: &[CredentialedEgressSpec]) -> Vec<RegistryEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.spec.admitted_by(admitted))
            .cloned()
            .collect()
    }
}

/// Validate an entry's `value_encoding` against its `value_prefix`.
///
/// `basic` carries its own scheme, so a `value_prefix` beside it is refused
/// rather than ignored or prepended: either would leave the operator's file
/// saying something the wire does not. The node refuses to START on it,
/// naming the entry.
fn value_encoding(
    name: &str,
    value_prefix: &str,
    file: Option<ValueEncodingFile>,
) -> Result<ValueEncoding, String> {
    match file {
        None | Some(ValueEncodingFile::Raw) => Ok(ValueEncoding::Raw),
        Some(ValueEncodingFile::Basic(BasicFile { username })) => {
            if !value_prefix.is_empty() {
                return Err(format!(
                    "upstream {name:?}: value_prefix may not be set with value_encoding.basic, \
                     which sends its own \"Basic \" scheme"
                ));
            }
            BasicUsername::new(&username)
                .map(ValueEncoding::Basic)
                .map_err(|e| format!("upstream {name:?}: value_encoding.basic: {e}"))
        }
    }
}

/// Validate an entry's `request_headers`: each a name a guest may propose at
/// all (`workload_egress::guest_may_propose_header`, so never `authorization`,
/// `cookie`, `proxy-authorization` or anything credential-shaped), and never
/// the entry's own credential `header`. The node refuses to START on a
/// violation, naming it: an operator who listed `authorization` expected the
/// guest to set it, and silently dropping it would hide that the expectation
/// is refused.
fn request_headers(
    name: &str,
    credential_header: &str,
    listed: Vec<String>,
    policy: &HeaderPolicy,
) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    for header in listed {
        let lower = header.to_ascii_lowercase();
        if lower.eq_ignore_ascii_case(credential_header)
            || !nucleus_spec::workload_egress::guest_may_propose_header(&lower)
            || policy.secret.contains(&lower)
        {
            return Err(format!(
                "upstream {name:?}: request_headers may not list {header:?}: credential, \
                 secret, framing and forwarding headers are set by the host only"
            ));
        }
        if policy.fixed.contains_key(&lower) {
            return Err(format!(
                "upstream {name:?}: request_headers may not list {header:?}: it is a fixed \
                 header, and a guest may not choose the value the operator fixed"
            ));
        }
        names.insert(lower);
    }
    if names.len() > nucleus_spec::workload_egress::MAX_PROPOSED_HEADERS {
        return Err(format!(
            "upstream {name:?}: request_headers lists {} names, above the {} a call may carry",
            names.len(),
            nucleus_spec::workload_egress::MAX_PROPOSED_HEADERS
        ));
    }
    Ok(names)
}

/// Validate an entry's `fixed_headers` and `secret_headers`.
///
/// A secret name must be a header token; it is stored lower-case. A fixed
/// header must be a name a guest could have proposed
/// (`workload_egress::guest_may_propose_header`): a credential-shaped name
/// belongs in the entry's credential source, where its value never reaches a
/// review, and a framing or forwarding header belongs to the host's HTTP
/// client. It may not be the credential header or a secret name, and its value
/// must be a non-empty admissible header value. The node refuses to START on a
/// violation, naming it.
fn header_policy(
    name: &str,
    credential_header: &str,
    fixed: BTreeMap<String, String>,
    secret: Vec<String>,
) -> Result<HeaderPolicy, String> {
    let mut secret_names = BTreeSet::new();
    for header in secret {
        let lower = header.to_ascii_lowercase();
        if lower.is_empty()
            || lower.len() > 64
            || !lower
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!(
                "upstream {name:?}: secret_headers lists {header:?}, which is not a header name"
            ));
        }
        secret_names.insert(lower);
    }
    let mut fixed_headers = BTreeMap::new();
    for (header, value) in fixed {
        let lower = header.to_ascii_lowercase();
        if lower.eq_ignore_ascii_case(credential_header)
            || secret_names.contains(&lower)
            || !nucleus_spec::workload_egress::guest_may_propose_header(&lower)
        {
            return Err(format!(
                "upstream {name:?}: fixed_headers may not set {header:?}: a fixed header is \
                 not secret, so it may not be a credential, secret, framing or forwarding header"
            ));
        }
        if value.is_empty() || !nucleus_spec::workload_egress::header_value_admissible(&value) {
            return Err(format!(
                "upstream {name:?}: fixed_headers sets {header:?} to a value that is not a \
                 non-empty visible-ASCII header value"
            ));
        }
        if fixed_headers.insert(lower, value).is_some() {
            return Err(format!(
                "upstream {name:?}: fixed_headers sets {header:?} twice, in different cases"
            ));
        }
    }
    if fixed_headers.len() > nucleus_spec::workload_egress::MAX_PROPOSED_HEADERS {
        return Err(format!(
            "upstream {name:?}: fixed_headers sets {} headers, above the {} a call may carry",
            fixed_headers.len(),
            nucleus_spec::workload_egress::MAX_PROPOSED_HEADERS
        ));
    }
    Ok(HeaderPolicy {
        fixed: fixed_headers,
        secret: secret_names,
    })
}

/// Validate one `federated` table.
///
/// The endpoint and parameters are checked by building the same
/// `TokenRequest` the exchange will build, with an empty subject — so "loads"
/// and "the token client accepts it" are one fact rather than two checks that
/// agree today.
fn federated(name: &str, f: FederatedFile) -> Result<FederatedUpstream, String> {
    let bad = |what: &str| format!("upstream {name:?}: credential.federated: {what}");
    match f.subject.as_deref() {
        None | Some("assertion") => {}
        Some("client-certificate") => return Err(client_certificate_subject(name, &f)),
        Some(_) => {
            return Err(bad(
                "subject must be \"assertion\" or \"client-certificate\"",
            ));
        }
    }
    if f.client_certificate.is_some() {
        return Err(bad(
            "client_certificate is only meaningful with subject = \"client-certificate\"",
        ));
    }
    let token_endpoint =
        Url::parse(&f.token_endpoint).map_err(|e| bad(&format!("token_endpoint: {e}")))?;
    let grant = match f.grant.as_str() {
        "token-exchange" => Grant::TokenExchange8693,
        "jwt-bearer" => Grant::JwtBearer7523,
        _ => return Err(bad("grant must be \"token-exchange\" or \"jwt-bearer\"")),
    };
    let encoding = match f.encoding.as_str() {
        "form" => Encoding::Form,
        "json" => Encoding::Json,
        _ => return Err(bad("encoding must be \"form\" or \"json\"")),
    };
    TokenRequest::new(
        token_endpoint.clone(),
        grant,
        encoding,
        CompactJwt::new(String::new()),
    )
    .map_err(|_| bad("token_endpoint must be https (or http to loopback)"))?
    .with_params(f.params.clone())
    .map_err(|_| bad("params may not set a key the token client sets itself"))?;
    let audience = match f.audience {
        Some(a) if !a.trim().is_empty() => a,
        _ => return Err(bad("audience must be set")),
    };
    if f.scope.as_deref().is_some_and(|s| s.trim().is_empty())
        || f.request_audience
            .as_deref()
            .is_some_and(|s| s.trim().is_empty())
    {
        return Err(bad(
            "scope and request_audience, when present, must be non-empty",
        ));
    }
    let assertion_ttl = match f.assertion_ttl_secs {
        None => DEFAULT_TTL,
        Some(secs) if secs >= 1 && secs <= MAX_TTL.as_secs() => Duration::from_secs(secs),
        Some(_) => {
            return Err(bad(&format!(
                "assertion_ttl_secs must be between 1 and {}",
                MAX_TTL.as_secs()
            )));
        }
    };
    Ok(FederatedUpstream {
        name: name.to_string(),
        token_endpoint,
        grant,
        encoding,
        audience,
        scope: f.scope,
        request_audience: f.request_audience,
        params: f.params,
        assertion_ttl,
    })
}

/// Validate a `subject = "client-certificate"` table in full, then refuse it.
///
/// Always an error: the variant is reserved, not served. The message says
/// "not supported yet" only for a table that is otherwise valid, so an
/// operator writing one ahead of support learns about a typo now rather than
/// on the release that serves it.
fn client_certificate_subject(name: &str, f: &FederatedFile) -> String {
    let bad = |what: &str| format!("upstream {name:?}: credential.federated: {what}");
    match f.client_certificate.as_deref() {
        Some("pod-svid" | "node-svid") => {}
        Some(_) => return bad("client_certificate must be \"pod-svid\" or \"node-svid\""),
        None => return bad("subject = \"client-certificate\" needs client_certificate"),
    }
    match Url::parse(&f.token_endpoint) {
        Ok(u) if u.scheme() == "https" && u.host_str().is_some() => {}
        Ok(_) => return bad("token_endpoint must be https: the certificate is presented in TLS"),
        Err(e) => return bad(&format!("token_endpoint: {e}")),
    }
    if f.grant != "token-exchange" {
        return bad("subject = \"client-certificate\" takes grant = \"token-exchange\" only");
    }
    if !matches!(f.encoding.as_str(), "form" | "json") {
        return bad("encoding must be \"form\" or \"json\"");
    }
    if f.audience.is_some() || f.assertion_ttl_secs.is_some() {
        return bad(
            "audience and assertion_ttl_secs describe an assertion; with a client certificate \
             the endpoint's audience is request_audience",
        );
    }
    if f.request_audience
        .as_deref()
        .is_none_or(|a| a.trim().is_empty())
    {
        return bad("subject = \"client-certificate\" needs request_audience");
    }
    if f.scope.as_deref().is_some_and(|s| s.trim().is_empty()) {
        return bad("scope, when present, must be non-empty");
    }
    if f.params
        .keys()
        .any(|k| RESERVED_FOR_CLIENT_CERTIFICATE.contains(&k.as_str()))
    {
        return bad("params may not set a key the token client sets itself");
    }
    bad(
        "subject = \"client-certificate\" is not supported yet; the entry is valid and will \
         load unchanged once it is",
    )
}

/// The request keys a client-certificate exchange sets itself, refused in
/// `params` for the reason the token client refuses its own.
const RESERVED_FOR_CLIENT_CERTIFICATE: &[&str] = &[
    "grant_type",
    "subject_token",
    "subject_token_type",
    "audience",
    "scope",
];

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = r#"
[[upstream]]
name = "model-api"
base_url = "https://model-api.invalid/v1"
header = "authorization"
value_prefix = "Bearer "

[upstream.credential.env]
var = "LLM_API_TOKEN"
"#;

    const FEDERATED: &str = r#"
[[upstream]]
name = "model-api"
base_url = "https://model-api.invalid/v1"
header = "authorization"
value_prefix = "Bearer "

[upstream.credential.federated]
token_endpoint = "https://auth.model-api.invalid/oauth/token"
grant = "token-exchange"
encoding = "form"
audience = "https://auth.model-api.invalid"
scope = "inference"

[upstream.credential.federated.params]
policy_id = "example-policy-0001"
"#;

    #[test]
    fn a_registry_loads_its_entries_whole() {
        let reg = UpstreamRegistry::from_toml_str(ONE).expect("a valid registry loads");
        assert_eq!(reg.entries().len(), 1);
        let e = &reg.entries()[0];
        assert_eq!(
            (
                e.name.as_str(),
                e.upstream.as_str(),
                e.credential_env.as_str(),
                e.value_prefix.as_str()
            ),
            (
                "model-api",
                "https://model-api.invalid/v1",
                "LLM_API_TOKEN",
                "Bearer "
            )
        );
        assert!(!reg.has_federated());
    }

    /// A federated entry loads with its exchange configuration, and its
    /// projection — what a pod spec can see and select — carries none of it.
    #[test]
    fn a_federated_entry_projects_nothing_of_its_federation() {
        let reg = UpstreamRegistry::from_toml_str(FEDERATED).expect("loads");
        assert!(reg.has_federated());
        let projection = &reg.entries()[0];
        assert_eq!(projection.credential_env, "");
        let as_json = serde_json::to_string(projection).unwrap();
        for private in ["auth.model-api.invalid", "example-policy-0001", "inference"] {
            assert!(
                !as_json.contains(private),
                "the spec projection carries {private:?}: {as_json}"
            );
        }
        let resolved = reg.resolve(reg.entries());
        let CredentialSource::Federated(fed) = resolved[0].credential() else {
            panic!("resolved to the wrong source");
        };
        assert_eq!(fed.grant, Grant::TokenExchange8693);
        assert_eq!(fed.encoding, Encoding::Form);
        assert_eq!(fed.assertion_ttl, DEFAULT_TTL);
        assert_eq!(fed.params["policy_id"], "example-policy-0001");
        assert_eq!(fed.name, "model-api");
    }

    /// The operator's request-header allowlist (#3210, #3213): protocol
    /// headers load and are forwarded; a credential header refuses the whole
    /// registry by name, whichever spelling; and an unlisted name is not
    /// forwarded. The per-call check also stands on its own: an entry whose
    /// list was never validated still forwards neither `authorization` nor
    /// its own credential header.
    #[test]
    fn request_headers_admit_protocol_headers_and_never_a_credential() {
        let with = |list: &str| {
            format!(
                "[[upstream]]\nname = \"git-remote\"\nbase_url = \"https://forge.invalid/\"\n\
                 header = \"x-forge-key\"\nrequest_headers = {list}\n\
                 [upstream.credential.env]\nvar = \"GIT_REMOTE_KEY\"\n"
            )
        };
        let reg = UpstreamRegistry::from_toml_str(&with(r#"["Accept", "git-protocol"]"#))
            .expect("protocol headers load");
        let entry = &reg.resolve(reg.entries())[0];
        assert!(entry.forwards_header("accept") && entry.forwards_header("git-protocol"));
        assert!(!entry.forwards_header("content-encoding"), "not listed");
        assert_eq!(
            UpstreamRegistry::from_toml_str(&with("[]"))
                .unwrap()
                .resolve(reg.entries())
                .len(),
            1,
            "the allowlist is the operator's, not part of the projection a spec selects by"
        );

        for refused in [
            "authorization",
            "Authorization",
            "cookie",
            "proxy-authorization",
            "x-forge-key",
            "X-Forge-Key",
            "private-token",
            "host",
        ] {
            let err = UpstreamRegistry::from_toml_str(&with(&format!("[{refused:?}]")))
                .expect_err(refused);
            assert!(
                err.contains("request_headers may not list") && err.contains(refused),
                "{err}"
            );
        }

        let unvalidated = RegistryEntry::env(reg.entries()[0].clone()).with_request_headers(&[
            "authorization",
            "x-forge-key",
            "accept",
        ]);
        assert!(!unvalidated.forwards_header("authorization"));
        assert!(!unvalidated.forwards_header("x-forge-key"));
        assert!(unvalidated.forwards_header("accept"), "the control");
    }

    /// Fixed and secret headers (#3213): a fixed header loads lower-cased and
    /// is never a guest's; a secret name is never forwarded; and each misuse
    /// refuses the whole registry by name. The per-call check stands alone:
    /// an unvalidated entry listing a fixed or secret name still drops it.
    #[test]
    fn fixed_and_secret_headers_are_never_the_guests() {
        let with = |extra: &str| {
            format!(
                "[[upstream]]\nname = \"forge-api\"\nbase_url = \"https://forge.invalid/\"\n\
                 header = \"authorization\"\n{extra}\n\
                 [upstream.credential.env]\nvar = \"FORGE_API_TOKEN\"\n"
            )
        };
        let reg = UpstreamRegistry::from_toml_str(&with(
            "request_headers = [\"accept\"]\nsecret_headers = [\"X-Account-Binding\"]\n\
             fixed_headers = { \"X-Api-Version\" = \"2026-01-01\" }",
        ))
        .expect("fixed and secret headers load");
        let entry = &reg.resolve(reg.entries())[0];
        assert_eq!(
            entry.fixed_headers(),
            &BTreeMap::from([("x-api-version".to_string(), "2026-01-01".to_string())])
        );
        assert!(entry.forwards_header("accept"), "the control");
        assert!(!entry.forwards_header("x-api-version"), "fixed");
        assert!(!entry.forwards_header("x-account-binding"), "secret");

        for (extra, refused) in [
            (
                "secret_headers = [\"x-bind\"]\nrequest_headers = [\"x-bind\"]",
                "request_headers may not list",
            ),
            (
                "fixed_headers = { \"x-v\" = \"1\" }\nrequest_headers = [\"X-V\"]",
                "it is a fixed header",
            ),
            (
                "secret_headers = [\"x-bind\"]\nfixed_headers = { \"x-bind\" = \"1\" }",
                "fixed_headers may not set",
            ),
            (
                "fixed_headers = { \"authorization\" = \"1\" }",
                "fixed_headers may not set",
            ),
            (
                "fixed_headers = { \"x-access-token\" = \"1\" }",
                "fixed_headers may not set",
            ),
            (
                "fixed_headers = { \"host\" = \"elsewhere.invalid\" }",
                "fixed_headers may not set",
            ),
            ("fixed_headers = { \"x-v\" = \"\" }", "not a"),
            ("fixed_headers = { \"x-v\" = \"a\\nb\" }", "not a"),
            ("secret_headers = [\"x bind\"]", "not a header name"),
        ] {
            let err = UpstreamRegistry::from_toml_str(&with(extra)).expect_err(extra);
            assert!(err.contains(refused), "{extra}: {err}");
        }

        let unvalidated = RegistryEntry::env(reg.entries()[0].clone())
            .with_request_headers(&["accept", "x-api-version", "x-account-binding"])
            .with_header_policy(&[("x-api-version", "2026-01-01")], &["x-account-binding"]);
        assert!(!unvalidated.forwards_header("x-api-version"));
        assert!(!unvalidated.forwards_header("x-account-binding"));
        assert!(unvalidated.forwards_header("accept"), "the control");
    }

    #[test]
    fn an_empty_file_is_an_empty_registry_not_an_error() {
        assert!(
            UpstreamRegistry::from_toml_str("")
                .unwrap()
                .entries()
                .is_empty()
        );
    }

    /// Each of these would otherwise be a registry that loads and then refuses,
    /// or worse, one whose meaning depends on which duplicate wins.
    #[test]
    fn malformed_registries_refuse_to_load() {
        let dup = format!("{ONE}\n{ONE}");
        let env = |extra: &str, base: &str, var: &str| {
            format!(
                "[[upstream]]\nname='x'\nbase_url='{base}'\nheader='h'\n{extra}\n[upstream.credential.env]\nvar='{var}'\n"
            )
        };
        let fed = |line: &str| FEDERATED.replace("grant = \"token-exchange\"", line);
        let cases = [
            (dup, "a duplicated name"),
            (env("typo=1", "https://a.invalid", "V"), "an unknown field"),
            (env("", "/relative", "V"), "a relative base URL"),
            (env("", "file:///etc/passwd", "V"), "a non-http scheme"),
            (env("", "https://a.invalid", ""), "an empty env var"),
            (
                "[[upstream]]\nname='x'\nupstream='https://a.invalid'\ncredential_env='V'\nheader='h'\n"
                    .to_string(),
                "the retired flat P0 shape",
            ),
            (
                "[[upstream]]\nname='x'\nbase_url='https://a.invalid'\nheader='h'\n".to_string(),
                "no credential source",
            ),
            (fed("grant = \"token_exchange\""), "an unknown grant spelling"),
            (
                FEDERATED.replace("encoding = \"form\"", "encoding = \"xml\""),
                "an unknown encoding",
            ),
            (
                FEDERATED.replace("https://auth.model-api.invalid/oauth", "http://auth.model-api.invalid/oauth"),
                "a cleartext non-loopback token endpoint",
            ),
            (
                FEDERATED.replace("policy_id =", "grant_type ="),
                "a param colliding with a standard key",
            ),
            (
                FEDERATED.replace("scope = \"inference\"", "assertion_ttl_secs = 3601"),
                "an assertion lifetime over the cap",
            ),
            (
                FEDERATED.replace("scope = \"inference\"", "assertion_ttl_secs = 0"),
                "a zero assertion lifetime",
            ),
            (
                FEDERATED.replace("audience = \"https://auth.model-api.invalid\"", "audience = \"\""),
                "an empty audience",
            ),
            (
                FEDERATED.replace("scope = \"inference\"", "token_url = \"x\""),
                "an unknown federated field",
            ),
        ];
        for (text, what) in cases {
            assert!(
                UpstreamRegistry::from_toml_str(&text).is_err(),
                "{what} must refuse to load"
            );
        }
        // The control: the unmodified federated fixture loads, so the cases
        // above fail on their perturbation and not on the fixture.
        assert!(UpstreamRegistry::from_toml_str(FEDERATED).is_ok());
    }

    const CLIENT_CERTIFICATE: &str = r#"
[[upstream]]
name = "object-store"
base_url = "https://objects.invalid"
header = "authorization"
value_prefix = "Bearer "

[upstream.credential.federated]
subject = "client-certificate"
client_certificate = "pod-svid"
token_endpoint = "https://sts.invalid/v1/token"
grant = "token-exchange"
encoding = "json"
request_audience = "example-provider-0001"

[upstream.credential.federated.params]
requested_token_type = "urn:ietf:params:oauth:token-type:access_token"
"#;

    const NOT_YET: &str = "is not supported yet";

    /// The reserved client-certificate subject: a valid entry is refused as
    /// not supported yet, and nothing else is.
    #[test]
    fn a_client_certificate_subject_is_reserved_and_refused() {
        let err = UpstreamRegistry::from_toml_str(CLIENT_CERTIFICATE)
            .expect_err("the client-certificate subject is not served");
        assert!(err.contains(NOT_YET), "{err}");
        assert!(err.contains("object-store"), "{err}");
        let node = CLIENT_CERTIFICATE.replace("\"pod-svid\"", "\"node-svid\"");
        let err = UpstreamRegistry::from_toml_str(&node).expect_err("not served either");
        assert!(err.contains(NOT_YET), "{err}");
    }

    /// The reserved form is validated in full, so each of these is refused
    /// for what is wrong with it, never as merely "not supported yet".
    #[test]
    fn a_malformed_client_certificate_entry_is_refused_for_its_defect() {
        let set = |old: &str, new: &str| CLIENT_CERTIFICATE.replace(old, new);
        let cases = [
            (
                set("client_certificate = \"pod-svid\"\n", ""),
                "no client_certificate",
            ),
            (
                set("\"pod-svid\"", "\"any-svid\""),
                "an unknown client_certificate",
            ),
            (
                set("https://sts.invalid", "http://127.0.0.1"),
                "a non-https endpoint",
            ),
            (
                set("\"token-exchange\"", "\"jwt-bearer\""),
                "an assertion-only grant",
            ),
            (set("\"json\"", "\"xml\""), "an unknown encoding"),
            (
                set("request_audience", "audience = \"x\"\nrequest_audience"),
                "an assertion audience",
            ),
            (
                set(
                    "request_audience",
                    "assertion_ttl_secs = 60\nrequest_audience",
                ),
                "an assertion lifetime",
            ),
            (
                set("request_audience = \"example-provider-0001\"\n", ""),
                "no request_audience",
            ),
            (
                set("requested_token_type", "subject_token_type"),
                "a reserved param",
            ),
            (
                set("subject = \"client-certificate\"", "subject = \"mtls\""),
                "an unknown subject",
            ),
            (
                set("encoding = \"json\"", "encoding = \"json\"\ntypo = 1"),
                "an unknown field",
            ),
        ];
        for (text, what) in cases {
            let err = UpstreamRegistry::from_toml_str(&text)
                .expect_err(&format!("{what} must refuse to load"));
            assert!(
                !err.contains(NOT_YET),
                "{what} was refused only as unsupported: {err}"
            );
        }
        // An assertion-subject entry may not name a client certificate.
        let stray = FEDERATED.replace(
            "grant = \"token-exchange\"",
            "grant = \"token-exchange\"\nclient_certificate = \"pod-svid\"",
        );
        assert!(UpstreamRegistry::from_toml_str(&stray).is_err());
        // The default subject is the assertion, spelled or not.
        let spelled = FEDERATED.replace(
            "grant = \"token-exchange\"",
            "grant = \"token-exchange\"\nsubject = \"assertion\"",
        );
        assert!(UpstreamRegistry::from_toml_str(&spelled).is_ok());
    }

    /// The broker's entries come from the registry, and only for what was
    /// admitted: an admitted set that names something the registry lacks
    /// contributes nothing.
    #[test]
    fn resolve_returns_only_registry_entries_that_were_admitted() {
        let reg = UpstreamRegistry::from_toml_str(ONE).unwrap();
        let resolved = reg.resolve(reg.entries());
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].spec(), &reg.entries()[0]);
        assert!(reg.resolve(&[]).is_empty());
        let mut forged = reg.entries()[0].clone();
        forged.credential_env = "SOME_OTHER_NODE_VAR".into();
        assert!(
            reg.resolve(&[forged]).is_empty(),
            "an entry differing from the registry's must not reach the store"
        );
    }

    /// A spec cannot turn a federated entry into an env one, or back: the
    /// projection's `credential_env` is part of the equality.
    #[test]
    fn a_spec_cannot_change_an_entrys_source_kind() {
        let reg = UpstreamRegistry::from_toml_str(FEDERATED).unwrap();
        let mut as_env = reg.entries()[0].clone();
        as_env.credential_env = "NUCLEUS_NODE_PROXY_AUTH_SECRET".into();
        assert!(reg.resolve(&[as_env]).is_empty());
    }

    /// `ONE` with `value_prefix` removed and `encoding` (a TOML value) set as
    /// its `value_encoding`.
    fn encoded(encoding: &str) -> String {
        ONE.replace(
            "value_prefix = \"Bearer \"",
            &format!("value_encoding = {encoding}"),
        )
    }

    /// **#3252: `basic` builds RFC 7617's value from the bare credential**, at
    /// the one function both call paths build their header with. The expected
    /// value is written out, not recomputed with the code under test. `raw`,
    /// spelled or absent, is `value_prefix` + credential, unchanged.
    #[test]
    fn basic_encoding_is_built_from_the_bare_credential_at_injection() {
        let reg =
            UpstreamRegistry::from_toml_str(&encoded(r#"{ basic = { username = "token-user" } }"#))
                .expect("a basic entry loads");
        let entry = &reg.resolve(reg.entries())[0];
        assert_eq!(
            entry.header_value("test-token-123"),
            "Basic dG9rZW4tdXNlcjp0ZXN0LXRva2VuLTEyMw=="
        );
        // The same entry in TOML's table form loads identically.
        let table = ONE.replace(
            "value_prefix = \"Bearer \"\n",
            "[upstream.value_encoding.basic]\nusername = \"token-user\"\n",
        );
        let reg_table = UpstreamRegistry::from_toml_str(&table).expect("table form loads");
        assert_eq!(&reg_table.resolve(reg_table.entries())[0], entry);

        for raw in [
            ONE.to_string(),
            ONE.replace(
                "[upstream.credential",
                "value_encoding = \"raw\"\n\n[upstream.credential",
            ),
        ] {
            let reg = UpstreamRegistry::from_toml_str(&raw).expect("a raw entry loads");
            assert_eq!(
                reg.resolve(reg.entries())[0].header_value("test-token-123"),
                "Bearer test-token-123"
            );
        }
    }

    /// The encoding is host-only: a basic entry's projection, which is what
    /// the guest sees and a pod spec selects by, carries neither the scheme
    /// nor the username, and is the projection the CLI computes from the
    /// same file (no `value_prefix`, so `""`).
    #[test]
    fn the_encoding_is_not_in_the_projection() {
        let reg =
            UpstreamRegistry::from_toml_str(&encoded(r#"{ basic = { username = "token-user" } }"#))
                .unwrap();
        let projection = &reg.entries()[0];
        assert_eq!(projection.value_prefix, "");
        let as_json = serde_json::to_string(projection).unwrap();
        for private in ["token-user", "basic", "Basic"] {
            assert!(!as_json.contains(private), "{private:?} in {as_json}");
        }
        assert_eq!(
            projection,
            &CredentialedEgressSpec::registry_projection(
                "model-api".into(),
                "https://model-api.invalid/v1".into(),
                "authorization".into(),
                String::new(),
                Some("LLM_API_TOKEN".into()),
                nucleus_spec::EffectTable::unclassified(),
            )
        );
    }

    /// Every malformed encoding refuses the whole registry, naming the entry:
    /// an empty username, one with `:` (which would move part of it into the
    /// password the upstream reads), a control character, an over-long one, a
    /// `value_prefix` beside `basic`, an unknown variant, and an unknown field.
    #[test]
    fn a_malformed_encoding_refuses_the_registry() {
        let long = format!(r#"{{ basic = {{ username = "{}" }} }}"#, "u".repeat(257));
        for (encoding, why) in [
            (r#"{ basic = { username = "" } }"#, "non-empty"),
            (r#"{ basic = { username = "token:user" } }"#, "':'"),
            (r#"{ basic = { username = "token\nuser" } }"#, "control"),
            (long.as_str(), "longer"),
        ] {
            let err = UpstreamRegistry::from_toml_str(&encoded(encoding)).expect_err(encoding);
            assert!(
                err.contains("model-api") && err.contains(why),
                "{encoding}: {err}"
            );
        }
        let with_prefix = ONE.replace(
            "[upstream.credential",
            "value_encoding = { basic = { username = \"token-user\" } }\n\n[upstream.credential",
        );
        let err = UpstreamRegistry::from_toml_str(&with_prefix).expect_err("prefix + basic");
        assert!(err.contains("value_prefix"), "{err}");
        for unknown in [
            r#""bearer""#,
            r#"{ digest = { username = "token-user" } }"#,
            r#"{ basic = { username = "token-user", password = "x" } }"#,
            r#"{ basic = {} }"#,
        ] {
            assert!(
                UpstreamRegistry::from_toml_str(&encoded(unknown)).is_err(),
                "{unknown} loaded"
            );
        }
        // The shipped git-remote example loads, and encodes as Basic.
        let example = UpstreamRegistry::from_toml_str(include_str!(
            "../../../examples/egress-git-remote/upstreams.toml"
        ))
        .expect("the example registry loads");
        assert!(
            example.resolve(example.entries())[0]
                .header_value("t")
                .starts_with("Basic ")
        );
        // The control: the boundary username loads.
        let max = format!(r#"{{ basic = {{ username = "{}" }} }}"#, "u".repeat(256));
        assert!(UpstreamRegistry::from_toml_str(&encoded(&max)).is_ok());
    }
}
