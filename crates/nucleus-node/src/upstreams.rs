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
//! URL, a header and prefix, and a **credential source**:
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
//!
//! [upstream.credential.env]
//! var = "SEARCH_API_TOKEN"
//! ```
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
    credential: CredentialFile,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum CredentialFile {
    Env { var: String },
    Federated(FederatedFile),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FederatedFile {
    token_endpoint: String,
    grant: String,
    encoding: String,
    audience: String,
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

/// One operator-defined upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegistryEntry {
    /// What a pod spec sees and admission compares. See the module docs.
    spec: CredentialedEgressSpec,
    credential: CredentialSource,
}

impl RegistryEntry {
    /// The projection a pod spec selects this entry by: name, base, header,
    /// prefix, and the env variable's name (empty for a federated entry).
    pub fn spec(&self) -> &CredentialedEgressSpec {
        &self.spec
    }

    /// Where the credential comes from.
    pub fn credential(&self) -> &CredentialSource {
        &self.credential
    }

    /// Whether this entry mints its credential per exchange.
    pub fn is_federated(&self) -> bool {
        matches!(self.credential, CredentialSource::Federated(_))
    }

    /// An `env` entry whose projection is `spec`. The registry's own loader
    /// builds entries from TOML; this is for tests that start from a spec.
    #[cfg(test)]
    pub fn env(spec: CredentialedEgressSpec) -> Self {
        let credential = CredentialSource::Env {
            var: spec.credential_env.clone(),
        };
        Self { spec, credential }
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
            let (credential, credential_env) = match up.credential {
                CredentialFile::Env { var } => {
                    if var.trim().is_empty() {
                        return Err(format!(
                            "upstream {:?}: credential.env.var must be set",
                            up.name
                        ));
                    }
                    (CredentialSource::Env { var: var.clone() }, var)
                }
                CredentialFile::Federated(fed) => (
                    CredentialSource::Federated(Arc::new(federated(&up.name, fed)?)),
                    String::new(),
                ),
            };
            entries.push(RegistryEntry {
                spec: CredentialedEgressSpec {
                    name: up.name,
                    upstream: up.base_url,
                    credential_env,
                    header: up.header,
                    value_prefix: up.value_prefix,
                },
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

/// Validate one `federated` table.
///
/// The endpoint and parameters are checked by building the same
/// `TokenRequest` the exchange will build, with an empty subject — so "loads"
/// and "the token client accepts it" are one fact rather than two checks that
/// agree today.
fn federated(name: &str, f: FederatedFile) -> Result<FederatedUpstream, String> {
    let bad = |what: &str| format!("upstream {name:?}: credential.federated: {what}");
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
    if f.audience.trim().is_empty() {
        return Err(bad("audience must be set"));
    }
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
        audience: f.audience,
        scope: f.scope,
        request_audience: f.request_audience,
        params: f.params,
        assertion_ttl,
    })
}

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
}
