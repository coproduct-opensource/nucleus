//! Where a pod's audit log is shipped belongs to the node's operator (#3131).
//!
//! # The hole this closes
//!
//! The tool-proxy ships a pod's audit entries to an S3-compatible store, and it signs those
//! writes with the operator's cloud credentials: the node forwards its ambient `AWS_*` variables
//! to a local or container proxy, and serves them to a microVM guest over the workload API
//! (`FETCH_AUDIT_CREDENTIALS`). Until this module existed, the bucket, prefix, region and
//! **endpoint** all came from the pod spec. So whoever wrote the spec chose the destination, and
//! the operator's key supplied the authority. That is a confused deputy: a tenant could write into
//! any bucket the operator's key reaches, or point the endpoint at a server it runs and receive the
//! operator's access key ID and session token in the request headers.
//!
//! # The model: the operator defines, the spec selects and narrows
//!
//! The operator lists the sinks this node writes to in a TOML file (`--audit-sinks`). A spec's
//! `audit_sink` names one of them and may append a sub-prefix under that sink's prefix. The spec
//! type ([`nucleus_spec::AuditSinkSpec`]) has no field that can carry a bucket, region or endpoint,
//! so a spec cannot express the defect at all, and the earlier `s3_*` shape fails to parse.
//!
//! This is the same split as the credentialed-upstream registry (`upstreams.rs`), but simpler:
//! there, admission compares a spec's projection with each entry, because the spec still states the
//! URL. Here the spec states only a name. The destination is written once, in the operator's file,
//! and nowhere else (ADR 0007 G-1).
//!
//! Why name selection plus prefix narrowing, and not an allowlist of `(endpoint, bucket)` pairs
//! the spec repeats: no spec, example or document in this repository names an audit sink. So there
//! is no caller to keep compatible, and a spec that restated the operator's bucket would only be a
//! second copy of a fact the node already holds. Why not "the spec says yes and the node picks":
//! a node may serve tenants that need separate buckets, and a name costs nothing over a boolean.
//!
//! # No file means no sink
//!
//! Without `--audit-sinks` the node configures no sink, and every spec that names one is refused
//! at create, by name. A spec without an `audit_sink` is unaffected.
//!
//! # Evidence, not a re-parse
//!
//! [`AuditSinks::resolve_for`] is the one decider. It returns an [`AuditTarget`], whose fields are
//! private and which nothing else constructs (ADR 0007 C-1). `create_pod_internal` gets that target
//! from admission and hands it to the driver that spawns the pod. The renderers take the target,
//! never the spec, so an unresolved spec value has no path to the guest command line or to a
//! proxy's environment.
//!
//! # File format
//!
//! TOML, one `[[sink]]` table per sink. Unknown fields are refused, and every value must be one
//! token of its grammar, because the values ride the guest kernel command line:
//!
//! ```toml
//! [[sink]]
//! name     = "audit"
//! bucket   = "operator-audit"
//! prefix   = "nucleus/node-1"               # optional
//! region   = "us-west-2"                    # optional
//! endpoint = "https://objects.internal:9000" # optional; S3-compatible endpoint
//! ```
//!
//! # Credentials
//!
//! The uploader never signs with the node's own key. Each pod's uploader gets a short-lived
//! credential minted for the resolved bucket and prefix only, and a node with no minter refuses
//! every audit sink by name (#3160, [`credentials`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nucleus_spec::{AuditSinkSpec, PodSpec};
use serde::Deserialize;

use crate::spec_posture::PostureRefused;

/// The node's audit sink flag, flattened into `Args`.
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct AuditSinkArgs {
    /// TOML file of the audit sinks this node ships pod audit logs to. A pod spec may only name one
    /// of these and narrow its prefix, and its uploader signs with a credential minted for that
    /// prefix alone, never the node's own. Unset: no sink, and a spec that names one is refused at
    /// create.
    #[arg(long = "audit-sinks", env = "NUCLEUS_NODE_AUDIT_SINKS")]
    pub audit_sinks: Option<PathBuf>,
}

impl AuditSinkArgs {
    /// The sinks in force. A file that does not load stops the node: an operator who wrote one
    /// expects it to be used.
    pub(crate) fn load(&self) -> Result<AuditSinks, String> {
        match &self.audit_sinks {
            None => Ok(AuditSinks::none()),
            Some(path) => AuditSinks::load(path),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SinksFile {
    #[serde(default)]
    sink: Vec<SinkFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SinkFile {
    name: String,
    bucket: String,
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
}

/// The operator's audit sinks, by name. No `Default`: an empty set is spelled
/// [`AuditSinks::none`] (ADR 0007 B-1).
#[derive(Debug, Clone)]
pub(crate) struct AuditSinks {
    by_name: BTreeMap<String, AuditTarget>,
}

/// Where one pod's audit log is written: the operator's bucket, region and endpoint, and a prefix
/// at or under the operator's prefix. Only [`AuditSinks`] constructs one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditTarget {
    /// The operator's name for the sink, so a refusal can name it.
    name: String,
    bucket: String,
    prefix: Option<String>,
    region: Option<String>,
    endpoint: Option<String>,
}

impl AuditSinks {
    /// No sinks configured: every `audit_sink` is refused.
    pub(crate) fn none() -> Self {
        Self {
            by_name: BTreeMap::new(),
        }
    }

    fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("--audit-sinks {}: {e}", path.display()))?;
        Self::from_toml(&text).map_err(|e| format!("--audit-sinks {}: {e}", path.display()))
    }

    /// Parse and validate the operator's file. Every value is checked against the same grammar a
    /// spec's prefix is, because all of them reach the guest kernel command line.
    pub(crate) fn from_toml(text: &str) -> Result<Self, String> {
        let file: SinksFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut by_name = BTreeMap::new();
        for SinkFile {
            name,
            bucket,
            prefix,
            region,
            endpoint,
        } in file.sink
        {
            sink_name(&name)?;
            let target = AuditTarget {
                name: name.clone(),
                bucket: valid_bucket(&bucket).map_err(|e| format!("sink `{name}`: {e}"))?,
                prefix: prefix
                    .map(|p| key_prefix("prefix", &p))
                    .transpose()
                    .map_err(|e| format!("sink `{name}`: {e}"))?,
                region: region
                    .map(|r| token("region", &r, is_region_char).map(str::to_string))
                    .transpose()
                    .map_err(|e| format!("sink `{name}`: {e}"))?,
                endpoint: endpoint
                    .map(|e| endpoint_url(&e).map(str::to_string))
                    .transpose()
                    .map_err(|e| format!("sink `{name}`: {e}"))?,
            };
            if by_name.insert(name.clone(), target).is_some() {
                return Err(format!("sink `{name}` is defined twice"));
            }
        }
        Ok(Self { by_name })
    }

    /// The one decider: the destination a spec's `audit_sink` resolves to, or the refusal that
    /// names it. `None` when the spec asks for no sink.
    pub(crate) fn resolve_for(
        &self,
        spec: &PodSpec,
    ) -> Result<Option<AuditTarget>, PostureRefused> {
        spec.spec
            .audit_sink
            .as_ref()
            .map(|sink| self.resolve(sink))
            .transpose()
    }

    fn resolve(&self, sink: &AuditSinkSpec) -> Result<AuditTarget, PostureRefused> {
        // No `..` (ADR 0007 E-1): a new spec field is a compile error here, not a value that skips
        // the resolution.
        let AuditSinkSpec { sink: name, prefix } = sink;
        let Some(operator) = self.by_name.get(name) else {
            return Err(PostureRefused::AuditSinkUnknown {
                name: name.clone(),
                configured: if self.by_name.is_empty() {
                    "this node configures none".to_string()
                } else {
                    let names: Vec<&str> = self.by_name.keys().map(String::as_str).collect();
                    format!("this node configures: {}", names.join(", "))
                },
            });
        };
        let AuditTarget {
            name: _,
            bucket,
            prefix: fixed,
            region,
            endpoint,
        } = operator;
        let prefix = match (fixed, prefix) {
            (fixed, None) => fixed.clone(),
            (fixed, Some(narrowing)) => {
                let narrowing = key_prefix("prefix", narrowing)?;
                let joined = match fixed {
                    Some(fixed) => format!("{fixed}/{narrowing}"),
                    None => narrowing,
                };
                if joined.len() > MAX_SINK_VALUE {
                    return Err(refuse(
                        "prefix",
                        &joined,
                        "the operator's prefix and this one together exceed 512 characters",
                    ));
                }
                Some(joined)
            }
        };
        Ok(AuditTarget {
            name: name.clone(),
            bucket: bucket.clone(),
            prefix,
            region: region.clone(),
            endpoint: endpoint.clone(),
        })
    }
}

impl AuditTarget {
    /// The tool-proxy's environment for this sink, in a fixed order. The local and container
    /// drivers set exactly these; the microVM guest's init maps the boot args below onto the same
    /// names (`nucleus-guest-init`).
    pub(crate) fn proxy_env(&self) -> Vec<(&'static str, &str)> {
        let Self {
            name: _,
            bucket,
            prefix,
            region,
            endpoint,
        } = self;
        let mut env = vec![("NUCLEUS_TOOL_PROXY_AUDIT_S3_BUCKET", bucket.as_str())];
        for (key, value) in [
            ("NUCLEUS_TOOL_PROXY_AUDIT_S3_PREFIX", prefix),
            ("NUCLEUS_TOOL_PROXY_AUDIT_S3_REGION", region),
            ("NUCLEUS_TOOL_PROXY_AUDIT_S3_ENDPOINT", endpoint),
        ] {
            if let Some(value) = value {
                env.push((key, value.as_str()));
            }
        }
        env
    }
}

/// The guest kernel command line tokens for a resolved sink: one token per value. Every value was
/// checked against its grammar when the operator's file loaded or the spec's prefix resolved.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn audit_sink_boot_args(target: &AuditTarget) -> Vec<String> {
    let AuditTarget {
        name: _,
        bucket,
        prefix,
        region,
        endpoint,
    } = target;
    let mut args = vec![format!("nucleus.audit_s3_bucket={bucket}")];
    if let Some(prefix) = prefix {
        args.push(format!("nucleus.audit_s3_prefix={prefix}"));
    }
    if let Some(region) = region {
        args.push(format!("nucleus.audit_s3_region={region}"));
    }
    if let Some(endpoint) = endpoint {
        args.push(format!("nucleus.audit_s3_endpoint={endpoint}"));
    }
    args
}

/// The longest audit sink value admitted.
const MAX_SINK_VALUE: usize = 512;

fn refuse(field: &'static str, value: &str, why: &'static str) -> PostureRefused {
    PostureRefused::AuditSink {
        field,
        value: value.to_string(),
        why,
    }
}

/// A sink name: 1 to 64 of `[a-z0-9_-]`.
fn sink_name(name: &str) -> Result<(), String> {
    if (1..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        Ok(())
    } else {
        Err(format!("sink name `{name}` must be 1 to 64 of [a-z0-9_-]"))
    }
}

/// One non-empty token of `allowed` characters, at most [`MAX_SINK_VALUE`] long.
fn token<'a>(
    field: &'static str,
    value: &'a str,
    allowed: fn(char) -> bool,
) -> Result<&'a str, PostureRefused> {
    if value.is_empty() || value.len() > MAX_SINK_VALUE {
        return Err(refuse(field, value, "it must be 1 to 512 characters"));
    }
    if !value.chars().all(allowed) {
        return Err(refuse(
            field,
            value,
            "it contains a character outside its grammar (whitespace and quotes are never allowed)",
        ));
    }
    Ok(value)
}

/// A key prefix: one token of S3's safe key characters, made of `/`-separated segments that are
/// neither empty nor `.` or `..`. A single trailing `/` is dropped, so joining never doubles one.
/// The segment rule is what makes a narrowing stay under the operator's prefix on a store that
/// normalises paths.
fn key_prefix(field: &'static str, value: &str) -> Result<String, PostureRefused> {
    let value = token(field, value, is_key_char)?;
    let trimmed = value.strip_suffix('/').unwrap_or(value);
    if trimmed
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(refuse(
            field,
            value,
            "a prefix is `/`-separated segments, none empty and none `.` or `..`",
        ));
    }
    Ok(trimmed.to_string())
}

/// An S3 bucket name: 3 to 63 of `[a-z0-9.-]`, starting and ending with a letter or digit.
fn valid_bucket(value: &str) -> Result<String, PostureRefused> {
    let edge = |c: Option<char>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let body = value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
    if (3..=63).contains(&value.len())
        && body
        && edge(value.chars().next())
        && edge(value.chars().last())
    {
        Ok(value.to_string())
    } else {
        Err(refuse(
            "bucket",
            value,
            "a bucket name is 3 to 63 of [a-z0-9.-], starting and ending with a letter or digit",
        ))
    }
}

/// An `http://` or `https://` URL with no whitespace or quote.
fn endpoint_url(value: &str) -> Result<&str, PostureRefused> {
    let value = token("endpoint", value, is_url_char)?;
    if value.starts_with("https://") || value.starts_with("http://") {
        Ok(value)
    } else {
        Err(refuse(
            "endpoint",
            value,
            "an endpoint is an http:// or https:// URL",
        ))
    }
}

/// S3's "safe" object key characters, plus `/`, minus `*`. The prefix becomes the object pattern a
/// minted credential is scoped to (`credentials::WriteScope::object_pattern`), where `*` is a
/// wildcard: a narrowing of `*` would scope a pod's credential to every sibling prefix (#3160).
fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '!' | '-' | '_' | '.' | '(' | ')')
}

fn is_region_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
}

/// Visible ASCII except the quote, which the kernel command line parser treats specially.
fn is_url_char(c: char) -> bool {
    c.is_ascii_graphic() && c != '"'
}

#[path = "audit_credentials.rs"]
pub(crate) mod credentials;

#[cfg(test)]
#[path = "audit_sink_tests.rs"]
mod tests;

/// The node's ambient cloud key, planted in this test process's environment so a test can prove
/// it never reaches a pod (#3160). Each value is a unique string a test searches a pod's whole
/// environment, or a guest reply, for.
#[cfg(all(test, any(target_os = "linux", feature = "local-driver")))]
pub(crate) mod ambient_fixture {
    /// The planted access key id.
    pub(crate) const KEY_ID: &str = "ambient-node-key-id-3160";
    /// The planted secret.
    pub(crate) const SECRET: &str = "ambient-node-secret-3160";
    /// The planted session token.
    pub(crate) const TOKEN: &str = "ambient-node-token-3160";

    /// Plant the node's ambient key under the names the uploader's credential chain reads.
    pub(crate) fn plant() {
        for (key, value) in [
            ("AWS_ACCESS_KEY_ID", KEY_ID),
            ("AWS_SECRET_ACCESS_KEY", SECRET),
            ("AWS_SESSION_TOKEN", TOKEN),
        ] {
            // SAFETY: edition 2024 makes env mutation unsafe -- it races any concurrent reader.
            // Every planting writes the same three values, and no test in this crate depends on
            // their absence.
            #[expect(
                clippy::disallowed_methods,
                reason = "ADR 0007 H-1: test-only process-global mutation; the subject under test \
                          is that the node's ambient environment does not reach a pod"
            )]
            unsafe {
                std::env::set_var(key, value)
            };
        }
    }

    /// Whether `text` carries any part of the planted key.
    pub(crate) fn leaks(text: &str) -> bool {
        [KEY_ID, SECRET, TOKEN].iter().any(|v| text.contains(v))
    }
}
