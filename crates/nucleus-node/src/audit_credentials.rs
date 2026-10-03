//! The credential a pod's audit uploader signs with: minted for that pod, limited to the
//! destination admission resolved, and never the node's own (#3160).
//!
//! # The hole this closes
//!
//! #3131 made the destination the operator's: a spec names a sink from `--audit-sinks` and may
//! only narrow its prefix. But the uploader still signed with the node's AMBIENT cloud key. The
//! local driver forwarded it (and every local tool-proxy inherited it, sink or not, because a
//! `Command` inherits the node's environment), the container driver copied it into the container,
//! and the microVM workload API served it over `FETCH_AUDIT_CREDENTIALS`. That key writes, reads
//! and deletes anywhere the operator's account reaches, so the pod held far more than "append to
//! this prefix", and a compromised uploader could reach other tenants' audit trails, or the
//! operator's.
//!
//! # The model
//!
//! A [`ScopedCredentialMinter`] takes a [`WriteScope`] (endpoint, bucket and key prefix, nothing
//! else) and a lifetime, and returns a short-lived credential that may only put objects under that
//! prefix. How it does so is the minter's business and is deliberately not in this crate: a token
//! service session restricted by a policy naming [`WriteScope::object_pattern`], a downscoped
//! token, or an object store's own temporary keys all fit behind the trait.
//!
//! No minter means no audit sink. A spec that names one on a node without a minter is refused at
//! create, by sink name ([`AuditGrantRefused::NoMinter`]). There is no fallback to the node's own
//! key, because that fallback is exactly the defect (ADR 0007 A, B: "could not mint" is never
//! "use what we have").
//!
//! # Evidence, not a re-read
//!
//! [`admit`] is the one decider, run at create beside posture admission. It turns the resolved
//! [`AuditTarget`] into an [`AuditMint`], which is consumed by value to mint (ADR 0007 C-4) once
//! the caller's authority is admitted. The result is an [`AuditGrant`]: the target and the
//! credential for it, which only [`AuditMint::mint`] constructs. The drivers take the grant, so
//! there is no way to configure an uploader with a destination and no credential, or with a
//! credential that was not minted for that destination.
//!
//! # Not done here
//!
//! - No concrete minter ships in this crate, so an audit sink is refused on every node until an
//!   embedding supplies one. That is the fail-closed half of the fix, not an omission of it.
//! - A credential is minted once, for the pod's lifetime capped at [`MAX_CREDENTIAL_TTL`]. A pod
//!   that outlives its credential stops shipping audit entries (the tool-proxy logs each failed
//!   write); refreshing over the workload API is a follow-up.
//! - The local driver is the unsandboxed host tier. Its tool-proxy no longer receives or inherits
//!   the key through its environment, but it runs as the node's user, so a credentials file or
//!   instance metadata service the node can read, it can read too.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::AuditTarget;

/// The longest credential the node asks a minter for: twelve hours. A pod's own `timeout_seconds`
/// is used when it is shorter.
pub(crate) const MAX_CREDENTIAL_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// The shortest credential the node asks for, so a pod with a tiny timeout still gets one that
/// lasts long enough to ship its first entries.
const MIN_CREDENTIAL_TTL: Duration = Duration::from_secs(15 * 60);

/// How far past the requested lifetime a minted credential's expiry may sit before it is refused:
/// clock skew between the node and the issuer, not extra lifetime.
const EXPIRY_SKEW: Duration = Duration::from_secs(60);

/// The environment names the uploader's object-store client reads a credential from, in the order
/// its default chain consults them. The minted credential is set under the first three; a
/// host-side uploader has every one of these removed from what it would inherit from the node, so
/// the chain cannot fall through to the node's own key.
pub(crate) const UPLOADER_CREDENTIAL_ENV: [&str; 14] = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
];

/// Where a minted credential may write: new objects under one key prefix of one bucket, at one
/// endpoint. Put only: no read, no list, no delete. Only [`AuditTarget::write_scope`] constructs
/// one, so a scope is always a destination admission resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriteScope {
    endpoint: Option<String>,
    region: Option<String>,
    bucket: String,
    prefix: Option<String>,
}

// What a minter reads. No minter ships in this crate, so outside tests nothing calls these.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the minter interface; implementations live outside this crate (#3160)"
    )
)]
impl WriteScope {
    /// The S3-compatible endpoint, or `None` for the client's default.
    pub(crate) fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    /// The region, when the operator named one.
    pub(crate) fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// The bucket.
    pub(crate) fn bucket(&self) -> &str {
        &self.bucket
    }

    /// The key prefix every write is under, or `None` when the operator's sink is a whole bucket
    /// and the spec did not narrow it.
    pub(crate) fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// The one object pattern a minted credential may put to: `bucket/prefix/*`, or `bucket/*`
    /// for a sink without a prefix. The prefix's grammar admits no `*`, so the pattern's only
    /// wildcard is the final one: `/`-separated segments of safe key characters, none empty, `.`
    /// or `..` (`key_prefix`).
    pub(crate) fn object_pattern(&self) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}/{prefix}/*", self.bucket),
            None => format!("{}/*", self.bucket),
        }
    }
}

impl fmt::Display for WriteScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.object_pattern())
    }
}

impl AuditTarget {
    /// What a credential for this target may write, and nothing more.
    pub(crate) fn write_scope(&self) -> WriteScope {
        let AuditTarget {
            name: _,
            bucket,
            prefix,
            region,
            endpoint,
        } = self;
        WriteScope {
            endpoint: endpoint.clone(),
            region: region.clone(),
            bucket: bucket.clone(),
            prefix: prefix.clone(),
        }
    }
}

/// A short-lived credential, as a minter returns it. Deliberately no derived `Debug`: a derived
/// one would put the secret one `{:?}` away from a log line.
pub(crate) struct MintedCredential {
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
    /// The session token, for credentials that carry one.
    pub(crate) session_token: Option<String>,
    /// When the credential stops working. Required: a credential without a bounded lifetime is
    /// a standing key, and is refused.
    pub(crate) expires_at: SystemTime,
}

impl fmt::Debug for MintedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedCredential")
            .field("access_key_id", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// What [`ScopedCredentialMinter::mint`] returns: the credential, or why there is none.
pub(crate) type MintFuture<'a> =
    Pin<Box<dyn Future<Output = Result<MintedCredential, String>> + Send + 'a>>;

/// Mints a short-lived credential that may only put objects within a [`WriteScope`].
///
/// Vendor-neutral by construction: the node hands over the destination and a lifetime and gets
/// back an access key, a secret, an optional session token and an expiry. An implementation must
/// return a credential that cannot write outside [`WriteScope::object_pattern`], and must not
/// return the identity it mints with.
pub(crate) trait ScopedCredentialMinter: Send + Sync {
    /// Mint a credential for `scope` that expires within `ttl`.
    fn mint<'a>(&'a self, scope: &'a WriteScope, ttl: Duration) -> MintFuture<'a>;
}

/// Why a pod's audit sink cannot be given a credential. Every variant names the sink.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AuditGrantRefused {
    /// The node has no minter, so it cannot give an uploader a credential limited to `scope`.
    #[error(
        "audit_sink.sink `{sink}` is refused: this node has no scoped credential minter, so it \
         cannot give the pod's uploader a credential limited to `{scope}`. Audit writes are never \
         signed with the node's own credentials, so audit sinks are unavailable on this node."
    )]
    NoMinter { sink: String, scope: String },
    /// The minter could not mint.
    #[error(
        "audit_sink.sink `{sink}` is refused: minting a credential for `{scope}` failed: {why}"
    )]
    MintFailed {
        sink: String,
        scope: String,
        why: String,
    },
    /// The minter returned something that is not a short-lived credential.
    #[error(
        "audit_sink.sink `{sink}` is refused: the credential minted for `{scope}` {why}, so it is \
         not a short-lived credential"
    )]
    NotShortLived {
        sink: String,
        scope: String,
        why: &'static str,
    },
}

impl From<AuditGrantRefused> for crate::ApiError {
    fn from(e: AuditGrantRefused) -> Self {
        match e {
            AuditGrantRefused::NoMinter { .. } => crate::ApiError::InvalidSpec(e.to_string()),
            AuditGrantRefused::MintFailed { .. } | AuditGrantRefused::NotShortLived { .. } => {
                crate::ApiError::Driver(e.to_string())
            }
        }
    }
}

/// An admitted audit sink, waiting for the pod's authority to be admitted before its credential
/// is minted. Consumed by [`AuditMint::mint`].
#[must_use = "an admitted audit sink is minted with `mint`, or the pod has no uploader credential"]
pub(crate) struct AuditMint {
    target: AuditTarget,
    minter: Arc<dyn ScopedCredentialMinter>,
}

/// The one decider: whether a resolved audit sink can be given a scoped credential on this node.
/// `None` when the pod has no audit sink; a named refusal when it has one and there is no minter.
pub(crate) fn admit(
    target: Option<AuditTarget>,
    minter: Option<&Arc<dyn ScopedCredentialMinter>>,
) -> Result<Option<AuditMint>, AuditGrantRefused> {
    let Some(target) = target else {
        return Ok(None);
    };
    match minter {
        Some(minter) => Ok(Some(AuditMint {
            target,
            minter: Arc::clone(minter),
        })),
        None => Err(AuditGrantRefused::NoMinter {
            sink: target.name.clone(),
            scope: target.write_scope().to_string(),
        }),
    }
}

/// The lifetime to ask a minter for: the pod's own timeout, between the floor and
/// [`MAX_CREDENTIAL_TTL`].
pub(crate) fn credential_ttl(timeout_seconds: u64) -> Duration {
    Duration::from_secs(timeout_seconds).clamp(MIN_CREDENTIAL_TTL, MAX_CREDENTIAL_TTL)
}

impl AuditMint {
    /// Mint the credential for this sink's scope, by value: one admission, one mint.
    pub(crate) async fn mint(self, ttl: Duration) -> Result<AuditGrant, AuditGrantRefused> {
        let Self { target, minter } = self;
        let scope = target.write_scope();
        let refuse_with = |why: &'static str| AuditGrantRefused::NotShortLived {
            sink: target.name.clone(),
            scope: scope.to_string(),
            why,
        };
        let asked_at = SystemTime::now();
        let credential =
            minter
                .mint(&scope, ttl)
                .await
                .map_err(|why| AuditGrantRefused::MintFailed {
                    sink: target.name.clone(),
                    scope: scope.to_string(),
                    why,
                })?;
        if credential.access_key_id.is_empty() || credential.secret_access_key.is_empty() {
            return Err(refuse_with("has an empty access key id or secret"));
        }
        if credential.expires_at <= SystemTime::now() {
            return Err(refuse_with("has already expired"));
        }
        if credential.expires_at > asked_at + ttl + EXPIRY_SKEW {
            return Err(refuse_with("outlives the lifetime the node asked for"));
        }
        Ok(AuditGrant {
            target,
            scope,
            credential,
        })
    }
}

/// A pod's uploader grant: where it writes, and the credential minted for exactly that place.
/// Only [`AuditMint::mint`] constructs one (ADR 0007 C-1). Not `Clone`: one pod, one grant.
pub(crate) struct AuditGrant {
    target: AuditTarget,
    scope: WriteScope,
    credential: MintedCredential,
}

impl fmt::Debug for AuditGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditGrant")
            .field("target", &self.target)
            .field("scope", &self.scope)
            .field("credential", &self.credential)
            .finish()
    }
}

impl AuditGrant {
    /// Where the uploader writes, as admission resolved it.
    pub(crate) fn target(&self) -> &AuditTarget {
        &self.target
    }

    /// What the credential was minted for.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read by tests; the drivers take the grant's environment"
        )
    )]
    pub(crate) fn scope(&self) -> &WriteScope {
        &self.scope
    }

    /// The uploader's whole environment for this sink: the destination, then the minted
    /// credential. The local and container drivers set exactly these.
    pub(crate) fn proxy_env(&self) -> Vec<(&'static str, &str)> {
        let MintedCredential {
            access_key_id,
            secret_access_key,
            session_token,
            expires_at: _,
        } = &self.credential;
        let mut env = self.target.proxy_env();
        let [key_id, secret, token, ..] = UPLOADER_CREDENTIAL_ENV;
        env.push((key_id, access_key_id.as_str()));
        env.push((secret, secret_access_key.as_str()));
        if let Some(session_token) = session_token {
            env.push((token, session_token.as_str()));
        }
        env
    }

    /// The credential as the microVM workload API serves it (`FETCH_AUDIT_CREDENTIALS`).
    pub(crate) fn served_credentials(&self) -> crate::workload_api_vsock::AuditCredentials {
        let MintedCredential {
            access_key_id,
            secret_access_key,
            session_token,
            expires_at: _,
        } = &self.credential;
        crate::workload_api_vsock::AuditCredentials {
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
            session_token: session_token.clone(),
        }
    }
}

/// A minter for tests: records every scope it is asked for and returns a credential it made up,
/// valid for exactly the lifetime asked.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::Mutex;

    /// The minted access key id the fake returns.
    pub(crate) const MINTED_KEY_ID: &str = "minted-key-id-3160";
    /// The minted secret the fake returns.
    pub(crate) const MINTED_SECRET: &str = "minted-secret-3160";
    /// The minted session token the fake returns.
    pub(crate) const MINTED_TOKEN: &str = "minted-token-3160";

    /// What the fake does when asked.
    pub(crate) enum Behaviour {
        /// Mint a credential valid for exactly the lifetime asked.
        Mint,
        /// Mint a credential valid for longer than asked.
        Overlong,
        /// Fail.
        Fail,
    }

    pub(crate) struct FakeMinter {
        behaviour: Behaviour,
        asked: Mutex<Vec<(WriteScope, Duration)>>,
    }

    impl FakeMinter {
        pub(crate) fn new(behaviour: Behaviour) -> Arc<Self> {
            Arc::new(Self {
                behaviour,
                asked: Mutex::new(Vec::new()),
            })
        }

        /// Every `(scope, ttl)` this minter was asked for, in order.
        pub(crate) fn asked(&self) -> Vec<(WriteScope, Duration)> {
            self.asked.lock().expect("not poisoned").clone()
        }
    }

    impl ScopedCredentialMinter for FakeMinter {
        fn mint<'a>(&'a self, scope: &'a WriteScope, ttl: Duration) -> MintFuture<'a> {
            self.asked
                .lock()
                .expect("not poisoned")
                .push((scope.clone(), ttl));
            let lifetime = match self.behaviour {
                Behaviour::Mint => ttl,
                Behaviour::Overlong => ttl * 10,
                Behaviour::Fail => {
                    return Box::pin(async { Err("the token service said no".to_string()) });
                }
            };
            Box::pin(async move {
                Ok(MintedCredential {
                    access_key_id: MINTED_KEY_ID.to_string(),
                    secret_access_key: MINTED_SECRET.to_string(),
                    session_token: Some(MINTED_TOKEN.to_string()),
                    expires_at: SystemTime::now() + lifetime,
                })
            })
        }
    }

    /// The operator's sink `audit` (bucket `operator-audit`, prefix `nucleus`), narrowed by a spec
    /// to `team-a`: resolved by the same decider admission runs.
    pub(crate) fn target() -> AuditTarget {
        let sinks = super::super::AuditSinks::from_toml(
            "[[sink]]\nname = \"audit\"\nbucket = \"operator-audit\"\nprefix = \"nucleus\"\n",
        )
        .expect("loads");
        let spec: nucleus_spec::PodSpec = serde_json::from_str(
            r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"audit_sink":{"sink":"audit","prefix":"team-a"}}}"#,
        )
        .expect("spec parses");
        sinks
            .resolve_for(&spec)
            .expect("admitted")
            .expect("resolved")
    }

    /// A grant for `target`, minted by a fresh [`FakeMinter`].
    pub(crate) async fn grant(target: AuditTarget) -> AuditGrant {
        let minter: Arc<dyn ScopedCredentialMinter> = FakeMinter::new(Behaviour::Mint);
        admit(Some(target), Some(&minter))
            .expect("a minter is configured")
            .expect("a sink was asked for")
            .mint(MAX_CREDENTIAL_TTL)
            .await
            .expect("the fake mints")
    }
}

#[cfg(test)]
#[path = "audit_credentials_tests.rs"]
mod tests;
