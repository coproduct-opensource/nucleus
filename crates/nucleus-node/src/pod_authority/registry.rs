//! The `--upstreams` registry and its `[[caller]]` bindings, reloadable while
//! the node runs.
//!
//! # Why
//!
//! A binding's ceiling carries its time window and its budget, and both are
//! renewed by an operator (or a keeper acting for one) rewriting the file. When
//! the file was read once at start, every renewal was stop, edit, restart, and a
//! node whose windows lapsed overnight stayed dead until someone came back.
//!
//! # What a reload does
//!
//! On SIGHUP, and whenever a poll sees the file's SHA-256 change, the file is
//! read and put through exactly the validation start-up uses
//! ([`UpstreamRegistry::from_toml_str`], the federation-issuer requirement,
//! [`CallerBindings::succeeding`]), plus one rule only a reload needs (below).
//! A file that passes replaces the registry and bindings as one value, so an
//! admission or exchange sees the old pair or the new pair, never half of each.
//! A file that fails changes nothing: the bindings in force stay in force, the
//! reason is logged, and `/v1/health` reports the refused file's digest (never
//! the reason, ADR 0004). A reload never stops the node.
//!
//! What a swap does NOT touch:
//!
//! * a pod already admitted keeps the certificate and upstreams it was issued;
//! * a delegation already exchanged stays valid until its own `not_after`,
//!   which is at most the binding's `svid_ttl_secs` and never past the window
//!   the binding had when it was minted. Narrowing a binding's capabilities
//!   takes effect at the next exchange; narrowing its BUDGET takes effect at
//!   the next admission, because the ledger is per binding (below);
//! * a spent token stays spent: a reloaded binding shares its predecessor's
//!   replay cache (`ExternalIssuerValidator::succeeding`).
//!
//! # The reload-only rule: the set of tenants is fixed for the process
//!
//! A binding's trust domain is wired into more than this registry: the node's
//! `AuthorizationPolicy` scopes federated tenants by it, built once at start.
//! A reload that added a tenant would admit a caller the policy does not scope;
//! one that removed a tenant would leave that tenant's still-valid delegations
//! falling through to the non-federated path, with a per-chain ledger instead of
//! the binding's. So a reload whose set of `trust_domain`s differs from the
//! running one is refused, and adding or removing a tenant remains a restart.
//!
//! # The ceiling and the persisted ledger
//!
//! The registry is authoritative for a binding's budget ceiling. A binding's
//! ledger used to be created with the ceiling of the moment and persisted with
//! it, and the persisted `max_micro` then won forever, so raising
//! `max_cost_usd` did nothing. Now each admission under a binding first sets
//! its ledger's ceiling to `max(registry ceiling, consumed + allocated)`
//! (`receil` in `pod_authority.rs`). Consumption and the retired list are
//! carried over exactly: a ceiling raised admits more, a ceiling lowered below
//! what is already used admits nothing more, and neither refunds nor rewrites
//! what was spent.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::federation_ingress::CallerBindings;
use crate::upstreams::UpstreamRegistry;

/// One validated reading of the file: what admission and the exchange use.
pub(crate) struct Loaded {
    pub(crate) upstreams: Option<Arc<UpstreamRegistry>>,
    pub(crate) bindings: Arc<CallerBindings>,
}

/// What a reload attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReloadOutcome {
    /// No `--upstreams` file is configured: there is nothing to reload, and
    /// configuring one is a restart.
    NotConfigured,
    /// The file's digest is the one in force, or the one already refused.
    Unchanged,
    /// The file passed and is now in force.
    Applied,
    /// The file did not pass; the registry in force is unchanged. The reason
    /// is for the log and for tests, never for a caller.
    Refused(String),
}

#[derive(Default)]
struct Status {
    /// Digest of the file in force.
    active: Option<[u8; 32]>,
    /// The latest attempt that failed, if the latest attempt failed: the
    /// digest of what was refused, `None` when the file could not be read.
    refused: Option<Option<[u8; 32]>>,
}

/// The reloadable registry. See the module docs.
pub(crate) struct Registry {
    path: Option<PathBuf>,
    node_trust_domain: String,
    current: RwLock<Arc<Loaded>>,
    status: Mutex<Status>,
    /// One reload at a time: read, validate and swap are one step.
    reloading: Mutex<()>,
}

/// Read and parse the file at `path`, returning the registry and the digest of
/// the bytes it was parsed from. Start-up and reload both read through here.
///
/// # Errors
/// An unreadable file, one that is not UTF-8, malformed TOML, or an entry
/// [`UpstreamRegistry::from_toml_str`] refuses. At START the node refuses to
/// run on any of these: a registry that half-loaded would be a smaller ceiling
/// than the operator wrote, which is safe, but silently so, and "my upstream is
/// refused" is a worse way to learn about a typo than "the node will not
/// start". On a RELOAD the registry in force stays in force instead.
pub(crate) fn load(path: &Path) -> Result<(UpstreamRegistry, [u8; 32]), String> {
    use sha2::Digest as _;
    let at = |e: &dyn std::fmt::Display| format!("upstream registry {}: {e}", path.display());
    let bytes = std::fs::read(path).map_err(|e| at(&e))?;
    let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    let text = std::str::from_utf8(&bytes).map_err(|e| at(&e))?;
    let registry = UpstreamRegistry::from_toml_str(text).map_err(|e| at(&e))?;
    Ok((registry, digest))
}

/// The start-up refusal for a federated upstream on a node with no issuer,
/// shared with the reload so the two cannot drift.
pub(crate) fn issuer_required() -> String {
    "the --upstreams registry has a `federated` credential, but --federation-issuer is not \
     set: the node cannot mint assertions for it. Set --federation-issuer \
     (NUCLEUS_FEDERATION_ISSUER) to the https URL upstreams register as this node's issuer."
        .into()
}

fn tenants(bindings: &CallerBindings) -> std::collections::BTreeSet<String> {
    bindings.trust_domains().map(str::to_string).collect()
}

impl Registry {
    pub(crate) fn new(
        path: Option<PathBuf>,
        node_trust_domain: &str,
        loaded: Loaded,
        digest: Option<[u8; 32]>,
    ) -> Self {
        Self {
            path,
            node_trust_domain: node_trust_domain.to_string(),
            current: RwLock::new(Arc::new(loaded)),
            status: Mutex::new(Status {
                active: digest,
                refused: None,
            }),
            reloading: Mutex::new(()),
        }
    }

    /// The registry and bindings in force. Held for the length of one decision,
    /// so a decision never mixes two readings of the file.
    pub(crate) fn current(&self) -> Arc<Loaded> {
        // A poisoned lock still holds a whole `Arc`: the swap is one store.
        Arc::clone(&self.current.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// Re-read the file and swap it in if it passes. `force` re-reads even a
    /// file whose digest is unchanged (SIGHUP); otherwise an unchanged file,
    /// or the file already refused, is left alone so a poll does not re-log it.
    pub(crate) fn reload(&self, force: bool, has_issuer: bool) -> ReloadOutcome {
        let Some(path) = self.path.as_deref() else {
            return ReloadOutcome::NotConfigured;
        };
        let _one = self.reloading.lock().unwrap_or_else(|p| p.into_inner());
        let digest = file_digest(path).ok();
        if !force {
            let mut status = self.status.lock().unwrap_or_else(|p| p.into_inner());
            if digest.is_some() && status.active == digest {
                // The file is the one in force (perhaps put back after a bad
                // edit): nothing on disk is refused any more.
                status.refused = None;
                return ReloadOutcome::Unchanged;
            }
            if status.refused == Some(digest) {
                return ReloadOutcome::Unchanged;
            }
        }
        match self.validate(path, has_issuer) {
            Ok((loaded, digest)) => {
                *self.current.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(loaded);
                let mut status = self.status.lock().unwrap_or_else(|p| p.into_inner());
                status.active = Some(digest);
                status.refused = None;
                tracing::info!(
                    path = %path.display(),
                    sha256 = %hex::encode(digest),
                    "reloaded the operator upstream registry"
                );
                ReloadOutcome::Applied
            }
            Err(why) => {
                self.status
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .refused = Some(digest);
                tracing::error!(
                    path = %path.display(),
                    error = %why,
                    "upstream registry reload refused: the registry in force is unchanged"
                );
                ReloadOutcome::Refused(why)
            }
        }
    }

    fn validate(&self, path: &Path, has_issuer: bool) -> Result<(Loaded, [u8; 32]), String> {
        let (registry, digest) = load(path)?;
        if registry.has_federated() && !has_issuer {
            return Err(issuer_required());
        }
        let previous = self.current();
        let bindings = CallerBindings::succeeding(
            registry.callers(),
            &registry,
            &self.node_trust_domain,
            Some(&previous.bindings),
        )?;
        if tenants(&bindings) != tenants(&previous.bindings) {
            return Err(
                "the set of [[caller]] trust domains differs from the running one; adding or \
                 removing a tenant needs a restart"
                    .into(),
            );
        }
        Ok((
            Loaded {
                upstreams: Some(Arc::new(registry)),
                bindings: Arc::new(bindings),
            },
            digest,
        ))
    }

    /// What `/v1/health` says about the registry: the digest in force and,
    /// when the latest reload failed, the digest it refused. No reason: that
    /// is in the node's log.
    pub(crate) fn health(&self) -> serde_json::Value {
        if self.path.is_none() {
            return serde_json::json!({ "configured": false });
        }
        let status = self.status.lock().unwrap_or_else(|p| p.into_inner());
        let mut v = serde_json::json!({
            "configured": true,
            "active_sha256": status.active.map(hex::encode),
            "reload": if status.refused.is_some() { "refused" } else { "ok" },
        });
        if let Some(refused) = status.refused {
            v["refused_sha256"] = serde_json::json!(refused.map(hex::encode));
        }
        v
    }
}

fn file_digest(path: &Path) -> std::io::Result<[u8; 32]> {
    use sha2::Digest as _;
    Ok(sha2::Sha256::digest(std::fs::read(path)?).into())
}

/// Reload on SIGHUP, and on a digest change seen every `poll` (none when
/// zero). Runs for the life of the process.
pub(crate) fn spawn(authority: Arc<super::PodAuthority>, poll: Duration) {
    #[cfg(unix)]
    {
        let on_signal = Arc::clone(&authority);
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(mut hup) => {
                tokio::spawn(async move {
                    while hup.recv().await.is_some() {
                        on_signal.reload_registry(true);
                    }
                });
            }
            Err(e) => {
                tracing::error!(error = %e, "no SIGHUP handler: registry reload is poll-only")
            }
        }
    }
    if !poll.is_zero() {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(poll);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                authority.reload_registry(false);
            }
        });
    }
}
