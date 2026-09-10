//! Per-effect enforcement at the egress boundary (ADR 0004, milestone 6).
//!
//! A sealed task grant seals its effects into the pod certificate as
//! `effect/<plugin>/<id>` keys. Until now that dimension narrowed correctly
//! across delegation hops but bounded a request only by host: a grant of
//! `github/read-ci-logs` let the pod `POST` to open a pull request on
//! `api.github.com`, because the host was on the list. This gate closes that:
//! when the pod's verified certificate carries an effect dimension, every
//! `web_fetch` and credentialed-egress request must be vouched for by a
//! granted effect's vocabulary (method + host + path, from the catalog), and
//! a request nothing vouches for is refused before any discharge is minted.
//!
//! A certificate without the dimension (a pod that did not run under a
//! grant) is unconstrained here and bounded by everything else exactly as
//! before. The gate adds a refusal, never an allowance.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use portcullis::verdict_sink::{ActorIdentity, VerdictContext, VerdictOutcome, VerdictSink};
use portcullis::{EffectAdmission, EffectCatalog, Operation, effect_surface};
use tracing::{info, warn};

use crate::ApiError;

/// The refusal code for a request no granted effect vouches for.
pub const EFFECT_NOT_GRANTED: &str = "EFFECT_NOT_GRANTED";

/// What the pod's certificate grants, and the vocabulary to read it with.
pub(crate) struct EffectGate {
    /// `effect/` keys of the verified certificate; `None` when the dimension
    /// is unset.
    granted: Option<BTreeSet<String>>,
    catalog: EffectCatalog,
}

impl EffectGate {
    /// From the verified pod certificate (if any) and the workspace's own
    /// `.nucleus/effects`. A repository catalog that fails to load is
    /// reported and the built-in catalog is used: a broken file must not
    /// silently widen (an unknown effect vouches for nothing).
    pub(crate) fn new(
        cert: Option<&crate::pod_cert::PodCertificate>,
        work_dir: &Path,
    ) -> Arc<Self> {
        let granted = cert.and_then(|c| effect_surface::granted_effects(&c.effective.capabilities));
        let mut catalog = EffectCatalog::builtin().unwrap_or_else(|e| {
            warn!(error = %e, "built-in effect catalog failed to load; effects vouch for nothing");
            EffectCatalog::empty()
        });
        if let Err(e) = catalog.load_from_dir(&work_dir.join(".nucleus/effects")) {
            warn!(error = %e, "repository effect catalog ignored");
        }
        match &granted {
            Some(g) => info!(
                effects = g.len(),
                "pod certificate carries an effect dimension: egress is enforced per effect"
            ),
            None => {
                info!("pod certificate carries no effect dimension: egress bounded by host only")
            }
        }
        Arc::new(Self { granted, catalog })
    }

    /// For tests and in-process callers: an explicit grant.
    #[cfg(test)]
    pub(crate) fn with(granted: Option<BTreeSet<String>>) -> Self {
        Self {
            granted,
            catalog: EffectCatalog::builtin().expect("built-in catalog"),
        }
    }

    /// Whether the dimension is in use.
    #[cfg(test)]
    pub(crate) fn is_enforcing(&self) -> bool {
        self.granted.is_some()
    }

    /// Refuse an HTTP request no granted effect vouches for. `Ok` names the
    /// effect that admitted it (or `None` when unconstrained).
    pub(crate) fn admit_http(
        &self,
        method: &str,
        url: &url::Url,
    ) -> Result<Option<String>, ApiError> {
        let host = url.host_str().unwrap_or_default();
        let path = url.path();
        match self
            .catalog
            .admits_http(self.granted.as_ref(), method, host, path)
        {
            EffectAdmission::Unconstrained => Ok(None),
            EffectAdmission::Admitted(id) => Ok(Some(id.to_string())),
            EffectAdmission::NotAdmitted { would_admit } => {
                let granted = self.granted.as_ref().map_or(0, BTreeSet::len);
                let remedy = if would_admit.is_empty() {
                    "no effect in the catalog covers it; declare one under .nucleus/effects/"
                        .to_string()
                } else {
                    let ids: Vec<String> = would_admit.iter().map(|e| e.to_string()).collect();
                    format!("would be admitted by {}", ids.join(", "))
                };
                Err(ApiError::KernelDenied(format!(
                    "{EFFECT_NOT_GRANTED}: {method} {host}{path} is vouched for by none of the {granted} \
                     effect(s) sealed into this pod's certificate ({remedy})"
                )))
            }
        }
    }

    /// `admit_http`, recording a refusal on the verdict sink first so the
    /// audit trail shows the request the gate stopped.
    pub(crate) fn admit_http_recorded(
        &self,
        method: &str,
        url: &url::Url,
        sink: &dyn VerdictSink,
        actor: ActorIdentity,
    ) -> Result<Option<String>, ApiError> {
        match self.admit_http(method, url) {
            Ok(v) => Ok(v),
            Err(e) => {
                if let Err(rec) = sink.record(VerdictContext {
                    operation: Operation::WebFetch,
                    subject: url.as_str().to_string(),
                    outcome: VerdictOutcome::Deny {
                        reason: e.to_string(),
                    },
                    actor,
                    policy_rule: Some(EFFECT_NOT_GRANTED.to_string()),
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %rec, "verdict recording failed -- audit gap");
                }
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn granted(ids: &[&str]) -> Option<BTreeSet<String>> {
        Some(ids.iter().map(|s| s.to_string()).collect())
    }

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn a_grant_of_read_ci_logs_cannot_open_a_pull_request() {
        let gate = EffectGate::with(granted(&["github/read-ci-logs"]));
        assert!(gate.is_enforcing());
        let ok = gate
            .admit_http("GET", &url("https://api.github.com/repos/o/r/actions/runs"))
            .unwrap();
        assert_eq!(ok.as_deref(), Some("github/read-ci-logs"));
        let err = gate
            .admit_http("POST", &url("https://api.github.com/repos/o/r/pulls"))
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(EFFECT_NOT_GRANTED), "{msg}");
        assert!(msg.contains("github/open-pr"), "{msg}");
    }

    #[test]
    fn a_host_no_effect_names_is_refused_with_the_remedy() {
        let gate = EffectGate::with(granted(&["fs/read-workspace"]));
        let err = gate
            .admit_http("GET", &url("https://evil.example/x"))
            .unwrap_err();
        assert!(err.to_string().contains(".nucleus/effects"), "{err}");
    }

    #[test]
    fn a_pod_without_the_dimension_is_unconstrained_here() {
        let gate = EffectGate::with(None);
        assert!(!gate.is_enforcing());
        assert_eq!(
            gate.admit_http("POST", &url("https://anywhere.example/"))
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_marked_but_empty_dimension_admits_nothing() {
        let gate = EffectGate::with(Some(BTreeSet::new()));
        assert!(
            gate.admit_http("GET", &url("https://api.github.com/repos/o/r/actions/runs"))
                .is_err()
        );
    }
}
