//! Calling an upstream on the workload's behalf, without giving it the credential.
//!
//! # What this closes
//!
//! A workload handed an API token in its environment can exfiltrate it, and its
//! calls to that API bypass every gate the runtime applies to tool calls: the
//! data it has read leaves in a request body that nothing inspected. Both are
//! consequences of the same choice — putting the credential in the guest.
//!
//! Here the runtime holds it. The workload is told a local address; the upstream
//! and the header come from the pod spec, so a request can neither redirect the
//! call nor read what authenticates it. And because the forward goes through the
//! kernel like any other outbound action, a tainted session's upstream call gets
//! the same treatment as its `web_fetch`.
//!
//! # Per-pod, and it must stay that way
//!
//! This concentrates a credential in the proxy. Credential-concentrating AI
//! gateways are a demonstrated supply-chain target — the LiteLLM compromise of
//! March 2026 shipped malicious releases that harvested exactly the keys such
//! services hold. The mitigation here is structural rather than vigilant: this
//! proxy is per-pod and holds one pod's credentials, not a fleet's, so a
//! compromise of it is a compromise of one sandbox. Turning it into a shared
//! gateway would trade that away.
//!
//! # The response is untrusted
//!
//! What comes back is external content, and on a model API it is also
//! AI-derived. It is observed as such, so anything the workload does with it
//! carries the taint — which is the whole point of routing the call through the
//! runtime rather than around it.

use nucleus_spec::CredentialedEgressSpec;

/// Resolve the credential for an upstream from the RUNTIME's environment.
///
/// `None` when unset. The caller must then refuse rather than forward
/// unauthenticated: an upstream that rejects the call would be the lucky case,
/// and one that accepts it anonymously is worse.
#[must_use]
pub(crate) fn credential_for(spec: &CredentialedEgressSpec) -> Option<String> {
    std::env::var(&spec.credential_env)
        .ok()
        .filter(|v| !v.is_empty())
}

/// The header value sent upstream.
#[must_use]
pub(crate) fn header_value(spec: &CredentialedEgressSpec, credential: &str) -> String {
    format!("{}{}", spec.value_prefix, credential)
}

/// Build the upstream URL for a request path.
///
/// The base comes from the spec and the path is appended. A path that tries to
/// leave the upstream — by being absolute, or by containing `..` — is refused
/// rather than normalised: the workload does not get to choose where the
/// credential is sent, and "normalise it and hope" is how that becomes possible.
pub(crate) fn upstream_url(spec: &CredentialedEgressSpec, path: &str) -> Option<String> {
    if path.contains("..") || path.starts_with("http://") || path.starts_with("https://") {
        return None;
    }
    let base = spec.upstream.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    Some(format!("{base}/{path}"))
}

/// The environment a workload is told about its upstreams.
///
/// Names and local addresses ONLY. The credential is deliberately absent — that
/// absence is the feature, and a test asserts it rather than trusting the
/// reading of this function.
#[must_use]
pub(crate) fn workload_egress_env(
    specs: &[CredentialedEgressSpec],
    proxy_url: &str,
) -> std::collections::BTreeMap<String, String> {
    specs
        .iter()
        .map(|s| {
            (
                format!(
                    "NUCLEUS_EGRESS_{}_URL",
                    s.name.to_uppercase().replace('-', "_")
                ),
                format!("{proxy_url}/v1/egress/{}", s.name),
            )
        })
        .collect()
}

/// The host of a credentialed upstream, for allowlist checking.
fn upstream_host(spec: &CredentialedEgressSpec) -> Option<String> {
    let rest = spec
        .upstream
        .strip_prefix("https://")
        .or_else(|| spec.upstream.strip_prefix("http://"))?;
    let host = rest.split('/').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Refuse a configuration where the workload can bypass the credentialed path.
///
/// # Why this is fail-closed and not a warning
///
/// The proxy only closes the inference-channel gap for calls that GO THROUGH it.
/// If the upstream host is also on the network allowlist, a workload can simply
/// call the API directly — same data leaving, no kernel decision, no IFC gate,
/// no Article 12 record — while the deployment looks like it has a credentialed
/// egress proxy. That is a control that appears to be working and is not, which
/// is the worst state to ship.
///
/// So a credentialed upstream whose host is directly reachable is a
/// misconfiguration and the pod refuses to start. Removing the host from the
/// allowlist is the fix; the proxy is what the workload should reach.
///
/// # Errors
/// Names every offending upstream, so an operator fixes them in one pass rather
/// than one boot at a time.
pub(crate) fn reject_bypassable_upstreams(
    specs: &[CredentialedEgressSpec],
    net_allow: &[String],
) -> Result<(), String> {
    let allowed: Vec<String> = net_allow.iter().map(|h| h.to_ascii_lowercase()).collect();
    let bypassable: Vec<String> = specs
        .iter()
        .filter_map(|s| {
            let host = upstream_host(s)?;
            allowed
                .iter()
                .any(|a| a == &host || a == "*" || host.ends_with(a.trim_start_matches('*')))
                .then(|| format!("{} ({host})", s.name))
        })
        .collect();
    if bypassable.is_empty() {
        return Ok(());
    }
    Err(format!(
        "these credentialed upstreams are ALSO on the network allowlist, so the workload can \
         bypass the credentialed path entirely and no gate would see it: {}. Remove the hosts \
         from the allowlist — the workload should reach the local forwarder, not the upstream.",
        bypassable.join(", ")
    ))
}

/// `POST /v1/egress/{name}/{*path}` — call an upstream on the workload's behalf.
///
/// # Order of operations, and why it is this order
///
/// 1. Resolve the named upstream. An unknown name is a refusal, not a passthrough.
/// 2. Resolve the path against the FIXED base. Absolute or traversing paths are
///    refused — the workload does not choose where the credential goes.
/// 3. Kernel decision, exactly as `web_fetch` does. This is what makes a tainted
///    session's upstream call subject to the same egress gate as its tool calls,
///    and it is the half that a plain credential-injecting proxy does not have.
/// 4. Inject the credential and forward.
/// 5. Observe the response as untrusted, AI-derived content, so anything the
///    workload does with it carries the taint.
///
/// The credential is read here, in the runtime, and never appears in the
/// workload's environment or in any response.
pub(crate) async fn credentialed_egress(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    axum::extract::Path((name, path)): axum::extract::Path<(String, String)>,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, crate::ApiError> {
    use crate::ApiError;
    use portcullis::Operation;

    let Some(spec) = state
        .credentialed_egress
        .iter()
        .find(|s| s.name == name)
        .cloned()
    else {
        return Err(ApiError::Spec(format!(
            "no credentialed upstream named {name:?} is configured for this pod"
        )));
    };

    let Some(url) = upstream_url(&spec, &path) else {
        return Err(ApiError::Spec(
            "the request path may not be absolute or contain `..`; the upstream is fixed by the \
             pod spec"
                .to_string(),
        ));
    };

    // The same gate a tool call gets. A tainted session calling its model API is
    // exfiltration by the same definition that governs `web_fetch`, and treating
    // it differently would be the hole this whole module exists to close.
    let _decision = crate::http_kernel_decide(&state, Operation::WebFetch, &url).await?;

    let Some(credential) = credential_for(&spec) else {
        // Refused rather than forwarded unauthenticated: at best the upstream
        // rejects it, at worst it accepts anonymously.
        return Err(ApiError::Spec(format!(
            "no credential in {} for upstream {name:?}",
            spec.credential_env
        )));
    };

    // Through the SEALED effect, exactly as `web_fetch` does — not a raw client.
    //
    // The mediation gate caught the first version of this doing its own
    // `.send()`. It was right to: the sealed `NetEffect::fetch` is reachable
    // only past a minted `DischargedBundle`, so "no un-preflighted agent egress
    // reaches the wire" is a property of what can be TYPED rather than of what
    // was remembered. Credentialed egress is still agent egress; allowlisting it
    // would have carved the one hole the gate exists to prevent.
    use portcullis_effects::{NetCapability, NetEffect};

    let discharge_bundle = {
        use nucleus_ifc_kernel::discharge::PreflightResult;
        let verified_scope = state.session_task_token.verified_scope();
        let level = state.runtime.policy().capabilities.web_fetch;
        let flow = state.flow_tracker.lock().await;
        let result =
            crate::run_gate::preflight_web(Operation::WebFetch, verified_scope, level, &url, &flow);
        drop(flow);
        match result {
            PreflightResult::Allowed(bundle) => bundle,
            PreflightResult::Denied { reason, .. }
            | PreflightResult::RequiresApproval { reason } => {
                return Err(ApiError::IfcDenied(format!("discharge denied: {reason}")));
            }
        }
    };

    let headers = vec![
        (spec.header.clone(), header_value(&spec, &credential)),
        ("content-type".to_string(), "application/json".to_string()),
    ];
    let effects = portcullis_effects::production_effects_concrete(crate::core_capabilities(
        &state.runtime.policy().capabilities,
    ));
    let resp = effects
        .fetch(
            &state.web_client,
            NetCapability::WebFetch,
            reqwest::Method::POST,
            reqwest::Url::parse(&url)
                .map_err(|e| ApiError::Spec(format!("upstream url is not parseable: {e}")))?,
            &headers,
            Some(body.to_vec()),
            None,
            portcullis_effects::authority::Authority::new(discharge_bundle),
        )
        .await
        .map_err(|e| ApiError::Spec(format!("upstream request failed: {e}")))?;

    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ApiError::Spec(format!("upstream response failed: {e}")))?;

    // External AND model-authored. Observing it is what makes the taint real for
    // everything the workload does next.
    crate::ingest::http_observe_flow(&state, portcullis::NodeKind::ModelPlan, &bytes).await;

    let mut out = axum::response::Response::new(axum::body::Body::from(bytes));
    *out.status_mut() = status;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> CredentialedEgressSpec {
        spec_named("NUCLEUS_TEST_EGRESS_CRED_DEFAULT")
    }

    /// Each env-touching test uses its OWN variable. Tests run in one process
    /// and in parallel, so two of them sharing a name is a race that shows up as
    /// an unrelated flake — which is worse than a slow test, because it teaches
    /// people to re-run rather than to look.
    fn spec_named(credential_env: &str) -> CredentialedEgressSpec {
        CredentialedEgressSpec {
            name: "model-api".into(),
            upstream: "https://upstream.invalid/v1".into(),
            credential_env: credential_env.into(),
            header: "authorization".into(),
            value_prefix: "Bearer ".into(),
        }
    }

    /// **The credential must not reach the workload.** This is the entire point;
    /// if it leaks into the env the rest of the design is decoration.
    #[test]
    fn the_workload_env_never_carries_the_credential() {
        // SAFETY-equivalent note: single-threaded test, restored below.
        let sp = spec_named("NUCLEUS_TEST_EGRESS_CRED_LEAK");
        std::env::set_var(&sp.credential_env, "super-secret-token");
        let env = workload_egress_env(std::slice::from_ref(&sp), "http://127.0.0.1:9");
        for (k, v) in &env {
            assert!(
                !v.contains("super-secret-token"),
                "the credential leaked into {k}"
            );
        }
        assert_eq!(
            env.get("NUCLEUS_EGRESS_MODEL_API_URL").map(String::as_str),
            Some("http://127.0.0.1:9/v1/egress/model-api"),
            "the workload must be pointed at the LOCAL forwarder"
        );
        std::env::remove_var(&sp.credential_env);
    }

    /// **A request cannot redirect where the credential is sent.** Absolute URLs
    /// and traversal are refused rather than normalised: normalising is how
    /// "the workload cannot choose the upstream" quietly stops being true.
    #[test]
    fn a_request_cannot_redirect_the_upstream() {
        for hostile in [
            "https://attacker.invalid/steal",
            "http://attacker.invalid/steal",
            "../../../other",
            "messages/../../escape",
        ] {
            assert!(
                upstream_url(&spec(), hostile).is_none(),
                "{hostile:?} must not resolve to an upstream URL"
            );
        }
    }

    /// The control: ordinary paths still resolve under the configured base, so
    /// the refusals above are not simply refusing everything.
    #[test]
    fn an_ordinary_path_resolves_under_the_configured_upstream() {
        assert_eq!(
            upstream_url(&spec(), "/messages").as_deref(),
            Some("https://upstream.invalid/v1/messages")
        );
        assert_eq!(
            upstream_url(&spec(), "messages").as_deref(),
            Some("https://upstream.invalid/v1/messages")
        );
    }

    /// An unset credential yields `None`, so the caller refuses. Forwarding
    /// unauthenticated would at best fail upstream and at worst succeed
    /// anonymously against something that does not require auth.
    #[test]
    fn an_unset_credential_is_absent_rather_than_empty() {
        let sp = spec_named("NUCLEUS_TEST_EGRESS_CRED_UNSET");
        std::env::remove_var(&sp.credential_env);
        assert!(credential_for(&sp).is_none());
        std::env::set_var(&sp.credential_env, "");
        assert!(
            credential_for(&sp).is_none(),
            "an empty value is not a credential"
        );
        std::env::remove_var(&sp.credential_env);
    }

    /// **A credentialed upstream that is also directly reachable is a control
    /// that appears to work and does not.** The workload would just call the API
    /// itself: same data out, no kernel decision, no IFC gate, no record.
    #[test]
    fn a_directly_reachable_upstream_is_refused() {
        let err = reject_bypassable_upstreams(&[spec()], &["upstream.invalid".to_string()])
            .expect_err("a bypassable upstream must be refused");
        assert!(
            err.contains("model-api"),
            "the offender must be named: {err}"
        );
        assert!(err.contains("bypass"), "and the reason given: {err}");
    }

    /// A wildcard allowlist is the same problem wearing a different hat.
    #[test]
    fn a_wildcard_allowlist_is_also_a_bypass() {
        assert!(reject_bypassable_upstreams(&[spec()], &["*".to_string()]).is_err());
        assert!(
            reject_bypassable_upstreams(&[spec()], &["*.invalid".to_string()]).is_err(),
            "a suffix wildcard covering the upstream host is still a bypass"
        );
    }

    /// The control: an allowlist that does not reach the upstream is fine, so
    /// the check is not simply refusing every configuration.
    #[test]
    fn an_allowlist_that_does_not_reach_the_upstream_is_accepted() {
        assert!(reject_bypassable_upstreams(
            &[spec()],
            &["registry.example".to_string(), "deps.example".to_string()]
        )
        .is_ok());
        assert!(reject_bypassable_upstreams(&[spec()], &[]).is_ok());
    }

    #[test]
    fn the_prefix_is_applied_to_the_header_value() {
        assert_eq!(header_value(&spec(), "tok"), "Bearer tok");
    }
}
