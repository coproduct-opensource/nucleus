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

use std::sync::Arc;

/// This pod's broker capability, from the environment `guest-init` prepared.
///
/// # There is no `credential_for` any more, and that is the change
///
/// This module used to read the credential itself, with
/// `std::env::var(&spec.credential_env)` — in the GUEST. That function and its
/// header-building sibling are deleted rather than kept as a fallback: a broker
/// that applies only when a credential happens to be absent is advisory, and an
/// attacker who can arrange for one to be present restores the exposure the
/// broker exists to remove. It was also dead weight on Firecracker, where the
/// value never reached the guest at all.
///
/// Both halves or neither: a secret with no port can sign and not connect. They
/// arrive together in one reply for exactly that reason, and are read together
/// here.
fn broker_capability() -> Option<crate::broker_client::Capability> {
    let secret = std::env::var("NUCLEUS_TOOL_PROXY_BROKER_SECRET").ok()?;
    let port: u32 = std::env::var("NUCLEUS_TOOL_PROXY_BROKER_PORT")
        .ok()?
        .parse()
        .ok()?;
    (!secret.is_empty() && port != 0).then_some(crate::broker_client::Capability { secret, port })
}

/// The idempotency key for one logical upstream call.
///
/// Derived from what the request IS — upstream name, path, body — rather than
/// randomly, so a retry of the same call carries the same key and the host's
/// ledger recognises it as one operation. A fresh random key per attempt would
/// leave the host unable to tell a retry from a new request, which is the exact
/// thing the key exists to prevent; the machinery would still run and still be
/// decorative.
///
/// Hashed rather than concatenated: the body can be large and the key is bounded
/// by `MAX_FIELD_BYTES` on the host, and a delimiter-joined key would let a
/// crafted path collide with a different (name, path) pair.
fn idempotency_key(name: &str, path: &str, body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    // Length-prefixed, so ("ab", "c") and ("a", "bc") cannot produce one digest.
    for part in [name.as_bytes(), path.as_bytes(), body] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    hex::encode(h.finalize())
}

/// Build the upstream URL for a request path.
///
/// # This used to be the implementation and is now a call
///
/// The same property — a caller-supplied path may not choose where the
/// credential is sent — is now needed by the HOST too, which performs the call
/// for a pod whose guest never receives the credential. One property should be
/// one function: `CredentialedEgressSpec::url_for` is it, and it carries the
/// traversal tests.
///
/// A second copy here would mean a traversal fix could land on one side and not
/// the other, with both test suites green. This delegates so that cannot happen.
pub(crate) fn upstream_url(spec: &CredentialedEgressSpec, path: &str) -> Option<String> {
    spec.url_for(path)
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

/// Refuse to start a pod that configures credentialed egress it cannot perform.
///
/// # Why at startup and not per request
///
/// Since the in-guest credential path was deleted, a credentialed upstream is
/// callable ONLY through the host broker. A pod configured with upstreams but no
/// broker capability will refuse every request at the moment the workload makes
/// one — which surfaces as an application error, minutes into a run, four layers
/// from the pod spec that caused it.
///
/// Refusing at startup names the cause once, before anything has been attempted.
/// It is the same reasoning `reject_bypassable_upstreams` gives, and it sits
/// beside it for that reason.
///
/// # The driver this affects
///
/// The container driver has no broker: `broker_identity` refuses a pod with no
/// host-established identity, and that driver registers none. Giving it one is a
/// design question rather than wiring — a Firecracker identity comes with an
/// attested SVID and a default-deny netns, and a container has neither, so the
/// identity would assert what the driver cannot back. So this refusal is what a
/// container pod with `credentialed_egress` now gets, and saying so loudly beats
/// a silent per-request failure.
///
/// # Errors
/// Names the upstreams, so an operator sees what to remove or which driver to use.
pub(crate) fn reject_egress_without_a_broker(
    specs: &[CredentialedEgressSpec],
    has_broker: bool,
) -> Result<(), String> {
    if specs.is_empty() || has_broker {
        return Ok(());
    }
    Err(format!(
        "this pod configures credentialed egress ({}) but has no credential-broker \
         capability, so the upstream cannot be called on its behalf. The in-guest \
         credential path was removed deliberately — a broker that applies only when a \
         credential happens to be absent is advisory. Either run this pod on a driver \
         that provides a broker, or remove the credentialed_egress entries.",
        specs
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
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
/// 4. Mint the discharge, then ask the HOST to perform the call. The credential
///    is never read here — see `broker_capability`.
/// 5. Observe the response as untrusted, AI-derived content, so anything the
///    workload does with it carries the taint.
///
/// The credential is in the NODE's environment and never enters this process.
/// What crosses is a request to act; what comes back is the upstream's answer.
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

    // ── The credential is NOT read here, and cannot be ─────────────────────
    //
    // This used to be `credential_for(&spec)` — a `std::env::var` in the GUEST.
    // That path is gone, not kept as a fallback, and the deletion is the point:
    // a broker that applies only when a credential happens to be absent is
    // advisory, and an attacker who can arrange for it to be present restores
    // the exposure. On Firecracker the value never reached the guest anyway, so
    // the in-guest path could only ever fail closed there.
    //
    // What crosses to the host is a request to ACT. What comes back is the
    // upstream's response. The credential stays in the node's environment.

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

    // The discharge is minted HERE and spent by `perform_line`. That is the
    // whole reason the guest half exists: the host applies a coarse capability
    // check and structurally cannot see `FlowTracker`, the session taint ceiling
    // or the lethal-trifecta guard. Those live in this process, and a
    // `PerformRequest` that was not composed past them would be egress the
    // kernel never saw.
    let authority = portcullis_effects::authority::Authority::new(discharge_bundle)
        .witnessed_by(Arc::clone(&state.receipts));

    let Some(capability) = broker_capability() else {
        // No capability means no broker. Refused, never forwarded another way —
        // see `broker_client`'s header: a broker that can be bypassed by
        // breaking it is not a boundary.
        return Err(ApiError::Spec(
            "this pod has no credential-broker capability, so the upstream cannot be \
             called on its behalf"
                .to_string(),
        ));
    };

    let request = nucleus_cred_protocol::PerformRequest {
        operation: "WebFetch".to_string(),
        target: name.clone(),
        justification: "credentialed egress".to_string(),
        // Derived from what the request IS, so a retry of the same call carries
        // the same key and the host's ledger sees one logical operation. A
        // random key per attempt would make the idempotency machinery decorative.
        idempotency_key: idempotency_key(&name, &path, &body),
        path: path.clone(),
        body: body.to_vec(),
    };

    let line =
        crate::broker_client::perform_line(authority, capability.secret.as_bytes(), &request)
            .map_err(|e| ApiError::IfcDenied(format!("authority not spendable: {e}")))?;

    let reply_line = crate::broker_client::ask(capability.port, &line)
        .await
        .map_err(|e| ApiError::Spec(format!("the credential broker did not answer: {e}")))?;

    let reply: nucleus_cred_protocol::PerformReply = serde_json::from_str(reply_line.trim_end())
        .map_err(|_| {
            ApiError::Spec("the credential broker sent an unreadable reply".to_string())
        })?;

    if !reply.granted {
        // The host's reason is deliberately coarse — it must not let a guest
        // enumerate which credentials exist — so it is passed through unchanged
        // rather than elaborated here.
        return Err(ApiError::IfcDenied(format!(
            "the credential broker refused: {}",
            reply.reason
        )));
    }

    let status = axum::http::StatusCode::from_u16(reply.status)
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let bytes = axum::body::Bytes::from(reply.body);

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

    /// **A pod that cannot perform credentialed egress refuses to start.**
    #[test]
    fn credentialed_egress_without_a_broker_refuses_to_start() {
        let err = reject_egress_without_a_broker(&[spec()], false)
            .expect_err("no capability means the upstream can never be called");
        assert!(err.contains("model-api"), "name the offender: {err}");
        assert!(
            err.contains("advisory"),
            "and say why there is no fallback: {err}"
        );
    }

    /// **The two controls, each doing its own job.** With a broker it starts; with
    /// no upstreams configured it starts regardless. Without both of these the
    /// refusal above is satisfied by a function that refuses everything.
    #[test]
    fn a_pod_that_can_perform_egress_is_not_refused() {
        assert!(reject_egress_without_a_broker(&[spec()], true).is_ok());
        assert!(
            reject_egress_without_a_broker(&[], false).is_ok(),
            "a pod configuring no credentialed egress needs no broker"
        );
    }

    /// **The in-guest credential path is GONE, not merely unused.**
    ///
    /// Scans the source, because the property is about what this module CAN do.
    /// A dead-but-present `credential_for` is one call site away from being a
    /// fallback again, and a fallback is what makes a broker advisory: an
    /// attacker who can arrange for the environment variable to be set restores
    /// exactly the exposure the broker removes.
    #[test]
    fn this_module_cannot_read_a_credential_from_the_guest_environment() {
        let src = include_str!("egress.rs");
        // PRODUCTION half only. The test module below names `credential_env` in
        // its fixtures and in this very assertion, and a scanner that counted
        // those would fire on the explanation of the property it checks — the
        // same scoping `nucleus_cred_protocol`'s `declarations()` helper needs.
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("source before tests");
        let code: String = production
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("///") && !t.starts_with("//!") && !t.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("credential_env"),
            "egress.rs reads `credential_env` again. That field names a variable in the \
             NODE's environment now; a read of it HERE is a read inside the guest, which \
             is the exposure this module was rewritten to remove."
        );
        assert!(
            !code.contains("fn credential_for") && !code.contains("fn header_value"),
            "the in-guest credential path is back"
        );
    }

    /// The idempotency key is a function of the REQUEST, so a retry repeats it.
    /// A random key per attempt would leave the host unable to recognise a retry
    /// and the whole ledger would be decoration.
    #[test]
    fn the_same_call_produces_the_same_idempotency_key() {
        let a = idempotency_key("model-api", "/messages", b"{}");
        let b = idempotency_key("model-api", "/messages", b"{}");
        assert_eq!(a, b);
    }

    /// Different calls must not collide, including under the delimiter attack a
    /// concatenated key would admit.
    #[test]
    fn different_calls_produce_different_keys() {
        let base = idempotency_key("model-api", "/messages", b"{}");
        assert_ne!(base, idempotency_key("other-api", "/messages", b"{}"));
        assert_ne!(base, idempotency_key("model-api", "/other", b"{}"));
        assert_ne!(base, idempotency_key("model-api", "/messages", b"{ }"));
        // Length-prefixing is what stops this pair colliding.
        assert_ne!(
            idempotency_key("ab", "c", b""),
            idempotency_key("a", "bc", b"")
        );
    }
}
