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
///
/// `door_url` is the workload door's `unix://<socket>` URL, so each upstream's
/// URL is `unix://<socket>/v1/egress/<name>`: a client connects to the socket
/// named by `NUCLEUS_TOOL_PROXY_URL`, which is a prefix of this one, and sends
/// the remainder as the HTTP path.
#[must_use]
pub(crate) fn workload_egress_env(
    specs: &[CredentialedEgressSpec],
    door_url: &str,
) -> std::collections::BTreeMap<String, String> {
    specs
        .iter()
        .map(|s| {
            (
                format!(
                    "NUCLEUS_EGRESS_{}_URL",
                    s.name.to_uppercase().replace('-', "_")
                ),
                format!("{door_url}/v1/egress/{}", s.name),
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
    certified: Option<axum::Extension<crate::pod_cert::CertifiedPermissions>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Body,
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

    // Per-effect gate (ADR 0004): the host performs credentialed calls as
    // `POST`, so that is the shape a granted effect must vouch for.
    if let Ok(parsed) = url::Url::parse(&url) {
        state.effect_gate.admit_http_recorded(
            "POST",
            &parsed,
            state.verdict_sink.as_ref(),
            crate::actor_from_auth(None),
        )?;
    }

    // The same gate a tool call gets. A tainted session calling its model API is
    // exfiltration by the same definition that governs `web_fetch`, and treating
    // it differently would be the hole this whole module exists to close.
    let _decision = crate::http_kernel_decide(&state, Operation::WebFetch, &url, None).await?;

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
        let level = crate::run_gate::levels_for(
            &state,
            Operation::WebFetch,
            certified.as_ref().map(|e| &e.0),
        );
        let flow = state.flow_graph.lock().await;
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
    // check and structurally cannot see the `FlowGraph`, the session taint ceiling
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

    // A STREAMED call (#2696 P4): the body goes up as it arrives from the
    // workload and the reply comes back as the upstream sends it, so a model
    // call larger than a perform frame's 256 KiB, and a server-sent-event
    // reply, both fit. Unique per call: a streamed body cannot be replayed, so
    // a workload's retry is a new call, and the host refuses a nonce it has
    // seen, which is what stops a captured open frame being sent twice.
    let request = nucleus_cred_protocol::StreamRequest {
        operation: "WebFetch".to_string(),
        target: name.clone(),
        justification: "credentialed egress".to_string(),
        nonce: uuid::Uuid::new_v4().to_string(),
        path: path.clone(),
        content_type: request_content_type(&headers),
    };

    let line =
        crate::broker_client::stream_open_line(authority, capability.secret.as_bytes(), &request)
            .map_err(|e| ApiError::IfcDenied(format!("authority not spendable: {e}")))?;

    let conn = crate::broker_client::dial(capability.port)
        .await
        .map_err(|e| ApiError::Spec(format!("the credential broker did not answer: {e}")))?;

    let relayed = forward_stream(conn, &line, body).await?;

    // External AND model-authored. Observed BEFORE the first byte reaches the
    // workload, which is what makes the taint real for everything it does
    // next. The reply has not arrived yet, so the content hash is over what is
    // known now (upstream, status, this call's nonce) rather than over the
    // body; see the follow-up in #2696.
    let known = format!("{name} {} {}", relayed.head.status, request.nonce);
    crate::ingest::http_observe_flow(&state, portcullis::NodeKind::ModelPlan, known.as_bytes())
        .await;

    Ok(relayed_response(relayed))
}

/// The media type the workload declared for its request body, if it is one
/// the host will put in a header; otherwise the JSON every model API takes.
fn request_content_type(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 256 && v.bytes().all(|b| (0x20..0x7f).contains(&b)))
        .unwrap_or("application/json")
        .to_string()
}

/// Relay a streamed call to the host over `conn`, mapping the outcome into the
/// proxy's errors.
///
/// A refusal carries the host's reason unchanged: coarse for policy (it must
/// not let a guest enumerate which credentials exist), and named for the pod's
/// own egress balance and per-call bounds, whose remedy the operator applies.
pub(crate) async fn forward_stream<C>(
    conn: C,
    open_line: &str,
    body: axum::body::Body,
) -> Result<crate::broker_client::Relayed, crate::ApiError>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    use crate::broker_client::RelayError;
    crate::broker_client::relay(conn, open_line, body)
        .await
        .map_err(|e| match e {
            RelayError::Refused(reason) => {
                crate::ApiError::IfcDenied(format!("the credential broker refused: {reason}"))
            }
            RelayError::Transport(why) => {
                crate::ApiError::Spec(format!("the credential broker did not answer: {why}"))
            }
        })
}

/// The workload's response: the upstream's status and media type, and its
/// reply streamed as it arrives.
pub(crate) fn relayed_response(relayed: crate::broker_client::Relayed) -> axum::response::Response {
    let status = axum::http::StatusCode::from_u16(relayed.head.status)
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let mut out = axum::response::Response::new(relayed.body);
    *out.status_mut() = status;
    if let Ok(value) = axum::http::HeaderValue::from_str(&relayed.head.content_type)
        && !relayed.head.content_type.is_empty()
    {
        out.headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, value);
    }
    out
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
        // SAFETY: edition 2024 makes env mutation unsafe -- it races any concurrent
        // reader. Sound here because this runs before any thread that reads the
        // environment is spawned.
        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 H-1: test-only process-global mutation"
        )]
        unsafe {
            std::env::set_var(&sp.credential_env, "super-secret-token")
        };
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
        // SAFETY: edition 2024 makes env mutation unsafe -- it races any concurrent
        // reader. Sound here because this runs before any thread that reads the
        // environment is spawned.
        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 H-1: test-only process-global mutation"
        )]
        unsafe {
            std::env::remove_var(&sp.credential_env)
        };
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
        assert!(
            reject_bypassable_upstreams(
                &[spec()],
                &["registry.example".to_string(), "deps.example".to_string()]
            )
            .is_ok()
        );
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

    /// A media type the host would refuse to put in a header falls back to
    /// JSON rather than reaching the host as a malformed request.
    #[test]
    fn the_request_media_type_is_header_safe() {
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(request_content_type(&headers), "application/json");
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        assert_eq!(request_content_type(&headers), "text/plain; charset=utf-8");
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_bytes(b"caf\xc3\xa9").expect("opaque bytes"),
        );
        assert_eq!(request_content_type(&headers), "application/json");
    }

    // ── The streamed call, end to end through the workload door ────────
    //
    // door (real socket, SO_PEERCRED) -> the proxy's relay (`forward_stream`,
    // `relayed_response`: the functions `credentialed_egress` calls) -> a
    // host over a real Unix socket. The host here is a stand-in that speaks
    // the shared codec; the node's REAL host half, against a real upstream, is
    // `nucleus_node::broker_stream::tests`. The two meet at
    // `nucleus_cred_protocol::stream`, which both link.

    use nucleus_cred_protocol::stream::io::{
        Chunk, read_chunk, read_line, write_chunks, write_end, write_line,
    };
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    const KEY: &[u8] = b"test-broker-capability";
    /// What the HOST holds and injects. The stand-in host never sends it to
    /// the guest; the tests assert it appears nowhere the guest can see.
    const TOKEN: &str = "test-token-123";
    const SSE: [&str; 3] = [
        "event: delta\ndata: {\"text\":\"hel\"}\n\n",
        "event: delta\ndata: {\"text\":\"lo\"}\n\n",
        "event: done\ndata: {}\n\n",
    ];

    /// How the stand-in host answers.
    #[derive(Clone, Copy)]
    enum HostBehaviour {
        /// Read the whole body, answer 200 with SSE events.
        Serve,
        /// Refuse once this many body bytes have arrived, by name.
        ExhaustAfter(usize),
    }

    /// What the stand-in host saw of the proxy's request.
    #[derive(Debug, Default, Clone)]
    struct HostSaw {
        open_frame: String,
        body_len: usize,
        authentic: bool,
    }

    /// A host broker stand-in on a Unix socket: one connection, the shared
    /// codec, and a record of what the proxy sent it.
    async fn stand_in_host(
        dir: &Path,
        behaviour: HostBehaviour,
    ) -> (PathBuf, std::sync::Arc<std::sync::Mutex<HostSaw>>) {
        let path = dir.join("host.sock");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind host");
        let saw = std::sync::Arc::new(std::sync::Mutex::new(HostSaw::default()));
        let record = std::sync::Arc::clone(&saw);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (r, mut w) = tokio::io::split(stream);
            let mut r = BufReader::new(r);
            let open = read_line(&mut r, 64 * 1024).await.expect("open frame");
            let authentic = nucleus_cred_protocol::frame::is_authentic(&open, Some(KEY));
            let mut body_len = 0;
            let mut refused = None;
            while let Ok(Chunk::Data(d)) = read_chunk(&mut r).await {
                body_len += d.len();
                if let HostBehaviour::ExhaustAfter(n) = behaviour
                    && body_len >= n
                {
                    refused = Some(
                        "egress budget exhausted (egress.max_bytes): 204800 of 204800 bytes \
                         already sent, 65536 more requested",
                    );
                    break;
                }
            }
            *record.lock().expect("record") = HostSaw {
                open_frame: open,
                body_len,
                authentic,
            };
            if let Some(reason) = refused {
                let head = nucleus_cred_protocol::StreamHead {
                    granted: false,
                    reason: reason.to_string(),
                    status: 0,
                    content_type: String::new(),
                };
                let _ = write_line(&mut w, &serde_json::to_string(&head).expect("json")).await;
                // Drain, as the real host does, so the proxy reads the head.
                while let Ok(Chunk::Data(_)) = read_chunk(&mut r).await {}
                return;
            }
            let head = nucleus_cred_protocol::StreamHead {
                granted: true,
                reason: "granted".into(),
                status: 200,
                content_type: "text/event-stream".into(),
            };
            write_line(&mut w, &serde_json::to_string(&head).expect("json"))
                .await
                .expect("head");
            for event in SSE {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                write_chunks(&mut w, event.as_bytes()).await.expect("chunk");
            }
            write_end(&mut w).await.expect("end");
            let end = nucleus_cred_protocol::StreamEnd {
                complete: true,
                reason: String::new(),
            };
            write_line(&mut w, &serde_json::to_string(&end).expect("json"))
                .await
                .expect("end line");
        });
        (path, saw)
    }

    /// Serve the door with its egress route bound to the proxy's relay toward
    /// `host`. The open frame is signed here as `credentialed_egress` signs it
    /// (the kernel decision and the discharge before it need a full
    /// `AppState`; they are unchanged by this path and tested where they live).
    fn serve_door(dir: &Path, host: PathBuf) -> PathBuf {
        use axum::extract::Path as RoutePath;
        let door_path = dir.join("door").join("workload.sock");
        let door = crate::workload_door::UnservedDoor::bind(&door_path).expect("bind door");
        let app = axum::Router::new().route(
            "/v1/egress/{name}/{*path}",
            axum::routing::post(
                move |RoutePath((name, path)): RoutePath<(String, String)>,
                      headers: axum::http::HeaderMap,
                      body: axum::body::Body| {
                    let host = host.clone();
                    async move {
                        let request = nucleus_cred_protocol::StreamRequest {
                            operation: "WebFetch".into(),
                            target: name,
                            justification: "credentialed egress".into(),
                            nonce: uuid::Uuid::new_v4().to_string(),
                            path,
                            content_type: request_content_type(&headers),
                        };
                        let line = format!(
                            "{}\n",
                            nucleus_cred_protocol::frame::sign(
                                KEY,
                                &serde_json::to_string(&request).expect("json")
                            )
                        );
                        let conn = tokio::net::UnixStream::connect(&host)
                            .await
                            .expect("the host");
                        match forward_stream(conn, &line, body).await {
                            Ok(relayed) => relayed_response(relayed),
                            Err(e) => axum::response::IntoResponse::into_response(e),
                        }
                    }
                },
            ),
        );
        door.serve(
            app,
            crate::workload::WorkloadUid::for_test(crate::workload::nix_getuid()),
        );
        door_path
    }

    /// Be the workload: POST `body` to the door's egress route as HTTP/1.1
    /// chunked, and read the whole response.
    async fn workload_post(door: &Path, body: &[u8]) -> String {
        // Bounded, so a regression that stalls the relay fails here in
        // seconds rather than hanging the suite.
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            workload_post_unbounded(door, body),
        )
        .await
        .expect("the call through the door finished within 30 s")
    }

    async fn workload_post_unbounded(door: &Path, body: &[u8]) -> String {
        let mut s = tokio::net::UnixStream::connect(door).await.expect("door");
        let head = "POST /v1/egress/model-api/v1/complete HTTP/1.1\r\nHost: x\r\n\
                    Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\
                    Connection: close\r\n\r\n";
        s.write_all(head.as_bytes()).await.expect("head");
        for piece in body.chunks(32 * 1024) {
            let chunk = format!("{:x}\r\n", piece.len());
            // Errors are expected once the proxy has refused and hung up.
            if s.write_all(chunk.as_bytes()).await.is_err()
                || s.write_all(piece).await.is_err()
                || s.write_all(b"\r\n").await.is_err()
            {
                break;
            }
        }
        let _ = s.write_all(b"0\r\n\r\n").await;
        let mut reply = Vec::new();
        let _ = s.read_to_end(&mut reply).await;
        String::from_utf8_lossy(&reply).into_owned()
    }

    fn mebibyte() -> Vec<u8> {
        (0..1024 * 1024)
            .map(|i: usize| b"0123456789abcdef"[i % 16])
            .collect()
    }

    /// **A 1 MiB streamed request with an SSE reply, through the workload
    /// door.** The proxy streams the body to the host as chunks (the host saw
    /// all of it, under a frame it could authenticate), and the workload reads
    /// the events back with the upstream's media type. Neither what the proxy
    /// sent nor what the workload received carries the credential: the host
    /// holds it, and `broker_stream`'s tests show the host injecting it.
    ///
    /// Red on main: the route read the body whole and sent it in one perform
    /// frame, which the host refuses above 256 KiB.
    #[tokio::test]
    async fn a_mebibyte_streams_through_the_door_and_sse_streams_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (host, saw) = stand_in_host(dir.path(), HostBehaviour::Serve).await;
        let door = serve_door(dir.path(), host);
        let reply = workload_post(&door, &mebibyte()).await;

        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(
            reply
                .to_ascii_lowercase()
                .contains("content-type: text/event-stream"),
            "{reply}"
        );
        for event in SSE {
            assert!(
                reply.contains(event.trim_end()),
                "missing {event:?} in {reply}"
            );
        }
        let saw = saw.lock().expect("saw").clone();
        assert!(
            saw.authentic,
            "the open frame verifies under the pod's capability"
        );
        assert_eq!(saw.body_len, 1024 * 1024, "the whole body went up");
        assert!(saw.open_frame.contains("\"target\":\"model-api\""));
        assert!(saw.open_frame.contains("\"path\":\"v1/complete\""));
        assert!(!saw.open_frame.contains(TOKEN) && !reply.contains(TOKEN));
    }

    /// **Exhaustion mid-stream reaches the workload by name.** The host
    /// refuses part way through the upload; the proxy reads that refusal while
    /// still uploading and answers the workload 403 with the reason.
    #[tokio::test]
    async fn a_mid_stream_refusal_reaches_the_workload_by_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (host, saw) = stand_in_host(dir.path(), HostBehaviour::ExhaustAfter(200 * 1024)).await;
        let door = serve_door(dir.path(), host);
        let reply = workload_post(&door, &mebibyte()).await;

        assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
        assert!(
            reply.contains("egress budget exhausted (egress.max_bytes)"),
            "the workload must see why: {reply}"
        );
        assert!(saw.lock().expect("saw").body_len < 1024 * 1024);
    }
}
