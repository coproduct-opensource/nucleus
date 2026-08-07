//! Per-caller identity for the node's management API.
//!
//! # The gap this fills
//!
//! The node cannot tell which pod is calling it. Every tool-proxy signs its
//! management requests as the literal actor `"tool-proxy"` with the SAME
//! node-wide secret (`nucleus-tool-proxy/src/node_client.rs`), so "authenticated"
//! means "someone inside this deployment", never "pod X". Three separate defects
//! found in one audit trace back to that single absence:
//!
//! * ownership on `list_sub_pods` / `get_pod_logs` / `cancel_sub_pod` can only be
//!   enforced PROXY-side, so it does not survive a compromised proxy;
//! * a credential store's binding to a pod is authored in a spec rather than
//!   established by the caller;
//! * an Article 12 record can be bound to a session but not to a pod.
//!
//! It is also the reason the formal corpus has no pod identifier: the model
//! cannot assign a material to a pod because the system does not either.
//!
//! # The mechanism, and why it is stateless
//!
//! `token(pod) = HMAC(node_secret, DOMAIN || pod_id)`.
//!
//! Derived rather than stored: there is no registry to keep in step with pod
//! lifecycle, nothing to leak on restart, and no "token exists but pod is gone"
//! state. The node recomputes and compares in constant time.
//!
//! A pod cannot compute another pod's token without the node secret, so
//! presenting `(pod_id, token)` proves the caller holds the token ISSUED FOR
//! that pod. That is the property the API needs: not "who are you" in the
//! abstract, but "which pod's authority are you exercising".
//!
//! # How a pod gets its token — and why that channel and no other
//!
//! Over the per-pod workload-API vsock socket, which the host creates per VM.
//! The pod does not name itself; the socket does. That is the same reasoning
//! `WorkloadApiCommand::FetchTaskToken` records for riding this channel: it
//! already serves per-pod artifacts over a per-pod socket, so a new artifact is
//! a variant rather than a protocol inside a protocol.
//!
//! Deliberately NOT delivered in the pod's environment: an env var is only as
//! trustworthy as everything that can write the environment, and this is the
//! value that decides whose pods you may manage.
//!
//! # What this module does NOT do
//!
//! It establishes identity. It makes no authorization decision — no ownership
//! check, no capability check. Wiring identity and then USING it are separate
//! changes on purpose: this one cannot alter any existing verdict, so it can be
//! reviewed for correctness rather than for blast radius.

use uuid::Uuid;

/// Domain separation — these bytes must never be a valid signature anywhere else
/// in the system, and the version lets the scheme change without ambiguity.
const DOMAIN: &[u8] = b"nucleus-pod-caller-v1\0";

/// The token a pod presents to prove which pod's authority it is exercising.
///
/// Hex-encoded HMAC-SHA256. Returned as a `String` because it crosses a wire.
#[must_use]
pub(crate) fn derive_token(node_secret: &[u8], pod_id: Uuid) -> String {
    // Built through the crate's own signer so derivation and verification are
    // the same computation by construction, not by two authors agreeing.
    let mut signed = Vec::with_capacity(DOMAIN.len() + 36);
    signed.extend_from_slice(DOMAIN);
    // The canonical hyphenated form, fixed width; the domain tag separates these
    // bytes from every other HMAC in the system.
    signed.extend_from_slice(pod_id.as_hyphenated().to_string().as_bytes());
    crate::auth::sign_message(node_secret, &signed)
}

/// Why a caller could not be identified.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CallerError {
    /// No identity presented — the caller is an operator or an older proxy.
    /// NOT an error on its own: today the API still accepts unidentified
    /// callers, and this simply reports that none was established.
    Absent,
    /// An identity was presented and did not check out. This is the interesting
    /// one: something claimed to be a pod and could not prove it.
    Invalid,
}

/// Establish which pod is calling, from a claimed id and its token.
///
/// Returns `Err(Absent)` when nothing was presented and `Err(Invalid)` when what
/// was presented does not verify — kept distinct because they mean different
/// things to a caller and to an operator reading logs.
pub(crate) fn identify_caller(
    node_secret: &[u8],
    claimed_pod_id: Option<&str>,
    presented_token: Option<&str>,
) -> Result<Uuid, CallerError> {
    let (Some(id), Some(token)) = (claimed_pod_id, presented_token) else {
        return Err(CallerError::Absent);
    };
    // An unparseable id is Invalid, not Absent: something WAS claimed.
    let pod_id = Uuid::parse_str(id).map_err(|_| CallerError::Invalid)?;
    // Reuse the crate's ONE HMAC verification path rather than comparing the
    // hex ourselves: `Mac::verify_slice` is constant-time, and a byte-by-byte
    // comparison would leak the expected token through timing, one byte at a
    // time, to a caller who may retry freely. Reusing it also means this cannot
    // drift from how every other signature in the node is checked.
    let mut signed = Vec::with_capacity(DOMAIN.len() + 36);
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(pod_id.as_hyphenated().to_string().as_bytes());
    match crate::auth::verify_signature_pub(node_secret, &signed, token) {
        Ok(()) => Ok(pod_id),
        Err(_) => Err(CallerError::Invalid),
    }
}

/// Identify the calling pod from an HTTP request's headers.
///
/// Lives here rather than inline in the auth middleware so the whole mechanism —
/// derivation, verification, and the header names it reads — is one module that
/// can be read in a single sitting.
///
/// Additive, and deliberately not yet an authorization input: an unidentified
/// caller is accepted exactly as before (operators and older proxies present
/// nothing), so this cannot change a verdict. What it DOES change is that a
/// caller CLAIMING to be a pod and failing to prove it becomes visible instead
/// of indistinguishable from every other request.
/// Identify the calling pod from gRPC request metadata.
///
/// The same two headers as the HTTP surface, read off `MetadataMap` instead of
/// `HeaderMap`. Sharing `identify_caller` rather than re-deriving means the two
/// transports cannot disagree about who a caller is.
pub(crate) fn identify_from_metadata(
    node_secret: &[u8],
    md: &tonic::metadata::MetadataMap,
) -> Result<Uuid, CallerError> {
    let get = |name: &str| md.get(name).and_then(|v| v.to_str().ok());
    let caller = identify_caller(
        node_secret,
        get(nucleus_client::HEADER_POD_ID),
        get(nucleus_client::HEADER_POD_TOKEN),
    );
    report_identification(&caller);
    caller
}

/// Log what the identification concluded. Shared so the two transports report
/// the same way; an "unidentified over gRPC but identified over HTTP" split
/// would be invisible if each logged its own way.
fn report_identification(caller: &Result<Uuid, CallerError>) {
    match caller {
        Ok(pod_id) => tracing::debug!(%pod_id, "identified the calling pod"),
        Err(CallerError::Absent) => {}
        Err(CallerError::Invalid) => {
            tracing::warn!("a request claimed a pod identity it could not prove");
        }
    }
}

pub(crate) fn identify_from_headers(
    node_secret: &[u8],
    headers: &axum::http::HeaderMap,
) -> Result<Uuid, CallerError> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let caller = identify_caller(
        node_secret,
        header(nucleus_client::HEADER_POD_ID),
        header(nucleus_client::HEADER_POD_TOKEN),
    );
    // Not refused — refusing would change behaviour for a caller that is
    // currently accepted — but a failed claim is the one case worth seeing.
    report_identification(&caller);
    caller
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"node-wide-management-secret";
    fn pod_a() -> Uuid {
        Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap()
    }
    fn pod_b() -> Uuid {
        Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap()
    }

    /// A pod's own token identifies it.
    #[test]
    fn a_pods_own_token_identifies_it() {
        let t = derive_token(SECRET, pod_a());
        assert_eq!(
            identify_caller(SECRET, Some(&pod_a().to_string()), Some(&t)),
            Ok(pod_a())
        );
    }

    /// **The property the whole mechanism exists for.** Holding pod A's token
    /// does not let you speak as pod B — which is what "the node cannot tell
    /// callers apart" cost us everywhere else.
    #[test]
    fn one_pods_token_cannot_claim_another_pod() {
        let token_a = derive_token(SECRET, pod_a());
        assert_eq!(
            identify_caller(SECRET, Some(&pod_b().to_string()), Some(&token_a)),
            Err(CallerError::Invalid)
        );
    }

    /// Distinct pods get distinct tokens — otherwise the above passes vacuously.
    #[test]
    fn distinct_pods_get_distinct_tokens() {
        assert_ne!(derive_token(SECRET, pod_a()), derive_token(SECRET, pod_b()));
    }

    /// Derivation is stable: the node must recompute the same value it served,
    /// across restarts, with no stored state.
    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(derive_token(SECRET, pod_a()), derive_token(SECRET, pod_a()));
    }

    /// A different node secret yields a different token, so a token minted by
    /// one deployment is meaningless to another.
    #[test]
    fn a_different_node_secret_yields_a_different_token() {
        assert_ne!(
            derive_token(SECRET, pod_a()),
            derive_token(b"other", pod_a())
        );
    }

    /// Absent and Invalid are different answers: "no identity offered" is an
    /// operator or an older proxy; "identity offered and wrong" is something
    /// claiming to be a pod it is not.
    #[test]
    fn absent_and_invalid_are_distinguished() {
        assert_eq!(
            identify_caller(SECRET, None, None),
            Err(CallerError::Absent)
        );
        assert_eq!(
            identify_caller(SECRET, Some(&pod_a().to_string()), None),
            Err(CallerError::Absent)
        );
        assert_eq!(
            identify_caller(SECRET, Some("not-a-uuid"), Some("whatever")),
            Err(CallerError::Invalid)
        );
        assert_eq!(
            identify_caller(SECRET, Some(&pod_a().to_string()), Some("deadbeef")),
            Err(CallerError::Invalid)
        );
    }

    /// An empty node secret must not make everything verify. HMAC accepts any
    /// key length, so this is a real reachable state if configuration is
    /// missing, and it is the fail-OPEN reading of "not configured".
    #[test]
    fn an_empty_secret_still_discriminates() {
        let t = derive_token(b"", pod_a());
        assert_eq!(
            identify_caller(b"", Some(&pod_b().to_string()), Some(&t)),
            Err(CallerError::Invalid)
        );
    }
}
