//! Evidence classification for the in-guest confinement canary.
//!
//! A failed operation is not necessarily a refused operation. Callers retain
//! the OS error and pass it to the classifier for the property being tested.
//! Incomplete observations never become evidence that a boundary held.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use serde::{Deserialize, Serialize};

pub mod network;

/// The three possible observations; an absent measurement is not a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", content = "reason", rename_all = "kebab-case")]
pub enum Verdict {
    Refused,
    Breach,
    CouldNotLook(&'static str),
}

/// An OS operation whose success would violate the property under test.
#[derive(Debug, Clone, Copy)]
pub enum Attempt {
    Succeeded,
    Failed(i32),
    ErrorWithoutErrno,
}

/// These are Linux UAPI errno values; observations from other hosts must not
/// be classified as Linux guest evidence.
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EACCES: i32 = 13;
const EROFS: i32 = 30;

/// Only a permission denial establishes this property. ENOENT (no target),
/// EINVAL (bad probe), resource exhaustion, and unknown failures are blindness.
#[must_use]
pub fn permission_denied(attempt: Attempt) -> Verdict {
    match attempt {
        Attempt::Succeeded => Verdict::Breach,
        Attempt::Failed(EPERM | EACCES) => Verdict::Refused,
        Attempt::Failed(_) | Attempt::ErrorWithoutErrno => {
            Verdict::CouldNotLook("operation failed without a permission denial")
        }
    }
}

/// A read-only or permission-protected base refuses file creation. Missing
/// parent directories do not exercise that protection.
#[must_use]
pub fn base_write_denied(attempt: Attempt) -> Verdict {
    match attempt {
        Attempt::Failed(EROFS) => Verdict::Refused,
        other => permission_denied(other),
    }
}

/// A host secret may be absent from the guest entirely. Other failures (for
/// example EIO) cannot establish that the secret was protected.
#[must_use]
pub fn host_secret_unreadable(attempt: Attempt) -> Verdict {
    match attempt {
        Attempt::Failed(ENOENT) => Verdict::Refused,
        other => permission_denied(other),
    }
}

/// Only EACCES is the exec-time observation expected from a noexec mount.
/// A missing interpreter, malformed executable, or killed child is not proof.
#[must_use]
pub fn noexec_denied(attempt: Attempt) -> Verdict {
    match attempt {
        Attempt::Succeeded => Verdict::Breach,
        Attempt::Failed(EACCES) => Verdict::Refused,
        Attempt::Failed(_) | Attempt::ErrorWithoutErrno => {
            Verdict::CouldNotLook("exec failed without the expected EACCES")
        }
    }
}

/// Classify one workload SVID response. Every workload fetch is later than
/// guest-init's provisioning fetch: leaking the key even once is a breach.
/// Never include reply bytes in a diagnostic, including malformed replies.
#[must_use]
pub fn svid_reply(bytes: &[u8]) -> Verdict {
    // Deriving Deserialize retains duplicate-field rejection; parsing through
    // Value first would silently keep the last private_key and hide a leak.
    #[derive(Deserialize)]
    struct Reply {
        private_key: Option<serde_json::Value>,
        certificate_chain: Option<serde_json::Value>,
        error: Option<serde_json::Value>,
    }
    let Ok(reply) = serde_json::from_slice::<Reply>(bytes) else {
        return Verdict::CouldNotLook("SVID response is malformed or has duplicate fields");
    };
    match reply.private_key.as_ref() {
        Some(serde_json::Value::String(key)) if !key.is_empty() => return Verdict::Breach,
        Some(serde_json::Value::Null) | None => {}
        Some(_) => return Verdict::CouldNotLook("SVID private_key field is malformed"),
    }
    if reply
        .certificate_chain
        .as_ref()
        .and_then(serde_json::Value::as_str)
        .is_some_and(|chain| !chain.is_empty())
    {
        return Verdict::Refused;
    }
    match reply.error.as_ref().and_then(serde_json::Value::as_str) {
        Some("svid key already served") => Verdict::Refused,
        _ => Verdict::CouldNotLook("SVID reply has neither a chain nor the expected refusal"),
    }
}

/// Failure while opening the identity channel, distinct from a failed reply.
/// A kernel permission denial prevents the workload from obtaining any key;
/// unreachable services and timeouts do not exercise that boundary.
#[must_use]
pub fn svid_channel_failure(errno: Option<i32>) -> Verdict {
    match errno {
        Some(EPERM | EACCES) => Verdict::Refused,
        _ => Verdict::CouldNotLook("SVID channel unavailable without a permission denial"),
    }
}

/// Any breach dominates blindness; all observations must be refusals to pass.
/// An empty run is never successful.
#[must_use]
pub fn exit_code(verdicts: &[Verdict]) -> u8 {
    if verdicts.iter().any(|v| matches!(v, Verdict::Breach)) {
        1
    } else if verdicts.is_empty()
        || verdicts
            .iter()
            .any(|v| matches!(v, Verdict::CouldNotLook(_)))
    {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_mount_target_is_not_a_permission_denial() {
        assert!(matches!(
            permission_denied(Attempt::Failed(ENOENT)),
            Verdict::CouldNotLook(_)
        ));
        for errno in [5, 12, 22, 24, 28, 38, 999] {
            assert!(matches!(
                permission_denied(Attempt::Failed(errno)),
                Verdict::CouldNotLook(_)
            ));
        }
        assert_eq!(permission_denied(Attempt::Succeeded), Verdict::Breach);
        assert_eq!(permission_denied(Attempt::Failed(EPERM)), Verdict::Refused);
        assert_eq!(permission_denied(Attempt::Failed(EACCES)), Verdict::Refused);
    }

    #[test]
    fn absent_host_credentials_and_missing_probe_targets_are_distinct() {
        assert_eq!(
            host_secret_unreadable(Attempt::Failed(ENOENT)),
            Verdict::Refused
        );
        assert!(matches!(
            base_write_denied(Attempt::Failed(ENOENT)),
            Verdict::CouldNotLook(_)
        ));
        assert_eq!(base_write_denied(Attempt::Failed(EROFS)), Verdict::Refused);
        assert!(matches!(
            host_secret_unreadable(Attempt::Failed(5)),
            Verdict::CouldNotLook(_)
        ));
    }

    #[test]
    fn a_missing_interpreter_does_not_prove_noexec() {
        assert!(matches!(
            noexec_denied(Attempt::Failed(ENOENT)),
            Verdict::CouldNotLook(_)
        ));
        assert_eq!(noexec_denied(Attempt::Failed(EACCES)), Verdict::Refused);
        assert_eq!(noexec_denied(Attempt::Succeeded), Verdict::Breach);
    }

    #[test]
    fn a_first_workload_fetch_leaking_the_key_is_already_a_breach() {
        let first = svid_reply(br#"{"private_key":"test-key","certificate_chain":"test-chain"}"#);
        let second = svid_reply(br#"{"certificate_chain":"test-chain"}"#);
        assert_eq!(first, Verdict::Breach);
        assert_eq!(second, Verdict::Refused);
        assert_eq!(exit_code(&[first, second]), 1);
    }

    #[test]
    fn malformed_or_unrelated_identity_failures_are_not_evidence() {
        for bytes in [
            b"[]".as_slice(),
            br#"{"private_key":"test-secret","private_key":null,"certificate_chain":"chain"}"#,
            br#"{"private_key":false,"certificate_chain":"chain"}"#,
            br#"{"error":"internal server error"}"#,
            br#"{"certificate_chain":[]}"#,
            br#"{"private_key":""}"#,
            br#"{"private_key":"test-secret""#,
        ] {
            let verdict = svid_reply(bytes);
            assert!(matches!(verdict, Verdict::CouldNotLook(_)));
            assert!(
                !serde_json::to_string(&verdict)
                    .unwrap()
                    .contains("test-secret")
            );
        }
        assert_eq!(
            svid_reply(br#"{"error":"svid key already served"}"#),
            Verdict::Refused
        );
    }

    #[test]
    fn a_denied_svid_channel_is_distinct_from_an_unavailable_service() {
        assert_eq!(svid_channel_failure(Some(EPERM)), Verdict::Refused);
        assert_eq!(svid_channel_failure(Some(EACCES)), Verdict::Refused);
        for errno in [None, Some(ENOENT), Some(110), Some(111), Some(97)] {
            assert!(matches!(
                svid_channel_failure(errno),
                Verdict::CouldNotLook(_)
            ));
        }
    }

    #[test]
    fn success_requires_nonempty_complete_refusal_evidence() {
        assert_eq!(exit_code(&[]), 2);
        assert_eq!(exit_code(&[Verdict::Refused]), 0);
        assert_eq!(
            exit_code(&[Verdict::Refused, Verdict::CouldNotLook("missing")]),
            2
        );
        assert_eq!(
            exit_code(&[Verdict::CouldNotLook("missing"), Verdict::Breach]),
            1
        );
    }
}
