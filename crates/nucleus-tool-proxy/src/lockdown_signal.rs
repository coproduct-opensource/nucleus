//! The operator's lockdown signal file, and what one watcher tick does with it.
//!
//! # Three ways into lockdown, one flag each
//!
//! Lockdown is entered by the operator's signal file, the node's gRPC stream, or
//! the denial circuit breaker. Each owns its own flag, and the proxy is locked when
//! any is set.
//!
//! The breaker used to set the SIGNAL FILE's flag. The file watcher polls every
//! 500 ms and, finding no file, stores "unlocked" — correct for the file's own
//! lock, and it silently lifted the breaker's lockdown within half a second. The
//! breaker's contract ("clearing lockdown is a human action") was false on every
//! pod without a signal file. `nucleus-perf stress` found it: concurrent calls saw
//! lockdown, and calls ~400 ms later were served normally with nobody restoring.
//!
//! So [`tick`] never touches the breaker's flag because a file is ABSENT. It clears
//! it only on a verified RESTORE signal — the human action the breaker names.

use std::sync::atomic::{AtomicBool, Ordering};

/// Verify a signal file's HMAC and read the state it asks for: `Some(true)` lock,
/// `Some(false)` restore, `None` if it is malformed or does not verify.
///
/// FAIL-CLOSED: an unverified file changes nothing, so an attacker cannot unlock
/// by corrupting or forging it.
pub(crate) fn verify(content: &str) -> Option<bool> {
    let envelope: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!("Lockdown signal file has invalid JSON — preserving current state");
            return None;
        }
    };
    let Some(signal) = envelope.get("signal") else {
        tracing::warn!("Lockdown signal file missing 'signal' field — preserving current state");
        return None;
    };
    let claimed_hmac = envelope.get("hmac").and_then(|h| h.as_str()).unwrap_or("");
    let body = serde_json::to_string_pretty(signal).unwrap_or_default();

    // HMAC key: hostname:username. This is a tamper-detection mechanism against
    // casual local attacks, not a cryptographic secret. For production fleet
    // lockdown, use the gRPC streaming path with proper HMAC auth.
    let key_material = format!(
        "nucleus-lockdown-{}:{}",
        whoami::hostname().unwrap_or_else(|_| "unknown".to_string()),
        whoami::username().unwrap_or_else(|_| "unknown".to_string()),
    );
    use hmac::{Hmac, Mac, digest::KeyInit};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key_material.as_bytes()).expect("hmac");
    mac.update(body.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if expected != claimed_hmac {
        tracing::warn!(
            "Lockdown signal HMAC mismatch — preserving current state (possible tampering)"
        );
        return None;
    }
    // A verified signal without a `restore` field asks for lockdown.
    Some(
        signal
            .get("restore")
            .and_then(|r| r.as_bool())
            .map(|restore| !restore)
            .unwrap_or(true),
    )
}

/// What one watcher tick decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tick {
    /// The signal file's own lock.
    pub file_locked: bool,
    /// A verified restore: the human action that also lifts the breaker's lockdown.
    pub restore: bool,
}

/// One tick: `signal` is `None` when there is no file, else what reading it gave.
pub(crate) fn tick(signal: Option<std::io::Result<String>>, file_locked_now: bool) -> Tick {
    match signal {
        // No file: the FILE does not lock. It says nothing about any other source.
        None => Tick {
            file_locked: false,
            restore: false,
        },
        Some(Err(e)) => {
            tracing::warn!(error = %e, "Failed to read lockdown signal file — preserving current state");
            Tick {
                file_locked: file_locked_now,
                restore: false,
            }
        }
        Some(Ok(content)) => match verify(&content) {
            None => Tick {
                file_locked: file_locked_now,
                restore: false,
            },
            Some(locked) => Tick {
                file_locked: locked,
                restore: !locked,
            },
        },
    }
}

/// Apply a tick to the flags it owns: the file's, and — only on a verified
/// restore — the breaker's.
pub(crate) fn apply(tick: Tick, file_flag: &AtomicBool, breaker_flag: &AtomicBool) {
    let was = file_flag.swap(tick.file_locked, Ordering::AcqRel);
    if tick.file_locked && !was {
        tracing::warn!(
            "LOCKDOWN ACTIVATED via verified signal file \
             — meet(current, read_only) applied, forensic reads still allowed"
        );
    } else if !tick.file_locked && was {
        tracing::info!("Lockdown lifted via verified signal file");
    }
    if tick.restore && breaker_flag.swap(false, Ordering::AcqRel) {
        tracing::info!("circuit-breaker lockdown lifted via verified restore signal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_file_clears_only_the_files_own_lock() {
        let (file, breaker) = (AtomicBool::new(true), AtomicBool::new(true));
        apply(tick(None, true), &file, &breaker);
        assert!(
            !file.load(Ordering::Acquire),
            "no file: the file does not lock"
        );
        assert!(
            breaker.load(Ordering::Acquire),
            "an absent file lifted the breaker's lockdown — that is not a human action"
        );
    }

    #[test]
    fn an_unverified_file_changes_nothing() {
        let (file, breaker) = (AtomicBool::new(false), AtomicBool::new(true));
        apply(
            tick(
                Some(Ok(r#"{"signal":{"restore":true},"hmac":"forged"}"#.into())),
                false,
            ),
            &file,
            &breaker,
        );
        assert!(!file.load(Ordering::Acquire));
        assert!(
            breaker.load(Ordering::Acquire),
            "a forged restore lifted lockdown"
        );
    }

    #[test]
    fn an_unreadable_file_preserves_the_files_lock() {
        let (file, breaker) = (AtomicBool::new(true), AtomicBool::new(false));
        apply(
            tick(Some(Err(std::io::Error::other("denied"))), true),
            &file,
            &breaker,
        );
        assert!(file.load(Ordering::Acquire));
    }
}
