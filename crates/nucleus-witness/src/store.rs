//! Per-origin witness state behind a small trait.
//!
//! For each origin the witness trusts, it tracks:
//! - the set of trusted LOG keys (which keys may sign a checkpoint for
//!   this origin), and
//! - the last-cosigned `(size, root)` — the witness's monotonic view of
//!   the log, used to enforce the C2SP rollback/conflict (409) checks
//!   and to anchor consistency-proof verification.
//!
//! The MVP backs this with an in-memory `Mutex<HashMap>`. Litewitness
//! uses sqlite; a persistent impl would slot in behind [`OriginStore`]
//! without touching the status-matrix logic in `server.rs`.

use std::collections::HashMap;
use std::sync::Mutex;

/// A trusted log key for an origin: its C2SP `key_name` plus 32-byte
/// Ed25519 pubkey. The witness will accept (and require) a valid
/// signature from one of these on every checkpoint for the origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedLogKey {
    pub key_name: String,
    pub pubkey: [u8; 32],
}

/// The witness's last-cosigned position for an origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CosignedPosition {
    pub size: u64,
    pub root: [u8; 32],
}

/// Per-origin configuration + mutable state.
#[derive(Debug, Clone)]
pub struct OriginRecord {
    pub trusted_log_keys: Vec<TrustedLogKey>,
    /// `None` until the first checkpoint is cosigned for this origin.
    pub last_cosigned: Option<CosignedPosition>,
}

/// Storage abstraction for per-origin witness state.
///
/// All methods take `&self` so the store can sit behind an `Arc` shared
/// across axum handlers. Implementations hold their own locking.
pub trait OriginStore: Send + Sync {
    /// Fetch the origin record, or `None` if the origin is not trusted
    /// (→ the handler returns 404).
    fn get(&self, origin: &str) -> Option<OriginRecord>;

    /// Atomically advance the last-cosigned position for `origin` to
    /// `pos`, but ONLY if the current position matches `expected`
    /// (compare-and-swap). Returns `true` on success. A `false` return
    /// means a concurrent writer advanced the state first — the handler
    /// should surface a 409 rather than mint a cosignature over a stale
    /// view.
    ///
    /// `expected == None` means "the origin has never been cosigned"
    /// (first submission). This CAS guard is what makes the status
    /// matrix safe under concurrent `POST /add-checkpoint` for the same
    /// origin.
    fn advance(
        &self,
        origin: &str,
        expected: Option<CosignedPosition>,
        pos: CosignedPosition,
    ) -> bool;
}

/// In-memory [`OriginStore`] (MVP). Documented non-persistent: a
/// process restart resets every origin's last-cosigned position to
/// `None`, which would let a producer replay an old checkpoint as a
/// "first submission". A production deployment MUST back this with
/// durable storage (sqlite, like litewitness) so the monotonicity
/// guarantee survives restarts.
#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<HashMap<String, OriginRecord>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an origin with its trusted log keys and (optionally) a
    /// starting last-cosigned position.
    pub fn add_origin(
        &self,
        origin: impl Into<String>,
        trusted_log_keys: Vec<TrustedLogKey>,
        last_cosigned: Option<CosignedPosition>,
    ) {
        self.inner.lock().expect("store mutex").insert(
            origin.into(),
            OriginRecord {
                trusted_log_keys,
                last_cosigned,
            },
        );
    }
}

impl OriginStore for InMemoryStore {
    fn get(&self, origin: &str) -> Option<OriginRecord> {
        self.inner.lock().expect("store mutex").get(origin).cloned()
    }

    fn advance(
        &self,
        origin: &str,
        expected: Option<CosignedPosition>,
        pos: CosignedPosition,
    ) -> bool {
        let mut guard = self.inner.lock().expect("store mutex");
        match guard.get_mut(origin) {
            Some(rec) if rec.last_cosigned == expected => {
                rec.last_cosigned = Some(pos);
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> TrustedLogKey {
        TrustedLogKey {
            key_name: format!("k{b}"),
            pubkey: [b; 32],
        }
    }

    #[test]
    fn unknown_origin_returns_none() {
        let store = InMemoryStore::new();
        assert!(store.get("ghost").is_none());
    }

    #[test]
    fn advance_cas_first_submission() {
        let store = InMemoryStore::new();
        store.add_origin("o", vec![key(1)], None);
        let pos = CosignedPosition {
            size: 5,
            root: [1u8; 32],
        };
        // CAS from None succeeds.
        assert!(store.advance("o", None, pos));
        // Re-attempt from None now fails (state moved).
        assert!(!store.advance("o", None, pos));
        // CAS from the real previous position succeeds.
        let pos2 = CosignedPosition {
            size: 9,
            root: [2u8; 32],
        };
        assert!(store.advance("o", Some(pos), pos2));
        assert_eq!(store.get("o").unwrap().last_cosigned, Some(pos2));
    }

    #[test]
    fn advance_on_unknown_origin_is_false() {
        let store = InMemoryStore::new();
        assert!(!store.advance(
            "ghost",
            None,
            CosignedPosition {
                size: 1,
                root: [0u8; 32]
            }
        ));
    }
}
