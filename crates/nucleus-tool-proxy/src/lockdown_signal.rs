//! Legacy signal files can only latch a lockdown. They carry no authority to
//! restore permissions: only an operator-authenticated node command may do so.
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tick {
    pub file_locked: bool,
}

/// Absence, corruption, or a forged restore cannot lift an existing lockdown.
pub(crate) fn tick(signal: Option<std::io::Result<String>>, file_locked_now: bool) -> Tick {
    let asks_lock = match signal {
        Some(Ok(content)) => serde_json::from_str::<serde_json::Value>(&content)
            .ok()
            .and_then(|v| v.get("signal").cloned())
            .is_some_and(|v| v.get("restore").and_then(|r| r.as_bool()) == Some(false)),
        Some(Err(_)) | None => false,
    };
    Tick {
        file_locked: file_locked_now || asks_lock,
    }
}

/// This channel can only narrow authority, never clear either lock.
pub(crate) fn apply(tick: Tick, file_flag: &AtomicBool, _breaker_flag: &AtomicBool) {
    if tick.file_locked {
        file_flag.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_mutations_never_restore_permissions() {
        for content in [
            None,
            Some("invalid"),
            Some(r#"{"signal":{"restore":true},"hmac":"anything"}"#),
        ] {
            let file = AtomicBool::new(true);
            let breaker = AtomicBool::new(true);
            apply(tick(content.map(|s| Ok(s.into())), true), &file, &breaker);
            assert!(file.load(Ordering::Acquire));
            assert!(breaker.load(Ordering::Acquire));
        }
    }
    #[test]
    fn legacy_lock_is_monotonic() {
        let file = AtomicBool::new(false);
        let breaker = AtomicBool::new(false);
        apply(
            tick(Some(Ok(r#"{"signal":{"restore":false}}"#.into())), false),
            &file,
            &breaker,
        );
        assert!(file.load(Ordering::Acquire));
        apply(tick(None, true), &file, &breaker);
        assert!(file.load(Ordering::Acquire));
    }
}
