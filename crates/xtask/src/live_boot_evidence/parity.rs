//! Do the three public verifiers agree on the same inputs?
//!
//! `nucleus-audit` (Rust), the JS SDK (wasm) and the Python SDK each judge the
//! live receipt and a tampered copy. Agreement is the property: every one
//! accepts the genuine receipt with the same root hash, and every one refuses
//! the tampered one. A single dissenter is red, whichever way it dissents.

use super::verdict::Verdict;
use serde::Serialize;

/// What one verifier said about one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "seen", content = "detail", rename_all = "snake_case")]
pub enum Seen {
    /// Accepted; the SDKs also report the root hash they recomputed.
    Accepted(Option<String>),
    /// Refused, and how.
    Refused(String),
    /// The verifier could not be run on this input.
    CouldNotRun(String),
}

/// Read an SDK verdict object (`{"outcome": …}`) as a [`Seen`]. `"error"` is
/// the runner's report of an exception: malformed input, not a refusal.
pub fn sdk(value: Option<&serde_json::Value>) -> Seen {
    let Some(value) = value else {
        return Seen::CouldNotRun("the runner returned no verdict for this input".into());
    };
    match value.get("outcome").and_then(|o| o.as_str()) {
        Some("verified") => Seen::Accepted(
            value
                .get("root_hash_hex")
                .and_then(|h| h.as_str())
                .map(str::to_owned),
        ),
        Some("error") => Seen::CouldNotRun(format!("threw: {}", value["message"])),
        Some(other) => Seen::Refused(other.to_owned()),
        None => Seen::CouldNotRun(format!("unreadable verdict {value}")),
    }
}

/// The agreement verdict for one input. `root` is the receipt's own
/// `root_hash_hex`, which every SDK that accepts must have recomputed.
pub fn agree(expect_accept: bool, root: &str, seen: &[(&str, Seen)]) -> Verdict {
    let unrun: Vec<String> = seen
        .iter()
        .filter_map(|(who, s)| match s {
            Seen::CouldNotRun(why) => Some(format!("{who}: {why}")),
            Seen::Accepted(_) | Seen::Refused(_) => None,
        })
        .collect();
    let dissent: Vec<String> = seen
        .iter()
        .filter_map(|(who, s)| match (expect_accept, s) {
            (true, Seen::Accepted(None)) | (false, Seen::Refused(_)) => None,
            (true, Seen::Accepted(Some(hash))) if hash == root => None,
            (true, Seen::Accepted(Some(hash))) => {
                Some(format!("{who} accepted with root hash {hash}, not {root}"))
            }
            (true, Seen::Refused(how)) => Some(format!("{who} refused ({how})")),
            (false, Seen::Accepted(_)) => Some(format!("{who} ACCEPTED the tampered input")),
            (_, Seen::CouldNotRun(_)) => None,
        })
        .collect();
    if !dissent.is_empty() {
        Verdict::Fail(format!("the verifiers disagree: {}", dissent.join("; ")))
    } else if !unrun.is_empty() {
        Verdict::CouldNotRun(unrun.join("; "))
    } else {
        let names: Vec<&str> = seen.iter().map(|(w, _)| *w).collect();
        Verdict::Pass(format!(
            "{} {} it",
            names.join(", "),
            if expect_accept { "accept" } else { "refuse" }
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(h: &str) -> Seen {
        Seen::Accepted(Some(h.into()))
    }

    #[test]
    fn three_verifiers_that_agree_pass_both_ways() {
        let seen = [
            ("nucleus-audit", Seen::Accepted(None)),
            ("js", acc("r")),
            ("py", acc("r")),
        ];
        assert!(matches!(agree(true, "r", &seen), Verdict::Pass(_)));
        let refused = [
            ("nucleus-audit", Seen::Refused("exit 1".into())),
            ("js", Seen::Refused("root_hash_mismatch".into())),
            ("py", Seen::Refused("root_hash_mismatch".into())),
        ];
        assert!(matches!(agree(false, "r", &refused), Verdict::Pass(_)));
    }

    /// A-19: one verifier disagreeing is red, in either direction.
    #[test]
    fn a_verifier_disagreement_is_red() {
        let py_refuses = [
            ("nucleus-audit", Seen::Accepted(None)),
            ("js", acc("r")),
            ("py", Seen::Refused("signature_mismatch".into())),
        ];
        assert!(matches!(agree(true, "r", &py_refuses), Verdict::Fail(_)));
        let js_accepts_tamper = [
            ("nucleus-audit", Seen::Refused("exit 1".into())),
            ("js", acc("x")),
            ("py", Seen::Refused("root_hash_mismatch".into())),
        ];
        assert!(matches!(
            agree(false, "r", &js_accepts_tamper),
            Verdict::Fail(_)
        ));
        let other_hash = [("js", acc("r")), ("py", acc("q"))];
        assert!(matches!(agree(true, "r", &other_hash), Verdict::Fail(_)));
    }

    #[test]
    fn a_missing_verifier_is_could_not_run_and_never_a_pass() {
        let seen = [
            ("nucleus-audit", Seen::Accepted(None)),
            ("js", Seen::CouldNotRun("wasm-pack missing".into())),
        ];
        assert!(matches!(agree(true, "r", &seen), Verdict::CouldNotRun(_)));
        assert_eq!(
            sdk(None),
            Seen::CouldNotRun("the runner returned no verdict for this input".into())
        );
        let thrown = serde_json::json!({"outcome": "error", "message": "bad"});
        assert!(matches!(sdk(Some(&thrown)), Seen::CouldNotRun(_)));
        let mismatch = serde_json::json!({"outcome": "root_hash_mismatch"});
        assert_eq!(
            sdk(Some(&mismatch)),
            Seen::Refused("root_hash_mismatch".into())
        );
    }
}
