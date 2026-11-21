//! The links gauntlet's verdicts (ADR 0017), as the slice Charon→Aeneas
//! translates to Lean. `GauntletVerdict.lean` is the meaning;
//! `GauntletVerdictExtracted.lean` proves these functions compute it.
//!
//! Found on the x86 runs (2026-11-19/20), three times: an item read "pass"
//! when it had not observed what it claims (a 503 in no bucket; 19,162 of
//! 50,000 requests sent; a race in which no link was made). The rule was the
//! defect each time, so the rules are decided here, once, and the harness
//! (`nucleus-cli`'s `host_evidence_live::links`) only gathers the counts.
//!
//! Written for extraction: integers and booleans only, no closures, and no
//! arithmetic that can overflow (a sum of counts is a disjunction of `> 0`).

/// One item's verdict. `Recorded` is a measurement reported and not judged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
    Recorded,
}

/// The one shape: bad fails; otherwise enough passes; otherwise inconclusive.
#[must_use]
pub fn judge(bad: bool, enough: bool) -> Verdict {
    if bad {
        Verdict::Fail
    } else if enough {
        Verdict::Pass
    } else {
        Verdict::Inconclusive
    }
}

/// Whether a verdict fails the run.
#[must_use]
pub fn fails(v: Verdict) -> bool {
    match v {
        Verdict::Fail => true,
        Verdict::Pass | Verdict::Inconclusive | Verdict::Recorded => false,
    }
}

/// (a) differential conformance.
#[must_use]
pub fn differential(mismatches: u64, errors: u64) -> Verdict {
    judge(mismatches > 0, errors == 0)
}

/// (b) per-request decisions.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    clippy::needless_bool,
    clippy::if_same_then_else,
    reason = "extracted by Aeneas: one argument per counted bucket, and each branch returns a \
              literal because a comparison returned as a value translates to a Prop"
)]
pub fn per_request(
    saw: bool,
    requested: u64,
    sent_fewest: u64,
    linked_ok: u64,
    linked_failed: u64,
    linked_missing: u64,
    refused_leaked: u64,
    undecided: u64,
) -> Verdict {
    // Each branch returns a literal: Aeneas translates a comparison returned as
    // a value into a `Prop` where a `Bool` is needed (local Aeneas d71d2e3).
    let bad = if linked_failed > 0 {
        true
    } else if linked_missing > 0 {
        true
    } else if refused_leaked > 0 {
        true
    } else if undecided > 0 {
        true
    } else {
        false
    };
    let enough = if saw && linked_ok > 0 && sent_fewest >= requested {
        true
    } else {
        false
    };
    judge(bad, enough)
}

/// (c) the guest-root adversary.
#[must_use]
pub fn adversary(any_bad: bool, attempts: u64) -> Verdict {
    judge(any_bad, attempts > 0)
}

/// (d) isolation: the two kinds of 404 are identical.
#[must_use]
pub fn isolation(identical: bool) -> Verdict {
    judge(!identical, true)
}

/// (e1) cancel while linked is refused, then exit drops the link.
#[must_use]
pub fn cancel_then_exit(link_ok: bool, cancel_refused: bool, dropped: bool) -> Verdict {
    judge(!(link_ok && cancel_refused && dropped), true)
}

/// (e2) concurrent link/unlink: no link made is inconclusive; otherwise the
/// row's presence (0 or 1) is links made less unlinks made.
#[must_use]
#[expect(
    clippy::needless_bool,
    reason = "extracted by Aeneas: a comparison returned as a value translates to a Prop"
)]
pub fn race(links_done: u64, unlinks_done: u64, present: u64) -> Verdict {
    if links_done == 0 {
        Verdict::Inconclusive
    } else {
        let consistent =
            if unlinks_done <= links_done && links_done - unlinks_done == present && present <= 1 {
                true
            } else {
                false
            };
        judge(!consistent, true)
    }
}

/// (f) a canary with no link.
#[must_use]
pub fn canary(received: u64, listening: bool) -> Verdict {
    judge(received > 0, listening)
}

/// (g) offline receipt verification.
#[must_use]
pub fn receipts(bad: u64, verified: u64) -> Verdict {
    judge(bad > 0, verified > 0)
}

/// Seconds the sender of `n` requests per kind is waited for.
#[must_use]
pub fn sender_wait(n: u64) -> u64 {
    let scaled = n / 10;
    if scaled > 900 { scaled } else { 900 }
}

/// Seconds the standing pods live. `None` past `u64` (never at any real scale).
#[must_use]
pub fn standing_lifetime(ops: u64, requests: u64) -> Option<u64> {
    // Three hours for the other items plus 600 s: 3 * 3600 + 600.
    let base: u64 = 11_400;
    match base.checked_add(ops) {
        None => None,
        Some(a) => a.checked_add(sender_wait(requests)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three findings, each with the run's own numbers.
    #[test]
    fn the_three_false_passes_are_not_passes() {
        assert_eq!(per_request(true, 200, 200, 63, 137, 0, 0, 0), Verdict::Fail);
        assert_eq!(
            per_request(true, 50_000, 19_162, 19_162, 0, 0, 0, 0),
            Verdict::Inconclusive
        );
        assert_eq!(race(0, 0, 0), Verdict::Inconclusive);
        assert_eq!(
            per_request(true, 50_000, 50_000, 50_000, 0, 0, 0, 0),
            Verdict::Pass
        );
        assert_eq!(race(2, 2, 0), Verdict::Pass);
        assert_eq!(race(2, 2, 1), Verdict::Fail);
    }

    #[test]
    fn standing_pods_outlive_the_sender_by_three_hours() {
        let wait = sender_wait(50_000);
        assert_eq!(wait, 5_000);
        assert!(standing_lifetime(10_000, 50_000).unwrap() >= wait + 3 * 3600);
        assert_eq!(standing_lifetime(u64::MAX, 0), None);
    }
}
