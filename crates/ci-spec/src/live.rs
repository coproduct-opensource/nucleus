//! Live parity: the tree's ledgers against what GitHub actually enforces.
//!
//! Two files in the tree claim to describe GitHub's configuration —
//! `ci/required-checks.txt` (the required status-check contexts) and
//! `ci/merge-queue.toml` (the merge-queue ruleset constants). Every
//! invariant in this crate reasons from those files; if they drift from the
//! live settings, the invariants are about a configuration nobody runs.
//! The North Star ledger has the same discipline ("a status table cannot
//! outrun its wiring"); this is the CI version of it.
//!
//! Observation is NOT here — the caller (`cargo xtask ci-spec live-parity`)
//! fetches `GET /repos/{o}/{r}/branches/main/protection` and
//! `GET /repos/{o}/{r}/rulesets/{id}` with `gh api` and hands the JSON in.
//! This module only parses and decides, so it is testable without a network
//! and without an admin token. A fetch that fails is exit 2 ("could not
//! look") at the caller, never a pass.

use serde::Deserialize;

use crate::invariants::finding;
use crate::model::Model;
use crate::{Finding, Severity};

/// What `GET /branches/{branch}/protection` says about required checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProtection {
    pub strict: bool,
    pub contexts: Vec<String>,
}

/// What `GET /rulesets/{id}` says about the merge queue.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LiveQueue {
    pub check_response_timeout_minutes: u64,
    pub max_entries_to_build: u64,
    pub max_entries_to_merge: u64,
    pub min_entries_to_merge: u64,
    pub min_entries_to_merge_wait_minutes: u64,
    pub grouping_strategy: String,
    pub merge_method: String,
}

#[derive(Deserialize)]
struct ProtectionJson {
    required_status_checks: Option<RscJson>,
}
#[derive(Deserialize)]
struct RscJson {
    strict: bool,
    #[serde(default)]
    contexts: Vec<String>,
    #[serde(default)]
    checks: Vec<CheckJson>,
}
#[derive(Deserialize)]
struct CheckJson {
    context: String,
}

/// Parse the branch-protection response. The `checks[].context` list is
/// authoritative (it is what the merge rollup evaluates); `contexts` is the
/// legacy mirror and is unioned in so a partial response cannot read as
/// fewer requirements.
pub fn parse_protection(json: &str) -> Result<LiveProtection, String> {
    let p: ProtectionJson =
        serde_json::from_str(json).map_err(|e| format!("protection JSON: {e}"))?;
    let Some(r) = p.required_status_checks else {
        return Err("branch protection has no required_status_checks block".into());
    };
    let mut contexts: Vec<String> = r.checks.into_iter().map(|c| c.context).collect();
    for c in r.contexts {
        if !contexts.contains(&c) {
            contexts.push(c);
        }
    }
    contexts.sort();
    Ok(LiveProtection {
        strict: r.strict,
        contexts,
    })
}

#[derive(Deserialize)]
struct RulesetJson {
    id: u64,
    enforcement: String,
    rules: Vec<RuleJson>,
}
#[derive(Deserialize)]
struct RuleJson {
    #[serde(rename = "type")]
    kind: String,
    parameters: Option<serde_json::Value>,
}

/// Parse the ruleset response: the one `merge_queue` rule's parameters.
pub fn parse_ruleset(json: &str, expected_id: u64) -> Result<LiveQueue, String> {
    let r: RulesetJson = serde_json::from_str(json).map_err(|e| format!("ruleset JSON: {e}"))?;
    if r.id != expected_id {
        return Err(format!("ruleset id {} ≠ pinned {expected_id}", r.id));
    }
    if r.enforcement != "active" {
        return Err(format!(
            "ruleset {} enforcement is {:?}, not active",
            r.id, r.enforcement
        ));
    }
    let mq: Vec<&RuleJson> = r.rules.iter().filter(|x| x.kind == "merge_queue").collect();
    if mq.len() != 1 {
        return Err(format!(
            "ruleset has {} merge_queue rules, expected 1",
            mq.len()
        ));
    }
    let params = mq[0]
        .parameters
        .clone()
        .ok_or_else(|| "merge_queue rule has no parameters".to_string())?;
    serde_json::from_value(params).map_err(|e| format!("merge_queue parameters: {e}"))
}

/// Decide parity: ledger == live protection, and the queue pin == the
/// live ruleset. Both directions on the contexts — a live requirement the
/// ledger does not know about means every invariant here was decided over
/// an incomplete set.
pub fn parity(m: &Model, live: &LiveProtection, queue: &LiveQueue) -> Vec<Finding> {
    let mut out = Vec::new();
    const F: &str = "ci/required-checks.txt";

    if live.contexts.len() < 2 {
        out.push(finding(
            "CI-LP-VACUOUS",
            Severity::Undecided,
            F,
            0,
            "live protection",
            format!(
                "GitHub reports {} required context(s) — either protection was removed or the \
                 response was partial; nothing below can be compared",
                live.contexts.len()
            ),
            "check the token's permissions and the branch-protection settings",
        ));
        return out;
    }

    for c in &m.ledger.contexts {
        if !live.contexts.contains(c) {
            out.push(finding(
                "CI-LP-MISSING",
                Severity::Critical,
                F,
                0,
                c,
                "the ledger lists this context as required but GitHub does not enforce it: \
                 every invariant decided over the ledger assumes a gate the merge rollup never \
                 consults"
                    .into(),
                "add it to branch protection (`gh api -X PATCH …/protection/required_status_checks`) \
                 or, if it was retired on purpose, remove it from the ledger with a dated note and \
                 lower the pin",
            ));
        }
    }
    for c in &live.contexts {
        if !m.is_required(c) {
            out.push(finding(
                "CI-LP-EXTRA",
                Severity::Critical,
                F,
                0,
                c,
                "GitHub requires this context but the ledger does not list it: the producer, \
                 twin and merge_group invariants were never checked for it"
                    .into(),
                "add it to ci/required-checks.txt and raise the pin",
            ));
        }
    }

    const Q: &str = "ci/merge-queue.toml";
    let p = &m.queue;
    let diffs: Vec<(&str, String, String)> = [
        (
            "check_response_timeout_minutes",
            p.check_response_timeout_minutes.to_string(),
            queue.check_response_timeout_minutes.to_string(),
        ),
        (
            "max_entries_to_build",
            p.max_entries_to_build.to_string(),
            queue.max_entries_to_build.to_string(),
        ),
        (
            "max_entries_to_merge",
            p.max_entries_to_merge.to_string(),
            queue.max_entries_to_merge.to_string(),
        ),
        (
            "min_entries_to_merge",
            p.min_entries_to_merge.to_string(),
            queue.min_entries_to_merge.to_string(),
        ),
        (
            "min_entries_to_merge_wait_minutes",
            p.min_entries_to_merge_wait_minutes.to_string(),
            queue.min_entries_to_merge_wait_minutes.to_string(),
        ),
        (
            "grouping_strategy",
            p.grouping_strategy.clone(),
            queue.grouping_strategy.clone(),
        ),
        (
            "merge_method",
            p.merge_method.clone(),
            queue.merge_method.clone(),
        ),
    ]
    .into_iter()
    .filter(|(_, a, b)| a != b)
    .collect();
    for (k, pinned, live_v) in diffs {
        out.push(finding(
            "CI-LP-QUEUE",
            Severity::Critical,
            Q,
            0,
            k,
            format!(
                "pinned {k} = {pinned} but the live ruleset says {live_v}: the capacity theorem's \
                 hypotheses and the timeout invariant (I7) are about a queue that is not the one \
                 running"
            ),
            "change the pin in the same PR that justifies the new setting, or revert the UI edit",
        ));
    }
    if p.strict != live.strict {
        out.push(finding(
            "CI-LP-STRICT",
            Severity::Critical,
            Q,
            0,
            "strict",
            format!(
                "pinned strict = {} but branch protection says {}: `strict = true` with a queue \
                 forces a rebase before every merge, the livelock of 2026-09-04",
                p.strict, live.strict
            ),
            "align the pin and the setting",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_unions_checks_and_contexts() {
        let j = r#"{"required_status_checks":{"strict":false,"contexts":["A","B"],"checks":[{"context":"B","app_id":1},{"context":"C","app_id":1}]}}"#;
        let p = parse_protection(j).unwrap();
        assert_eq!(p.contexts, vec!["A", "B", "C"]);
        assert!(!p.strict);
    }

    #[test]
    fn ruleset_requires_one_active_merge_queue_rule() {
        let j = r#"{"id":1,"enforcement":"active","rules":[{"type":"merge_queue","parameters":{"check_response_timeout_minutes":360,"grouping_strategy":"ALLGREEN","max_entries_to_build":1,"max_entries_to_merge":1,"merge_method":"SQUASH","min_entries_to_merge":1,"min_entries_to_merge_wait_minutes":0}}]}"#;
        let q = parse_ruleset(j, 1).unwrap();
        assert_eq!(q.max_entries_to_build, 1);
        assert!(parse_ruleset(j, 2).is_err(), "wrong id must not parse");
        let off = j.replace("\"active\"", "\"disabled\"");
        assert!(
            parse_ruleset(&off, 1).is_err(),
            "a disabled ruleset is not a queue"
        );
    }
}
