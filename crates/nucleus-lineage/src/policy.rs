//! Sigsum-style k-of-n witnessing policy parser + quorum evaluator.
//!
//! Implements the grammar from the [sigsum-go policy
//! documentation](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md):
//!
//! ```text
//! log     <pubkey-hex>            [url]
//! witness <name> <pubkey-hex>     [url]
//! group   <name> all|any|<k>      <member> [member ...]
//! quorum  <name>
//! ```
//!
//! - `log` declares a trusted log key (recorded but not used by the
//!   quorum evaluator — present for grammar completeness / future
//!   submission routing).
//! - `witness <name> <pubkey>` declares a named witness with a 32-byte
//!   Ed25519 verifying key (hex-encoded).
//! - `group <name> <threshold> <members...>` declares a named group.
//!   `threshold` is `all` (every member), `any` (≥ 1 member), or a
//!   decimal `k` (≥ k distinct members). Members are witness names or
//!   other group names — **groups nest**.
//! - `quorum <name>` names the single top-level group (or witness) that
//!   the whole policy is satisfied by. Exactly one `quorum` line is
//!   required.
//!
//! # Quorum semantics (the security-load-bearing part)
//!
//! [`Policy::is_satisfied`] counts **distinct** witnesses that produced
//! a valid cosignature, then evaluates the quorum tree:
//!
//! - `any`  → satisfied iff ≥ 1 distinct member is satisfied.
//! - `all`  → satisfied iff EVERY member is satisfied.
//! - `<k>`  → satisfied iff ≥ k distinct members are satisfied.
//! - a witness leaf → satisfied iff that witness is in the
//!   valid-cosigner set.
//!
//! A witness that signs twice counts **once** — the caller passes a
//! set of witness identities, and even if it doesn't de-duplicate,
//! the evaluator does (it works over the set of names that satisfy
//! each leaf). Below-threshold ⇒ NOT satisfied. There is no implicit
//! "fail open" path.
//!
//! # What this module does NOT do
//!
//! It does not itself verify Ed25519 signatures — that is the caller's
//! job (e.g. [`crate::cosign::Cosignature`] verification against the
//! witness's pubkey). The evaluator consumes the SET OF WITNESS NAMES
//! whose cosignatures already verified, so the trust boundary is: only
//! pass names whose signatures you cryptographically checked.

use std::collections::{HashMap, HashSet};

use thiserror::Error;

/// Errors raised while parsing or evaluating a Sigsum policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// A line had too few tokens for its keyword.
    #[error("line {line}: `{keyword}` needs more arguments")]
    TooFewArgs { line: usize, keyword: String },
    /// An unknown leading keyword.
    #[error("line {line}: unknown keyword `{keyword}`")]
    UnknownKeyword { line: usize, keyword: String },
    /// A pubkey hex string didn't decode to 32 bytes.
    #[error("line {line}: pubkey must be 32-byte hex, got: {value}")]
    BadPubkey { line: usize, value: String },
    /// A `group` threshold was neither `all`, `any`, nor a decimal.
    #[error("line {line}: group threshold must be `all`, `any`, or a decimal, got `{value}`")]
    BadThreshold { line: usize, value: String },
    /// A name was declared twice (witness or group).
    #[error("line {line}: duplicate name `{name}`")]
    DuplicateName { line: usize, name: String },
    /// A `group`/`quorum` referenced a name that was never declared.
    #[error("unknown reference `{name}` (must be a declared witness or group)")]
    UnknownReference { name: String },
    /// More than one `quorum` line, or none.
    #[error("policy must have exactly one `quorum` line, found {found}")]
    QuorumCount { found: usize },
    /// A `group` with a decimal threshold larger than its member count
    /// can never be satisfied — reject at parse time.
    #[error("line {line}: group `{name}` needs {k} of {members} members — unsatisfiable")]
    ThresholdExceedsMembers {
        line: usize,
        name: String,
        k: usize,
        members: usize,
    },
    /// A group declared as a member of itself (direct cycle). Indirect
    /// cycles are caught at evaluation time via the visited-set guard.
    #[error("group `{name}` is a member of itself")]
    SelfReference { name: String },
}

/// A declared witness: a name bound to a 32-byte Ed25519 pubkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub name: String,
    pub pubkey: [u8; 32],
    pub url: Option<String>,
}

/// A declared log key (grammar completeness; not used by the quorum
/// evaluator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    pub pubkey: [u8; 32],
    pub url: Option<String>,
}

/// The threshold of a [`Group`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Threshold {
    /// Every member must be satisfied.
    All,
    /// At least one member must be satisfied.
    Any,
    /// At least `k` distinct members must be satisfied.
    K(usize),
}

/// A named group of members (witness names or nested group names) plus
/// a threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    pub threshold: Threshold,
    pub members: Vec<String>,
}

/// A fully-parsed Sigsum policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub logs: Vec<Log>,
    /// Witnesses by name.
    pub witnesses: HashMap<String, Witness>,
    /// Groups by name.
    pub groups: HashMap<String, Group>,
    /// The top-level reference (witness or group name) the whole
    /// policy is satisfied by.
    pub quorum: String,
}

impl Policy {
    /// Parse a policy from its text form. Blank lines and `#` comments
    /// are ignored. Tokens are whitespace-separated.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let mut logs = Vec::new();
        let mut witnesses: HashMap<String, Witness> = HashMap::new();
        let mut groups: HashMap<String, Group> = HashMap::new();
        let mut quorum: Option<String> = None;
        let mut quorum_count = 0usize;

        for (idx, raw) in text.lines().enumerate() {
            let line = idx + 1;
            // Strip comments (everything after an unquoted '#') and trim.
            let content = match raw.find('#') {
                Some(pos) => &raw[..pos],
                None => raw,
            };
            let tokens: Vec<&str> = content.split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }
            match tokens[0] {
                "log" => {
                    // log <pubkey> [url]
                    if tokens.len() < 2 {
                        return Err(PolicyError::TooFewArgs {
                            line,
                            keyword: "log".into(),
                        });
                    }
                    let pubkey = parse_pubkey(line, tokens[1])?;
                    let url = tokens.get(2).map(|s| s.to_string());
                    logs.push(Log { pubkey, url });
                }
                "witness" => {
                    // witness <name> <pubkey> [url]
                    if tokens.len() < 3 {
                        return Err(PolicyError::TooFewArgs {
                            line,
                            keyword: "witness".into(),
                        });
                    }
                    let name = tokens[1].to_string();
                    if witnesses.contains_key(&name) || groups.contains_key(&name) {
                        return Err(PolicyError::DuplicateName { line, name });
                    }
                    let pubkey = parse_pubkey(line, tokens[2])?;
                    let url = tokens.get(3).map(|s| s.to_string());
                    witnesses.insert(name.clone(), Witness { name, pubkey, url });
                }
                "group" => {
                    // group <name> all|any|<k> <member>...
                    if tokens.len() < 4 {
                        return Err(PolicyError::TooFewArgs {
                            line,
                            keyword: "group".into(),
                        });
                    }
                    let name = tokens[1].to_string();
                    if witnesses.contains_key(&name) || groups.contains_key(&name) {
                        return Err(PolicyError::DuplicateName { line, name });
                    }
                    let threshold = match tokens[2] {
                        "all" => Threshold::All,
                        "any" => Threshold::Any,
                        k => {
                            let parsed =
                                k.parse::<usize>().map_err(|_| PolicyError::BadThreshold {
                                    line,
                                    value: k.to_string(),
                                })?;
                            Threshold::K(parsed)
                        }
                    };
                    let members: Vec<String> = tokens[3..].iter().map(|s| s.to_string()).collect();
                    // Direct self-reference is always a bug.
                    if members.iter().any(|m| m == &name) {
                        return Err(PolicyError::SelfReference { name });
                    }
                    // A decimal threshold larger than the member count is
                    // unsatisfiable; reject early so an operator notices
                    // the typo instead of silently never-quorum-ing.
                    if let Threshold::K(k) = threshold {
                        if k > members.len() {
                            return Err(PolicyError::ThresholdExceedsMembers {
                                line,
                                name,
                                k,
                                members: members.len(),
                            });
                        }
                    }
                    groups.insert(
                        name.clone(),
                        Group {
                            name,
                            threshold,
                            members,
                        },
                    );
                }
                "quorum" => {
                    // quorum <name>
                    if tokens.len() < 2 {
                        return Err(PolicyError::TooFewArgs {
                            line,
                            keyword: "quorum".into(),
                        });
                    }
                    quorum = Some(tokens[1].to_string());
                    quorum_count += 1;
                }
                other => {
                    return Err(PolicyError::UnknownKeyword {
                        line,
                        keyword: other.to_string(),
                    });
                }
            }
        }

        if quorum_count != 1 {
            return Err(PolicyError::QuorumCount {
                found: quorum_count,
            });
        }
        let quorum = quorum.expect("quorum_count == 1 implies Some");

        let policy = Policy {
            logs,
            witnesses,
            groups,
            quorum,
        };
        // Validate every reference (quorum + each group member) resolves
        // to a declared witness or group. This turns a typo'd member
        // name into a hard parse error rather than a silently-false
        // quorum.
        policy.validate_references()?;
        Ok(policy)
    }

    /// Check that every group member and the quorum target name a
    /// declared witness or group.
    fn validate_references(&self) -> Result<(), PolicyError> {
        let resolves =
            |name: &str| self.witnesses.contains_key(name) || self.groups.contains_key(name);
        if !resolves(&self.quorum) {
            return Err(PolicyError::UnknownReference {
                name: self.quorum.clone(),
            });
        }
        for group in self.groups.values() {
            for member in &group.members {
                if !resolves(member) {
                    return Err(PolicyError::UnknownReference {
                        name: member.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Evaluate the quorum against the SET OF WITNESS NAMES whose
    /// cosignatures already cryptographically verified.
    ///
    /// **The caller MUST only include names whose Ed25519 signatures
    /// were checked against the witness's pubkey.** This evaluator does
    /// no crypto; it counts distinct satisfied members against the
    /// thresholds. A witness appearing twice in `valid_witnesses` is
    /// counted once (the input is treated as a set).
    ///
    /// Returns `true` iff the top-level quorum reference is satisfied.
    pub fn is_satisfied(&self, valid_witnesses: &HashSet<String>) -> bool {
        let mut visited = HashSet::new();
        self.eval(&self.quorum, valid_witnesses, &mut visited)
    }

    /// Recursive evaluator. `visited` guards against indirect group
    /// cycles (a group reachable from itself) — a cycle short-circuits
    /// to `false` rather than recursing forever.
    fn eval(&self, name: &str, valid: &HashSet<String>, visited: &mut HashSet<String>) -> bool {
        // A witness leaf: satisfied iff it produced a valid cosig.
        if self.witnesses.contains_key(name) {
            return valid.contains(name);
        }
        // A group: evaluate members against the threshold.
        if let Some(group) = self.groups.get(name) {
            // Cycle guard: if we're already inside this group, treat as
            // unsatisfiable to avoid infinite recursion.
            if !visited.insert(name.to_string()) {
                return false;
            }
            // Count DISTINCT satisfied members. De-dup member names so a
            // group that lists the same member twice can't double-count.
            let satisfied: usize = {
                let mut seen = HashSet::new();
                group
                    .members
                    .iter()
                    .filter(|m| seen.insert((*m).clone()))
                    .filter(|m| self.eval(m, valid, visited))
                    .count()
            };
            // De-dup member count for the `all` denominator too.
            let distinct_members = {
                let mut seen = HashSet::new();
                group
                    .members
                    .iter()
                    .filter(|m| seen.insert((*m).clone()))
                    .count()
            };
            visited.remove(name);
            return match group.threshold {
                Threshold::Any => satisfied >= 1,
                Threshold::All => satisfied == distinct_members,
                Threshold::K(k) => satisfied >= k,
            };
        }
        // Dangling reference (should be caught at parse time) → not
        // satisfied. Fail closed.
        false
    }
}

/// Parse a 32-byte Ed25519 pubkey from hex.
fn parse_pubkey(line: usize, hex_str: &str) -> Result<[u8; 32], PolicyError> {
    let bytes = hex::decode(hex_str).map_err(|_| PolicyError::BadPubkey {
        line,
        value: hex_str.to_string(),
    })?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| PolicyError::BadPubkey {
            line,
            value: hex_str.to_string(),
        })?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> String {
        hex::encode([b; 32])
    }

    fn set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_witnesses_and_quorum() {
        let text = format!(
            "witness w1 {}\nwitness w2 {}\ngroup g any w1 w2\nquorum g\n",
            pk(1),
            pk(2)
        );
        let p = Policy::parse(&text).unwrap();
        assert_eq!(p.witnesses.len(), 2);
        assert_eq!(p.groups.len(), 1);
        assert_eq!(p.quorum, "g");
        assert_eq!(p.witnesses["w1"].pubkey, [1u8; 32]);
    }

    #[test]
    fn parses_log_and_url() {
        let text = format!(
            "log {} https://log.example/\nwitness w1 {} https://w1.example/\ngroup g any w1\nquorum g\n",
            pk(9),
            pk(1)
        );
        let p = Policy::parse(&text).unwrap();
        assert_eq!(p.logs.len(), 1);
        assert_eq!(p.logs[0].url.as_deref(), Some("https://log.example/"));
        assert_eq!(
            p.witnesses["w1"].url.as_deref(),
            Some("https://w1.example/")
        );
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let text = format!(
            "# a policy\n\nwitness w1 {}   # trailing comment\n\nquorum w1\n",
            pk(1)
        );
        let p = Policy::parse(&text).unwrap();
        assert_eq!(p.quorum, "w1");
    }

    #[test]
    fn any_satisfied_with_one() {
        let text = format!(
            "witness w1 {}\nwitness w2 {}\ngroup g any w1 w2\nquorum g\n",
            pk(1),
            pk(2)
        );
        let p = Policy::parse(&text).unwrap();
        assert!(p.is_satisfied(&set(&["w1"])));
        assert!(!p.is_satisfied(&set(&[])));
    }

    #[test]
    fn all_requires_every_member() {
        let text = format!(
            "witness w1 {}\nwitness w2 {}\ngroup g all w1 w2\nquorum g\n",
            pk(1),
            pk(2)
        );
        let p = Policy::parse(&text).unwrap();
        assert!(!p.is_satisfied(&set(&["w1"])));
        assert!(p.is_satisfied(&set(&["w1", "w2"])));
    }

    // ── NEGATIVE TEST 5: k of n with k-1 → NOT satisfied; k → satisfied;
    //    duplicate cosig from same witness counts once. ──────────────
    #[test]
    fn negative_test_5_k_of_n_threshold_and_dedup() {
        let text = format!(
            "witness w1 {}\nwitness w2 {}\nwitness w3 {}\ngroup g 2 w1 w2 w3\nquorum g\n",
            pk(1),
            pk(2),
            pk(3)
        );
        let p = Policy::parse(&text).unwrap();

        // (a) k-1 = 1 distinct valid cosig → NOT satisfied.
        assert!(
            !p.is_satisfied(&set(&["w1"])),
            "1 of 2 must NOT satisfy a k=2 group"
        );

        // (b) positive control: k = 2 distinct → satisfied.
        assert!(
            p.is_satisfied(&set(&["w1", "w2"])),
            "2 of 2 must satisfy a k=2 group"
        );

        // (c) duplicate cosig from the SAME witness counts once: even if
        //     the caller's set somehow only has w1, a HashSet input
        //     already de-dups, so {w1} stays below threshold. Prove the
        //     evaluator never double-counts a single witness by checking
        //     that {w1} (one distinct witness) is still below k=2.
        let mut dup = HashSet::new();
        dup.insert("w1".to_string());
        dup.insert("w1".to_string()); // no-op on a set
        assert_eq!(dup.len(), 1);
        assert!(!p.is_satisfied(&dup), "one witness can't satisfy k=2");
    }

    #[test]
    fn nested_groups_evaluate() {
        // Top quorum requires both subgroup-a (any of w1,w2) AND w3.
        let text = format!(
            "witness w1 {}\nwitness w2 {}\nwitness w3 {}\n\
             group suba any w1 w2\n\
             group top all suba w3\n\
             quorum top\n",
            pk(1),
            pk(2),
            pk(3)
        );
        let p = Policy::parse(&text).unwrap();
        // suba satisfied by w2, but w3 missing → top all fails.
        assert!(!p.is_satisfied(&set(&["w2"])));
        // suba via w1 + w3 → top all satisfied.
        assert!(p.is_satisfied(&set(&["w1", "w3"])));
    }

    #[test]
    fn witness_counted_once_even_listed_twice_in_group() {
        // A group that lists w1 twice must not let w1 satisfy a k=2.
        let text = format!(
            "witness w1 {}\nwitness w2 {}\ngroup g 2 w1 w1 w2\nquorum g\n",
            pk(1),
            pk(2)
        );
        let p = Policy::parse(&text).unwrap();
        assert!(
            !p.is_satisfied(&set(&["w1"])),
            "w1 listed twice must still count once → below k=2"
        );
        assert!(p.is_satisfied(&set(&["w1", "w2"])));
    }

    #[test]
    fn quorum_can_be_a_single_witness() {
        let text = format!("witness w1 {}\nquorum w1\n", pk(1));
        let p = Policy::parse(&text).unwrap();
        assert!(p.is_satisfied(&set(&["w1"])));
        assert!(!p.is_satisfied(&set(&["w2"])));
    }

    #[test]
    fn rejects_unknown_reference() {
        let text = format!("witness w1 {}\ngroup g any w1 ghost\nquorum g\n", pk(1));
        let err = Policy::parse(&text).unwrap_err();
        assert!(matches!(err, PolicyError::UnknownReference { .. }));
    }

    #[test]
    fn rejects_missing_quorum() {
        let text = format!("witness w1 {}\n", pk(1));
        let err = Policy::parse(&text).unwrap_err();
        assert!(matches!(err, PolicyError::QuorumCount { found: 0 }));
    }

    #[test]
    fn rejects_two_quorum_lines() {
        let text = format!("witness w1 {}\nquorum w1\nquorum w1\n", pk(1));
        let err = Policy::parse(&text).unwrap_err();
        assert!(matches!(err, PolicyError::QuorumCount { found: 2 }));
    }

    #[test]
    fn rejects_bad_pubkey() {
        let text = "witness w1 deadbeef\nquorum w1\n";
        let err = Policy::parse(text).unwrap_err();
        assert!(matches!(err, PolicyError::BadPubkey { .. }));
    }

    #[test]
    fn rejects_threshold_exceeding_members() {
        let text = format!("witness w1 {}\ngroup g 3 w1\nquorum g\n", pk(1));
        let err = Policy::parse(&text).unwrap_err();
        assert!(matches!(err, PolicyError::ThresholdExceedsMembers { .. }));
    }

    #[test]
    fn rejects_duplicate_name() {
        let text = format!("witness w1 {}\nwitness w1 {}\nquorum w1\n", pk(1), pk(2));
        let err = Policy::parse(&text).unwrap_err();
        assert!(matches!(err, PolicyError::DuplicateName { .. }));
    }

    #[test]
    fn rejects_self_referential_group() {
        let text = format!("witness w1 {}\ngroup g any g w1\nquorum g\n", pk(1));
        let err = Policy::parse(&text).unwrap_err();
        assert!(matches!(err, PolicyError::SelfReference { .. }));
    }

    #[test]
    fn indirect_cycle_fails_closed_not_infinite_loop() {
        // a → b → a. validate_references passes (both declared); the
        // eval-time visited guard must prevent infinite recursion and
        // return false.
        let text = format!(
            "witness w1 {}\ngroup a any b w1\ngroup b any a\nquorum a\n",
            pk(1)
        );
        let p = Policy::parse(&text).unwrap();
        // a's `any` is satisfied by w1 regardless of the cycle.
        assert!(p.is_satisfied(&set(&["w1"])));
        // With no valid witnesses, the cycle must not hang and must be
        // unsatisfied.
        assert!(!p.is_satisfied(&set(&[])));
    }
}
