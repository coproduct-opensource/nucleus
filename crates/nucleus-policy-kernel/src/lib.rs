//! **A self-proving reference monitor for agent actions** — a
//! "Cedar-of-agent-actions" whose defining property is *governance
//! monotonicity*: a policy can only ever get **more** restrictive, never
//! weaken itself.
//!
//! # Two functions, one keystone
//!
//! - [`decide`] is the reference monitor: given a [`Policy`] and a
//!   [`Request`], return `Allow`/`Deny` under **default-deny with
//!   Forbid-overrides-Permit** — the same evaluation order Cedar / AWS IAM
//!   use. It is a pure, deterministic function, so any party can re-run it to
//!   verify an authorization decision (recompute-verifiable; the PoHAW policy
//!   node commits the decision).
//!
//! - [`governance_monotone`] is the keystone. It proves — *exactly*, not by
//!   sampling — that an update `old → new` never grants a privilege `old`
//!   denied (`allowed(new) ⊆ allowed(old)`). This is the **anti-self-
//!   weakening** invariant a frozen verifier enforces (the GSAI / Löb
//!   discipline): even a system that rewrites its own policy cannot escalate
//!   its own authority, because the only admissible successor policies are
//!   non-weakening ones. A violating update is rejected *with the witness
//!   request it would newly allow* — a concrete privilege escalation.
//!
//! # Why the monotonicity check is sound, not heuristic
//!
//! For a fixed policy, [`decide`] depends on a request only through, for each
//! field, *which* `Exact` matchers (appearing anywhere in either policy) the
//! field value equals. So requests partition into finitely many equivalence
//! classes, one per assignment of "equals this exact / equals none" to each
//! field. [`representative_requests`] enumerates exactly one member of every
//! class — every `Exact` string in either policy, plus a *fresh* value that
//! equals none of them (exercising the `Any` wildcard). Checking
//! `allowed(new) ⊆ allowed(old)` over that finite domain therefore decides
//! the property over the **entire** (infinite) request space. No floats, no
//! `unsafe`, no zkVM toolchain in the default build.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Whether a matching rule permits or forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    /// Grant access (unless an overriding `Forbid` also matches).
    Permit,
    /// Deny access — overrides any `Permit` (the safe default of the two).
    Forbid,
}

/// A per-field pattern: the wildcard, or an exact value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Matcher {
    /// Matches any value.
    Any,
    /// Matches iff the field equals this string exactly.
    Exact(String),
}

impl Matcher {
    fn matches(&self, value: &str) -> bool {
        match self {
            Matcher::Any => true,
            Matcher::Exact(s) => s == value,
        }
    }
    /// The exact string this matcher names, if any (used to build the
    /// representative request domain).
    fn exact(&self) -> Option<&str> {
        match self {
            Matcher::Any => None,
            Matcher::Exact(s) => Some(s),
        }
    }
}

/// One policy rule: an [`Effect`] on a `(principal, action, resource)`
/// pattern. A rule matches a [`Request`] iff all three matchers match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub effect: Effect,
    pub principal: Matcher,
    pub action: Matcher,
    pub resource: Matcher,
}

impl Rule {
    fn matches(&self, r: &Request) -> bool {
        self.principal.matches(&r.principal)
            && self.action.matches(&r.action)
            && self.resource.matches(&r.resource)
    }
}

/// An ordered set of rules. Evaluation is order-independent (Forbid wins, then
/// Permit, else default-deny), but the order is preserved for a stable
/// commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Policy {
    pub rules: Vec<Rule>,
}

/// A concrete access request the monitor decides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub principal: String,
    pub action: String,
    pub resource: String,
}

/// The monitor's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
}

/// **The reference monitor.** Evaluate `request` against `policy` under
/// default-deny with Forbid-overrides-Permit: any matching `Forbid` denies;
/// otherwise any matching `Permit` allows; otherwise deny. Pure +
/// deterministic — recompute-verifiable.
pub fn decide(policy: &Policy, request: &Request) -> Decision {
    let mut permitted = false;
    for rule in &policy.rules {
        if rule.matches(request) {
            match rule.effect {
                Effect::Forbid => return Decision::Deny,
                Effect::Permit => permitted = true,
            }
        }
    }
    if permitted {
        Decision::Allow
    } else {
        Decision::Deny
    }
}

/// A string guaranteed not to be in `set` — used as the "matches no named
/// exact" representative for a field. Built by extending a sentinel until it
/// misses the (finite) set, so it always terminates.
fn fresh_not_in(set: &BTreeSet<String>) -> String {
    let mut candidate = String::from("\u{0}fresh");
    while set.contains(&candidate) {
        candidate.push('\u{0}');
    }
    candidate
}

/// The exact values a field takes across two policies' rules, by selector.
fn field_exacts<'a>(
    a: &'a Policy,
    b: &'a Policy,
    field: impl Fn(&'a Rule) -> &'a Matcher,
) -> BTreeSet<String> {
    a.rules
        .iter()
        .chain(b.rules.iter())
        .filter_map(|r| field(r).exact())
        .map(str::to_string)
        .collect()
}

/// One representative value per equivalence class of a field across `old` and
/// `new`: every `Exact` value either policy names, plus one fresh value that
/// equals none of them (the `Any`-only class).
fn field_representatives<'a>(
    old: &'a Policy,
    new: &'a Policy,
    field: impl Fn(&'a Rule) -> &'a Matcher,
) -> Vec<String> {
    let exacts = field_exacts(old, new, field);
    let fresh = fresh_not_in(&exacts);
    let mut out: Vec<String> = exacts.into_iter().collect();
    out.push(fresh);
    out
}

/// Every request needed to decide a policy property over `old` and `new`
/// exactly — the Cartesian product of the per-field representatives. Finite,
/// and sound+complete for this matcher language (see the module docs).
pub fn representative_requests(old: &Policy, new: &Policy) -> Vec<Request> {
    let principals = field_representatives(old, new, |r| &r.principal);
    let actions = field_representatives(old, new, |r| &r.action);
    let resources = field_representatives(old, new, |r| &r.resource);
    let mut out = Vec::with_capacity(principals.len() * actions.len() * resources.len());
    for p in &principals {
        for a in &actions {
            for res in &resources {
                out.push(Request {
                    principal: p.clone(),
                    action: a.clone(),
                    resource: res.clone(),
                });
            }
        }
    }
    out
}

/// **The keystone: anti-self-weakening.** Proves the update `old → new` is
/// non-weakening — every request `new` allows, `old` also allowed
/// (`allowed(new) ⊆ allowed(old)`). `Ok(())` if safe; `Err(request)` with the
/// **witness** the update would newly allow (a concrete privilege escalation)
/// otherwise.
///
/// Decided exactly over [`representative_requests`] (sound + complete for this
/// language), so a passing check holds for the entire infinite request space:
/// an autonomous system may rewrite its policy only into a successor that
/// grants strictly no new authority.
pub fn governance_monotone(old: &Policy, new: &Policy) -> Result<(), Request> {
    for req in representative_requests(old, new) {
        if decide(new, &req) == Decision::Allow && decide(old, &req) == Decision::Deny {
            return Err(req);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(p: &str, a: &str, r: &str) -> Request {
        Request {
            principal: p.into(),
            action: a.into(),
            resource: r.into(),
        }
    }
    fn permit(p: Matcher, a: Matcher, r: Matcher) -> Rule {
        Rule {
            effect: Effect::Permit,
            principal: p,
            action: a,
            resource: r,
        }
    }
    fn forbid(p: Matcher, a: Matcher, r: Matcher) -> Rule {
        Rule {
            effect: Effect::Forbid,
            principal: p,
            action: a,
            resource: r,
        }
    }
    use Matcher::{Any, Exact};
    fn ex(s: &str) -> Matcher {
        Exact(s.into())
    }

    #[test]
    fn default_deny() {
        let p = Policy::default();
        assert_eq!(decide(&p, &req("alice", "read", "doc")), Decision::Deny);
    }

    #[test]
    fn permit_allows_matching_only() {
        let p = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Any)],
        };
        assert_eq!(decide(&p, &req("alice", "read", "doc")), Decision::Allow);
        assert_eq!(decide(&p, &req("alice", "write", "doc")), Decision::Deny);
        assert_eq!(decide(&p, &req("bob", "read", "doc")), Decision::Deny);
    }

    #[test]
    fn forbid_overrides_permit_regardless_of_order() {
        let p1 = Policy {
            rules: vec![permit(Any, Any, Any), forbid(Any, ex("delete"), Any)],
        };
        let p2 = Policy {
            rules: vec![forbid(Any, ex("delete"), Any), permit(Any, Any, Any)],
        };
        for p in [&p1, &p2] {
            assert_eq!(decide(p, &req("alice", "read", "doc")), Decision::Allow);
            assert_eq!(decide(p, &req("alice", "delete", "doc")), Decision::Deny);
        }
    }

    #[test]
    fn identity_update_is_monotone() {
        let p = Policy {
            rules: vec![permit(Any, ex("read"), Any)],
        };
        assert_eq!(governance_monotone(&p, &p), Ok(()));
    }

    #[test]
    fn tightening_is_monotone() {
        let old = Policy {
            rules: vec![permit(Any, Any, Any)],
        };
        // Add a Forbid → strictly more restrictive.
        let new = Policy {
            rules: vec![permit(Any, Any, Any), forbid(Any, ex("delete"), Any)],
        };
        assert_eq!(governance_monotone(&old, &new), Ok(()));
    }

    #[test]
    fn adding_a_permit_for_a_denied_action_is_weakening() {
        let old = Policy {
            rules: vec![permit(Any, ex("read"), Any)],
        };
        // Now also permit "write" — grants authority old denied.
        let new = Policy {
            rules: vec![permit(Any, ex("read"), Any), permit(Any, ex("write"), Any)],
        };
        let witness = governance_monotone(&old, &new).unwrap_err();
        assert_eq!(witness.action, "write");
        assert_eq!(decide(&old, &witness), Decision::Deny);
        assert_eq!(decide(&new, &witness), Decision::Allow);
    }

    #[test]
    fn removing_a_forbid_is_weakening() {
        // old forbids deletes on top of a broad permit; removing the forbid
        // re-grants deletes.
        let old = Policy {
            rules: vec![permit(Any, Any, Any), forbid(Any, ex("delete"), Any)],
        };
        let new = Policy {
            rules: vec![permit(Any, Any, Any)],
        };
        let witness = governance_monotone(&old, &new).unwrap_err();
        assert_eq!(witness.action, "delete");
    }

    #[test]
    fn widening_a_principal_to_any_is_weakening() {
        // old permits only alice; new permits anyone → escalation.
        let old = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Any)],
        };
        let new = Policy {
            rules: vec![permit(Any, ex("read"), Any)],
        };
        let witness = governance_monotone(&old, &new).unwrap_err();
        // the witness is a non-alice principal reading.
        assert_ne!(witness.principal, "alice");
        assert_eq!(witness.action, "read");
    }

    #[test]
    fn narrowing_a_principal_is_monotone() {
        // old permits anyone to read; new permits only alice → tightening.
        let old = Policy {
            rules: vec![permit(Any, ex("read"), Any)],
        };
        let new = Policy {
            rules: vec![permit(ex("alice"), ex("read"), Any)],
        };
        assert_eq!(governance_monotone(&old, &new), Ok(()));
    }

    #[test]
    fn decide_is_deterministic_and_serializable() {
        let p = Policy {
            rules: vec![permit(Any, ex("read"), Any)],
        };
        let r = req("alice", "read", "doc");
        assert_eq!(decide(&p, &r), decide(&p, &r));
        // round-trips (the policy node commits these).
        let bytes = serde_json::to_vec(&p).unwrap();
        let back: Policy = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(p, back);
    }
}
