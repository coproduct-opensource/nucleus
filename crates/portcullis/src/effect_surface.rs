//! The **granted effect set** as a signed, attenuating dimension of the pod
//! certificate (ADR 0004, milestone 2).
//!
//! A task grant names semantic effects (`github/read-ci-logs`,
//! `shell/run-tests`). When the grant is sealed, every effect it grants
//! becomes an `extensions` key on the certificate's root lattice, exactly as
//! [`crate::tool_surface`] encodes approved MCP tools: the key is inside every
//! signature and the fingerprint, and because `CapabilityLattice::meet` reads
//! an ABSENT key as `Never`, a child certificate may **drop** an effect but
//! can never **add** one. Narrowing across hops is the existing meet, not a
//! new rule.
//!
//! The marker follows the same reasoning as the tool surface's. The meet
//! drops `Never` entries, so "granted nothing" and "unconstrained" would both
//! be an empty map; the bare [`EFFECT_SURFACE_MARKER`] key at `Always` says
//! the dimension is in use. Two rules keep it honest across hops, both
//! applied by `LatticeCertificate::delegate_with_scope_using_key`:
//!
//! - a request that says nothing about effects **inherits** its parent's
//!   ([`inherit_effects`]), so an ordinary sub-pod keeps the effects it was
//!   delegated under rather than escaping the dimension;
//! - a child whose effective lattice has lost the marker while its parent had
//!   it is **refused** ([`effects_preserved`]).
//!
//! Keys are `effect/<plugin>/<id>`; the id grammar is the catalog's
//! (`[a-z0-9-]+` per segment). This module is deliberately independent of the
//! `spec` feature that compiles the catalog: a verifier that never loads a
//! catalog can still read which effects a certificate grants.

use crate::{CapabilityLattice, CapabilityLevel, ExtensionOperation};
use std::collections::BTreeSet;

/// Prefix of every effect key, and — as a key on its own — the marker that
/// the effect dimension is in use.
pub const EFFECT_SURFACE_MARKER: &str = "effect/";

/// Is `effect` a well-formed `<plugin>/<id>` (lowercase, digits, hyphens)?
#[must_use]
pub fn is_well_formed(effect: &str) -> bool {
    let Some((plugin, id)) = effect.split_once('/') else {
        return false;
    };
    let ok = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    ok(plugin) && ok(id)
}

/// The extension key granting `effect` (`<plugin>/<id>`).
#[must_use]
pub fn effect_key(effect: &str) -> ExtensionOperation {
    ExtensionOperation::new(format!("{EFFECT_SURFACE_MARKER}{}", effect.trim()))
}

fn marker() -> ExtensionOperation {
    ExtensionOperation::new(EFFECT_SURFACE_MARKER)
}

fn is_effect_key(key: &ExtensionOperation) -> bool {
    key.0.starts_with(EFFECT_SURFACE_MARKER)
}

/// Grant `effect` in `caps` (level `Always`), marking the dimension as in
/// use. Returns `false`, granting nothing, if the id is malformed.
pub fn grant_effect(caps: &mut CapabilityLattice, effect: &str) -> bool {
    let effect = effect.trim();
    if !is_well_formed(effect) {
        return false;
    }
    caps.extensions.insert(marker(), CapabilityLevel::Always);
    caps.extensions
        .insert(effect_key(effect), CapabilityLevel::Always);
    true
}

/// Mark the dimension as in use without granting anything.
pub fn mark_effects(caps: &mut CapabilityLattice) {
    caps.extensions.insert(marker(), CapabilityLevel::Always);
}

/// Does `caps` carry the effect dimension at all (the marker or any effect
/// key above `Never`)?
#[must_use]
pub fn has_effects(caps: &CapabilityLattice) -> bool {
    caps.extensions
        .iter()
        .any(|(k, l)| is_effect_key(k) && *l != CapabilityLevel::Never)
}

/// The effects `caps` grants: `None` when the dimension is unset (nothing is
/// constrained); otherwise every `<plugin>/<id>` above `Never`, possibly
/// empty (granted nothing).
#[must_use]
pub fn granted_effects(caps: &CapabilityLattice) -> Option<BTreeSet<String>> {
    if !has_effects(caps) {
        return None;
    }
    let mut out = BTreeSet::new();
    for (key, level) in &caps.extensions {
        if *level == CapabilityLevel::Never {
            continue;
        }
        let Some(rest) = key.0.strip_prefix(EFFECT_SURFACE_MARKER) else {
            continue;
        };
        if is_well_formed(rest) {
            out.insert(rest.to_string());
        }
    }
    Some(out)
}

/// A request that says nothing about effects inherits its parent's: the
/// parent's marker and effect keys are copied in at `Always`, so the meet
/// keeps exactly the parent's effects. A request that names effects but not
/// the marker gets the marker. A request under a parent with no effects is
/// left alone.
pub fn inherit_effects(requested: &mut CapabilityLattice, parent: &CapabilityLattice) {
    if !has_effects(parent) {
        return;
    }
    if !has_effects(requested) {
        for (key, level) in &parent.extensions {
            if is_effect_key(key) {
                requested.extensions.insert(key.clone(), *level);
            }
        }
    }
    requested
        .extensions
        .entry(marker())
        .or_insert(CapabilityLevel::Always);
}

/// Did a hop keep the effect dimension it was under? `true` unless the
/// parent had effects and the child has none.
#[must_use]
pub fn effects_preserved(child: &CapabilityLattice, parent: &CapabilityLattice) -> bool {
    !has_effects(parent) || has_effects(child)
}

/// An effect against the grant a certificate carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectVerdict {
    /// The certificate carries no effect dimension: nothing to check against.
    Unconstrained,
    /// The effect is granted.
    Granted,
    /// The dimension is in use and the effect is not in it.
    NotGranted,
}

/// Is `effect` granted by `caps`?
#[must_use]
pub fn admits(caps: &CapabilityLattice, effect: &str) -> EffectVerdict {
    match granted_effects(caps) {
        None => EffectVerdict::Unconstrained,
        Some(granted) if granted.contains(effect.trim()) => EffectVerdict::Granted,
        Some(_) => EffectVerdict::NotGranted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(effects: &[&str]) -> CapabilityLattice {
        let mut caps = CapabilityLattice::permissive();
        for e in effects {
            assert!(grant_effect(&mut caps, e), "{e} is well-formed");
        }
        caps
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_grant_admits_its_effects_and_nothing_else() {
        let caps = with(&["github/read-ci-logs", "shell/run-tests"]);
        assert_eq!(admits(&caps, "shell/run-tests"), EffectVerdict::Granted);
        assert_eq!(admits(&caps, "git/push-branch"), EffectVerdict::NotGranted);
        assert_eq!(
            admits(&CapabilityLattice::permissive(), "anything/at-all"),
            EffectVerdict::Unconstrained,
            "no effect keys: the dimension is unset"
        );
        let mut nothing = CapabilityLattice::permissive();
        mark_effects(&mut nothing);
        assert_eq!(
            admits(&nothing, "shell/run-tests"),
            EffectVerdict::NotGranted,
            "a marked dimension that grants nothing is constrained to nothing"
        );
        assert_eq!(granted_effects(&nothing), Some(BTreeSet::new()));
    }

    #[test]
    fn malformed_ids_are_refused_and_never_stored() {
        let mut caps = CapabilityLattice::permissive();
        for bad in [
            "",
            "shell",
            "Shell/run",
            "shell/run tests",
            "a/b/c",
            "/x",
            "x/",
        ] {
            assert!(!grant_effect(&mut caps, bad), "{bad:?}");
        }
        assert!(caps.extensions.is_empty());
        // A malformed key smuggled in directly is not read back as granted.
        caps.extensions.insert(
            ExtensionOperation::new("effect/Bad Id"),
            CapabilityLevel::Always,
        );
        assert_eq!(granted_effects(&caps), Some(BTreeSet::new()));
    }

    /// Across a hop the set can only narrow: this is `CapabilityLattice::meet`,
    /// and the marker keeps "granted nothing" distinct from "unconstrained".
    #[test]
    fn a_child_grant_is_the_meet_and_can_only_narrow() {
        let parent = with(&["fs/read-workspace", "shell/run-tests"]);

        let greedy = with(&["fs/read-workspace", "shell/run-tests", "git/push-branch"]);
        let child = parent.meet(&greedy);
        assert_eq!(
            granted_effects(&child).unwrap(),
            set(&["fs/read-workspace", "shell/run-tests"]),
            "git/push-branch was never granted above: min(Never, Always) = Never"
        );
        assert!(child.leq(&parent));

        let modest = with(&["shell/run-tests"]);
        assert_eq!(
            granted_effects(&parent.meet(&modest)).unwrap(),
            set(&["shell/run-tests"])
        );

        let disjoint = with(&["web/search"]);
        let child = parent.meet(&disjoint);
        assert!(has_effects(&child), "the marker survives the meet");
        assert_eq!(granted_effects(&child).unwrap(), BTreeSet::new());

        let unset = CapabilityLattice::permissive();
        assert_eq!(granted_effects(&unset.meet(&modest)), None);
    }

    #[test]
    fn a_silent_request_inherits_the_parent_effects() {
        let parent = with(&["fs/read-workspace", "shell/run-tests"]);

        let mut silent = CapabilityLattice::permissive();
        inherit_effects(&mut silent, &parent);
        assert_eq!(
            granted_effects(&parent.meet(&silent)).unwrap(),
            set(&["fs/read-workspace", "shell/run-tests"])
        );

        let mut named = CapabilityLattice::permissive();
        named
            .extensions
            .insert(effect_key("shell/run-tests"), CapabilityLevel::Always);
        inherit_effects(&mut named, &parent);
        assert!(named.extensions.contains_key(&marker()));
        assert_eq!(
            granted_effects(&parent.meet(&named)).unwrap(),
            set(&["shell/run-tests"])
        );

        let mut under_unset = CapabilityLattice::permissive();
        inherit_effects(&mut under_unset, &CapabilityLattice::permissive());
        assert!(under_unset.extensions.is_empty());
    }

    #[test]
    fn shedding_the_marker_is_detectable() {
        let parent = with(&["shell/run-tests"]);
        let mut shed = CapabilityLattice::permissive();
        shed.extensions.insert(marker(), CapabilityLevel::Never);
        let child = parent.meet(&shed);
        assert!(!effects_preserved(&child, &parent));
        assert!(effects_preserved(
            &parent.meet(&with(&["shell/run-tests"])),
            &parent
        ));
        assert!(effects_preserved(
            &CapabilityLattice::permissive(),
            &CapabilityLattice::permissive()
        ));
    }

    /// The two surfaces share the `extensions` map and must not read each
    /// other's keys.
    #[test]
    fn effect_keys_and_tool_keys_do_not_alias() {
        let mut caps = CapabilityLattice::permissive();
        crate::tool_surface::approve_tool(&mut caps, "read_file", "ab");
        assert_eq!(granted_effects(&caps), None);
        grant_effect(&mut caps, "fs/read-workspace");
        assert_eq!(crate::tool_surface::approved_tools(&caps).unwrap().len(), 1);
        assert_eq!(granted_effects(&caps).unwrap().len(), 1);
    }
}
