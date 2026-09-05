//! The **approved tool surface** as a signed, attenuating dimension of the pod
//! certificate (#2485).
//!
//! A pod's certificate already carries a `CapabilityLattice` whose
//! `extensions` map is signed (`canonical_permissions_hash` covers it, #2463)
//! and meets as `min` per key with an ABSENT key read as `Never`
//! (`CapabilityLattice::meet`, fail-closed; entries that fall to `Never` are
//! dropped). Encoding each approved tool as an extension key therefore gives,
//! with no new lattice code, that a child may DROP a tool but can never ADD
//! one: `min(absent = Never, Always) = Never`. Narrowing across hops is
//! `mint_child`'s existing meet, not a new rule, and the surface is inside
//! every signature and the fingerprint.
//!
//! # The marker, and why it exists
//!
//! Because the meet drops `Never` entries, "constrained to nothing" and
//! "unconstrained" would both look like an empty map — and a child that asked
//! for every approved tool at a DIFFERENT digest would come out with no keys
//! and read as unconstrained. So a surface always carries the bare
//! [`TOOL_SURFACE_MARKER`] key at `Always`: present means the dimension is IN
//! USE (possibly approving nothing); absent, together with no tool keys, means
//! a certificate minted before this dimension existed, which constrains
//! nothing. Two rules keep the marker honest across hops, both applied by
//! `LatticeCertificate::delegate_with_scope_using_key`:
//!
//! - a request that says nothing about tools **inherits** its parent's
//!   surface ([`inherit_surface`]), so an ordinary sub-pod keeps its parent's
//!   tools rather than silently keeping none or escaping the dimension;
//! - a child whose effective lattice has lost the marker while its parent had
//!   it is **refused** ([`surface_preserved`]), so the dimension cannot be
//!   shed by asking for it at `Never`.
//!
//! The key binds the tool NAME and the DIGEST of the descriptor the approver
//! saw — `ToolSchemaRegistry::hash_schema(name, description, parameters)`, the
//! same digest `mcp-guard` pins and signed manifests carry — so a server that
//! serves the approved name with a different descriptor is not approved. The
//! consumer is `mcp-guard`, which verifies the pod certificate from the
//! environment the node delivers it in and refuses any served tool the surface
//! does not approve. The root minter states the FULL surface at pod-create.

use crate::{CapabilityLattice, CapabilityLevel, ExtensionOperation};
use std::collections::BTreeMap;

/// Prefix of every tool-surface extension key, and — as a key on its own —
/// the marker that the surface dimension is in use.
pub const TOOL_SURFACE_MARKER: &str = "mcp-tool/";

/// The extension key approving `name` at descriptor digest `digest_hex`.
#[must_use]
pub fn surface_key(name: &str, digest_hex: &str) -> ExtensionOperation {
    ExtensionOperation::new(format!(
        "{TOOL_SURFACE_MARKER}{name}/{}",
        digest_hex.trim().to_ascii_lowercase()
    ))
}

fn marker() -> ExtensionOperation {
    ExtensionOperation::new(TOOL_SURFACE_MARKER)
}

fn is_surface_key(key: &ExtensionOperation) -> bool {
    key.0.starts_with(TOOL_SURFACE_MARKER)
}

/// Approve `name` at `digest_hex` in `caps` (level `Always`), marking the
/// surface as in use.
pub fn approve_tool(caps: &mut CapabilityLattice, name: &str, digest_hex: &str) {
    caps.extensions.insert(marker(), CapabilityLevel::Always);
    caps.extensions
        .insert(surface_key(name, digest_hex), CapabilityLevel::Always);
}

/// Mark the surface as in use without approving anything (a surface that
/// approves no tool at all).
pub fn mark_surface(caps: &mut CapabilityLattice) {
    caps.extensions.insert(marker(), CapabilityLevel::Always);
}

/// Does `caps` carry the surface dimension at all (the marker or any tool
/// key above `Never`)?
#[must_use]
pub fn has_surface(caps: &CapabilityLattice) -> bool {
    caps.extensions
        .iter()
        .any(|(k, l)| is_surface_key(k) && *l != CapabilityLevel::Never)
}

/// The surface `caps` carries: `None` when the dimension is unset (nothing
/// is constrained); otherwise `name → digest` for every tool above `Never`,
/// possibly empty (constrained to nothing).
#[must_use]
pub fn approved_tools(caps: &CapabilityLattice) -> Option<BTreeMap<String, String>> {
    if !has_surface(caps) {
        return None;
    }
    let mut out = BTreeMap::new();
    for (key, level) in &caps.extensions {
        if *level == CapabilityLevel::Never {
            continue;
        }
        let Some(rest) = key.0.strip_prefix(TOOL_SURFACE_MARKER) else {
            continue;
        };
        if let Some((name, digest)) = rest.rsplit_once('/') {
            out.insert(name.to_string(), digest.to_string());
        }
    }
    Some(out)
}

/// A request that says nothing about tools inherits its parent's surface:
/// the parent's marker and tool keys are copied in at `Always`, so the meet
/// keeps exactly the parent's tools. A request that names tools but not the
/// marker gets the marker. A request under a parent with no surface is left
/// alone (there is nothing to inherit, and the meet drops whatever it asked
/// for).
pub fn inherit_surface(requested: &mut CapabilityLattice, parent: &CapabilityLattice) {
    if !has_surface(parent) {
        return;
    }
    if !has_surface(requested) {
        for (key, level) in &parent.extensions {
            if is_surface_key(key) {
                requested.extensions.insert(key.clone(), *level);
            }
        }
    }
    requested
        .extensions
        .entry(marker())
        .or_insert(CapabilityLevel::Always);
}

/// Did a hop keep the surface dimension it was under? `true` unless the
/// parent had a surface and the child has none.
#[must_use]
pub fn surface_preserved(child: &CapabilityLattice, parent: &CapabilityLattice) -> bool {
    !has_surface(parent) || has_surface(child)
}

/// A served tool against the surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceVerdict {
    /// The certificate carries no surface: nothing to check against.
    Unconstrained,
    /// Name and digest are approved.
    Approved,
    /// The name is not approved, or is approved at a different descriptor.
    NotApproved,
}

/// Is the served `(name, digest_hex)` on the surface?
#[must_use]
pub fn admits(caps: &CapabilityLattice, name: &str, digest_hex: &str) -> SurfaceVerdict {
    match approved_tools(caps) {
        None => SurfaceVerdict::Unconstrained,
        Some(approved) => match approved.get(name) {
            Some(d) if d.eq_ignore_ascii_case(digest_hex.trim()) => SurfaceVerdict::Approved,
            _ => SurfaceVerdict::NotApproved,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(tools: &[(&str, &str)]) -> CapabilityLattice {
        let mut caps = CapabilityLattice::permissive();
        for (n, d) in tools {
            approve_tool(&mut caps, n, d);
        }
        caps
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(n, d)| (n.to_string(), d.to_string()))
            .collect()
    }

    #[test]
    fn a_surface_admits_its_tools_at_their_digests_and_nothing_else() {
        let caps = surface(&[("read_file", "AB"), ("list_dir", "cd")]);
        assert_eq!(admits(&caps, "read_file", "ab"), SurfaceVerdict::Approved);
        assert_eq!(
            admits(&caps, "read_file", "ff"),
            SurfaceVerdict::NotApproved
        );
        assert_eq!(
            admits(&caps, "exfiltrate", "ab"),
            SurfaceVerdict::NotApproved
        );
        assert_eq!(
            admits(&CapabilityLattice::permissive(), "anything", "00"),
            SurfaceVerdict::Unconstrained,
            "no surface keys: the dimension is unset"
        );
        let mut nothing = CapabilityLattice::permissive();
        mark_surface(&mut nothing);
        assert_eq!(
            admits(&nothing, "anything", "00"),
            SurfaceVerdict::NotApproved,
            "a marked surface that approves nothing is constrained to nothing"
        );
    }

    /// The property #2485 asks for: across a hop, the surface can only narrow.
    /// Nothing here is new lattice code — it is `CapabilityLattice::meet` — and
    /// the marker is what keeps "constrained to nothing" distinct from
    /// "unconstrained" after the meet drops `Never` entries.
    #[test]
    fn a_child_surface_is_the_meet_and_can_only_narrow() {
        let parent = surface(&[("a", "11"), ("b", "22")]);

        let greedy = surface(&[("a", "11"), ("b", "22"), ("c", "33")]);
        let child = parent.meet(&greedy);
        assert_eq!(
            approved_tools(&child).unwrap(),
            map(&[("a", "11"), ("b", "22")]),
            "c was never approved above: min(Never, Always) = Never"
        );
        assert_eq!(admits(&child, "c", "33"), SurfaceVerdict::NotApproved);
        assert!(child.leq(&parent));

        let modest = surface(&[("a", "11")]);
        assert_eq!(
            approved_tools(&parent.meet(&modest)).unwrap(),
            map(&[("a", "11")])
        );

        // Same name, different digest, is a different key: NOT approved, and
        // the marker survives so the child is constrained to nothing rather
        // than reading as unconstrained.
        let drifted = surface(&[("a", "99")]);
        let child = parent.meet(&drifted);
        assert!(has_surface(&child), "the marker survives the meet");
        assert_eq!(approved_tools(&child).unwrap(), BTreeMap::new());

        // A parent with NO surface is unconstrained, and stays so: a child
        // cannot introduce the dimension below it.
        let unset = CapabilityLattice::permissive();
        assert_eq!(approved_tools(&unset.meet(&modest)), None);
    }

    /// A request that says nothing about tools keeps its parent's surface; one
    /// that names tools gets the marker; one under an unconstrained parent is
    /// untouched.
    #[test]
    fn a_silent_request_inherits_the_parent_surface() {
        let parent = surface(&[("a", "11"), ("b", "22")]);

        let mut silent = CapabilityLattice::permissive();
        inherit_surface(&mut silent, &parent);
        assert_eq!(
            approved_tools(&parent.meet(&silent)).unwrap(),
            map(&[("a", "11"), ("b", "22")])
        );

        let mut named = CapabilityLattice::permissive();
        named
            .extensions
            .insert(surface_key("a", "11"), CapabilityLevel::Always);
        inherit_surface(&mut named, &parent);
        assert!(named.extensions.contains_key(&marker()));
        assert_eq!(
            approved_tools(&parent.meet(&named)).unwrap(),
            map(&[("a", "11")])
        );

        let mut under_unset = CapabilityLattice::permissive();
        inherit_surface(&mut under_unset, &CapabilityLattice::permissive());
        assert!(under_unset.extensions.is_empty());
    }

    /// Asking for the marker at `Never` is the one way a request could shed
    /// the dimension; `surface_preserved` is what the delegation path checks.
    #[test]
    fn shedding_the_marker_is_detectable() {
        let parent = surface(&[("a", "11")]);
        let mut shed = CapabilityLattice::permissive();
        shed.extensions.insert(marker(), CapabilityLevel::Never);
        let child = parent.meet(&shed);
        assert!(!surface_preserved(&child, &parent));
        assert!(surface_preserved(
            &parent.meet(&surface(&[("a", "11")])),
            &parent
        ));
        assert!(surface_preserved(
            &CapabilityLattice::permissive(),
            &CapabilityLattice::permissive()
        ));
    }
}
