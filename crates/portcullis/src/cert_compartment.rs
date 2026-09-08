//! The pod's **compartment** as a signed, narrow-only dimension of the pod
//! certificate (#2484).
//!
//! `portcullis_core::compartment::Compartment` is a total order
//! (`Research < Draft < Execute < Breakglass`), each level a capability
//! ceiling. Until now nothing on the live path carried one. Here it rides
//! the certificate's signed `extensions` map the same way the tool surface
//! does (`crate::tool_surface`), so the node sets it at pod-create, it is
//! inside every signature and the fingerprint, and a hop can only lower it.
//!
//! # Encoding: the down-set
//!
//! The meet on extensions is `min` per key with an absent key read as
//! `Never`, and `verify_certificate` requires each block `leq` its parent —
//! a child may not carry a key its parent lacks. A single `compartment/draft`
//! key would therefore be dropped by the meet when the parent says
//! `compartment/execute`, erasing a legitimate narrowing. So a compartment
//! `c` is written as the keys of EVERY compartment `≤ c` (`compartment/
//! research`, `compartment/draft`, ... up to `c`), all at `Always`. The pod's
//! compartment is the highest key present. A child that asks for a lower
//! compartment keeps a subset of its parent's keys — the meet does the
//! narrowing and `leq` holds; one that asks for a higher compartment is
//! refused by the delegation path before the meet (`CompartmentEscalated`),
//! not silently clamped; a silent request inherits its parent's.
//!
//! # The ceiling is applied
//!
//! A compartment is not a label: the delegation path (and the root mint)
//! meets the requested capabilities with `Compartment::ceiling()` — on the
//! named dimensions only, so the extension keys that carry the surface and
//! the compartment itself survive — before the chain meet. A pod in
//! `research` therefore holds a certificate whose effective lattice cannot
//! write or execute, whatever it asked for, and the tool-proxy's kernel is
//! built from that certificate.
//!
//! The second enforcement point is `mcp-guard`: a tool whose signed manifest
//! lists `allowed_compartments` is refused at `tools/list` (and so at
//! `tools/call`) when the pod's compartment is not among them.

pub use portcullis_core::compartment::Compartment;

use crate::{CapabilityLattice, CapabilityLevel, ExtensionOperation};

/// Prefix of every compartment extension key.
pub const COMPARTMENT_PREFIX: &str = "compartment/";

const ALL: [Compartment; 4] = [
    Compartment::Research,
    Compartment::Draft,
    Compartment::Execute,
    Compartment::Breakglass,
];

fn key(c: Compartment) -> ExtensionOperation {
    ExtensionOperation::new(format!("{COMPARTMENT_PREFIX}{c}"))
}

/// Set `caps` to compartment `c`: every compartment key `≤ c` at `Always`,
/// every higher one removed.
pub fn set_compartment(caps: &mut CapabilityLattice, c: Compartment) {
    for other in ALL {
        let k = key(other);
        if other <= c {
            caps.extensions.insert(k, CapabilityLevel::Always);
        } else {
            caps.extensions.remove(&k);
        }
    }
}

/// The compartment `caps` carries: the highest compartment key above
/// `Never`, or `None` when the dimension is unset.
#[must_use]
pub fn compartment_of(caps: &CapabilityLattice) -> Option<Compartment> {
    ALL.into_iter().rev().find(|c| {
        caps.extensions
            .get(&key(*c))
            .is_some_and(|l| *l != CapabilityLevel::Never)
    })
}

/// A request that says nothing about compartments inherits its parent's.
pub fn inherit_compartment(requested: &mut CapabilityLattice, parent: &CapabilityLattice) {
    if compartment_of(requested).is_none() {
        if let Some(p) = compartment_of(parent) {
            set_compartment(requested, p);
        }
    }
}

/// Meet the NAMED capability dimensions of `caps` with `c`'s ceiling, keeping
/// every extension key exactly as it is (a plain `meet` with the ceiling,
/// whose extension map is empty, would drop them all to `Never`).
pub fn clamp_to_ceiling(caps: &mut CapabilityLattice, c: Compartment) {
    // `Compartment::ceiling` is portcullis-core's lattice (the same thirteen
    // named dimensions, no extension map); clamp each named dimension and
    // leave `extensions` untouched.
    let ceiling = c.ceiling();
    caps.read_files = caps.read_files.min(ceiling.read_files);
    caps.write_files = caps.write_files.min(ceiling.write_files);
    caps.edit_files = caps.edit_files.min(ceiling.edit_files);
    caps.run_bash = caps.run_bash.min(ceiling.run_bash);
    caps.glob_search = caps.glob_search.min(ceiling.glob_search);
    caps.grep_search = caps.grep_search.min(ceiling.grep_search);
    caps.web_search = caps.web_search.min(ceiling.web_search);
    caps.web_fetch = caps.web_fetch.min(ceiling.web_fetch);
    caps.git_commit = caps.git_commit.min(ceiling.git_commit);
    caps.git_push = caps.git_push.min(ceiling.git_push);
    caps.create_pr = caps.create_pr.min(ceiling.create_pr);
    caps.manage_pods = caps.manage_pods.min(ceiling.manage_pods);
    caps.spawn_agent = caps.spawn_agent.min(ceiling.spawn_agent);
}

/// Why a hop's compartment is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompartmentHopError {
    /// The child asked for a higher compartment than its parent holds.
    Escalated {
        /// The parent's compartment.
        from: Compartment,
        /// The child's requested compartment.
        to: Compartment,
    },
    /// The parent holds a compartment and the child's effective lattice has
    /// none.
    Dropped,
}

impl std::fmt::Display for CompartmentHopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Escalated { from, to } => {
                write!(f, "requested compartment {to} is above the parent's {from}")
            }
            Self::Dropped => write!(f, "requested lattice sheds the parent's compartment"),
        }
    }
}

/// Before the meet: may `requested` follow `parent`? Only downward or equal.
///
/// # Errors
/// [`CompartmentHopError::Escalated`] when the request is above the parent.
pub fn check_request(
    requested: &CapabilityLattice,
    parent: &CapabilityLattice,
) -> Result<(), CompartmentHopError> {
    match (compartment_of(parent), compartment_of(requested)) {
        (Some(from), Some(to)) if to > from => Err(CompartmentHopError::Escalated { from, to }),
        _ => Ok(()),
    }
}

/// After the meet: did the hop keep the dimension it was under?
///
/// # Errors
/// [`CompartmentHopError::Dropped`] when the parent had a compartment and the
/// child has none.
pub fn check_effective(
    effective: &CapabilityLattice,
    parent: &CapabilityLattice,
) -> Result<(), CompartmentHopError> {
    if compartment_of(parent).is_some() && compartment_of(effective).is_none() {
        return Err(CompartmentHopError::Dropped);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_compartment(c: Compartment) -> CapabilityLattice {
        let mut caps = CapabilityLattice::permissive();
        set_compartment(&mut caps, c);
        caps
    }

    #[test]
    fn the_compartment_is_the_highest_key_of_its_down_set() {
        let caps = in_compartment(Compartment::Execute);
        assert_eq!(compartment_of(&caps), Some(Compartment::Execute));
        assert_eq!(caps.extensions.len(), 3, "research, draft, execute");
        assert_eq!(compartment_of(&CapabilityLattice::permissive()), None);

        let mut lowered = caps.clone();
        set_compartment(&mut lowered, Compartment::Research);
        assert_eq!(compartment_of(&lowered), Some(Compartment::Research));
        assert_eq!(lowered.extensions.len(), 1);
    }

    /// Narrowing is the meet: a lower request keeps a subset of the parent's
    /// keys; a higher request is caught BEFORE the meet; a silent request
    /// inherits.
    #[test]
    fn a_hop_can_lower_a_compartment_but_never_raise_it() {
        let parent = in_compartment(Compartment::Execute);

        let lower = in_compartment(Compartment::Draft);
        let child = parent.meet(&lower);
        assert_eq!(compartment_of(&child), Some(Compartment::Draft));
        assert!(child.leq(&parent));
        assert_eq!(check_request(&lower, &parent), Ok(()));
        assert_eq!(check_effective(&child, &parent), Ok(()));

        let higher = in_compartment(Compartment::Breakglass);
        assert_eq!(
            check_request(&higher, &parent),
            Err(CompartmentHopError::Escalated {
                from: Compartment::Execute,
                to: Compartment::Breakglass
            })
        );

        let mut silent = CapabilityLattice::permissive();
        inherit_compartment(&mut silent, &parent);
        assert_eq!(
            compartment_of(&parent.meet(&silent)),
            Some(Compartment::Execute)
        );

        let mut under_unset = CapabilityLattice::permissive();
        inherit_compartment(&mut under_unset, &CapabilityLattice::permissive());
        assert!(under_unset.extensions.is_empty());
    }

    /// The ceiling is applied to the named dimensions and leaves the
    /// extension keys (the compartment itself, the tool surface) untouched.
    #[test]
    fn the_ceiling_clamps_named_capabilities_and_keeps_extensions() {
        let mut caps = in_compartment(Compartment::Research);
        crate::tool_surface::approve_tool(&mut caps, "read_file", "11");
        assert_eq!(
            caps.run_bash,
            CapabilityLevel::Always,
            "permissive before the clamp"
        );

        clamp_to_ceiling(&mut caps, Compartment::Research);
        assert_eq!(caps.run_bash, CapabilityLevel::Never);
        assert_eq!(caps.write_files, CapabilityLevel::Never);
        assert_eq!(caps.read_files, CapabilityLevel::Always);
        assert_eq!(compartment_of(&caps), Some(Compartment::Research));
        assert!(
            crate::tool_surface::has_surface(&caps),
            "extension keys survived"
        );
    }
}
