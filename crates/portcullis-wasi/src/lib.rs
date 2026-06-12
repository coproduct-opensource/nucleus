//! WASI 0.3.0 **world functor** — compiles a Nucleus capability lattice into a
//! WebAssembly Component Model *import world*.
//!
//! ## What this is
//!
//! WASI is capability-based access control: a component can only do what its
//! **world** (its set of imported interfaces) grants — no ambient authority.
//! Nucleus's [`CapabilityLattice`] is a richer, *graded* lattice
//! (`Never < LowRisk < Always` per dimension) with information-flow control
//! layered on top. This crate is the bridge for the *capability half*: the
//! functor
//!
//! ```text
//!     world_of : CapabilityLattice → WasiWorld
//! ```
//!
//! that turns "what may this agent do" into "which WASI interfaces does its
//! component import, and with what rights".
//!
//! ## The functor in two layers
//!
//! 1. **Per-interface core** — [`WasiGrant::from`] maps each [`CapabilityLevel`]
//!    onto a 3-element *grant chain* `Absent < Restricted < Full`. This is a
//!    **lattice isomorphism**: it preserves meet, join, and both bounds. The
//!    Lean side ([`WasiWorldFunctor.phi_meet`] / `phi_join`) proves it by
//!    `decide`; [`tests`] mirrors it exhaustively over the 9 ordered pairs.
//!
//! 2. **Dimension folding** — several capability dimensions collapse onto one
//!    WASI interface (e.g. `read_files`, `glob_search`, `grep_search` all imply
//!    "needs a readable `wasi:filesystem` preopen"). The fold is built from
//!    `join`, so `world_of` is a **join-semilattice homomorphism** (preserves ⊔
//!    and ⊥) and **monotone**.
//!
//!    But folding **breaks meet-preservation**: if lattice `a` imports HTTP via
//!    `git_push` and `b` imports it via `web_fetch`, their meet imports it via
//!    *neither*, yet the pointwise meet of the two worlds would keep it. So in
//!    general `world_of` is only **lax** for meet:
//!
//!    ```text
//!        world_of(a ⊓ b)  ≤  world_of(a) ⊓ world_of(b)
//!    ```
//!
//!    This is the *security-safe* direction — restricting capabilities can only
//!    remove interfaces, never add them. Exact meet-preservation (`meet ↦
//!    import intersection`) holds at the per-dimension core φ and on
//!    **single-source** interfaces (`Sockets`←`git_push`, `Exec`←`run_bash`,
//!    `Search`←`web_search`), but not on the multi-source folded ones. The Lean
//!    side proves both the join-homomorphism (`fold2_join_hom`) and the
//!    meet-laxness (`fold2_meet_lax`, with a strict witness `fold2_meet_strict`).
//!
//! ## What does *not* map (deliberately)
//!
//! Three capability dimensions have **no WASI-standard target** and are modeled
//! as non-standard host imports ([`WasiInterface::is_wasi_standard`] = `false`):
//!
//! - `run_bash` → [`WasiInterface::Exec`]. WASI has no `exec`, by design — this
//!   is the ambient authority the sandbox exists to forbid. It stays a custom
//!   host import (or, in production, the Firecracker lane).
//! - `web_search` → [`WasiInterface::Search`]. Not an OS capability.
//! - `manage_pods` / `spawn_agent` → [`WasiInterface::Control`]. Control-plane,
//!   not a guest syscall surface.
//!
//! And note the *other* half of Nucleus — IFC labels, taint, discharge
//! obligations — has **no WASI expression at all**. It rides above this functor
//! as a host-side monitor. This crate only claims the access-control mapping.

#![forbid(unsafe_code)]

pub mod ifc;

#[cfg(feature = "host")]
pub mod host;

use portcullis_core::{CapabilityLattice, CapabilityLevel};

// ═══════════════════════════════════════════════════════════════════════════
// WasiGrant — the per-interface grant chain (image of CapabilityLevel)
// ═══════════════════════════════════════════════════════════════════════════

/// The grant level for a single WASI interface — the image of a
/// [`CapabilityLevel`] under the world functor.
///
/// A 3-element chain mirroring `CapabilityLevel`, so `from` is a lattice
/// isomorphism (`Absent ↔ Never`, `Restricted ↔ LowRisk`, `Full ↔ Always`):
///
/// - `Absent` — interface **not imported** into the component world (⊥).
/// - `Restricted` — imported, but **narrowed**: a read-only preopen, an egress
///   allowlist, or otherwise the least-authority form the interface supports.
/// - `Full` — imported with full rights (⊤).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum WasiGrant {
    /// Interface not imported — bottom (⊥).
    #[default]
    Absent = 0,
    /// Imported with reduced authority (read-only / allowlisted).
    Restricted = 1,
    /// Imported with full rights — top (⊤).
    Full = 2,
}

impl From<CapabilityLevel> for WasiGrant {
    /// The functor core: a lattice isomorphism of 3-chains.
    ///
    /// Mirrors `WasiWorldFunctor.φ` in the Lean proof.
    fn from(level: CapabilityLevel) -> Self {
        match level {
            CapabilityLevel::Never => WasiGrant::Absent,
            CapabilityLevel::LowRisk => WasiGrant::Restricted,
            CapabilityLevel::Always => WasiGrant::Full,
        }
    }
}

impl WasiGrant {
    /// Meet (greatest lower bound): pointwise min. Mirrors `WasiGrant.meet`.
    pub fn meet(self, other: Self) -> Self {
        if self <= other {
            self
        } else {
            other
        }
    }

    /// Join (least upper bound): pointwise max. Mirrors `WasiGrant.join`.
    pub fn join(self, other: Self) -> Self {
        if self >= other {
            self
        } else {
            other
        }
    }

    /// Import-presence projection `π : WasiGrant → Bool` (`Absent ↦ false`).
    ///
    /// This is the homomorphism onto the boolean "is the interface in the
    /// world at all?" lattice — `present(a ⊓ b) = present(a) ∧ present(b)`,
    /// i.e. **meet ↦ import intersection**. Mirrors `WasiWorldFunctor.present`.
    pub fn present(self) -> bool {
        self != WasiGrant::Absent
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WasiInterface — the named import surface
// ═══════════════════════════════════════════════════════════════════════════

/// A WASI 0.3.0 interface (or non-standard host import) that a Nucleus
/// capability dimension can land on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum WasiInterface {
    /// `wasi:filesystem` — preopened directory handles.
    Filesystem,
    /// `wasi:http` outgoing-handler — egress HTTP requests.
    HttpOutgoing,
    /// `wasi:sockets` — raw TCP/UDP (e.g. git wire protocol).
    Sockets,
    /// **Non-standard.** Process exec — WASI has no `exec` by design.
    Exec,
    /// **Non-standard.** Web search — not an OS capability.
    Search,
    /// **Non-standard.** Control-plane (pod lifecycle / sub-agent spawn).
    Control,
}

impl WasiInterface {
    /// Every interface a [`WasiWorld`] tracks, in a stable order.
    pub const ALL: [WasiInterface; 6] = [
        WasiInterface::Filesystem,
        WasiInterface::HttpOutgoing,
        WasiInterface::Sockets,
        WasiInterface::Exec,
        WasiInterface::Search,
        WasiInterface::Control,
    ];

    /// Whether this is a real WASI-standard interface (vs. a non-standard host
    /// import that has no WASI counterpart).
    pub fn is_wasi_standard(self) -> bool {
        matches!(
            self,
            WasiInterface::Filesystem | WasiInterface::HttpOutgoing | WasiInterface::Sockets
        )
    }

    /// The WIT package name, or a `host:*` marker for non-standard imports.
    pub fn wit_package(self) -> &'static str {
        match self {
            WasiInterface::Filesystem => "wasi:filesystem",
            WasiInterface::HttpOutgoing => "wasi:http/outgoing-handler",
            WasiInterface::Sockets => "wasi:sockets",
            WasiInterface::Exec => "host:exec (non-standard)",
            WasiInterface::Search => "host:search (non-standard)",
            WasiInterface::Control => "host:control (non-standard)",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WasiWorld — a point in world space (one grant per interface)
// ═══════════════════════════════════════════════════════════════════════════

/// A point in WASI-world space: the grant level for each interface a component
/// might import. This is the codomain of [`world_of`].
///
/// `WasiWorld` is itself a product lattice (pointwise [`meet`](Self::meet) /
/// [`join`](Self::join)), so `world_of` is a lattice homomorphism into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WasiWorld {
    /// `wasi:filesystem` — folded from `read_files`/`write_files`/`edit_files`/
    /// `glob_search`/`grep_search`.
    pub filesystem: WasiGrant,
    /// `wasi:http` outgoing — folded from `web_fetch`/`create_pr`/`git_push`.
    pub http_out: WasiGrant,
    /// `wasi:sockets` — from `git_push` (raw wire protocol).
    pub sockets: WasiGrant,
    /// Non-standard exec import — from `run_bash`.
    pub exec: WasiGrant,
    /// Non-standard search import — from `web_search`.
    pub search: WasiGrant,
    /// Non-standard control import — folded from `manage_pods`/`spawn_agent`.
    pub control: WasiGrant,
}

impl WasiWorld {
    /// The empty world — nothing imported (⊥).
    pub fn bottom() -> Self {
        WasiWorld::default()
    }

    /// The full world — every interface at `Full` (⊤).
    pub fn top() -> Self {
        WasiWorld {
            filesystem: WasiGrant::Full,
            http_out: WasiGrant::Full,
            sockets: WasiGrant::Full,
            exec: WasiGrant::Full,
            search: WasiGrant::Full,
            control: WasiGrant::Full,
        }
    }

    /// The grant for a given interface.
    pub fn grant(&self, iface: WasiInterface) -> WasiGrant {
        match iface {
            WasiInterface::Filesystem => self.filesystem,
            WasiInterface::HttpOutgoing => self.http_out,
            WasiInterface::Sockets => self.sockets,
            WasiInterface::Exec => self.exec,
            WasiInterface::Search => self.search,
            WasiInterface::Control => self.control,
        }
    }

    /// The set of interfaces actually imported into the component world
    /// (grant ≠ `Absent`) — the "import-presence" view used in the
    /// `meet ↦ import intersection` law.
    pub fn imports(&self) -> Vec<WasiInterface> {
        WasiInterface::ALL
            .into_iter()
            .filter(|&i| self.grant(i).present())
            .collect()
    }

    /// Pointwise meet — the product-lattice GLB.
    pub fn meet(&self, other: &Self) -> Self {
        WasiWorld {
            filesystem: self.filesystem.meet(other.filesystem),
            http_out: self.http_out.meet(other.http_out),
            sockets: self.sockets.meet(other.sockets),
            exec: self.exec.meet(other.exec),
            search: self.search.meet(other.search),
            control: self.control.meet(other.control),
        }
    }

    /// Pointwise join — the product-lattice LUB.
    pub fn join(&self, other: &Self) -> Self {
        WasiWorld {
            filesystem: self.filesystem.join(other.filesystem),
            http_out: self.http_out.join(other.http_out),
            sockets: self.sockets.join(other.sockets),
            exec: self.exec.join(other.exec),
            search: self.search.join(other.search),
            control: self.control.join(other.control),
        }
    }

    /// Pointwise order: `self ≤ other` iff every grant is ≤.
    pub fn leq(&self, other: &Self) -> bool {
        self.filesystem <= other.filesystem
            && self.http_out <= other.http_out
            && self.sockets <= other.sockets
            && self.exec <= other.exec
            && self.search <= other.search
            && self.control <= other.control
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// The functor: world_of
// ═══════════════════════════════════════════════════════════════════════════

/// Fold the filesystem dimensions into one `wasi:filesystem` grant.
///
/// `Full` if any write-ish capability is present, else `Restricted` if any
/// read-ish capability is present (read-only preopen), else `Absent`.
/// Mirrors `WasiWorldFunctor.filesystemGrant`.
fn filesystem_grant(fs_read: CapabilityLevel, fs_write: CapabilityLevel) -> WasiGrant {
    match (fs_write, fs_read) {
        (CapabilityLevel::Never, CapabilityLevel::Never) => WasiGrant::Absent,
        (CapabilityLevel::Never, _) => WasiGrant::Restricted,
        (_, _) => WasiGrant::Full,
    }
}

/// Compile a [`CapabilityLattice`] into a WASI [`WasiWorld`].
///
/// The functor. Standard interfaces (`filesystem`/`http_out`/`sockets`) are
/// real WASI imports; `exec`/`search`/`control` are non-standard host imports
/// with no WASI counterpart (see crate docs). The reduction is monotone, so
/// `a ≤ b ⟹ world_of(a) ≤ world_of(b)`, and on the unfolded dimensions it is a
/// bounded-lattice homomorphism.
pub fn world_of(cap: &CapabilityLattice) -> WasiWorld {
    // Read-ish ⇒ needs a readable preopen; write-ish ⇒ needs an RW preopen.
    let fs_read = cap.read_files.join(cap.glob_search).join(cap.grep_search);
    let fs_write = cap.write_files.join(cap.edit_files);

    WasiWorld {
        filesystem: filesystem_grant(fs_read, fs_write),
        http_out: cap.web_fetch.join(cap.create_pr).join(cap.git_push).into(),
        sockets: cap.git_push.into(),
        exec: cap.run_bash.into(),
        search: cap.web_search.into(),
        control: cap.manage_pods.join(cap.spawn_agent).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEVELS: [CapabilityLevel; 3] = [
        CapabilityLevel::Never,
        CapabilityLevel::LowRisk,
        CapabilityLevel::Always,
    ];
    const GRANTS: [WasiGrant; 3] = [WasiGrant::Absent, WasiGrant::Restricted, WasiGrant::Full];

    // ── Functor core: WasiGrant::from is a lattice iso of 3-chains ──────────
    // These mirror WasiWorldFunctor.phi_meet / phi_join / phi_injective.

    #[test]
    fn from_preserves_meet() {
        for &a in &LEVELS {
            for &b in &LEVELS {
                let lhs = WasiGrant::from(a.meet(b));
                let rhs = WasiGrant::from(a).meet(WasiGrant::from(b));
                assert_eq!(lhs, rhs, "phi_meet failed at {a:?},{b:?}");
            }
        }
    }

    #[test]
    fn from_preserves_join() {
        for &a in &LEVELS {
            for &b in &LEVELS {
                let lhs = WasiGrant::from(a.join(b));
                let rhs = WasiGrant::from(a).join(WasiGrant::from(b));
                assert_eq!(lhs, rhs, "phi_join failed at {a:?},{b:?}");
            }
        }
    }

    #[test]
    fn from_preserves_bounds() {
        assert_eq!(WasiGrant::from(CapabilityLevel::Never), WasiGrant::Absent);
        assert_eq!(WasiGrant::from(CapabilityLevel::Always), WasiGrant::Full);
    }

    #[test]
    fn from_is_injective() {
        for &a in &LEVELS {
            for &b in &LEVELS {
                if WasiGrant::from(a) == WasiGrant::from(b) {
                    assert_eq!(a, b, "phi collapsed distinct levels {a:?},{b:?}");
                }
            }
        }
    }

    // ── Presence projection: π is a hom to Bool (meet ↦ ∩, join ↦ ∪) ────────
    // Mirrors WasiWorldFunctor.present_meet / present_join.

    #[test]
    fn presence_is_lattice_hom() {
        for &a in &GRANTS {
            for &b in &GRANTS {
                assert_eq!(
                    a.meet(b).present(),
                    a.present() && b.present(),
                    "present_meet failed at {a:?},{b:?}"
                );
                assert_eq!(
                    a.join(b).present(),
                    a.present() || b.present(),
                    "present_join failed at {a:?},{b:?}"
                );
            }
        }
    }

    // ── world_of: bounds, monotonicity, and meet ↦ import intersection ──────

    #[test]
    fn world_of_bottom_is_empty() {
        let w = world_of(&CapabilityLattice::bottom());
        assert_eq!(w, WasiWorld::bottom());
        assert!(w.imports().is_empty());
    }

    #[test]
    fn world_of_top_is_full() {
        let w = world_of(&CapabilityLattice::top());
        assert_eq!(w, WasiWorld::top());
        assert_eq!(w.imports().len(), WasiInterface::ALL.len());
    }

    #[test]
    fn read_only_profile_gets_restricted_filesystem_no_exec() {
        let cap = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        };
        let w = world_of(&cap);
        // read-only ⇒ Restricted filesystem (read-only preopen), never Full.
        assert_eq!(w.filesystem, WasiGrant::Restricted);
        // run_bash absent ⇒ no exec import.
        assert_eq!(w.exec, WasiGrant::Absent);
        assert_eq!(w.imports(), vec![WasiInterface::Filesystem]);
    }

    #[test]
    fn write_promotes_filesystem_to_full() {
        let cap = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            edit_files: CapabilityLevel::LowRisk,
            ..CapabilityLattice::bottom()
        };
        assert_eq!(world_of(&cap).filesystem, WasiGrant::Full);
    }

    #[test]
    fn non_standard_imports_are_flagged() {
        for iface in WasiInterface::ALL {
            let standard = matches!(
                iface,
                WasiInterface::Filesystem | WasiInterface::HttpOutgoing | WasiInterface::Sockets
            );
            assert_eq!(iface.is_wasi_standard(), standard, "{iface:?}");
        }
    }

    /// `world_of` preserves **join** (and ⊥): it is a join-semilattice
    /// homomorphism, because every fold is itself built from `join`. Checked
    /// exhaustively over a 2-D slice. Mirrors Lean `fold2_join_hom`.
    #[test]
    fn world_of_preserves_join() {
        let mk = |gp: CapabilityLevel, wf: CapabilityLevel| CapabilityLattice {
            git_push: gp,  // feeds http_out AND sockets
            web_fetch: wf, // feeds http_out only
            ..CapabilityLattice::bottom()
        };
        for &gp_a in &LEVELS {
            for &wf_a in &LEVELS {
                for &gp_b in &LEVELS {
                    for &wf_b in &LEVELS {
                        let a = mk(gp_a, wf_a);
                        let b = mk(gp_b, wf_b);
                        let folded = world_of(&a.join(&b));
                        let pointwise = world_of(&a).join(&world_of(&b));
                        assert_eq!(folded, pointwise, "join not preserved");
                    }
                }
            }
        }
    }

    /// Folding breaks **exact** meet-preservation, but only in the safe
    /// direction: `world_of(a ⊓ b) ≤ world_of(a) ⊓ world_of(b)`. Restricting
    /// capabilities can only remove interfaces, never add them. The strict
    /// witness below is the `git_push` vs `web_fetch` HTTP collision.
    /// Mirrors Lean `fold2_meet_lax` / `fold2_meet_strict`.
    #[test]
    fn world_of_meet_is_lax_and_safe() {
        // a imports HTTP via git_push; b imports HTTP via web_fetch.
        let a = CapabilityLattice {
            git_push: CapabilityLevel::LowRisk,
            ..CapabilityLattice::bottom()
        };
        let b = CapabilityLattice {
            web_fetch: CapabilityLevel::LowRisk,
            ..CapabilityLattice::bottom()
        };

        let folded = world_of(&a.meet(&b));
        let pointwise = world_of(&a).meet(&world_of(&b));

        // Lax: the compiled world of the meet is no more permissive.
        assert!(folded.leq(&pointwise), "meet laxness violated (unsafe!)");
        // Strict: folding genuinely loses the equality here.
        assert_ne!(folded, pointwise, "expected folding to be strict on HTTP");
        // Concretely: a⊓b has no HTTP reason left, so http_out is Absent…
        assert_eq!(folded.http_out, WasiGrant::Absent);
        // …even though intersecting the worlds would have kept it.
        assert_eq!(pointwise.http_out, WasiGrant::Restricted);
    }

    /// On **single-source** interfaces (one capability dimension → one
    /// interface), meet *is* preserved exactly — there is nothing to fold.
    /// `Exec`←`run_bash` is the clean case. Checked exhaustively.
    #[test]
    fn single_source_interface_preserves_meet() {
        let mk = |rb: CapabilityLevel| CapabilityLattice {
            run_bash: rb,
            ..CapabilityLattice::bottom()
        };
        for &rb_a in &LEVELS {
            for &rb_b in &LEVELS {
                let folded = world_of(&mk(rb_a).meet(&mk(rb_b)));
                let pointwise = world_of(&mk(rb_a)).meet(&world_of(&mk(rb_b)));
                assert_eq!(folded.exec, pointwise.exec, "exec meet not preserved");
            }
        }
    }

    /// Monotonicity over a 2-D slice (read_files × run_bash), exhaustively.
    /// `a ≤ b ⟹ world_of(a) ≤ world_of(b)`.
    #[test]
    fn world_of_is_monotone_on_slice() {
        let mk = |rf: CapabilityLevel, rb: CapabilityLevel| CapabilityLattice {
            read_files: rf,
            run_bash: rb,
            ..CapabilityLattice::bottom()
        };
        for &rf_a in &LEVELS {
            for &rb_a in &LEVELS {
                for &rf_b in &LEVELS {
                    for &rb_b in &LEVELS {
                        if rf_a <= rf_b && rb_a <= rb_b {
                            let wa = world_of(&mk(rf_a, rb_a));
                            let wb = world_of(&mk(rf_b, rb_b));
                            assert!(wa.leq(&wb), "monotonicity broke: {wa:?} !≤ {wb:?}");
                        }
                    }
                }
            }
        }
    }
}
