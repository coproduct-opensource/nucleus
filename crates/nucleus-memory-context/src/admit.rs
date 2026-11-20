//! Bindings and current-epoch admission.

use crate::history::{History, Version};
use crate::section::{Section, observe};
use crate::view::View;

/// A space's (or policy's) revocation epoch. Revocation bumps it; every binding
/// minted under an older epoch is refused for new mediated ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epoch(pub u32);

/// What a binding may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Read the pinned base through the view.
    Read,
    /// Read, and write a private branch over the pinned base.
    ReadPropose,
}

/// A run's binding to a memory space, minted by the node at pod creation from a
/// policy. Never inherited: every run gets its own. Bounded twice — by the epoch it
/// was minted in and by `not_after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// Which binding this is.
    pub binding_id: u32,
    /// What the run may see.
    pub view: View,
    /// The pinned base version.
    pub base: Version,
    /// What the run may do.
    pub mode: Mode,
    /// The epoch the binding was minted in.
    pub epoch: Epoch,
    /// The last instant (inclusive) at which the binding is valid.
    pub not_after: u64,
}

/// Why a binding was refused, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitRefusal {
    /// The binding was minted in another epoch — revoked, or not yet current.
    ForeignEpoch {
        /// The binding's epoch.
        binding: Epoch,
        /// The current epoch.
        current: Epoch,
    },
    /// `now` is past the binding's `not_after`.
    Expired {
        /// The binding's last valid instant.
        not_after: u64,
        /// The instant it was presented.
        now: u64,
    },
}

/// One admitted mediated op.
///
/// Private constructor (minted only by [`admit`]), not `Clone`, consumed by value by
/// the op it admits (ADR 0007 C-1, C-4). It carries the epoch and `not_after` it was
/// admitted under.
#[must_use = "an admission that is never used is an op that was admitted and not performed"]
#[derive(Debug, PartialEq, Eq)]
pub struct AdmittedOp {
    binding_id: u32,
    view: View,
    base: Version,
    mode: Mode,
    epoch: Epoch,
    not_after: u64,
}

/// Why an admitted read found nothing to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadRefusal {
    /// The pinned base has not been committed in this history.
    BaseNotCommitted {
        /// The pinned base.
        base: Version,
        /// The history's head.
        head: Version,
    },
}

impl AdmittedOp {
    /// The binding admitted.
    pub const fn binding_id(&self) -> u32 {
        self.binding_id
    }

    /// The view the op runs through.
    pub const fn view(&self) -> View {
        self.view
    }

    /// The pinned base.
    pub const fn base(&self) -> Version {
        self.base
    }

    /// What the binding may do.
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// The epoch it was admitted under.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The binding's last valid instant.
    pub const fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Read the pinned base through the bound view. A later commit does not change
    /// what this returns: the base is pinned, not the head.
    pub fn read(self, history: &History) -> Result<Section, ReadRefusal> {
        match history.snapshot(self.base) {
            Some(snapshot) => Ok(observe(snapshot.section(), self.view)),
            None => Err(ReadRefusal::BaseNotCommitted {
                base: self.base,
                head: history.head(),
            }),
        }
    }
}

/// Admit `binding` for one mediated op at `now`, in `current_epoch`.
///
/// The epoch is checked first: a revoked binding is refused as `ForeignEpoch` even
/// when it has also expired. Revocation does not erase what was already disclosed;
/// it refuses what has not happened yet.
pub fn admit(
    binding: &Binding,
    current_epoch: Epoch,
    now: u64,
) -> Result<AdmittedOp, AdmitRefusal> {
    if binding.epoch != current_epoch {
        return Err(AdmitRefusal::ForeignEpoch {
            binding: binding.epoch,
            current: current_epoch,
        });
    }
    if now > binding.not_after {
        return Err(AdmitRefusal::Expired {
            not_after: binding.not_after,
            now,
        });
    }
    Ok(AdmittedOp {
        binding_id: binding.binding_id,
        view: binding.view,
        base: binding.base,
        mode: binding.mode,
        epoch: binding.epoch,
        not_after: binding.not_after,
    })
}
