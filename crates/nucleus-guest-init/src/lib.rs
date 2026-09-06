//! Library half of the guest init: the boot typestate (`boot`), exposed so its
//! ordering guarantee is checkable by the compiler in doctests, not only by
//! reading `main.rs` top to bottom.
//!
//! # The guarantee, as compile errors
//!
//! `exec` exists only on `Boot<Sealed>`, and `Sealed` is only produced by
//! `seal` (the read-only remount). Skipping the seal is a type error:
//!
//! ```compile_fail
//! use nucleus_guest_init::boot::{Boot, MountSpec};
//! let boot = Boot::start().mount_all(&[], |_| Ok(())).unwrap().provisioned();
//! // no `seal` — `Boot<Provisioned>` has no `exec`
//! boot.exec(|_proof| ());
//! ```
//!
//! Skipping the mounts is a type error too — `provisioned` exists only on
//! `Boot<Mounted>`:
//!
//! ```compile_fail
//! use nucleus_guest_init::boot::Boot;
//! let boot = Boot::start().provisioned();
//! ```
//!
//! And the launcher cannot be reached without the proof only `exec` mints —
//! `SealedProof` has no public constructor:
//!
//! ```compile_fail
//! use nucleus_guest_init::boot::SealedProof;
//! let _forged = SealedProof { _priv: () };
//! ```
//!
//! The happy path compiles, and the launcher runs only after the remount:
//!
//! ```
//! use nucleus_guest_init::boot::{Boot, MountSpec};
//! let remounted = std::cell::Cell::new(false);
//! let ran_after = Boot::start()
//!     .mount_all(&[], |_| Ok(()))
//!     .unwrap()
//!     .provisioned()
//!     .seal(|| { remounted.set(true); Ok(()) })
//!     .unwrap()
//!     .exec(|_proof| remounted.get());
//! assert!(ran_after);
//! ```

pub mod boot;
