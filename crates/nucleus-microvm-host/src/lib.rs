//! What a host must provide to run nucleus microVMs, and how a workspace gets
//! into and out of one.
//!
//! - [`probe`]: the host requirements table the node's launch preflight uses,
//!   plus [`probe::kvm`], which opens `/dev/kvm` and creates a VM rather than
//!   trusting that the device node exists.
//! - [`ext4`]: the one ext4 writer. Builds an image from a tar or a directory
//!   whose bytes depend on content and a seed, not on the host or the clock.
//! - [`image_store`]: stage two of an OCI import — overlay the guest layer,
//!   build the ext4, file it under its digest — and the record a node checks a
//!   spec's `rootfs_oci` against.
//! - [`workspace`]: seed a directory into an ext4 scratch image (returning the
//!   digest a spec pins) and harvest the guest's tree back out.
//! - [`scratch_readback`]: reading files out of a guest's ext4 image from the
//!   host, unprivileged, after replaying its journal.
//!
//! The `nucleus-hostctl` binary exposes them as `probe`, `seed`, `harvest` and
//! `image build`, for the process that hosts the node.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

pub mod ext4;
pub mod image_store;
pub mod probe;
pub mod scratch_readback;
pub mod workspace;
