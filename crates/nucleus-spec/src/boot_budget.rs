//! How long a pod may take to come up, stated once for the node that enforces it
//! and the clients that wait on it.
//!
//! # Why a client's deadline lives beside the node's
//!
//! `nucleus node create` gave up after 30 s — the same 30 s the node gives a guest's
//! tool-proxy to answer (#2904). Every pod whose guest did not come up therefore
//! reported `timeout: global` at the client, a moment before the node would have
//! reported which stage failed and what the guest console said. The node had the
//! diagnosis; the client's clock made sure nobody read it.
//!
//! A client that waits on a pod must outlast the node's own bound on that pod, so
//! that the node — which knows why — is the one that says no. That is a relation
//! between two numbers in two crates, and the only way it cannot drift is for both
//! to read it from here. [`POD_CREATE_CLIENT_TIMEOUT`] is derived from the node's
//! budget, and a compile-time assertion below refuses a build where it is not
//! longer.

use std::time::Duration;

/// Default seconds the node waits for a guest's tool-proxy to answer its first
/// health probe, before contention scaling. Overridable on the node with
/// `NUCLEUS_NODE_PROXY_HEALTH_TIMEOUT_SECS`.
pub const PROXY_HEALTH_TIMEOUT_SECS_DEFAULT: u64 = 30;

/// Cap on how far the node stretches that budget for a busy host (one multiple
/// per live microVM, plus one).
pub const HEALTH_BUDGET_MAX_MULTIPLIER: u64 = 8;

/// The longest the node will wait for a guest's health with no operator override.
pub const MAX_DEFAULT_HEALTH_BUDGET_SECS: u64 =
    PROXY_HEALTH_TIMEOUT_SECS_DEFAULT * HEALTH_BUDGET_MAX_MULTIPLIER;

/// Headroom for everything a pod create does besides the health wait: admission,
/// network setup, jail preparation, and measuring the kernel and rootfs, which for
/// an 8 GiB build image was measured at up to 16 s.
const CREATE_STAGES_HEADROOM_SECS: u64 = 60;

/// How long a client waits for `POST /v1/pods` to answer.
///
/// Longer than the node's own worst default bound on the same request, so a pod
/// that will not come up is reported by the node, with its stage and its guest
/// console, rather than by the client's clock.
pub const POD_CREATE_CLIENT_TIMEOUT: Duration =
    Duration::from_secs(MAX_DEFAULT_HEALTH_BUDGET_SECS + CREATE_STAGES_HEADROOM_SECS);

// The relation this module exists for, checked where it cannot be skipped.
const _: () = assert!(
    POD_CREATE_CLIENT_TIMEOUT.as_secs() > MAX_DEFAULT_HEALTH_BUDGET_SECS,
    "a client must outlast the node's health budget, or the node's diagnosis is never read"
);
