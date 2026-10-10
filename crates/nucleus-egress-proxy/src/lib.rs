//! The per-pod host egress proxy (ADR 0015, step E2).
//!
//! An eval cell's one way out is this process (ADR 0015 §1). It reads one
//! HTTP/1.1 request from the guest, refuses anything that is not plainly one
//! (§4's table), and asks the node to decide it. Only an allow from the node
//! is performed, and only to an address the proxy resolved itself and found
//! admissible (§3).
//!
//! # What this process decides, and what it does not
//!
//! It decides **nothing about policy** (ADR 0007 G-1). Which upstreams exist,
//! which methods and paths each one admits, and whether this pod may send
//! this request now are the node's: the operator's registry and the pod's
//! `PodPolicy`, consulted on the node's side of the decision channel. The
//! proxy holds no registry, no allowlist and no key. What it does own is what
//! only it can see:
//!
//! * **the bytes the guest sent** ([`request`]): a request that is not one
//!   unambiguous HTTP/1.1 request cannot be summarised for a decision, so it
//!   is refused before anyone is asked;
//! * **the address a name resolved to** ([`address`]): the node decides on
//!   the name the operator registered, and only the proxy learns which
//!   address that name resolves to at connect time. A metadata, link-local,
//!   node-floor, private or loopback answer is refused there (the
//!   DNS-rebinding defence).
//!
//! # No answer is a denial (ADR 0014 §7)
//!
//! [`decision::HostAnswer`] has two arms, a verdict and
//! [`decision::HostUnavailable`]; the match that forms the outcome has no
//! `_` arm and the unavailable arm refuses (ADR 0007 A-1, B-3). There is no
//! direct-egress fallback, because there is no path for one.
//!
//! # Not yet (E3)
//!
//! TLS termination and credential injection. In E2 a `CONNECT` is refused
//! outright: without termination the proxy cannot see the request inside
//! the tunnel, so it has nothing to ask the node about (§4: never tunnelled
//! opaquely).

#![forbid(unsafe_code)]
// Declared panic-free for the shipped build (the scorecard's `tot` family):
// this crate parses bytes guest root wrote, and a parser that can panic is a
// proxy a guest can stop (ADR 0015 §7).
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

pub mod address;
pub mod decision;
pub mod posture;
pub mod refusal;
pub mod request;
pub mod resolve;
pub mod serve;
pub mod summary;

pub use refusal::Refusal;
