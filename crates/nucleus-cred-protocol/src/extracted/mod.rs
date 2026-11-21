//! The broker's egress decisions, written so Charon and Aeneas translate them
//! to Lean: the effect classifier ([`classify`]), header admission
//! ([`headers`]) and upstream admission ([`admission`]).
//!
//! # These are the deciders, not mirrors
//!
//! Elsewhere in this repository an `extracted` module is a copy of production
//! logic held equal to it by a parity test. Here it is the other way round:
//! the production functions (`operation_for`, `EffectTable::declared` and
//! `::from_parts` in this crate; `CredentialedEgressSpec::admitted_by` and
//! `::clamp` in `nucleus-spec`; `PodAuthority::admit_upstreams`,
//! `header_policy` and `forwarded_headers` in `nucleus-node`) convert their
//! inputs and call these, so each decision is written once (ADR 0007 G-1)
//! and the Lean definitions are of the code that runs.
//!
//! The shape follows from what Aeneas translates: byte slices and `Vec`s
//! rather than `str` and `String`, slices of views rather than maps, `while`
//! loops rather than iterator adaptors and closures, free functions rather
//! than inherent methods (Charon's `--start-from` takes a free function), and
//! enum equality by exhaustive `match`.
//!
//! The extraction is committed under `lean/generated/` beside this crate;
//! `lean/README.md` says how it is produced and with which tools.

pub mod admission;
pub mod classify;
pub mod headers;

#[cfg(test)]
mod parity_tests;
