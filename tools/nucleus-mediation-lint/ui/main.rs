// UI fixtures for the `mediated` pass.
//
// Each case pins one behaviour of the call-graph closure. The transitive cases
// are the point: `check_fn` sees one function at a time, so a lint that only
// looked at direct I/O would pass `public_two_hops` and be worthless.
//
// To (re)generate main.stderr: run `cargo test --test ui`; on mismatch the
// harness prints `Actual stderr saved to <PATH>` — copy that over ui/main.stderr.

#![allow(dead_code, unused_variables)]

use std::path::Path;

// A stand-in for `portcullis_effects::authority::Authority`. The lint matches on
// a def-path ending in `authority::Authority`, so the module name is what makes
// this a boundary — not the type name alone.
mod authority {
    pub struct Authority;
}
use authority::Authority;

// ── Clean: no I/O at all ────────────────────────────────────────────────────

pub fn pure_addition(a: u64, b: u64) -> u64 {
    a + b
}

// ── Flagged: public, direct I/O, no Authority ───────────────────────────────

pub fn public_direct_io(p: &Path, b: &[u8]) -> std::io::Result<()> {
    std::fs::write(p, b)
}

// ── Clean: public, direct I/O, but demands an Authority ─────────────────────

pub fn public_mediated_io(p: &Path, b: &[u8], a: Authority) -> std::io::Result<()> {
    let _ = a;
    std::fs::write(p, b)
}

// ── Flagged: public, reaches I/O two hops away ──────────────────────────────
//
// The case that a per-function lint cannot catch. `public_two_hops` contains no
// I/O of its own; only the closure over `hop` -> `leaf_io` reveals it.

fn leaf_io(p: &Path) -> std::io::Result<Vec<u8>> {
    std::fs::read(p)
}

fn hop(p: &Path) -> std::io::Result<Vec<u8>> {
    leaf_io(p)
}

pub fn public_two_hops(p: &Path) -> std::io::Result<Vec<u8>> {
    hop(p)
}

// ── Clean: a boundary on the path absorbs it ────────────────────────────────
//
// Same shape as above, except the middle hop demands an Authority. The boundary
// stops the propagation, so the public caller is clean — this is what "mediated"
// has to mean for the lint to be usable at all.

fn mediated_hop(p: &Path, a: Authority) -> std::io::Result<Vec<u8>> {
    let _ = a;
    leaf_io(p)
}

pub fn public_behind_boundary(p: &Path, a: Authority) -> std::io::Result<Vec<u8>> {
    mediated_hop(p, a)
}

// ── Flagged: a reference is not a boundary ──────────────────────────────────
//
// `&Authority` is the ambient shape the affine cutover removed: it can be
// replayed, so it must not count. Without this case a regression to `&Authority`
// would silently report clean.

pub fn borrowed_authority_is_not_a_boundary(p: &Path, a: &Authority) -> std::io::Result<Vec<u8>> {
    std::fs::read(p)
}

// ── Flagged: process spawn ──────────────────────────────────────────────────

pub fn public_spawn() -> std::io::Result<std::process::Output> {
    std::process::Command::new("echo").output()
}

// ── Flagged: call through a function pointer defeats the closure ────────────
//
// Reported rather than ignored. Silently skipping it would turn a hole in the
// analysis into a clean pass, which is the one failure mode this lint must not
// have.

pub fn call_through_pointer(f: fn(&Path) -> std::io::Result<Vec<u8>>, p: &Path) {
    let _ = f(p);
}
