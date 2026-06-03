// UI fixtures for the `aeneas_eligible` screen.
//
// One CLEAN function (must PASS — no diagnostic) plus one function per rule, each
// tripping exactly one construct in the deny-set (Research Report 3).
//
// To (re)generate main.stderr: run `cargo test`; on mismatch the harness prints
// `Actual stderr saved to <PATH>` — copy that file over `ui/main.stderr`
// (compiletest_rs copy-the-path workflow; there is no BLESS env var). (Research 1, §3)

#![allow(dead_code, unused_variables, unused_unsafe)]

// edition 2024 requires `unsafe extern`.
unsafe extern "C" {
    fn abs(input: i32) -> i32;
}

// ---- POSITIVE FIXTURE: clean, pure-integer fn — MUST PASS (no warning) ----
fn clean_add(a: u64, b: u64) -> u64 {
    a + b
}

// A second clean case: recursion + a single (non-nested) construct, all in-subset.
fn clean_factorial(n: u64) -> u64 {
    if n == 0 { 1 } else { n * clean_factorial(n - 1) }
}

// ---- NEGATIVE FIXTURES: each trips exactly one rule ----

// (a) unsafe fn signature
unsafe fn ineligible_unsafe_fn() -> u64 {
    0
}

// (a) user-written unsafe block
fn ineligible_unsafe_block() -> u64 {
    unsafe { 0 }
}

// (b) async fn
async fn ineligible_async() -> u64 {
    0
}

// (c) closure
fn ineligible_closure() -> u64 {
    let f = |x: u64| x + 1;
    f(1)
}

// (d) dyn Trait in the signature
fn ineligible_dyn(x: &dyn std::fmt::Debug) {}

// (e) FFI / extern call
fn ineligible_ffi() -> i32 {
    unsafe { abs(-1) }
}

// (f) raw pointer in the signature
fn ineligible_raw_ptr(p: *const u64) -> u64 {
    0
}

fn main() {}
