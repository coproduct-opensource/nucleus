// UI fixtures for the `cb4a_separation` pass.
//
// Each case pins one behaviour of the FORWARD call-graph closure. The transitive
// cases are the point: a lint that only checked the root's own signature would
// pass `pdp_decide_via_helper`, which is exactly the shape a separation-of-duty
// failure takes — nobody adds `CredentialStore` to the decider's arguments, they
// add it to something the decider calls.
//
// To (re)generate main.stderr: run `cargo test --test ui`; on mismatch the
// harness prints `Actual stderr saved to <PATH>` — copy that over ui/main.stderr.

#![allow(dead_code, unused_variables)]

// Stand-ins for the real types. The lint matches on def-path substrings, so the
// NAMES are what make these credential and policy material.
pub struct Credential {
    value: String,
}

pub struct CredentialStore;

impl CredentialStore {
    pub fn get(&self) -> Credential {
        Credential {
            value: String::new(),
        }
    }
}

pub struct PermissionLattice;

impl PermissionLattice {
    pub fn allows(&self) -> bool {
        true
    }
}

pub struct Envelope;
pub struct Approved;

// ── Clean: a PDP that touches only policy ───────────────────────────────────

pub fn pdp_decide(env: &Envelope, policy: &PermissionLattice) -> Option<Approved> {
    if policy.allows() { Some(Approved) } else { None }
}

// ── Flagged: a PDP whose own signature names credential material ────────────

pub fn pdp_decide_with_store(
    env: &Envelope,
    policy: &PermissionLattice,
    store: &CredentialStore,
) -> Option<Approved> {
    Some(Approved)
}

// ── Flagged: a PDP that reaches credentials ONE HOP away ────────────────────
//
// The case a signature check cannot catch. `pdp_decide_via_helper` names nothing
// forbidden; only the closure over `audit_helper` reveals the violation.

pub fn pdp_decide_via_helper(env: &Envelope, policy: &PermissionLattice) -> Option<Approved> {
    audit_helper();
    Some(Approved)
}

fn audit_helper() {
    let store = CredentialStore;
    let _c = store.get();
}

// ── Flagged: a PDP that reaches credentials TWO HOPS away ───────────────────

pub fn pdp_decide_two_hops(env: &Envelope, policy: &PermissionLattice) -> Option<Approved> {
    hop();
    Some(Approved)
}

fn hop() {
    audit_helper();
}

// ── Clean: a CDP that touches only credentials ──────────────────────────────

pub fn cdp_fetch(approved: &Approved, store: &CredentialStore) -> Credential {
    store.get()
}

// ── Flagged: a CDP that reaches policy ──────────────────────────────────────

pub fn cdp_fetch_recheck(approved: &Approved, store: &CredentialStore) -> Credential {
    let lattice = PermissionLattice;
    if lattice.allows() {
        store.get()
    } else {
        store.get()
    }
}

// ── Clean: NOT reachable from any root ──────────────────────────────────────
//
// The composition root legitimately touches both — it is where the two halves
// meet, in one direction. It is not a root, so the closure never reaches it and
// it must not be flagged. A lint that fired here would flag the intended design.

pub fn authorize_and_fetch(
    env: &Envelope,
    policy: &PermissionLattice,
    store: &CredentialStore,
) -> Option<Credential> {
    let approved = pdp_decide(env, policy)?;
    Some(cdp_fetch(&approved, store))
}

// ── Flagged: an unresolvable call reachable from a root ─────────────────────
//
// Where the closure stops being sound. Reported rather than skipped, because a
// clean pass over a graph with holes in it is the one lie this must not tell.

pub fn pdp_decide_via_fn_ptr(env: &Envelope, policy: &PermissionLattice) -> Option<Approved> {
    let f: fn() = audit_helper;
    f();
    Some(Approved)
}
