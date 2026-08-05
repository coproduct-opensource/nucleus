// UI fixtures for the `workload_identity_isolation` pass.
//
// Each case pins one behaviour of the FORWARD call-graph closure. The
// transitive cases are the point: a lint that only checked the root's own
// signature would pass `workload_env_via_helper`, which is exactly the shape
// the defect takes — nobody adds `SessionTaskToken` to the spawn path's
// arguments, they add it to something the spawn path calls.
//
// To (re)generate main.stderr: run `cargo test --test ui`; on mismatch the
// harness prints `Actual stderr saved to <PATH>` — copy that over
// ui/main.stderr.

#![allow(dead_code, unused_variables)]

// Stand-ins for the real types. The lint matches on def-path substrings, so
// the NAMES are what make these identity material.
pub struct SessionTaskToken {
    token: String,
}

pub struct BrokerCapability {
    secret: String,
    port: u32,
}

pub fn broker_capability() -> Option<BrokerCapability> {
    None
}

// A NON-forbidden type whose name contains "Credential" as a substring — the
// legitimate input of the real `workload_egress_env`. The lint must NOT fire
// on it; a pass that flags the intended shape gets suppressed, not obeyed.
pub struct CredentialedEgressSpec {
    pub name: String,
}

// ── Case 1: a clean spawn path. No finding. ────────────────────────────────
pub fn workload_env(spec_env: &[(String, String)]) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = spec_env.to_vec();
    env.push(("NUCLEUS_TOOL_PROXY_URL".into(), "http://127.0.0.1:1".into()));
    env
}

// ── Case 2: a root that DIRECTLY holds identity material. Finding. ─────────
pub fn spawn_workload(token: &SessionTaskToken) {
    let _ = &token.token;
}

// ── Case 3: the transitive case — the root is clean, its helper is not. ────
// Finding at the helper, because it is REACHABLE from the root.
fn helper_reads_the_capability() -> Option<String> {
    broker_capability().map(|c| c.secret)
}

pub fn workload_env_via_helper() -> Vec<(String, String)> {
    let mut env = Vec::new();
    if let Some(s) = helper_reads_the_capability() {
        env.push(("X".to_string(), s));
    }
    env
}

// ── Case 4: the same helper NOT reachable from any root. No finding. ───────
// The lint is about the spawn path, not a crate-wide ban — the runtime
// legitimately holds this material everywhere else.
pub fn runtime_uses_the_capability() -> Option<String> {
    broker_capability().map(|c| c.secret)
}

// ── Case 5: an egress spec in the spawn path. No finding — precision. ──────
pub fn workload_egress_env(specs: &[CredentialedEgressSpec]) -> Vec<(String, String)> {
    specs
        .iter()
        .map(|s| (format!("NUCLEUS_EGRESS_{}_URL", s.name), "local".to_string()))
        .collect()
}

// ── Case 6: a function-pointer call in the spawn path. Finding (unsound
// hole reported, not skipped). ─────────────────────────────────────────────
pub fn start_if_configured(f: fn() -> u32) -> u32 {
    f()
}

fn main() {}
