// Fixtures for `rest_pattern_on_policy_path`.
//
// The records are declared locally with the names the pass watches: it resolves
// the pattern's TYPE and matches `item_name`, so a local `PodSpecInner` exercises
// exactly the same path as the real one without this fixture depending on
// `nucleus-spec`.

pub struct PodSpecInner {
    pub work_dir: String,
    pub timeout_seconds: u64,
    pub policy: String,
}

pub struct Metadata {
    pub name: Option<String>,
    pub namespace: Option<String>,
}

/// NOT a policy record. `..` here is ordinary and correct — the pass must say
/// nothing, or it becomes the workspace-wide ban that would need 284 exceptions.
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<String>,
}

// ── Flagged: a field nobody decided about ───────────────────────────────────

pub fn delegate(spec: &PodSpecInner) -> &str {
    let PodSpecInner { policy, .. } = spec;
    policy
}

// ── Flagged: `Self` resolves to the record ──────────────────────────────────
//
// Text matching would miss this. The pass resolves the type, so it does not.

impl Metadata {
    pub fn label(&self) -> bool {
        let Self { name, .. } = self;
        name.is_some()
    }
}

// ── Clean: every field named ────────────────────────────────────────────────
//
// Binding to `_`-prefixed names is a standing decision to forward the field
// unclamped. The pass forces the decision; it does not check it.

pub fn delegate_exhaustively(spec: &PodSpecInner) -> &str {
    let PodSpecInner {
        policy,
        work_dir: _work_dir,
        timeout_seconds: _timeout_seconds,
    } = spec;
    policy
}

// ── Clean: `..` on a record that carries no authority ───────────────────────

pub fn route(req: &HttpRequest) -> &str {
    let HttpRequest { path, .. } = req;
    path
}

fn main() {}
