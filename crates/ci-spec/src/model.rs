//! The typed model of a CI configuration.
//!
//! Everything the invariants reason about is a field here. The loader fills
//! it from `.github/workflows/*.yml`, the required-check ledger and the
//! merge-queue pin; the invariants never touch YAML or the filesystem again,
//! which is what makes them unit-testable from in-memory fixtures.

use std::collections::BTreeMap;

/// One `.github/workflows/*.yml` file.
#[derive(Debug, Clone)]
pub struct Workflow {
    /// Repo-relative path, e.g. `.github/workflows/ci.yml`.
    pub path: String,
    /// The `name:` — what `${{ github.workflow }}` expands to, and what the
    /// checks UI groups by. Twins share it on purpose.
    pub name: String,
    pub triggers: Triggers,
    pub concurrency: Option<Concurrency>,
    /// `defaults.run.shell`, if declared.
    pub default_shell: Option<String>,
    pub jobs: Vec<Job>,
    /// The raw text, kept for line recovery and for "is script X mentioned".
    pub raw: String,
}

impl Workflow {
    /// The twin-pair key: `foo-noop.yml` and `foo.yml` share `foo`.
    #[must_use]
    pub fn pair_key(&self) -> String {
        let base = self.path.rsplit('/').next().unwrap_or(&self.path);
        let base = base.trim_end_matches(".yml").trim_end_matches(".yaml");
        base.trim_end_matches("-noop").to_string()
    }

    /// Is this the `-noop` half of a twin pair?
    #[must_use]
    pub fn is_noop(&self) -> bool {
        let base = self.path.rsplit('/').next().unwrap_or(&self.path);
        base.ends_with("-noop.yml") || base.ends_with("-noop.yaml")
    }
}

/// What fires the workflow.
#[derive(Debug, Clone, Default)]
pub struct Triggers {
    pub push: Option<PathFilter>,
    pub pull_request: Option<PathFilter>,
    pub merge_group: bool,
    pub schedule: bool,
    pub workflow_dispatch: bool,
    /// Any other event names, verbatim.
    pub other: Vec<String>,
}

/// `paths:` / `paths-ignore:` under one event. Both empty means unfiltered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathFilter {
    pub paths: Vec<String>,
    pub paths_ignore: Vec<String>,
    /// `types:` if declared.
    pub types: Vec<String>,
}

/// The workflow-level `concurrency:` block.
#[derive(Debug, Clone)]
pub struct Concurrency {
    pub group: String,
    /// The raw scalar of `cancel-in-progress` — `true`, `false`, or an expression.
    pub cancel_in_progress: String,
    pub line: usize,
}

/// One job.
#[derive(Debug, Clone)]
pub struct Job {
    /// The YAML key.
    pub id: String,
    /// `name:` if declared.
    pub name: Option<String>,
    pub runs_on: String,
    /// Job-level `if:`.
    pub if_expr: Option<String>,
    pub needs: Vec<String>,
    pub timeout_minutes: Option<u64>,
    pub continue_on_error: bool,
    /// 1-indexed line of the `<id>:` key.
    pub line: usize,
    pub steps: Vec<Step>,
    /// `strategy.matrix` combinations as `(key, value)` lists, in declaration
    /// order. Empty when the job has no matrix. `include`/`exclude` are not
    /// expanded; `matrix_opaque` says so.
    pub matrix: Vec<Vec<(String, String)>>,
    pub matrix_opaque: bool,
    /// `outputs:` — output name to its expression, e.g. `verify_strict` →
    /// `${{ steps.verify_strict.outcome }}`. A relay job reads these through
    /// `needs.<job>.outputs.<name>`, which is the only path from a status context back to the
    /// command whose result it reports.
    pub outputs: BTreeMap<String, String>,
}

impl Job {
    /// The status-check context this job reports: `name:` if present, else the id.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }

    /// Every check-run name this job produces. A matrix job produces one per
    /// combination: `name (v1, v2)`, or the `name:` with `${{ matrix.k }}`
    /// substituted when it interpolates the matrix.
    #[must_use]
    pub fn contexts(&self) -> Vec<String> {
        let base = self.display_name();
        if self.matrix.is_empty() {
            return vec![base.to_string()];
        }
        self.matrix
            .iter()
            .map(|combo| {
                if base.contains("${{ matrix.") {
                    let mut s = base.to_string();
                    for (k, v) in combo {
                        s = s.replace(&format!("${{{{ matrix.{k} }}}}"), v);
                    }
                    s
                } else {
                    let vals: Vec<&str> = combo.iter().map(|(_, v)| v.as_str()).collect();
                    format!("{base} ({})", vals.join(", "))
                }
            })
            .collect()
    }
}

/// One step.
#[derive(Debug, Clone)]
pub struct Step {
    pub name: String,
    pub id: Option<String>,
    pub run: Option<String>,
    /// The step's `shell:`, or the job/workflow default that applies.
    pub shell: Option<String>,
    pub if_expr: Option<String>,
    pub continue_on_error: bool,
    pub env: BTreeMap<String, String>,
    pub working_directory: Option<String>,
    /// 1-indexed line of the step's first line in the file.
    pub line: usize,
}

impl Step {
    /// Can this step deliberately fail? Only such steps are gates; a build
    /// step is not one. (Heuristic inherited from proofcard; stated as such.)
    #[must_use]
    pub fn is_gate(&self) -> bool {
        self.run
            .as_deref()
            .is_some_and(|s| s.contains("exit 1") || s.contains("::error::"))
    }

    /// Does `pipefail` apply? Naming the shell buys it on GitHub
    /// (`bash --noprofile --norc -eo pipefail {0}`); so does setting it in
    /// the script. The default `bash -e {0}` has errexit and NOT pipefail.
    #[must_use]
    pub fn pipefail(&self) -> bool {
        self.shell.is_some() || self.run.as_deref().is_some_and(|s| s.contains("pipefail"))
    }
}

fn github_owns_the_merge() -> String {
    "github".to_string()
}

/// The merge-queue ruleset constants, pinned in `ci/merge-queue.toml`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct QueueConfig {
    /// Who enforces the merge. `github` — the ruleset below carries the `merge_queue` rule and
    /// GitHub builds every group. `gatehouse` — gatehouse's queue verifies receipts and calls
    /// the merge API itself, and no ruleset may carry a `merge_queue` rule; the constants below
    /// then describe gatehouse's queue, which is what the capacity theorem is about either way.
    #[serde(default = "github_owns_the_merge")]
    pub owner: String,
    pub ruleset_id: u64,
    pub check_response_timeout_minutes: u64,
    pub max_entries_to_build: u64,
    pub max_entries_to_merge: u64,
    pub min_entries_to_merge: u64,
    pub min_entries_to_merge_wait_minutes: u64,
    pub grouping_strategy: String,
    pub merge_method: String,
    /// Classic branch-protection `required_status_checks.strict`.
    pub strict: bool,
}

/// The required-check ledger (`ci/required-checks.txt`).
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    pub contexts: Vec<String>,
    /// Contexts produced by a GitHub App rather than a workflow job, with the App id branch
    /// protection must bind them to: `gatehouse/required @app 4853870`. No workflow produces
    /// them, so the producer and merge-group invariants cannot be decided from the tree; what
    /// the tree CAN pin is which App's check run counts, and live parity holds GitHub to it.
    pub app_contexts: BTreeMap<String, u64>,
    /// `# PINNED = N` — the population pin; grow-only.
    pub pinned: Option<usize>,
}

/// One `<context> <- <gate>` line of `ci/gatehouse-replacements.txt`: a required context that a
/// gatehouse plan gate took over.
///
/// The declaration is what makes a cutover checkable. Retiring a context is two edits in two
/// files — a line out of `ci/required-checks.txt`, a rule out of the GitHub ruleset — and nothing
/// in either of them says what now does the work. This says it, and CI-RP-2 holds the claim to
/// the two commands.
#[derive(Debug, Clone)]
pub struct Replacement {
    /// The retired status-check context, as branch protection spelled it.
    pub context: String,
    /// The gatehouse gate that took it over, as `.gatehouse/gates/<gate>.json` is named.
    pub gate: String,
    /// 1-indexed line in `ci/gatehouse-replacements.txt`.
    pub line: usize,
    /// The gate's argv. Empty when no such gate definition exists.
    pub cmd: Vec<String>,
    /// `cmd`, plus the text of every repository script `cmd` invokes. A gate may reach a command
    /// through a wrapper — nucleus's clippy gate runs `wasm-pack` through
    /// `scripts/gatehouse-verifier-sdk.sh` — and a parity check that could not see through one
    /// would force every gate to inline its scripts.
    pub expanded: String,
}

/// `ci/gatehouse-replacements.txt`.
#[derive(Debug, Clone, Default)]
pub struct Replacements {
    pub entries: Vec<Replacement>,
    /// Absent file: no cutover has been declared, and CI-RP is silent rather than wrong.
    pub present: bool,
}

/// The inline-gate inventory (`ci/inline-gates.txt`).
#[derive(Debug, Clone, Default)]
pub struct InlineGates {
    /// key (`workflow::job::step`) → falsifier text (or `UNCOVERED: reason`).
    pub entries: BTreeMap<String, String>,
    pub uncovered_ceiling: Option<usize>,
}

/// The gate-integrity allowlist (`ci/gate-integrity-allowlist.txt`).
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    /// key (`RULE workflow::step`) → reason.
    pub entries: BTreeMap<String, String>,
}

/// Everything the invariants see.
#[derive(Debug, Clone)]
pub struct Model {
    pub workflows: Vec<Workflow>,
    pub ledger: Ledger,
    pub queue: QueueConfig,
    pub inline_gates: InlineGates,
    pub allowlist: Allowlist,
    /// What each retired context was replaced by (`ci/gatehouse-replacements.txt`).
    pub replacements: Replacements,
    /// Repo-relative paths of every `scripts/check-*.sh` and `ci/*.sh` on disk.
    pub gate_scripts: Vec<String>,
    /// The pinned population of image-dependent jobs (I10), from
    /// `ci/image-dependent-jobs.txt`. Empty when the file is absent, which makes every such job
    /// read as new — the right answer for a repository that has not pinned it.
    pub image_dependent_pinned: std::collections::BTreeSet<String>,
}

impl Model {
    /// Every (workflow index, job index) whose display name is `ctx`.
    pub fn producers(&self, ctx: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for (wi, w) in self.workflows.iter().enumerate() {
            for (ji, j) in w.jobs.iter().enumerate() {
                if j.contexts().iter().any(|c| c == ctx) {
                    out.push((wi, ji));
                }
            }
        }
        out
    }

    /// Is `name` a required context?
    #[must_use]
    pub fn is_required(&self, name: &str) -> bool {
        self.ledger.contexts.iter().any(|c| c == name)
    }
}
