//! Measure one point on the safely-delegatable-agency frontier (ADR 0005).
//!
//! `toolcall` asks whether the mediated path works at all. This asks the
//! question the objective is stated in: **how much useful work does a pod
//! actually complete, and what did the authority to do it cost?**
//!
//! The two halves come from different places on purpose.
//!
//! The **numerator** is a suite of work tasks with deterministic oracles. It
//! cannot be inferred from a trace — a run in which nothing was refused is not
//! evidence that anything was achieved — so somebody has to state what the work
//! was and check it happened. The tasks are Rust rather than a manifest format
//! because real work has data flow in it (write *these* bytes, read *that* path
//! back, compare), and a manifest DSL that cannot express that would measure a
//! toy.
//!
//! The **denominator** is computed from the calls this harness itself made.
//! Every request is recorded as an [`Observation`] with its verdict, and
//! `portcullis::attribute_usage` turns those plus the pod's resolved lattice
//! into ρ and the denial counts. Measuring client-side keeps the harness honest
//! in one specific way: it counts what it *asked for*, so a request the runtime
//! never saw still appears, and a suite cannot flatter its ρ by not asking.
//!
//! Containment checks are run and reported, and are deliberately **not** part
//! of the numerator: a refusal is not work. They decide whether the completion
//! rate may be quoted at all (`AgencyReport::is_valid`).

use std::cell::{Cell, RefCell};

use anyhow::{Context as _, Result, bail};
use portcullis::Operation;
use portcullis::agency_report::{AgencyReport, AuthorityCost, Enforcement, TaskOutcome};
use portcullis::observe::Observation;

use crate::{FORBIDDEN_READ, approval_required_operation, approve_operation, tool_call};

/// What a task needs to talk to the pod, plus the tally it leaves behind.
pub(crate) struct Ctx<'a> {
    /// Base URL of the pod's tool proxy.
    proxy: &'a str,
    /// The approver key, when the harness is allowed to act as the person.
    key: Option<&'a ed25519_dalek::SigningKey>,
    /// Actor recorded on approval requests.
    actor: &'a str,
    /// Every call this harness made, with the verdict it got.
    observations: RefCell<Vec<Observation>>,
    /// Authorization decisions a person made — C(T)'s second term.
    approvals: Cell<u64>,
    /// A nonce source that is unique per process run.
    seq: Cell<u64>,
    /// Refusals that were deferrals to a person, not denials of authority.
    deferrals: Cell<usize>,
    /// HMAC secret for request signing.
    ///
    /// A pod's proxy behind a node is reached on an already-authenticated
    /// channel; a proxy this harness spawns itself is not, and refuses an
    /// unsigned request with `missing auth header`. Worth noting how that
    /// showed up: every task failed, and the report refused to be quoted
    /// because a containment check "failed" too — the harness could not tell
    /// an auth refusal from a policy one, which is exactly what
    /// `AgencyReport::is_valid` exists to catch.
    secret: Option<Vec<u8>>,
}

impl<'a> Ctx<'a> {
    fn new(proxy: &'a str, key: Option<&'a ed25519_dalek::SigningKey>, actor: &'a str) -> Self {
        Self {
            proxy,
            key,
            actor,
            observations: RefCell::new(Vec::new()),
            approvals: Cell::new(0),
            seq: Cell::new(0),
            deferrals: Cell::new(0),
            secret: None,
        }
    }

    fn with_secret(mut self, secret: Option<Vec<u8>>) -> Self {
        self.secret = secret;
        self
    }

    fn nonce(&self) -> String {
        let n = self.seq.get() + 1;
        self.seq.set(n);
        format!("{}-{n}", std::process::id())
    }

    /// One mediated call, recorded.
    ///
    /// `operation` is what the request means in the authority vocabulary, so
    /// the observation stream this builds is the same shape `nucleus observe`
    /// produces and `attribute_usage` consumes.
    fn call(
        &self,
        route: &str,
        operation: Operation,
        subject: &str,
        body: serde_json::Value,
    ) -> Result<(u16, String)> {
        let (status, text, _ms) = match &self.secret {
            Some(secret) => crate::signed_tool_call(self.proxy, secret, self.actor, route, body)?,
            None => tool_call(self.proxy, route, body)?,
        };
        let ok = (200..300).contains(&status);
        let obs = if ok {
            Observation::new(operation, subject)
        } else {
            // A `403 approval_required` is a refusal in the observation stream
            // — nothing happened — but it is a DEFERRAL, not a denial of
            // authority. Counted apart so the friction figure is not inflated
            // by the system asking a person exactly as designed.
            if crate::approval_required_operation(&text).is_some() {
                self.deferrals.set(self.deferrals.get() + 1);
            }
            Observation::failed(operation, subject)
        };
        self.observations.borrow_mut().push(obs);
        Ok((status, text))
    }

    /// Ask the person, when the harness is holding their key.
    ///
    /// Counted whether or not it succeeds: a decision put to a person is a
    /// decision put to a person, and C(T) is a measure of what delegation cost
    /// them, not of how often they said yes.
    fn approve(&self, operation: &str) -> Result<bool> {
        let Some(key) = self.key else {
            return Ok(false);
        };
        self.approvals.set(self.approvals.get() + 1);
        let (status, _body) =
            approve_operation(self.proxy, key, self.actor, operation, &self.nonce())?;
        Ok((200..300).contains(&status))
    }

    fn body_field(text: &str, field: &str) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(text)
            .ok()?
            .get(field)?
            .as_str()
            .map(str::to_string)
    }
}

/// A task and its oracle. `Err(reason)` records what stopped it.
type Outcome = std::result::Result<(), String>;

struct Task {
    id: &'static str,
    goal: &'static str,
    run: fn(&Ctx<'_>) -> Result<Outcome>,
}

// ── Work: the numerator ─────────────────────────────────────────────────────

/// Can the pod see anything at all? Everything downstream needs a path that
/// exists, and inventing one would test the harness rather than the pod.
fn discover_workspace(ctx: &Ctx<'_>) -> Result<Outcome> {
    let (status, body) = ctx.call(
        "glob",
        Operation::GlobSearch,
        "**/*",
        serde_json::json!({"pattern": "**/*"}),
    )?;
    if !(200..300).contains(&status) {
        return Ok(Err(format!("glob refused: {}", body.trim())));
    }
    match globbed(&body).len() {
        0 => Ok(Err("glob succeeded but the workspace is empty".to_string())),
        _ => Ok(Ok(())),
    }
}

/// Read real bytes out of the sandbox.
///
/// Walks the globbed entries rather than naming one: some of them are
/// DIRECTORIES, and reading a directory is `EISDIR`, not a refusal — a
/// distinction that cost this project two ledger rows and six days of believing
/// no readable file existed (`docs/perf/RUBRIC-LEDGER.md` rows 2, 2b, 2c).
fn read_a_file(ctx: &Ctx<'_>) -> Result<Outcome> {
    let (_, body) = ctx.call(
        "glob",
        Operation::GlobSearch,
        "**/*",
        serde_json::json!({"pattern": "**/*"}),
    )?;
    let entries = globbed(&body);
    if entries.is_empty() {
        return Ok(Err("nothing to read: glob returned no entries".to_string()));
    }
    let mut last = String::new();
    for target in entries.iter().take(12) {
        let (status, body) = ctx.call(
            "read",
            Operation::ReadFiles,
            target,
            serde_json::json!({"path": target}),
        )?;
        if (200..300).contains(&status) && Ctx::body_field(&body, "contents").is_some() {
            return Ok(Ok(()));
        }
        last = body;
    }
    Ok(Err(format!(
        "no globbed entry yielded bytes; last answer: {}",
        last.trim()
    )))
}

/// The task the whole write path exists for: the HOST chooses bytes, the guest
/// writes them, the guest reads them back, the host compares. An empty success
/// would pass a status check and fail this.
fn write_and_read_back(ctx: &Ctx<'_>) -> Result<Outcome> {
    let nonce = ctx.nonce();
    let path = format!("agency-{nonce}.txt");
    let payload = format!("nucleus agency round trip {nonce}");
    write_with_approval(ctx, &path, &payload)
}

/// Writing over a file that already exists is a different capability
/// (`edit_files`, not `write_files`) and a different gate. A suite that only
/// ever created new files would report the edit path as working without having
/// touched it.
fn edit_an_existing_file(ctx: &Ctx<'_>) -> Result<Outcome> {
    let nonce = ctx.nonce();
    let path = format!("agency-edit-{nonce}.txt");
    if let Err(why) = write_with_approval(ctx, &path, "first")? {
        return Ok(Err(format!("could not create the file to edit: {why}")));
    }
    write_with_approval(ctx, &path, "second")
}

/// Run a command. `codegen` grants `run_bash` at `low_risk`, which is the whole
/// point of the profile — an agent that cannot run its own tests cannot fix a
/// build.
fn run_a_command(ctx: &Ctx<'_>) -> Result<Outcome> {
    let args = vec!["echo".to_string(), "nucleus-agency".to_string()];
    let subject = args.join(" ");
    let (status, body) = ctx.call(
        "run",
        Operation::RunBash,
        &subject,
        serde_json::json!({"args": args}),
    )?;
    if (200..300).contains(&status) {
        return Ok(Ok(()));
    }
    if let Some(op) = approval_required_operation(&body) {
        if ctx.approve(&op)? {
            let (status, body) = ctx.call(
                "run",
                Operation::RunBash,
                &subject,
                serde_json::json!({"args": args}),
            )?;
            if (200..300).contains(&status) {
                return Ok(Ok(()));
            }
            return Ok(Err(format!("refused after approval: {}", body.trim())));
        }
    }
    Ok(Err(format!("refused: {}", body.trim())))
}

/// Write, approving once if the profile defers, then read back and compare.
fn write_with_approval(ctx: &Ctx<'_>, path: &str, payload: &str) -> Result<Outcome> {
    let body = serde_json::json!({"path": path, "contents": payload});
    let (status, text) = ctx.call("write", Operation::WriteFiles, path, body.clone())?;
    if !(200..300).contains(&status) {
        let Some(op) = approval_required_operation(&text) else {
            return Ok(Err(format!("write refused: {}", text.trim())));
        };
        if !ctx.approve(&op)? {
            return Ok(Err(format!("approval refused for {op}")));
        }
        let (status, text) = ctx.call("write", Operation::WriteFiles, path, body)?;
        if !(200..300).contains(&status) {
            return Ok(Err(format!(
                "write refused after approval: {}",
                text.trim()
            )));
        }
    }
    let (status, text) = ctx.call(
        "read",
        Operation::ReadFiles,
        path,
        serde_json::json!({"path": path}),
    )?;
    if !(200..300).contains(&status) {
        return Ok(Err(format!("read back refused: {}", text.trim())));
    }
    match Ctx::body_field(&text, "contents").as_deref() {
        Some(got) if got == payload => Ok(Ok(())),
        Some(got) => Ok(Err(format!(
            "read back {got:?}, wrote {payload:?} — the write path answered without serving the sandbox"
        ))),
        None => Ok(Err("read back returned no contents field".to_string())),
    }
}

const WORK: &[Task] = &[
    Task {
        id: "discover-workspace",
        goal: "see what is in the workspace",
        run: discover_workspace,
    },
    Task {
        id: "read-a-file",
        goal: "read real bytes out of the sandbox",
        run: read_a_file,
    },
    Task {
        id: "write-and-read-back",
        goal: "write a file and read the same bytes back",
        run: write_and_read_back,
    },
    Task {
        id: "edit-an-existing-file",
        goal: "change a file that already exists",
        run: edit_an_existing_file,
    },
    Task {
        id: "run-a-command",
        goal: "run a command, the way a test run would",
        run: run_a_command,
    },
];

// ── Containment: what makes the numerator quotable ──────────────────────────

/// A read every profile must refuse, matched by two independent rules in
/// `PathLattice::block_sensitive` — so a refusal is policy, not absence.
fn refuses_secret_read(ctx: &Ctx<'_>) -> Result<Outcome> {
    let (status, body) = ctx.call(
        "read",
        Operation::ReadFiles,
        FORBIDDEN_READ,
        serde_json::json!({"path": FORBIDDEN_READ}),
    )?;
    if (200..300).contains(&status) {
        return Ok(Err(format!("{FORBIDDEN_READ} was SERVED: {}", body.trim())));
    }
    Ok(Ok(()))
}

/// `codegen` grants no egress at all. A pod that fetches is not isolating
/// anything, and every completion rate measured on it is worthless.
fn refuses_uncredentialed_egress(ctx: &Ctx<'_>) -> Result<Outcome> {
    let url = "http://127.0.0.1/";
    let (status, body) = ctx.call(
        "web_fetch",
        Operation::WebFetch,
        url,
        serde_json::json!({"url": url}),
    )?;
    if (200..300).contains(&status) {
        return Ok(Err(format!("egress SUCCEEDED: {}", body.trim())));
    }
    Ok(Ok(()))
}

/// A write to a path no policy admits must not land.
///
/// This replaced a check that asserted an unapproved write is DEFERRED, and the
/// replacement is worth explaining because the old one failing is what exposed
/// it. Under the `codegen` profile writes are `low_risk`, so they defer and the
/// check passed. Under a compiled grant for the same work they are authorised
/// outright — `nucleus run --goal` says so in as many words, "no approval
/// prompts expected" — so the write landed and the check reported a breach.
///
/// It was the check that was wrong. It encoded a property of one profile rather
/// than an invariant, and containment checks decide whether a whole reading may
/// be quoted, so a check that depends on which grant is in force can void a
/// perfectly good measurement. Worth noting the mechanism did exactly what it
/// is for: the report refused to be quoted, and the thing it caught was a
/// defect in the suite rather than in the runtime.
///
/// A blocked path is refused under every profile and every grant — `.env` is in
/// the path lattice's sensitive set, which the grant's own `Limits` line names —
/// so this holds regardless of how writes are graded.
fn refuses_write_to_a_blocked_path(ctx: &Ctx<'_>) -> Result<Outcome> {
    let path = ".env";
    let (status, body) = ctx.call(
        "write",
        Operation::WriteFiles,
        path,
        serde_json::json!({"path": path, "contents": "SECRET=leaked"}),
    )?;
    if (200..300).contains(&status) {
        return Ok(Err(format!("a write to {path} SUCCEEDED")));
    }
    if approval_required_operation(&body).is_some() {
        return Ok(Err(format!(
            "{path} was deferred to a person rather than refused; a blocked path is not \
             an approval question: {}",
            body.trim()
        )));
    }
    Ok(Ok(()))
}

const CONTAINMENT: &[Task] = &[
    Task {
        id: "refuses-secret-read",
        goal: "a private key is not readable",
        run: refuses_secret_read,
    },
    Task {
        id: "refuses-uncredentialed-egress",
        goal: "there is no egress from this pod",
        run: refuses_uncredentialed_egress,
    },
    Task {
        id: "refuses-write-to-a-blocked-path",
        goal: "a write to a path no policy admits does not land",
        run: refuses_write_to_a_blocked_path,
    },
];

fn globbed(body: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("matches").and_then(|m| m.as_array()).map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
        })
        .unwrap_or_default()
}

fn run_tasks(ctx: &Ctx<'_>, tasks: &[Task]) -> Result<Vec<TaskOutcome>> {
    let mut out = Vec::with_capacity(tasks.len());
    for t in tasks {
        let result = (t.run)(ctx)?;
        let (completed, refused_by) = match result {
            Ok(()) => (true, None),
            Err(why) => (false, Some(why)),
        };
        println!(
            "  {:<32} {}",
            t.id,
            if completed {
                "completed"
            } else {
                "NOT COMPLETED"
            }
        );
        if let Some(why) = &refused_by {
            println!("      {why}");
        }
        out.push(TaskOutcome {
            id: t.id.to_string(),
            goal: t.goal.to_string(),
            completed,
            refused_by,
        });
    }
    Ok(out)
}

/// Run both suites against a live pod and build the report.
pub(crate) fn measure(
    proxy: &str,
    key: Option<&ed25519_dalek::SigningKey>,
    actor: &str,
    lattice: &portcullis::PermissionLattice,
    label: &str,
    enforcement: Enforcement,
    commit: Option<String>,
) -> Result<AgencyReport> {
    let ctx = Ctx::new(proxy, key, actor);

    println!("\nwork (the numerator)");
    let tasks = run_tasks(&ctx, WORK)?;
    println!("\ncontainment (what makes it quotable)");
    let containment = run_tasks(&ctx, CONTAINMENT)?;

    let deferrals = ctx.deferrals.get();
    let observations = ctx.observations.into_inner();
    let risk = risk_of(lattice);
    let usage = usage_from(lattice, risk.clone(), &observations)?;

    Ok(AgencyReport {
        schema_version: AgencyReport::SCHEMA_VERSION,
        label: label.to_string(),
        commit,
        enforcement,
        tasks,
        containment,
        cost: AuthorityCost {
            overhead_dimensions: usage.authority_overhead(),
            // Not measured here, and null rather than 1.0 to say so: this pod
            // ran under a PROFILE, and ρ over effects needs a compiled grant
            // to divide by. `nucleus run --goal` produces one; a profile does
            // not. A default of 1.0 would report perfect precision for a
            // quantity nobody computed.
            overhead_effects: None,
            clicks: ctx.approvals.get(),
            denials_within_grant: usage.denials_within_grant(),
            denials_total: usage.denied,
            deferrals,
            residual_risk: risk.after,
        },
        recovery: None,
    })
}

/// Measure under a compiled grant: the same suites, attributed against the
/// grant's own effects.
///
/// This is the only path where ρ_effect is a number. `attribute_usage` divides
/// granted effects by exercised ones, and a profile has none — so the profile
/// arm reports `None` and says why, while this arm reports the ratio the effect
/// catalog is supposed to move.
pub(crate) struct GrantRun<'a> {
    /// Where the proxy is listening.
    pub proxy: &'a str,
    /// HMAC secret, when the proxy this harness spawned requires signing.
    pub secret: Option<Vec<u8>>,
    /// The approver key, when the harness may act as the person.
    pub key: Option<&'a ed25519_dalek::SigningKey>,
    /// Actor recorded on approvals.
    pub actor: &'a str,
    /// What the measurement is.
    pub label: &'a str,
    /// Which boundary the work crossed.
    pub enforcement: Enforcement,
    /// The commit measured.
    pub commit: Option<String>,
}

pub(crate) fn measure_under_grant(
    run: GrantRun<'_>,
    grant: &portcullis::task_grant::TaskGrant,
) -> Result<AgencyReport> {
    let GrantRun {
        proxy,
        secret,
        key,
        actor,
        label,
        enforcement,
        commit,
    } = run;
    let ctx = Ctx::new(proxy, key, actor).with_secret(secret);

    println!("\nwork (the numerator)");
    let tasks = run_tasks(&ctx, WORK)?;
    println!("\ncontainment (what makes it quotable)");
    let containment = run_tasks(&ctx, CONTAINMENT)?;

    // C(T) = confirmations BEFORE the run plus approvals during it. A compiled
    // grant costs exactly one confirmation — the person reading Can / Cannot /
    // Limits / Risk once and accepting it — and that one is counted here rather
    // than quietly dropped, because dropping it would make the grant arm look
    // free next to the profile arm when it is not. It is cheaper, not free.
    let clicks = 1 + ctx.approvals.get();
    let deferrals = ctx.deferrals.get();
    let observations = ctx.observations.into_inner();
    let catalog = portcullis::effect_catalog::EffectCatalog::builtin()
        .context("the built-in effect catalog must parse")?;
    let usage = portcullis::attribute_usage(grant, &catalog, &observations);

    Ok(AgencyReport {
        schema_version: AgencyReport::SCHEMA_VERSION,
        label: label.to_string(),
        commit,
        enforcement,
        tasks,
        containment,
        cost: AuthorityCost {
            overhead_dimensions: usage.authority_overhead(),
            overhead_effects: usage.effect_overhead(),
            clicks,
            denials_within_grant: usage.denials_within_grant(),
            denials_total: usage.denied,
            deferrals,
            residual_risk: grant.risk.after,
        },
        recovery: None,
    })
}

/// Attribute the harness's own observations against the pod's lattice.
///
/// A grant with no effects: the pod ran under a profile, so there are no
/// semantic effects to attribute to, and every effect-level figure is `None`
/// rather than invented. The dimension-level figures are real — they come from
/// the lattice the pod actually resolved.
fn usage_from(
    lattice: &portcullis::PermissionLattice,
    risk: portcullis::task_grant::RiskSummary,
    observations: &[Observation],
) -> Result<portcullis::UsageReport> {
    let catalog = portcullis::effect_catalog::EffectCatalog::builtin()
        .context("the built-in effect catalog must parse")?;
    let grant = profile_shaped_grant(lattice, risk);
    Ok(portcullis::attribute_usage(&grant, &catalog, observations))
}

/// The uninhabitable-state analysis of the lattice the pod ran under,
/// measured against the restrictive floor the grant compiler measures against.
fn risk_of(lattice: &portcullis::PermissionLattice) -> portcullis::task_grant::RiskSummary {
    let gap = portcullis::WeakeningCostConfig::default()
        .compute_gap(&portcullis::PermissionLattice::restrictive(), lattice);
    portcullis::task_grant::summarise_risk(lattice, gap)
}

fn profile_shaped_grant(
    lattice: &portcullis::PermissionLattice,
    risk: portcullis::task_grant::RiskSummary,
) -> portcullis::task_grant::TaskGrant {
    use portcullis::task_grant::{CompilerProvenance, GrantLimits, TaskGrant};
    let goal = "agency suite";
    TaskGrant {
        version: TaskGrant::VERSION,
        id: uuid::Uuid::new_v4(),
        goal: goal.to_string(),
        goal_digest: TaskGrant::digest_goal(goal),
        ceiling_profile: "profile".to_string(),
        can: Default::default(),
        cannot: Vec::new(),
        limits: GrantLimits {
            max_cost_usd: lattice.budget.max_cost_usd,
            duration_secs: 0,
            hosts: Vec::new(),
            blocked_paths: Vec::new(),
            commands: Vec::new(),
        },
        lattice: lattice.clone(),
        risk,
        provenance: CompilerProvenance {
            compiler: concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")).to_string(),
            proposers: Vec::new(),
            rules_fired: Vec::new(),
            repo_context_digest: String::new(),
        },
        created_at: chrono::Utc::now(),
        not_after: chrono::Utc::now(),
    }
}

/// Compile a goal into a grant, seal it, and stand up a local tool-proxy under
/// it — Tier 1, no microVM, no node.
///
/// This is the arm that makes ρ_effect a number rather than a `None`. Under a
/// *profile* there are no semantic effects to divide by; under a compiled grant
/// there are, and the same grant's effects are sealed into the certificate the
/// proxy verifies, so the run is bounded by the effects it is measured against
/// rather than merely described by them.
///
/// The proxy is spawned exactly as `nucleus run --local` spawns it — same
/// flags, same Tier-3 orchestrator token, same announce-file handshake — so
/// this measures the shipped local path and not a parallel copy of it.
pub(crate) struct LocalGrantRun {
    /// Where the proxy is listening.
    pub proxy_url: String,
    /// The grant the run is bounded by, and attributed against.
    pub grant: portcullis::task_grant::TaskGrant,
    /// The per-run HMAC secret the proxy was spawned with.
    pub auth_secret: Vec<u8>,
    /// Kept alive for the duration: dropping it kills the proxy and removes
    /// the temporary directory.
    _proxy: ProxyChild,
    _tmp: TempDir,
}

/// A spawned proxy that is killed when it goes out of scope.
pub(crate) struct ProxyChild(std::process::Child);

impl Drop for ProxyChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A temporary directory removed on drop.
pub(crate) struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Compile `goal` against `ceiling`, seal it, and spawn a proxy under it.
///
/// `explicit` is what `nucleus grant widen` adds: effects granted on top of
/// what the goal implies, still clamped by the ceiling. The recovery lane uses
/// it to grant exactly the minimum a proposal named, which is what makes that
/// path one decision rather than a person editing a profile.
pub(crate) fn spawn_local_under_grant(
    goal: &str,
    ceiling_profile: &str,
    proxy_bin: &str,
    work_dir: &std::path::Path,
    explicit: &std::collections::BTreeSet<portcullis::EffectId>,
) -> Result<LocalGrantRun> {
    use portcullis::sealed_grant::SealedTaskGrant;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    let catalog = portcullis::effect_catalog::EffectCatalog::builtin()
        .context("the built-in effect catalog must parse")?;
    let registry = portcullis::profile::ProfileRegistry::default();
    let ceiling = registry
        .resolve(ceiling_profile)
        .with_context(|| format!("unknown ceiling profile '{ceiling_profile}'"))?;
    let ctx = nucleus_task_compiler::probe(work_dir)
        .with_context(|| format!("probing the repository at {}", work_dir.display()))?;
    let proposer = nucleus_task_compiler::RuleProposer;
    let cost = portcullis::WeakeningCostConfig::default();
    let grant = nucleus_task_compiler::compile(nucleus_task_compiler::CompileInput {
        goal,
        ctx: &ctx,
        catalog: &catalog,
        ceiling_profile,
        ceiling: &ceiling,
        proposers: &[&proposer],
        explicit,
        limits: Default::default(),
        cost_config: &cost,
    })
    .with_context(|| format!("compiling the goal {goal:?}"))?;

    // Seal it. The harness holds the approver key for the length of the run,
    // which is the same standing `nucleus grant seal` gives a person's key.
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow::anyhow!("generating an approver key"))?;
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow::anyhow!("loading the approver key"))?;
    let root_pubkey = hex::encode(key.public_key().as_ref());
    let sealed = SealedTaskGrant::seal(grant.clone(), "nucleus-perf".to_string(), &key);
    let cert_b64 = sealed
        .token
        .to_base64()
        .context("encoding the sealed certificate")?;

    let run_id = format!("agency-{}-{}", std::process::id(), grant.id.simple());
    let tmp = std::env::temp_dir().join(format!("nucleus-{run_id}"));
    std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let tmp_guard = TempDir(tmp.clone());

    // The spec carries the SEALED permissions, so the on-disk policy and the
    // certificate agree; the proxy warns when they do not and runs under the
    // certificate either way.
    let spec_path = tmp.join("pod.yaml");
    let spec = serde_json::json!({
        "apiVersion": "nucleus/v1",
        "kind": "Pod",
        "metadata": { "name": "agency-local" },
        "spec": {
            "work_dir": work_dir,
            "timeout_seconds": 600,
            "policy": { "type": "inline", "lattice": grant.sealed_permissions() },
        }
    });
    std::fs::write(&spec_path, serde_yaml::to_string(&spec)?)
        .with_context(|| format!("writing {}", spec_path.display()))?;

    let auth_secret = hex::encode(rand_bytes32());
    let approval_secret = hex::encode(rand_bytes32());
    let spec_contents = std::fs::read_to_string(&spec_path)?;
    let spec_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(spec_contents.as_bytes()))
    };
    let sandbox_token =
        nucleus_client::generate_sandbox_token(auth_secret.as_bytes(), &run_id, &spec_hash);

    // The session capability token. Without one the proxy's discharge gate has
    // `verified_scope == None`, and `InScopeWithTask` denies EVERY operation
    // fail-closed — correct behaviour, and the reason a first local run scored
    // 1/5 with "no verified scope present" on every task. The node mints this
    // per pod; a local run has to mint its own, from the same input: the scope
    // is the grant's granted operations, which is a subset of the grant by
    // construction.
    let task_key = ed25519_dalek::SigningKey::from_bytes(&rand_bytes32());
    let mut nonce = [0u8; 16];
    {
        use ring::rand::SecureRandom as _;
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .expect("system randomness");
    }
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let scope =
        nucleus_provenance_memory::TokenScope::new(grant.lattice.granted_operations(), Vec::new());
    let task_token = nucleus_provenance_memory::SignedTaskRef::issue(
        run_id.clone(),
        scope,
        nonce,
        now_unix,
        grant.limits.duration_secs.max(600),
        &task_key,
    );
    let task_token_json =
        serde_json::to_string(&task_token).context("serialising the session task token")?;

    let announce = tmp.join("proxy.addr");
    let child = std::process::Command::new(proxy_bin)
        .arg("--spec")
        .arg(&spec_path)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--announce-path")
        .arg(&announce)
        .arg("--auth-secret")
        .arg(&auth_secret)
        .arg("--approval-secret")
        .arg(&approval_secret)
        .arg("--pod-cert")
        .arg(&cert_b64)
        .arg("--cert-root-pubkey")
        .arg(&root_pubkey)
        // Keep the audit log inside the run's own directory. The default is
        // `/var/log/nucleus`, which a non-root local run cannot create, and the
        // proxy refuses to start without somewhere to record verdicts — as it
        // should: a mediated run with no audit sink is the one shape this
        // system must never quietly allow.
        .arg("--audit-log")
        .arg(tmp.join("audit.log"))
        .env("NUCLEUS_SANDBOX_TOKEN", &sandbox_token)
        .env("NUCLEUS_TASK_TOKEN", &task_token_json)
        .env("NUCLEUS_TASK_TOKEN_NONCE", hex::encode(nonce))
        .env(
            "NUCLEUS_TASK_TOKEN_ISSUER",
            hex::encode(task_key.verifying_key().to_bytes()),
        )
        .env("NUCLEUS_TOOL_PROXY_DRAND_ENABLED", "false")
        .stdout(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {proxy_bin}"))?;
    let proxy = ProxyChild(child);

    // The announce file is the proxy's own readiness signal, so waiting on it
    // cannot race the bind the way a fixed sleep does.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let addr = loop {
        if let Ok(s) = std::fs::read_to_string(&announce) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                break s;
            }
        }
        if std::time::Instant::now() > deadline {
            bail!("the tool-proxy did not announce an address within 20s");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };

    Ok(LocalGrantRun {
        proxy_url: format!("http://{addr}"),
        grant,
        auth_secret: auth_secret.clone().into_bytes(),
        _proxy: proxy,
        _tmp: tmp_guard,
    })
}

// ── Recovery friction ───────────────────────────────────────────────────────

/// Measure the path from a refusal back to working.
///
/// `D`'s denominator has four terms and only `C(T)` was ever measured. This
/// measures the one that decides whether a delegation *survives* being wrong:
/// an agent refused something it needed, and how far it is from there to a
/// grant that works.
///
/// The lane is deliberately under-granted. `goal` is compiled with no explicit
/// effects, and the work attempted is a write — so a read-shaped goal is
/// refused, on purpose, by the boundary doing its job. Then:
///
/// 1. the refusal is read off the wire,
/// 2. `escalation_proposal::propose` names the least authority that would have
///    allowed it,
/// 3. the grant is recompiled with exactly that effect added — **one decision**,
/// 4. the same work is attempted again.
///
/// # What the harness is not allowed to know
///
/// The effect that fixes it comes from `propose`, never from this file. A lane
/// that hard-coded `fs/edit-workspace` would report one decision while proving
/// only that the author knew the answer. The assertion worth making is that
/// the proposal's minimum was **sufficient** — refused before, granted, and
/// completed after — because a proposal that names a minimum which does not
/// work is worse than none: it spends the person's one decision and leaves
/// them exactly where they started.
///
/// # On reconstructing the reason
///
/// `propose` takes a structured `DenyReason`; the wire carries the stable deny
/// *code*. The code is the contract (`gate_class::deny_code`), and for a
/// capability held at `never` the mapping back is exact. It is still a
/// reconstruction, and it exists only because a denial does not yet carry its
/// own proposal in band — when it does, this step is deleted and the harness
/// reads `proposal.minimum` straight off the refusal it was given.
pub(crate) fn measure_recovery(
    goal: &str,
    ceiling_profile: &str,
    proxy_bin: &str,
    work_dir: &std::path::Path,
) -> Result<portcullis::agency_report::Recovery> {
    use portcullis::escalation_proposal::propose;
    use portcullis::kernel::DenyReason;

    let none = std::collections::BTreeSet::new();
    let under = spawn_local_under_grant(goal, ceiling_profile, proxy_bin, work_dir, &none)?;

    // The attempt that must fail. A lane whose first attempt SUCCEEDS has not
    // measured recovery — it has measured a grant that was wide enough all
    // along — so that case is an error rather than a zero.
    let nonce = std::process::id();
    let path = format!("agency-recovery-{nonce}.txt");
    let payload = format!("nucleus recovery {nonce}");
    let attempt = |run: &LocalGrantRun| -> Result<(u16, String)> {
        let ctx = Ctx::new(&run.proxy_url, None, "nucleus-agency")
            .with_secret(Some(run.auth_secret.clone()));
        ctx.call(
            "write",
            Operation::WriteFiles,
            &path,
            serde_json::json!({"path": &path, "contents": &payload}),
        )
    };

    let started = std::time::Instant::now();
    let (status, body) = attempt(&under)?;
    if (200..300).contains(&status) {
        bail!(
            "the recovery lane's goal {goal:?} already grants the write it is supposed to be \
             refused; under-grant it or the measurement means nothing"
        );
    }
    let blocked_by = Ctx::body_field(&body, "kind").unwrap_or_else(|| format!("http {status}"));

    // The proposal. The reason is reconstructed from the stable code; the
    // ANSWER is not — that comes from the catalog, the grant and the ceiling.
    let catalog = portcullis::effect_catalog::EffectCatalog::builtin()
        .context("the built-in effect catalog must parse")?;
    let ceiling = portcullis::profile::ProfileRegistry::default()
        .resolve(ceiling_profile)
        .with_context(|| format!("unknown ceiling profile '{ceiling_profile}'"))?;
    let proposal = propose(
        &under.grant,
        &ceiling,
        &catalog,
        &portcullis::WeakeningCostConfig::default(),
        Operation::WriteFiles,
        &path,
        &DenyReason::InsufficientCapability,
    );
    let named = proposal
        .minimum
        .as_ref()
        .and_then(|m| m.effects.first())
        .cloned();

    let Some(effect) = named.clone() else {
        // The loop is open. Reported, not hidden: a denial that proposes
        // nothing is the failure this whole part exists to detect, and it is
        // worth a row in the report rather than an error that stops the run.
        return Ok(portcullis::agency_report::Recovery {
            task: "write-after-refusal".to_string(),
            blocked_by,
            proposal_named: None,
            decisions: 0,
            seconds: started.elapsed().as_secs_f64(),
            recovered: false,
        });
    };

    // ONE decision: re-seal the same goal under the same ceiling with exactly
    // the effect the proposal named. Nothing else changes — not the goal, not
    // the ceiling, not the limits.
    let mut widened = std::collections::BTreeSet::new();
    widened.insert(effect.clone());
    drop(under);
    let after = spawn_local_under_grant(goal, ceiling_profile, proxy_bin, work_dir, &widened)?;
    let (status, body) = attempt(&after)?;
    let recovered = (200..300).contains(&status);
    if !recovered {
        println!(
            "  recovery: still refused after granting {effect}: {}",
            body.trim()
        );
    }

    Ok(portcullis::agency_report::Recovery {
        task: "write-after-refusal".to_string(),
        blocked_by,
        proposal_named: Some(effect.to_string()),
        decisions: 1,
        seconds: started.elapsed().as_secs_f64(),
        recovered,
    })
}

fn rand_bytes32() -> [u8; 32] {
    use ring::rand::SecureRandom as _;
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("system randomness");
    b
}

/// The `agency` subcommand: boot nothing, measure a pod that is already up.
pub(crate) fn write_report(report: &AgencyReport, out: Option<&str>) -> Result<()> {
    println!("\n{}", report.render());
    if let Some(path) = out {
        let json = serde_json::to_string_pretty(report)? + "\n";
        std::fs::write(path, json).with_context(|| format!("writing {path}"))?;
        println!("wrote {path}");
    }
    if !report.is_valid() {
        bail!("containment did not hold: this run is not a point on the frontier");
    }
    Ok(())
}
