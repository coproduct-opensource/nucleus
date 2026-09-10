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
        }
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
        let (status, text, _ms) = tool_call(self.proxy, route, body)?;
        let ok = (200..300).contains(&status);
        let obs = if ok {
            Observation::new(operation, subject)
        } else {
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

/// The gate that the work tasks above lean on. If an unapproved write
/// succeeded, `write-and-read-back` would pass for the wrong reason and C(T)
/// would read zero because nobody was ever asked.
fn refuses_unapproved_write(ctx: &Ctx<'_>) -> Result<Outcome> {
    let path = format!("agency-unapproved-{}.txt", ctx.nonce());
    let (status, body) = ctx.call(
        "write",
        Operation::WriteFiles,
        &path,
        serde_json::json!({"path": path, "contents": "should not land"}),
    )?;
    if (200..300).contains(&status) {
        return Ok(Err("an unapproved write SUCCEEDED".to_string()));
    }
    if approval_required_operation(&body).is_none() {
        return Ok(Err(format!(
            "refused, but not as an approval deferral: {}",
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
        id: "refuses-unapproved-write",
        goal: "a write nobody approved does not land",
        run: refuses_unapproved_write,
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
            residual_risk: risk.after,
        },
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
