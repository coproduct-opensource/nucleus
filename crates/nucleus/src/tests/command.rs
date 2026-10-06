//! Tests for [`crate::command`], in their own file so the module stays under
//! its line ceiling.

// This crate is `#![deny(unsafe_code)]` and that stays true of everything it
// ships. Edition 2024 made `std::env::set_var` unsafe, and two tests here
// must set a variable in the PARENT process to prove the child cannot see
// it -- which is the property under test, so it cannot be rewritten to use
// `Command::env`. The exception is therefore scoped to the test module and
// goes nowhere near the library.
#![allow(unsafe_code)]

use super::*;

/// Path-qualified git/gh must classify by operation, not slip into `run_bash`.
/// Before the basename fix the three path-qualified asserts RED (`/usr/bin/git
/// push` has args[0]="/usr/bin/git" != "git"), so a `git_push=Never` policy with
/// `run_bash` open is bypassed by path-qualifying the binary.
#[test]
fn path_qualified_git_ops_are_classified() {
    assert!(is_git_push_command(&["/usr/bin/git".into(), "push".into()]));
    assert!(is_git_commit_command(&[
        "/usr/bin/git".into(),
        "commit".into()
    ]));
    assert!(is_pr_command(&[
        "/usr/local/bin/gh".into(),
        "pr".into(),
        "create".into()
    ]));
    // Baseline unchanged.
    assert!(is_git_push_command(&["git".into(), "push".into()]));
    // No false positive: a different program whose basename isn't `git`.
    assert!(!is_git_push_command(&["mygit".into(), "push".into()]));
}
use crate::budget::AtomicBudget;
use crate::sandbox::Sandbox;
// Sanctioned cross-crate test-only bundle: runs a real `preflight_action` on a
// known-good term. This is the only supported way for out-of-module tests to
// obtain a sealed `DischargedBundle` (the constructor is private to discharge).
use nucleus_ifc_kernel::{Operation, SinkClass};

/// Every test in this module drives the SHELL executor, so its bundle must be
/// one earned for running a shell — not the generic write-scoped helper.
///
/// This is the point of the scope check rather than an obstacle to it: a
/// bundle discharged for WriteFiles/WorkspaceWrite does not authorise
/// RunBash/BashExec, and `require_scope` refuses it. Before the check existed
/// these tests passed with a bundle earned for a different action entirely,
/// which is exactly the confused-deputy shape the check closes.
/// The bundle `Executor::run(cmd)` needs.
///
/// `run` splits the command string and the spawn boundary rejoins it, so
/// the subject the spend sees is `shell_words::split(cmd).join(" ")` — not
/// `cmd`. The two differ whenever the command carries quoting
/// (`bash -c "echo hi"` becomes `bash -c echo hi`), so a test that used the
/// literal would be minting for a target the spend never sees.
fn run_bundle(cmd: &str) -> nucleus_ifc_kernel::discharge::DischargedBundle {
    allowed_bundle(
        &shell_words::split(cmd)
            .expect("test command parses")
            .join(" "),
    )
}

/// A shell bundle earned for a SPECIFIC command.
///
/// The spend in `RealEffects::run_argv` binds the target, and the target it
/// renders is `args.join(" ")` with the program first — the same string
/// `run_args_internal` builds as `display_command`. So a test authorising
/// `echo hello` must mint for `"echo hello"`; a bundle for anything else is
/// refused, which is the property.
fn allowed_bundle(subject: &str) -> nucleus_ifc_kernel::discharge::DischargedBundle {
    nucleus_ifc_kernel::discharge::test_helpers::bundle_for_subject(
        Operation::RunBash,
        SinkClass::BashExec,
        subject,
    )
}
use portcullis::BudgetLattice;
use portcullis::kernel::Kernel;
use rust_decimal::Decimal;
use tempfile::tempdir;

fn test_policy() -> PermissionLattice {
    let mut policy = PermissionLattice::default();
    policy.capabilities.read_files = CapabilityLevel::Never;
    policy.capabilities.run_bash = CapabilityLevel::LowRisk;
    policy.capabilities.web_fetch = CapabilityLevel::Never;
    policy.capabilities.web_search = CapabilityLevel::Never;
    policy.obligations = Obligations::default();
    policy.commands = CommandLattice::permissive();
    policy
}

fn test_budget() -> BudgetLattice {
    BudgetLattice {
        max_cost_usd: Decimal::try_from(10.0).unwrap(),
        consumed_usd: Decimal::ZERO,
        max_input_tokens: 100_000,
        max_output_tokens: 10_000,
        consumed_input_tokens: 0,
        consumed_output_tokens: 0,
    }
}

fn zero_budget() -> BudgetLattice {
    BudgetLattice {
        max_cost_usd: Decimal::ZERO,
        consumed_usd: Decimal::ZERO,
        max_input_tokens: 100_000,
        max_output_tokens: 10_000,
        consumed_input_tokens: 0,
        consumed_output_tokens: 0,
    }
}

/// Helper: get a DecisionToken for RunBash from a kernel matching the test policy.
#[allow(deprecated)] // Migration to decide_term tracked in #1194
fn run_token(kernel: &mut Kernel, subject: &str) -> DecisionToken {
    let (_decision, tok) = kernel.decide(Operation::RunBash, subject);
    tok.expect("test kernel should allow RunBash")
}

#[test]
fn test_basic_command() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    let dt = run_token(&mut kernel, "echo hello");
    let output = executor
        .run("echo hello", dt, Authority::new(run_bundle("echo hello")))
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
}

/// The trust-handoff escape through the shell: one `RunBash` decision about
/// a command string, and the process writes a git hook the next host
/// `git commit` would run. The executor reverts it and refuses the command;
/// the ordinary file the same command wrote is the control, and survives.
#[test]
fn a_command_that_writes_a_git_hook_is_reverted_and_refused() {
    let tmp = tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".git/hooks")).unwrap();
    // A root runtime's child runs as the drop uid (owner decision 2), so
    // the hook directory must be its to write, or the escape this test
    // reverts never happens and the test proves nothing.
    let confinement = ChildConfinement::for_containment(
        ContainmentMode::Unsandboxed,
        crate::UnsandboxedOptIn::Explicit,
        crate::LandlockWaiver::Absent,
    )
    .unwrap();
    for dir in [".git", ".git/hooks"] {
        confinement.hand_over(&tmp.path().join(dir)).unwrap();
    }
    let policy = test_policy();
    let budget = AtomicBudget::new(&test_budget());
    let mut kernel = Kernel::new(policy.clone());
    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    let cmd = "touch .git/hooks/pre-commit";
    let dt = run_token(&mut kernel, cmd);
    match executor.run(cmd, dt, Authority::new(run_bundle(cmd))) {
        Err(NucleusError::CommandDenied { reason, .. }) => {
            assert!(reason.contains(".git/hooks/pre-commit"), "{reason}")
        }
        other => panic!("expected CommandDenied naming the hook, got {other:?}"),
    }
    assert!(!tmp.path().join(".git/hooks/pre-commit").exists());

    // The control: the same command against an unwatched path runs as before.
    let cmd = "touch src.txt";
    let dt = run_token(&mut kernel, cmd);
    executor
        .run(cmd, dt, Authority::new(run_bundle(cmd)))
        .expect("an unwatched write is not refused");
    assert!(tmp.path().join("src.txt").exists());
}

#[test]
fn test_budget_exhausted_blocks_execution() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = zero_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    let dt = run_token(&mut kernel, "echo hello");
    let result = executor.run("echo hello", dt, Authority::new(run_bundle("echo hello")));
    assert!(matches!(result, Err(NucleusError::BudgetExhausted { .. })));
}

#[test]
fn test_blocked_command() {
    let tmp = tempdir().unwrap();
    let mut policy = test_policy();
    policy.commands = CommandLattice::default(); // Has blocklist
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    // rm -rf should be blocked by executor's command policy.
    // Kernel also blocks it (CommandBlocked), so force a token to test the executor layer.
    let dt = kernel.issue_approved_token(
        Operation::RunBash,
        "test: bypass kernel for executor blocklist test",
    );
    let result = executor.run("rm -rf /", dt, Authority::new(run_bundle("rm -rf /")));
    assert!(result.is_err());
}

#[test]
#[allow(deprecated)] // Migration to decide_term tracked in #1194
fn test_never_capability() {
    let tmp = tempdir().unwrap();
    let mut policy = test_policy();
    policy.capabilities.run_bash = CapabilityLevel::Never;
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    // Kernel will deny — no token. Use issue_approved_token to force a token for test.
    let (_d, tok) = kernel.decide(Operation::RunBash, "echo hello");
    assert!(tok.is_none(), "kernel should deny Never capability");

    let forced = kernel.issue_approved_token(Operation::RunBash, "test: force token");
    let result = executor.run(
        "echo hello",
        forced,
        Authority::new(run_bundle("echo hello")),
    );
    assert!(matches!(
        result,
        Err(NucleusError::InsufficientCapability { .. })
    ));
}

#[test]
fn test_approval_required_without_callback() {
    let tmp = tempdir().unwrap();
    let mut policy = test_policy();
    policy.obligations.insert(Operation::RunBash);
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    // Kernel requires approval — force a token via issue_approved_token to test executor layer
    let forced = kernel.issue_approved_token(Operation::RunBash, "test: force token");
    let result = executor.run(
        "echo hello",
        forced,
        Authority::new(run_bundle("echo hello")),
    );
    assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));
}

#[test]
fn test_approval_with_token() {
    let tmp = tempdir().unwrap();
    let mut policy = test_policy();
    policy.obligations.insert(Operation::RunBash);
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .with_approval_callback(|_| true)
        .allow_unsandboxed_local(); // Always approve

    // Grant approval in kernel, then get a token
    kernel.grant_approval(Operation::RunBash, 1);
    let dt = run_token(&mut kernel, "echo hello");

    // Derived from the rule, not spelled out: a test that hardcoded this
    // gate's own wording is how three vocabularies drifted apart without
    // any suite going red (#2406).
    let approval = executor
        .request_approval(&crate::approval::approval_key(
            Operation::RunBash,
            "echo hello",
        ))
        .unwrap();
    let result = executor.run_with_approval(
        "echo hello",
        dt,
        &approval,
        Authority::new(run_bundle("echo hello")),
    );
    assert!(result.is_ok());
}

/// End to end: a token decided by a kernel under one policy is refused by an
/// executor running another.
///
/// This is the A-19 probe for the redeem-side check, on the real types
/// rather than on two strings. Before it, the only redeem-side question was
/// "is this the right Operation?", and the answer for a token from an
/// entirely different policy was yes.
#[test]
fn a_token_from_another_policy_is_refused_by_this_executor() {
    let tmp = tempdir().unwrap();

    // Kernel A: bash allowed.
    let lenient = test_policy();
    let mut kernel = Kernel::new(lenient.clone());
    let foreign =
        kernel.issue_approved_token(Operation::RunBash, "decided under the lenient policy");

    // Executor B: a different policy entirely.
    // Same shape, one capability different — so the refusal below is about
    // the policy differing, not about the effect being disallowed.
    let mut other = lenient.clone();
    other.capabilities.write_files = CapabilityLevel::Never;

    let sandbox = Sandbox::new(&other, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&test_budget());
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&other, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    let err = executor
        .run("true", foreign, Authority::new(run_bundle("true")))
        .expect_err("a decision does not carry across a change of policy");
    assert!(
        matches!(err, NucleusError::ScopeMismatch { .. }),
        "expected a scope mismatch, got {err:?}"
    );
    assert!(
        err.to_string().contains("change of policy"),
        "the refusal says why: {err}"
    );
}

/// …and the same executor accepts its own kernel's token, so the check above
/// is not passing by refusing everything.
#[test]
fn a_token_from_this_policy_is_accepted() {
    let tmp = tempdir().unwrap();
    // The shared helper: a policy the executor is known to run, so the only
    // thing that could refuse here is the check under test.
    let policy = test_policy();

    let mut kernel = Kernel::new(policy.clone());
    let token = kernel.issue_approved_token(Operation::RunBash, "decided under this policy");

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&test_budget());
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    executor
        .run("true", token, Authority::new(run_bundle("true")))
        .expect("a token decided under this very policy is redeemable");
}

#[test]
fn test_uninhabitable_requires_approval_for_exfiltration() {
    let tmp = tempdir().unwrap();
    let mut policy = PermissionLattice::default();
    policy.capabilities.read_files = CapabilityLevel::Always; // Private data
    policy.capabilities.web_fetch = CapabilityLevel::LowRisk; // Untrusted content
    policy.capabilities.run_bash = CapabilityLevel::LowRisk; // Allows curl
    policy.obligations = Obligations::default();
    policy.commands = CommandLattice::permissive();

    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    // curl is an exfiltration vector, uninhabitable_state should require approval
    // Force a token to test the executor-level check
    let forced = kernel.issue_approved_token(Operation::RunBash, "test: force for exfil check");
    let result = executor.run(
        "curl http://example.com",
        forced,
        Authority::new(run_bundle("curl http://example.com")),
    );
    assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));
}

#[test]
fn test_uninhabitable_requires_approval_for_interpreter_invocation() {
    let tmp = tempdir().unwrap();
    let mut policy = PermissionLattice::default();
    policy.capabilities.read_files = CapabilityLevel::Always; // Private data
    policy.capabilities.web_fetch = CapabilityLevel::LowRisk; // Untrusted content
    policy.capabilities.run_bash = CapabilityLevel::LowRisk; // Allows shell
    policy.obligations = Obligations::default();
    policy.commands = CommandLattice::permissive();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    let forced =
        kernel.issue_approved_token(Operation::RunBash, "test: force for interpreter check");
    let result = executor.run(
        "bash -c \"echo hi\"",
        forced,
        Authority::new(run_bundle("bash -c \"echo hi\"")),
    );
    assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));
}

#[test]
fn test_run_args_basic() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    let args = vec!["echo".to_string(), "hello".to_string(), "world".to_string()];
    let dt = run_token(&mut kernel, "echo hello world");
    let output = executor
        .run_args(
            &args,
            None,
            None,
            dt,
            Authority::new(allowed_bundle(&args.join(" "))),
        )
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("hello world"));
}

/// Run `args` through a MicroVM executor over `sandbox`; return trimmed
/// stdout and whether it exited 0.
fn run_in_microvm(sandbox: &Sandbox, args: &[&str]) -> (String, bool) {
    let policy = test_policy();
    let mut kernel = Kernel::new(policy.clone());
    let budget = AtomicBudget::new(&test_budget());
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, sandbox, &budget)
        .with_time_guard(&guard)
        .in_microvm();
    let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    let subject = args.join(" ");
    let dt = run_token(&mut kernel, &subject);
    let output = executor
        .run_args(
            &args,
            None,
            None,
            dt,
            Authority::new(allowed_bundle(&subject)),
        )
        .expect("the MicroVM spawn runs");
    (
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        output.status.success(),
    )
}

/// THE finding, on a real spawn: inside a guest the tool-proxy is PID 1 and
/// root, and a `/v1/run` child under MicroVM ran as root too — so it could
/// read the runtime's environment (broker secret, mediation signing key,
/// audit credentials) out of procfs. It must run as the workload uid.
///
/// Needs root, because only root can drop — which is exactly the guest's
/// situation. Run with
/// `sudo <test-binary> --ignored a_microvm_child_of_a_root_runtime`.
/// Red on the parent commit (`id -u` printed `0` and the read succeeded).
#[test]
#[ignore = "needs root: only a root runtime can drop the child's uid"]
fn a_microvm_child_of_a_root_runtime_is_not_root_and_cannot_read_the_runtimes_environ() {
    // Spelled with std and a literal rather than this crate's names, so the
    // SAME test compiles on the parent commit and shows the defect there.
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        std::fs::metadata("/proc/self").map(|m| m.uid()).ok(),
        Some(0),
        "run this test as root; as anyone else it proves nothing"
    );
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

    let (uid, ok) = run_in_microvm(&sandbox, &["id", "-u"]);
    assert!(ok, "id -u failed");
    assert_eq!(uid, "65534", "child uid (the workload's)");

    // The runtime here is this test process, root, exactly as PID 1 is in
    // the guest. Non-vacuity: the runtime itself CAN read its environ.
    let environ = format!("/proc/{}/environ", std::process::id());
    assert!(
        std::fs::read(&environ).is_ok_and(|b| !b.is_empty()),
        "positive control: the runtime reads its own environ"
    );
    let (_, read_ok) = run_in_microvm(&sandbox, &["cat", environ.as_str()]);
    assert!(!read_ok, "the child read the root runtime's {environ}");
    let (_, read_pid1) = run_in_microvm(&sandbox, &["cat", "/proc/1/environ"]);
    assert!(!read_pid1, "the child read /proc/1/environ");
}

/// Owner decision (2026-10-02, follow-up on #3129): every bare execution
/// traces to an explicit opt-in. A `/v1/run` child of a non-root runtime
/// declared `Unsandboxed`, with no `UnsandboxedOptIn::Explicit`, is
/// refused BY NAME (naming `--unsandboxed`) -- declaring the mode alone
/// used to run it at the runtime's uid. A root runtime drops instead, so
/// it needs no opt-in. On a real spawn.
#[test]
fn an_unsandboxed_child_without_the_opt_in_is_refused_by_name() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let mut kernel = Kernel::new(policy.clone());
    let budget = AtomicBudget::new(&test_budget());
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .with_containment(ContainmentMode::Unsandboxed);
    let args = vec!["id".to_string(), "-u".to_string()];
    let subject = args.join(" ");
    let dt = run_token(&mut kernel, &subject);
    let result = executor.run_args(
        &args,
        None,
        None,
        dt,
        Authority::new(allowed_bundle(&subject)),
    );
    match crate::runtime_uid() {
        0 => {
            let out = result.expect("a root runtime drops; it needs no opt-in");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                crate::DEFAULT_CHILD_UID.to_string()
            );
        }
        runtime => match result {
            Err(NucleusError::UnsandboxedNotOptedIn { runtime_uid }) => {
                assert_eq!(runtime_uid, runtime);
            }
            Err(other) => panic!("refused, but not by name: {other:?}"),
            Ok(out) => panic!(
                "a bare child ran at the runtime's uid ({runtime}) with no opt-in: id -u = {}",
                String::from_utf8_lossy(&out.stdout).trim()
            ),
        },
    }
}

/// Owner decision 2 (2026-10-02, #3129): whenever the runtime is root,
/// its `/v1/run` children leave root in EVERY mode -- `Unsandboxed` and
/// `HostHardened` included, not only `MicroVM`. `Unsandboxed` then means
/// no namespace or seccomp confinement, but never root.
///
/// On a real spawn, each runtime uid asserting its own exact outcome: a
/// root runtime's child is uid 65534 and cannot read the runtime's
/// environ; a non-root runtime's child keeps that runtime's uid (the
/// declared bare / self-restricted tiers, unchanged).
#[test]
fn a_root_runtimes_child_is_never_root_in_any_mode() {
    let mut modes = vec![ContainmentMode::Unsandboxed];
    if cfg!(target_os = "linux") {
        modes.push(ContainmentMode::HostHardened);
    }
    let runtime = crate::runtime_uid();
    let environ = format!("/proc/{}/environ", std::process::id());
    for mode in modes {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let mut kernel = Kernel::new(policy.clone());
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_containment(mode)
            .with_unsandboxed_opt_in(crate::UnsandboxedOptIn::Explicit);
        let run = |kernel: &mut Kernel, args: Vec<String>| {
            let subject = args.join(" ");
            let dt = run_token(kernel, &subject);
            executor
                .run_args(
                    &args,
                    None,
                    None,
                    dt,
                    Authority::new(allowed_bundle(&subject)),
                )
                .unwrap_or_else(|e| panic!("{mode:?}: spawn refused: {e}"))
        };
        let id = run(&mut kernel, vec!["id".into(), "-u".into()]);
        let child_uid = String::from_utf8_lossy(&id.stdout).trim().to_string();
        let read = run(&mut kernel, vec!["cat".into(), environ.clone()]);
        if runtime == 0 {
            assert_eq!(
                child_uid,
                crate::DEFAULT_CHILD_UID.to_string(),
                "{mode:?}: a root runtime's child ran as root"
            );
            assert!(
                !read.status.success() && read.stdout.is_empty(),
                "{mode:?}: the dropped child read the runtime's environ ({} bytes)",
                read.stdout.len()
            );
        } else {
            assert_eq!(child_uid, runtime.to_string(), "{mode:?}");
        }
    }
}

/// The fd half of the confinement, on a real spawn: a `HostHardened`
/// child (restricted, or dropped under a root runtime) inherits no
/// descriptor beyond its own stdio, while the bare tier's child keeps
/// whatever the runtime leaves open. `ls /proc/self/fd` opens one more fd
/// for its directory listing, so a confined child lists at most four.
///
/// This is the mechanism the tool-proxy's workload test used to cover
/// through a non-root harness; since #3120 a non-root workload is either
/// refused or on the declared bare tier, which closes nothing, so the
/// close-on-exec sweep is asserted here, where a non-root CI runner still
/// reaches it. The test harness itself holds high non-CLOEXEC fds (seen in
/// CI: 149 and 152), which is what the bare row shows.
#[cfg(target_os = "linux")]
#[test]
fn a_confined_child_inherits_no_fd_beyond_its_stdio() {
    let list = |mode: ContainmentMode| {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let mut kernel = Kernel::new(policy.clone());
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_containment(mode)
            .with_unsandboxed_opt_in(crate::UnsandboxedOptIn::Explicit);
        let args = vec!["ls".to_string(), "/proc/self/fd".to_string()];
        let subject = args.join(" ");
        let dt = run_token(&mut kernel, &subject);
        let out = executor
            .run_args(
                &args,
                None,
                None,
                dt,
                Authority::new(allowed_bundle(&subject)),
            )
            .unwrap_or_else(|e| panic!("{mode:?}: spawn refused: {e}"));
        assert!(out.status.success(), "{mode:?}: ls ran");
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let confined = list(ContainmentMode::HostHardened);
    assert!(
        confined.len() >= 3,
        "non-vacuity: the child has its stdio; got {confined:?}"
    );
    assert!(
        confined.len() <= 4,
        "a confined child inherited a descriptor beyond its stdio: {confined:?}"
    );
    let bare = list(ContainmentMode::Unsandboxed);
    if crate::runtime_uid() != 0 {
        // The contrast, reported rather than required: whether the bare
        // child sees extra fds depends on what the harness left open.
        eprintln!("bare-tier child fds (no sweep, by design): {bare:?}");
    }
}

/// #2696 P3b through the Executor's own spawn path (the `/v1/run` child):
/// a `HostHardened` child carries one more seccomp filter than this process,
/// and the declared bare tier none of ours. The mechanism's behaviour (what
/// the filter refuses) is asserted in `tests/child_seccomp.rs`; this pins that
/// the Executor's children get it at all. Counted relative to this process,
/// which may already sit under a container's filter.
#[cfg(target_os = "linux")]
#[test]
fn a_run_child_carries_the_workload_syscall_filter() {
    let filters = |status: &str| -> u32 {
        status
            .lines()
            .find_map(|l| l.strip_prefix("Seccomp_filters:"))
            .and_then(|v| v.trim().parse().ok())
            .expect("Seccomp_filters is readable (Linux 5.9+)")
    };
    let own = filters(&std::fs::read_to_string("/proc/self/status").unwrap());
    let child = |mode: ContainmentMode| {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let mut kernel = Kernel::new(policy.clone());
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_containment(mode)
            .with_unsandboxed_opt_in(crate::UnsandboxedOptIn::Explicit);
        let args = vec!["cat".to_string(), "/proc/self/status".to_string()];
        let subject = args.join(" ");
        let dt = run_token(&mut kernel, &subject);
        let out = executor
            .run_args(
                &args,
                None,
                None,
                dt,
                Authority::new(allowed_bundle(&subject)),
            )
            .unwrap_or_else(|e| panic!("{mode:?}: spawn refused: {e}"));
        assert!(out.status.success(), "{mode:?}: cat ran");
        filters(&String::from_utf8_lossy(&out.stdout))
    };
    assert_eq!(
        child(ContainmentMode::HostHardened),
        own + 1,
        "HostHardened"
    );
    assert_eq!(child(ContainmentMode::Unsandboxed), own, "Unsandboxed");
}

/// #3120 item 2, on a real spawn: a MicroVM child never reads the
/// runtime's environment, whoever the runtime is.
///
/// Root (the guest): the child drops and the read fails. Any other uid:
/// the runtime cannot drop, and the spawn is refused BY NAME — before the
/// fix it ran `cat /proc/<runtime>/environ` at the runtime's uid and
/// printed every byte (red on the parent commit, as uid 1001: "read the
/// runtime's environ: 1943 bytes"). Not `#[ignore]`d: each uid asserts
/// its own exact outcome, so CI as root and a developer as themselves
/// both run it.
#[cfg(target_os = "linux")]
#[test]
fn a_microvm_child_never_reads_the_runtimes_environ_whoever_the_runtime_is() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let mut kernel = Kernel::new(policy.clone());
    let budget = AtomicBudget::new(&test_budget());
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .in_microvm();
    let environ = format!("/proc/{}/environ", std::process::id());
    assert!(
        std::fs::read(&environ).is_ok_and(|b| !b.is_empty()),
        "positive control: the runtime reads its own environ"
    );
    let args = vec!["cat".to_string(), environ];
    let subject = args.join(" ");
    let dt = run_token(&mut kernel, &subject);
    let result = executor.run_args(
        &args,
        None,
        None,
        dt,
        Authority::new(allowed_bundle(&subject)),
    );
    match crate::runtime_uid() {
        0 => {
            let out = result.expect("a root runtime drops and spawns");
            assert!(
                !out.status.success() && out.stdout.is_empty(),
                "the dropped child read the runtime's environ"
            );
        }
        runtime_uid => match result {
            Err(NucleusError::ChildSeparationUnavailable {
                runtime_uid: r,
                child_uid,
            }) => {
                assert_eq!(r, runtime_uid);
                assert_eq!(child_uid, crate::DEFAULT_CHILD_UID);
            }
            Ok(out) => panic!(
                "a MicroVM child of a non-root runtime (uid {runtime_uid}) ran at its uid \
                 (read {} bytes of its environ)",
                out.stdout.len()
            ),
            Err(other) => panic!("refused, but not by name: {other:?}"),
        },
    }
}

/// The other half of "don't break the workspace": a file the runtime writes
/// through a MicroVM pod's sandbox belongs to the child uid, so the agent's
/// next command can rewrite it in place.
#[test]
#[ignore = "needs root: only root can chown"]
fn a_microvm_pods_sandbox_hands_what_it_creates_to_the_child_uid() {
    use std::os::unix::fs::MetadataExt;
    assert_eq!(crate::runtime_uid(), 0, "run this test as root");
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap().owned_for(
        ChildConfinement::for_containment(
            ContainmentMode::MicroVM,
            crate::UnsandboxedOptIn::Absent,
            crate::LandlockWaiver::Absent,
        )
        .unwrap(),
    );
    sandbox
        .write_owned(std::path::Path::new("new.txt"), b"x")
        .unwrap();
    let meta = std::fs::metadata(tmp.path().join("new.txt")).unwrap();
    assert_eq!(meta.uid(), crate::DEFAULT_CHILD_UID);

    // And the child, as that uid, can rewrite it in place.
    let (_, ok) = run_in_microvm(&sandbox, &["truncate", "-s", "0", "new.txt"]);
    assert!(
        ok,
        "the dropped child could not write a file the runtime created"
    );
}

#[test]
fn test_run_args_prevents_shell_injection() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    // With array form, shell metacharacters are passed literally
    let args = vec!["echo".to_string(), "$(whoami)".to_string()];
    let dt = run_token(&mut kernel, "echo $(whoami)");
    let output = executor
        .run_args(
            &args,
            None,
            None,
            dt,
            Authority::new(allowed_bundle(&args.join(" "))),
        )
        .unwrap();
    // Should print the literal string, not execute whoami
    assert!(String::from_utf8_lossy(&output.stdout).contains("$(whoami)"));
}

#[test]
fn test_run_args_with_stdin() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    let args = vec!["cat".to_string()];
    let dt = run_token(&mut kernel, "cat");
    let output = executor
        .run_args(
            &args,
            Some("hello from stdin"),
            None,
            dt,
            Authority::new(allowed_bundle(&args.join(" "))),
        )
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("hello from stdin"));
}

#[test]
fn test_run_args_empty_command() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    let args: Vec<String> = vec![];
    // Kernel also blocks empty commands, so force a token to test executor layer
    let dt = kernel.issue_approved_token(Operation::RunBash, "test: empty command");
    let result = executor.run_args(
        &args,
        None,
        None,
        dt,
        Authority::new(allowed_bundle(&args.join(" "))),
    );
    assert!(matches!(result, Err(NucleusError::CommandDenied { .. })));
}

#[test]
fn test_run_args_directory_escape() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    let args = vec!["pwd".to_string()];
    let dt = run_token(&mut kernel, "pwd");
    // Attempt to escape sandbox using absolute path
    let result = executor.run_args(
        &args,
        None,
        Some("/etc"),
        dt,
        Authority::new(allowed_bundle(&args.join(" "))),
    );
    assert!(matches!(result, Err(NucleusError::SandboxEscape { .. })));
}

#[test]
fn test_env_isolation_clears_parent_env() {
    // Set a secret in the parent environment
    // SAFETY: edition 2024 makes env mutation unsafe because it races any
    // concurrent reader, and the test harness is multi-threaded. This is
    // a real caveat, not a formality: it is sound here only because the
    // key is unique to this test, so no other test reads or writes it.
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 H-1: test-only process-global mutation"
    )]
    unsafe {
        std::env::set_var("TEST_PARENT_SECRET", "super-secret-value")
    };

    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .allow_unsandboxed_local();

    // Try to access the parent env var - should NOT be visible
    let dt = run_token(&mut kernel, "printenv TEST_PARENT_SECRET");
    let output = executor
        .run(
            "printenv TEST_PARENT_SECRET",
            dt,
            Authority::new(run_bundle("printenv TEST_PARENT_SECRET")),
        )
        .unwrap();

    // Command should succeed but output should be empty (var not found)
    // printenv returns exit code 1 when var is not found
    assert!(!output.status.success(), "env var should not be accessible");

    // Clean up
    // SAFETY: edition 2024 makes env mutation unsafe because it races any
    // concurrent reader, and the test harness is multi-threaded. This is
    // a real caveat, not a formality: it is sound here only because the
    // key is unique to this test, so no other test reads or writes it.
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 H-1: test-only process-global mutation"
    )]
    unsafe {
        std::env::remove_var("TEST_PARENT_SECRET")
    };
}

#[test]
fn test_env_isolation_passes_allowed_env() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);

    // Explicitly allow a specific env var
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .with_env_var("ALLOWED_TOKEN", "test-value-123")
        .allow_unsandboxed_local();

    // The allowed var should be visible
    let dt = run_token(&mut kernel, "printenv ALLOWED_TOKEN");
    let output = executor
        .run(
            "printenv ALLOWED_TOKEN",
            dt,
            Authority::new(run_bundle("printenv ALLOWED_TOKEN")),
        )
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("test-value-123"));
}

#[test]
fn test_env_isolation_with_multiple_vars() {
    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);

    let mut env = BTreeMap::new();
    env.insert("VAR_A".to_string(), "value_a".to_string());
    env.insert("VAR_B".to_string(), "value_b".to_string());

    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .with_env(env)
        .allow_unsandboxed_local();

    // Both vars should be visible
    let dt_a = run_token(&mut kernel, "printenv VAR_A");
    let output_a = executor
        .run(
            "printenv VAR_A",
            dt_a,
            Authority::new(run_bundle("printenv VAR_A")),
        )
        .unwrap();
    assert!(output_a.status.success());
    assert!(String::from_utf8_lossy(&output_a.stdout).contains("value_a"));

    let dt_b = run_token(&mut kernel, "printenv VAR_B");
    let output_b = executor
        .run(
            "printenv VAR_B",
            dt_b,
            Authority::new(run_bundle("printenv VAR_B")),
        )
        .unwrap();
    assert!(output_b.status.success());
    assert!(String::from_utf8_lossy(&output_b.stdout).contains("value_b"));
}

#[test]
fn test_env_isolation_run_args() {
    // Verify env isolation also works for run_args
    // SAFETY: edition 2024 makes env mutation unsafe because it races any
    // concurrent reader, and the test harness is multi-threaded. This is
    // a real caveat, not a formality: it is sound here only because the
    // key is unique to this test, so no other test reads or writes it.
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 H-1: test-only process-global mutation"
    )]
    unsafe {
        std::env::set_var("TEST_RUN_ARGS_SECRET", "leaked-secret")
    };

    let tmp = tempdir().unwrap();
    let policy = test_policy();
    let budget_policy = test_budget();
    let mut kernel = Kernel::new(policy.clone());

    let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
    let budget = AtomicBudget::new(&budget_policy);
    let guard = MonotonicGuard::seconds(10);
    let executor = Executor::new(&policy, &sandbox, &budget)
        .with_time_guard(&guard)
        .with_env_var("ALLOWED_VAR", "allowed-value")
        .allow_unsandboxed_local();

    // Parent env should not be visible
    let args = vec!["printenv".to_string(), "TEST_RUN_ARGS_SECRET".to_string()];
    let dt1 = run_token(&mut kernel, "printenv TEST_RUN_ARGS_SECRET");
    let output = executor
        .run_args(
            &args,
            None,
            None,
            dt1,
            Authority::new(allowed_bundle(&args.join(" "))),
        )
        .unwrap();
    assert!(
        !output.status.success(),
        "parent env should not be accessible"
    );

    // But allowed env should be visible
    let args = vec!["printenv".to_string(), "ALLOWED_VAR".to_string()];
    let dt2 = run_token(&mut kernel, "printenv ALLOWED_VAR");
    let output = executor
        .run_args(
            &args,
            None,
            None,
            dt2,
            Authority::new(allowed_bundle(&args.join(" "))),
        )
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("allowed-value"));

    // Clean up
    // SAFETY: edition 2024 makes env mutation unsafe because it races any
    // concurrent reader, and the test harness is multi-threaded. This is
    // a real caveat, not a formality: it is sound here only because the
    // key is unique to this test, so no other test reads or writes it.
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 H-1: test-only process-global mutation"
    )]
    unsafe {
        std::env::remove_var("TEST_RUN_ARGS_SECRET")
    };
}

// ───────────────────────────────────────────────────────────────────────
// Fail-closed isolation gate (most-paranoid #2)
// ───────────────────────────────────────────────────────────────────────
mod isolation_gate {
    use super::*;

    /// Default `Unconfigured` containment refuses to spawn — the hard-flip
    /// fail-closed default that closes "silently run as a bare host process".
    #[test]
    fn unconfigured_default_refuses_spawn() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        // NOTE: no containment builder called — stays Unconfigured.
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let dt = run_token(&mut kernel, "echo hi");
        let err = executor
            .run("echo hi", dt, Authority::new(run_bundle("echo hi")))
            .unwrap_err();
        assert!(
            matches!(err, NucleusError::IsolationNotConfigured),
            "expected IsolationNotConfigured, got {err:?}"
        );
    }

    /// `run_args` is gated too (not just `run`).
    #[test]
    fn unconfigured_refuses_run_args() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget).with_time_guard(&guard);

        let args = vec!["echo".to_string(), "hi".to_string()];
        let dt = run_token(&mut kernel, "echo hi");
        let err = executor
            .run_args(
                &args,
                None,
                None,
                dt,
                Authority::new(allowed_bundle(&args.join(" "))),
            )
            .unwrap_err();
        assert!(
            matches!(err, NucleusError::IsolationNotConfigured),
            "got {err:?}"
        );
    }

    /// Explicit Tier-1 opt-in to unsandboxed execution allows spawn when the
    /// policy demands no stronger isolation.
    #[test]
    fn unsandboxed_opt_in_allows_spawn() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let dt = run_token(&mut kernel, "echo hi");
        let output = executor
            .run("echo hi", dt, Authority::new(run_bundle("echo hi")))
            .unwrap();
        assert!(output.status.success());
    }

    /// A policy requiring a microVM is refused — never silently downgraded —
    /// when the Executor can only attest unsandboxed host execution. This is
    /// the fail-closed-without-a-VM property (the "not contained" state is
    /// simulated purely via the declared containment mode; no KVM needed).
    #[test]
    fn microvm_required_but_unsandboxed_refuses() {
        let tmp = tempdir().unwrap();
        let policy = test_policy().with_minimum_isolation(IsolationLattice::microvm());
        // Kernel built WITH microvm isolation so it still mints a token; the
        // Executor gate is what must refuse.
        let mut kernel = Kernel::with_isolation(policy.clone(), IsolationLattice::microvm());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let dt = run_token(&mut kernel, "echo hi");
        let err = executor
            .run("echo hi", dt, Authority::new(run_bundle("echo hi")))
            .unwrap_err();
        assert!(
            matches!(err, NucleusError::IsolationInsufficient { .. }),
            "expected IsolationInsufficient, got {err:?}"
        );
    }

    /// When the Executor attests it is inside a microVM, a microVM-requiring
    /// policy passes the gate. What happens next depends on the REAL
    /// runtime uid, and both outcomes are asserted exactly: a root runtime
    /// (the guest) runs the child; any other refuses it by name at the
    /// confinement step, which runs after this gate — so the refusal is
    /// not `IsolationInsufficient`.
    #[test]
    fn microvm_required_and_in_microvm_allows() {
        let tmp = tempdir().unwrap();
        let policy = test_policy().with_minimum_isolation(IsolationLattice::microvm());
        let mut kernel = Kernel::with_isolation(policy.clone(), IsolationLattice::microvm());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .in_microvm();

        let dt = run_token(&mut kernel, "echo hi");
        let result = executor.run("echo hi", dt, Authority::new(run_bundle("echo hi")));
        match crate::runtime_uid() {
            0 => assert!(result.unwrap().status.success()),
            runtime_uid => assert!(
                matches!(
                    result,
                    Err(NucleusError::ChildSeparationUnavailable { runtime_uid: r, .. })
                        if r == runtime_uid
                ),
                "a non-root MicroVM executor must refuse by name, got {result:?}"
            ),
        }
    }

    /// On non-Linux hosts, requesting host hardening fails CLOSED rather than
    /// silently running unhardened. (On Linux this path attests a strengthened
    /// file dimension instead; see the Linux smoke test.)
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn host_hardening_fails_closed_off_linux() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_host_hardening();

        let dt = run_token(&mut kernel, "echo hi");
        let err = executor
            .run("echo hi", dt, Authority::new(run_bundle("echo hi")))
            .unwrap_err();
        assert!(
            matches!(err, NucleusError::HardeningUnavailable { .. }),
            "expected HardeningUnavailable off-Linux, got {err:?}"
        );
    }

    /// Linux smoke test: a host-hardened child actually has seccomp/no-new-privs
    /// posture. Marked ignore — needs a Linux host; validated in Linux CI.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Linux host; run in linux CI (NoNewPrivs check)"]
    fn host_hardened_child_has_no_new_privs() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_host_hardening();

        let dt = run_token(&mut kernel, "cat /proc/self/status");
        let output = executor
            .run(
                "cat /proc/self/status",
                dt,
                Authority::new(run_bundle("cat /proc/self/status")),
            )
            .unwrap();
        let status = String::from_utf8_lossy(&output.stdout);
        assert!(
            status
                .lines()
                .any(|l| l.starts_with("NoNewPrivs:") && l.contains('1')),
            "hardened child should have NoNewPrivs:1, got:\n{status}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
// Async timeout spawn (B3): `run_with_timeout*` now DELEGATE to the sealed
// async home `AsyncShellSpawnEffect::run_argv_async`. These exercise the
// delegated path end-to-end to prove behavior is preserved: a fast command
// succeeds, a slow command hits the timeout and maps to `TimeViolation`
// (kill_on_drop reaps the child), and env isolation still holds.
// ───────────────────────────────────────────────────────────────────────
#[cfg(feature = "async")]
mod async_timeout {
    use super::*;

    /// A command that finishes inside the timeout returns its output — the
    /// happy path through the delegated `run_argv_async`.
    #[tokio::test]
    async fn run_with_timeout_returns_output() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let dt = run_token(&mut kernel, "echo hello");
        let output = executor
            .run_with_timeout(
                "echo hello",
                Duration::from_secs(5),
                dt,
                Authority::new(run_bundle("echo hello")),
            )
            .await
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
    }

    /// A command that outlives the timeout maps to `TimeViolation` (the
    /// child is killed on drop), preserving the pre-relocation error.
    #[tokio::test]
    async fn run_with_timeout_times_out() {
        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .allow_unsandboxed_local();

        let dt = run_token(&mut kernel, "sleep 30");
        let err = executor
            .run_with_timeout(
                "sleep 30",
                Duration::from_millis(100),
                dt,
                Authority::new(run_bundle("sleep 30")),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, NucleusError::TimeViolation { .. }),
            "expected TimeViolation, got {err:?}"
        );
    }

    /// Env isolation still holds on the async path: the parent environment
    /// is cleared, and only explicitly-allowed vars reach the child.
    #[tokio::test]
    async fn run_with_timeout_isolates_env() {
        // SAFETY: edition 2024 makes env mutation unsafe because it races any
        // concurrent reader, and the test harness is multi-threaded. This is
        // a real caveat, not a formality: it is sound here only because the
        // key is unique to this test, so no other test reads or writes it.
        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 H-1: test-only process-global mutation"
        )]
        unsafe {
            std::env::set_var("TEST_ASYNC_PARENT_SECRET", "leaked")
        };

        let tmp = tempdir().unwrap();
        let policy = test_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let budget = AtomicBudget::new(&test_budget());
        let guard = MonotonicGuard::seconds(10);
        let executor = Executor::new(&policy, &sandbox, &budget)
            .with_time_guard(&guard)
            .with_env_var("ALLOWED_ASYNC_VAR", "async-allowed")
            .allow_unsandboxed_local();

        // Parent secret must NOT be visible (printenv exits non-zero).
        let dt1 = run_token(&mut kernel, "printenv TEST_ASYNC_PARENT_SECRET");
        let secret = executor
            .run_with_timeout(
                "printenv TEST_ASYNC_PARENT_SECRET",
                Duration::from_secs(5),
                dt1,
                Authority::new(run_bundle("printenv TEST_ASYNC_PARENT_SECRET")),
            )
            .await
            .unwrap();
        assert!(!secret.status.success(), "parent env leaked to async child");

        // Allowed var must be visible.
        let dt2 = run_token(&mut kernel, "printenv ALLOWED_ASYNC_VAR");
        let allowed = executor
            .run_with_timeout(
                "printenv ALLOWED_ASYNC_VAR",
                Duration::from_secs(5),
                dt2,
                Authority::new(run_bundle("printenv ALLOWED_ASYNC_VAR")),
            )
            .await
            .unwrap();
        assert!(allowed.status.success());
        assert!(String::from_utf8_lossy(&allowed.stdout).contains("async-allowed"));

        // SAFETY: edition 2024 makes env mutation unsafe because it races any

        // concurrent reader, and the test harness is multi-threaded. This is

        // a real caveat, not a formality: it is sound here only because the

        // key is unique to this test, so no other test reads or writes it.

        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 H-1: test-only process-global mutation"
        )]
        unsafe {
            std::env::remove_var("TEST_ASYNC_PARENT_SECRET")
        };
    }
}

/// `Executor` ≡ `RealEffects::run_argv` on argv admission (#2573).
///
/// Over generated argvs — empty, empty program, NUL bytes in the program
/// or in any argument, and well-formed — the executor refuses with a
/// `CommandDenied` carrying the shared prefix EXACTLY when the sealed home
/// refuses with an `InvalidInput` carrying the same prefix, and both agree
/// with `argv::split_and_check`. Accepted argvs name a program that does
/// not exist, so the spawn fails with ENOENT on both sides and no process
/// is ever run; the property is about the refusal, not the spawn.
mod argv_parity {
    use super::*;
    use portcullis_effects::argv::{ARGV_REFUSED_PREFIX, split_and_check};
    use proptest::prelude::*;

    fn token() -> impl Strategy<Value = String> {
        proptest::collection::vec(prop_oneof![Just('a'), Just('-'), Just('\0')], 0..3)
            .prop_map(|cs| cs.into_iter().collect())
    }

    fn argv() -> impl Strategy<Value = Vec<String>> {
        let program = prop_oneof![
            Just(String::new()),
            token().prop_map(|t| format!("/nonexistent/nucleus-argv-parity-{t}")),
        ];
        let args = proptest::collection::vec(token(), 0..3);
        prop_oneof![
            Just(Vec::new()),
            (program, args).prop_map(|(p, a)| std::iter::once(p).chain(a).collect()),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn executor_and_sealed_home_refuse_the_same_argv(argv in argv()) {
            let verdict = split_and_check(&argv);

            // Executor side: the public array entry.
            let tmp = tempdir().unwrap();
            let policy = test_policy();
            let budget_policy = test_budget();
            let mut kernel = Kernel::new(policy.clone());
            let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
            let budget = AtomicBudget::new(&budget_policy);
            let guard = MonotonicGuard::seconds(10);
            let executor = Executor::new(&policy, &sandbox, &budget)
                .with_time_guard(&guard)
                .allow_unsandboxed_local();
            let dt = run_token(&mut kernel, "argv-parity");
            let exec = executor.run_args(&argv, None, None, dt, Authority::new(allowed_bundle(&argv.join(" "))));
            let exec_refused = matches!(
                &exec,
                Err(NucleusError::CommandDenied { reason, .. }) if reason.starts_with(ARGV_REFUSED_PREFIX)
            );
            prop_assert_eq!(exec_refused, verdict.is_err(), "executor: {:?}", exec.as_ref().err());
            if let Err(rejection) = verdict {
                let same_reason = matches!(&exec, Err(NucleusError::CommandDenied { reason, .. }) if *reason == rejection.message());
                prop_assert!(same_reason, "executor reason differs: {:?}", exec.as_ref().err());
            }

            // Sealed-home side: the same argv straight into `run_argv`.
            if let Some((program, args)) = argv.split_first() {
                let home = production_effects_concrete(core_capabilities(&policy.capabilities));
                let r = home.run_argv(
                    program,
                    args,
                    tmp.path(),
                    None,
                    &BTreeMap::new(),
                    None,
                    Authority::new(allowed_bundle(&args.join(" "))),
                );
                let home_refused = matches!(
                    &r,
                    Err(e) if e.kind() == io::ErrorKind::InvalidInput && e.to_string().starts_with(ARGV_REFUSED_PREFIX)
                );
                prop_assert_eq!(home_refused, verdict.is_err(), "sealed home: {:?}", r.as_ref().err());
                if let Err(rejection) = verdict {
                    prop_assert_eq!(r.unwrap_err().to_string(), rejection.message());
                }
            } else {
                prop_assert_eq!(verdict, Err(portcullis_effects::argv::ArgvRejection::EmptyArgv));
            }
        }
    }
}
