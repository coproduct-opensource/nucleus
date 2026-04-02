//! Comprehensive help output for `nucleus-claude-hook`.
//!
//! Extracted from `main.rs` to reduce its line count and provide topic-based
//! help pages requested in <https://github.com/coproduct-opensource/nucleus/issues/568>.

/// Profile name/description pairs for the help output.
/// Keep in sync with `PROFILE_DESCRIPTIONS` in main.rs.
const PROFILE_HELP: &[(&str, &str)] = &[
    ("read_only", "Read + search only, no writes or execution"),
    ("code_review", "Read + search, no writes (PR review)"),
    ("edit_only", "Read + write, no execution or web"),
    ("fix_issue", "Read + write + bash + web, no push"),
    (
        "safe_pr_fixer",
        "Full dev workflow, no git push/PR (DEFAULT)",
    ),
    ("release", "Full access including git push and PR creation"),
    (
        "permissive",
        "All capabilities, audit-only (no enforcement)",
    ),
];

/// Print the main `--help` output.
pub fn print_help() {
    let version = env!("CARGO_PKG_VERSION");
    println!("nucleus-claude-hook {version} — Nucleus verified permission kernel for Claude Code");
    println!();

    // -- Synopsis --------------------------------------------------------
    println!("SYNOPSIS:");
    println!("  nucleus-claude-hook                Read hook JSON from stdin (normal mode)");
    println!("  nucleus-claude-hook <COMMAND>       Run a subcommand (see below)");
    println!("  nucleus-claude-hook --help <TOPIC>  Show detailed help for a topic");
    println!();

    // -- Commands --------------------------------------------------------
    println!("COMMANDS:");
    println!("  --setup                Configure ~/.claude/settings.json to install the hook");
    println!("  --init                 Scaffold a .nucleus/ project directory with defaults");
    println!("  --build [DIR]          Build a pre-signed policy artifact from .nucleus/");
    println!("    -o, --output FILE      Write artifact JSON to file instead of stdout");
    println!("  --status               Show active sessions, profile, and compartment");
    println!("    --json                 Machine-parseable JSON output");
    println!("  --show-profile [NAME]  Display a profile's full capability matrix");
    println!("  --receipts [SID]       View the signed receipt chain for a session");
    println!("  --doctor               Run diagnostic checks (hook install, dirs, etc.)");
    println!("  --smoke-test           Quick self-test: pipe synthetic hook input and verify");
    println!("  --gc                   Garbage-collect stale session files (>24h)");
    println!("  --reset-session <SID>  Clear taint on a session (receipts preserved)");
    println!("  --compartment-path <SID>  Print the compartment file path for a session");
    println!("  --uninstall            Remove hook configuration from settings.json");
    println!("  --completions <SHELL>  Print shell completions (bash, zsh, fish)");
    println!("  --exit-codes           Print the exit code protocol documentation");
    println!("  --benchmark            Measure hook decision latency (p50/p95/p99)");
    println!("    --iterations N         Number of iterations (default: 100)");
    println!("  --statusline           Output compact status for Claude Code status line");
    println!("  --help, -h             This message");
    println!("  --version, -V          Show version");
    println!();

    // -- Profiles -------------------------------------------------------
    println!("PROFILES (set NUCLEUS_PROFILE):");
    for (name, desc) in PROFILE_HELP {
        println!("  {name:<16} {desc}");
    }
    println!();

    // -- Compartments (brief) -------------------------------------------
    println!("COMPARTMENTS (set NUCLEUS_COMPARTMENT):");
    println!("  research    Read + web only (no writes, no execution)");
    println!("  draft       Read + write (no execution, no web)");
    println!("  execute     Read + write + bash (no push)");
    println!("  breakglass  All capabilities + enhanced audit (reason required)");
    println!();

    // -- Environment Variables ------------------------------------------
    println!("ENVIRONMENT VARIABLES:");
    println!("  NUCLEUS_PROFILE            Permission profile (default: safe_pr_fixer)");
    println!("  NUCLEUS_COMPARTMENT        Compartment: research, draft, execute, breakglass");
    println!("  NUCLEUS_FAIL_CLOSED        Set to 1: deny on infrastructure errors (CISO mode)");
    println!("  NUCLEUS_REQUIRE_MANIFESTS  Set to 1: deny MCP tools without manifests");
    println!("  NUCLEUS_TIMING             Set to 1: emit phase latency breakdown to stderr");
    println!("  NUCLEUS_AUTONOMY_CEILING   Org cap: production, sandbox (default: unrestricted)");
    println!("  NUCLEUS_LOG_CLASSIFICATION Set to 1: log tool classification to stderr");
    println!("  NUCLEUS_NO_COLOR           Disable ANSI color output (stderr only)");
    println!("  NO_COLOR                   Same (https://no-color.org/ convention)");
    println!("  NUCLEUS_PARENT_LABEL       IFC label for child sessions (taint propagation)");
    println!("  NUCLEUS_PARENT_SESSION     Parent session ID (receipt chain link)");
    println!("  NUCLEUS_PARENT_CHAIN_HASH  Parent chain head hash at spawn time");
    println!();

    // -- Topic Help -----------------------------------------------------
    println!("HELP TOPICS (--help <topic>):");
    println!("  compartments  Detailed compartment system and transitions");
    println!("  flow          Information flow control enforcement pipeline");
    println!("  profiles      All profiles with full capability matrices");
    println!();

    // -- Quick Start ----------------------------------------------------
    println!("QUICK START:");
    println!("  nucleus-claude-hook --init           # scaffold .nucleus/ in your project");
    println!("  nucleus-claude-hook --setup          # install hook into Claude Code settings");
    println!("  NUCLEUS_PROFILE=fix_issue claude     # start Claude with a restrictive profile");
    println!("  nucleus-claude-hook --status         # verify hook is active");
    println!();

    println!("Learn more: https://github.com/coproduct-opensource/nucleus/blob/main/docs/quickstart-hook.md");
}

/// Print detailed help for the compartment system.
pub fn print_help_compartments() {
    println!("COMPARTMENTS — Information Flow Control Boundaries");
    println!("==================================================");
    println!();
    println!("Compartments restrict which capabilities are available during a session.");
    println!("They are the runtime enforcement layer on top of profiles — a profile sets");
    println!("the *maximum* permissions, compartments narrow them based on the current");
    println!("phase of work.");
    println!();
    println!("AVAILABLE COMPARTMENTS:");
    println!();
    println!("  research");
    println!("    Allowed:  read_files, glob_search, grep_search, web_search, web_fetch");
    println!("    Denied:   write_files, edit_files, run_bash, git_*, create_pr, spawn_agent");
    println!("    Use case: Exploring code, reading docs, searching the web.");
    println!("              No side effects — the agent cannot modify anything.");
    println!();
    println!("  draft");
    println!("    Allowed:  read_files, write_files, edit_files, glob_search, grep_search");
    println!("    Denied:   run_bash, web_*, git_*, create_pr, spawn_agent");
    println!("    Use case: Writing code, editing files. No execution or network.");
    println!("              Prevents the agent from running its own code or pushing.");
    println!();
    println!("  execute");
    println!("    Allowed:  read, write, edit, bash, glob, grep, git_commit");
    println!("    Denied:   web_*, git_push, create_pr, spawn_agent");
    println!("    Use case: Running tests, building code. No network egress, no push.");
    println!("              The agent can run code but cannot exfiltrate data.");
    println!();
    println!("  breakglass");
    println!("    Allowed:  ALL capabilities");
    println!("    Requires: A reason string (logged in the receipt chain)");
    println!("    Use case: Emergency override. All actions are allowed but every");
    println!("              operation is logged with enhanced audit detail.");
    println!();
    println!("SETTING A COMPARTMENT:");
    println!("  export NUCLEUS_COMPARTMENT=research     # env var (session-wide)");
    println!(
        "  echo research > $(nucleus-claude-hook --compartment-path $SID)  # per-session file"
    );
    println!();
    println!("TRANSITIONS:");
    println!("  Compartments can be narrowed (research -> draft) at any time.");
    println!("  Widening (draft -> execute) requires the profile to permit it.");
    println!("  Breakglass can always be entered but generates an audit alert.");
    println!();
    println!("TAINT PROPAGATION:");
    println!("  When a child session is spawned, the parent's IFC label (taint) is");
    println!("  propagated via NUCLEUS_PARENT_LABEL. The child cannot exceed the");
    println!("  parent's compartment. This ensures information flow control is");
    println!("  transitive across agent hierarchies.");
}

/// Print detailed help for the enforcement pipeline / information flow control.
pub fn print_help_flow() {
    println!("ENFORCEMENT PIPELINE — How Nucleus Decides");
    println!("==========================================");
    println!();
    println!("When Claude Code invokes a tool, the hook receives a JSON event on stdin");
    println!("and must return a verdict (allow/deny/ask) on stdout. The decision flows");
    println!("through a multi-stage pipeline:");
    println!();
    println!("  1. PARSE & CLASSIFY");
    println!("     The hook reads the PreToolUse JSON from stdin and classifies the");
    println!("     tool invocation into an Operation (read_files, run_bash, etc.).");
    println!("     Set NUCLEUS_LOG_CLASSIFICATION=1 to see classifications on stderr.");
    println!();
    println!("  2. MANIFEST CHECK");
    println!("     For MCP (third-party) tools, the hook checks for a signed manifest");
    println!("     in .nucleus/manifests/. If NUCLEUS_REQUIRE_MANIFESTS=1 and no");
    println!("     manifest exists, the tool is denied immediately.");
    println!();
    println!("  3. PROFILE EVALUATION");
    println!("     The operation is checked against the permission lattice defined by");
    println!("     NUCLEUS_PROFILE. Each capability has a level: Never, LowRisk, Always.");
    println!("     - Always: auto-allow (no user prompt)");
    println!("     - LowRisk: allow if the operation is low-risk, else ask the user");
    println!("     - Never: deny unconditionally");
    println!();
    println!("  4. COMPARTMENT ENFORCEMENT");
    println!("     If NUCLEUS_COMPARTMENT is set, the operation must be in the");
    println!("     compartment's allow-list. This is an intersection with the profile —");
    println!("     both must permit the operation.");
    println!();
    println!("  5. AUTONOMY CEILING");
    println!("     NUCLEUS_AUTONOMY_CEILING applies an org-wide cap. In 'sandbox' mode,");
    println!("     production-impacting operations (git_push, create_pr, manage_pods)");
    println!("     are downgraded to 'ask' regardless of profile.");
    println!();
    println!("  6. FLOW GRAPH & IFC");
    println!("     The operation is added to a per-session flow graph. Nucleus tracks");
    println!("     information flow between nodes (reads -> writes, web -> bash) and");
    println!("     enforces flow rules: e.g., data read from the web cannot be written");
    println!("     to sensitive paths without user approval.");
    println!();
    println!("  7. EXPOSURE TRACKING");
    println!("     The session state tracks cumulative exposure (files read, commands");
    println!("     run, data sources accessed). High-water marks prevent regressions —");
    println!("     once a session is tainted by web data, it stays tainted.");
    println!();
    println!("  8. RECEIPT SIGNING");
    println!("     Every decision is recorded as a signed receipt in a JSONL chain.");
    println!("     Each receipt includes the operation, verdict, flow ancestors, an");
    println!("     Ed25519 signature, and a hash linking it to the previous receipt.");
    println!("     Receipts are append-only and tamper-evident.");
    println!();
    println!("  9. VERDICT");
    println!("     The final verdict (allow/deny/ask) is written to stdout as JSON.");
    println!("     Exit code 0 = allow, 2 = deny. See --exit-codes for the full protocol.");
    println!();
    println!("FAIL-CLOSED MODE:");
    println!("  Set NUCLEUS_FAIL_CLOSED=1 to deny on any infrastructure error (missing");
    println!("  session dir, parse failure, etc.). Default is fail-open with a warning.");
    println!();
    println!("TIMING:");
    println!("  Set NUCLEUS_TIMING=1 to see per-phase latency breakdown on stderr.");
}

/// Print detailed help for all profiles with their full capability matrices.
pub fn print_help_profiles() {
    println!("PROFILES — Permission Lattice Definitions");
    println!("=========================================");
    println!();
    println!("Each profile defines a PermissionLattice that maps capabilities to levels:");
    println!("  Always  — auto-allow, no user prompt");
    println!("  LowRisk — allow if the operation is classified as low-risk, else ask");
    println!("  Never   — deny unconditionally");
    println!();
    println!("Set the profile with: export NUCLEUS_PROFILE=<name>");
    println!("View a single profile: nucleus-claude-hook --show-profile <name>");
    println!();
    println!(
        "{:<16} {:<6} {:<6} {:<6} {:<6} {:<6} {:<6} {:<6} {:<6} {:<6} {:<6} {:<6} {:<6} {:<6}",
        "PROFILE",
        "read",
        "write",
        "edit",
        "bash",
        "glob",
        "grep",
        "web_s",
        "web_f",
        "commit",
        "push",
        "pr",
        "pods",
        "spawn"
    );
    println!("{}", "-".repeat(100));

    // Capability matrix — matches the profiles defined in portcullis
    let matrix: &[(&str, &str)] = &[
        (
            "read_only",
            " A     -     -     -     A     A     -     -     -     -     -     -     -",
        ),
        (
            "code_review",
            " A     -     -     -     A     A     -     -     -     -     -     -     -",
        ),
        (
            "edit_only",
            " A     A     A     -     A     A     -     -     -     -     -     -     -",
        ),
        (
            "fix_issue",
            " A     A     A     L     A     A     L     L     -     -     -     -     -",
        ),
        (
            "safe_pr_fixer",
            " A     A     A     A     A     A     A     A     A     -     -     -     -",
        ),
        (
            "release",
            " A     A     A     A     A     A     A     A     A     A     A     -     -",
        ),
        (
            "permissive",
            " A     A     A     A     A     A     A     A     A     A     A     A     A",
        ),
    ];

    for (name, caps) in matrix {
        println!("{name:<16}{caps}");
    }

    println!();
    println!("Legend: A = Always, L = LowRisk, - = Never");
    println!();
    println!("PROFILE DETAILS:");
    println!();
    for (name, desc) in PROFILE_HELP {
        println!("  {name}");
        println!("    {desc}");
    }
    println!();
    println!("The profiles form a lattice ordered by permission inclusion:");
    println!("  read_only <= code_review <= edit_only <= fix_issue <= safe_pr_fixer <= release <= permissive");
    println!();
    println!("The default profile is 'safe_pr_fixer'. It permits a full development");
    println!("workflow (read, write, edit, bash, search, web, commit) but blocks");
    println!("git push and PR creation — the human must do the final push.");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_help_does_not_panic() {
        // Smoke test: ensure help functions don't panic.
        print_help();
    }

    #[test]
    fn print_help_compartments_does_not_panic() {
        print_help_compartments();
    }

    #[test]
    fn print_help_flow_does_not_panic() {
        print_help_flow();
    }

    #[test]
    fn print_help_profiles_does_not_panic() {
        print_help_profiles();
    }
}
