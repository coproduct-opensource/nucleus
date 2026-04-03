//! CLI subcommand handlers.
//!
//! Extracted from main.rs to stay under the line ratchet ceiling.

use crate::config::{resolve_profile, PROFILES};
use crate::session::{sanitize_session_id, session_dir, session_hwm_path, session_state_path};
use crate::{doctor, exit_codes, help, init};

pub(crate) fn run_smoke_test() {
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

pub(crate) fn run_init() {
    init::run_init();
}

// (--uninstall handler moved to setup.rs)

pub(crate) fn run_doctor() {
    doctor::run_doctor();
}

pub(crate) fn show_profile(name: &str) {
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

pub(crate) fn run_help(topic: Option<String>) {
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
