//! `--doctor` diagnostic command — checks hook installation health.

use crate::session::session_dir;
use crate::{default_profile_name, resolve_profile};

pub(crate) fn run_doctor() {
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

                    // Check for incomplete hook registration (#874)
                    if let Ok(settings) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(hooks_obj) = settings.get("hooks").and_then(|h| h.as_object()) {
                            if crate::setup::needs_migration(hooks_obj) {
                                println!(
                                    "\x1b[33m!\x1b[0m Hook config is outdated (missing PostToolUse/SessionStart/SessionEnd) — run --setup to upgrade"
                                );
                                ok = false;
                            }
                        }
                    }
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
