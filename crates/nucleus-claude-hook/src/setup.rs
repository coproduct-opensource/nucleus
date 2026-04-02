//! `--setup` and `--uninstall` commands for managing Claude Code integration.

use crate::session::session_dir;

// ---------------------------------------------------------------------------
// --setup: auto-configure Claude Code settings.json
// ---------------------------------------------------------------------------

pub(crate) fn run_setup() {
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
        crate::default_profile_name()
    );
}

// ---------------------------------------------------------------------------
// --uninstall: remove nucleus-claude-hook from Claude Code
// ---------------------------------------------------------------------------

pub(crate) fn run_uninstall() {
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
