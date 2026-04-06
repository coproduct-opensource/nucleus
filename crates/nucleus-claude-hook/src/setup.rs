#![allow(clippy::disallowed_types)] // #1216 exempt: CLI --setup command, operator-initiated
//! `--setup` and `--uninstall` commands for managing Claude Code integration.

use crate::session::session_dir;

// ---------------------------------------------------------------------------
// --setup: auto-configure Claude Code settings.json
// ---------------------------------------------------------------------------

/// All hook types that nucleus requires, with their matchers and commands.
///
/// Tool hooks (PreToolUse, PostToolUse) use `".*"` to match all tools.
/// Lifecycle hooks (SessionStart, SessionEnd) use `""` (no tool matcher needed).
pub(crate) fn nucleus_hook_specs(binary: &str) -> Vec<(&'static str, &'static str, String)> {
    vec![
        ("PreToolUse", ".*", binary.to_string()),
        ("PostToolUse", ".*", binary.to_string()),
        ("SessionStart", "", format!("{binary} --session-init")),
        ("SessionEnd", "", format!("{binary} --session-end")),
    ]
}

/// Check whether a hook entry's command references nucleus-claude-hook.
pub(crate) fn is_nucleus_hook(entry: &serde_json::Value) -> bool {
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
}

/// Detect old-format setup: only PreToolUse registered, or any nucleus hook
/// entry using empty-string matcher where `".*"` is expected.
pub(crate) fn needs_migration(hooks_obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    // Missing any of the 4 required hook types → needs migration.
    for key in &["PreToolUse", "PostToolUse", "SessionStart", "SessionEnd"] {
        match hooks_obj.get(*key) {
            None => return true,
            Some(arr_val) => {
                if let Some(arr) = arr_val.as_array() {
                    if !arr.iter().any(is_nucleus_hook) {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }
    }

    // Tool hooks should use ".*" matcher, not "".
    for key in &["PreToolUse", "PostToolUse"] {
        if let Some(arr_val) = hooks_obj.get(*key) {
            if let Some(arr) = arr_val.as_array() {
                for entry in arr {
                    if is_nucleus_hook(entry) {
                        if let Some(matcher) = entry.get("matcher").and_then(|m| m.as_str()) {
                            if matcher.is_empty() {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

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

    let specs = nucleus_hook_specs(&binary);

    // Ensure hooks object exists
    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let hooks_obj = hooks.as_object_mut().unwrap();

    let migrating = needs_migration(hooks_obj);
    if migrating {
        eprintln!("nucleus: migrating hook configuration to full 4-event format");
    }

    // Register / update each hook type — PRESERVE existing non-nucleus hooks (#546)
    for (hook_type, matcher, command) in &specs {
        let nucleus_entry = serde_json::json!({
            "matcher": matcher,
            "hooks": [
                {
                    "type": "command",
                    "command": command
                }
            ]
        });

        if let Some(existing) = hooks_obj.get_mut(*hook_type) {
            if let Some(arr) = existing.as_array_mut() {
                // Check if nucleus is already configured for this hook type
                let already_present = arr.iter().any(is_nucleus_hook);

                if already_present {
                    // Update the existing nucleus entry's command path and matcher
                    for entry in arr.iter_mut() {
                        if is_nucleus_hook(entry) {
                            // Update matcher to correct value
                            if let Some(obj) = entry.as_object_mut() {
                                obj.insert("matcher".to_string(), serde_json::json!(matcher));
                            }
                            // Update command path
                            if let Some(hooks_arr) =
                                entry.get_mut("hooks").and_then(|h| h.as_array_mut())
                            {
                                for hook in hooks_arr.iter_mut() {
                                    if hook
                                        .get("command")
                                        .and_then(|c| c.as_str())
                                        .map(|s| s.contains("nucleus-claude-hook"))
                                        .unwrap_or(false)
                                    {
                                        hook.as_object_mut().unwrap().insert(
                                            "command".to_string(),
                                            serde_json::json!(command),
                                        );
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Append — preserve existing hooks
                    arr.push(nucleus_entry);
                }
            } else {
                // Hook type exists but isn't an array — replace
                hooks_obj.insert(hook_type.to_string(), serde_json::json!([nucleus_entry]));
            }
        } else {
            // Hook type not present — create fresh
            hooks_obj.insert(hook_type.to_string(), serde_json::json!([nucleus_entry]));
        }
    }

    let json = serde_json::to_string_pretty(&settings).expect("failed to serialize settings");
    std::fs::write(&settings_path, json).expect("failed to write settings.json");

    eprintln!(
        "nucleus: configured hooks (PreToolUse, PostToolUse, SessionStart, SessionEnd) in {}",
        settings_path.display()
    );
    if migrating {
        eprintln!("nucleus: migration complete — PostToolUse, SessionStart, SessionEnd now active");
    }
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

    // 1. Remove hooks from settings.json (all 4 hook types)
    if let Some(home) = dirs_next::home_dir() {
        let settings_path = home.join(".claude").join("settings.json");
        if settings_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&settings_path) {
                if let Ok(mut settings) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) {
                        let mut removed_any = false;
                        let hook_types =
                            ["PreToolUse", "PostToolUse", "SessionStart", "SessionEnd"];

                        for hook_type in &hook_types {
                            if let Some(hook_val) = hooks.get_mut(*hook_type) {
                                if let Some(arr) = hook_val.as_array_mut() {
                                    let before = arr.len();
                                    arr.retain(|entry| !is_nucleus_hook(entry));
                                    if arr.len() < before {
                                        removed_any = true;
                                    }
                                    if arr.is_empty() {
                                        hooks.remove(*hook_type);
                                    }
                                }
                            }
                        }

                        if removed_any {
                            if let Ok(json) = serde_json::to_string_pretty(&settings) {
                                std::fs::write(&settings_path, json).ok();
                            }
                            println!(
                                "  \x1b[32m\u{2713}\x1b[0m Removed hooks from {}",
                                settings_path.display()
                            );
                        } else {
                            println!("  - Hooks not found in {}", settings_path.display());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_produces_valid_hooks_format() {
        let binary = "/usr/local/bin/nucleus-claude-hook";
        let specs = nucleus_hook_specs(binary);

        let mut hooks_obj = serde_json::Map::new();
        for (hook_type, matcher, command) in &specs {
            hooks_obj.insert(
                hook_type.to_string(),
                serde_json::json!([{
                    "matcher": matcher,
                    "hooks": [{"type": "command", "command": command}]
                }]),
            );
        }

        // All 4 hook types present with correct structure
        for key in &["PreToolUse", "PostToolUse", "SessionStart", "SessionEnd"] {
            let arr = hooks_obj
                .get(*key)
                .unwrap_or_else(|| panic!("{key} missing"))
                .as_array()
                .unwrap();
            assert!(!arr.is_empty(), "{key} array should not be empty");
            let entry = &arr[0];
            assert!(entry.get("matcher").is_some(), "{key} entry needs matcher");
            let hooks_arr = entry
                .get("hooks")
                .unwrap_or_else(|| panic!("{key} needs hooks array"))
                .as_array()
                .unwrap();
            assert!(!hooks_arr.is_empty());
            assert_eq!(hooks_arr[0]["type"], "command");
            assert!(hooks_arr[0].get("command").is_some());
        }

        // Tool hooks use ".*" matcher, lifecycle hooks use ""
        assert_eq!(hooks_obj["PreToolUse"][0]["matcher"], ".*");
        assert_eq!(hooks_obj["PostToolUse"][0]["matcher"], ".*");
        assert_eq!(hooks_obj["SessionStart"][0]["matcher"], "");
        assert_eq!(hooks_obj["SessionEnd"][0]["matcher"], "");
    }

    #[test]
    fn test_setup_matches_init_hook_config() {
        // Setup and init must produce identical hook structures (#874)
        let binary = "nucleus-claude-hook";
        let specs = nucleus_hook_specs(binary);

        let mut setup_hooks = serde_json::Map::new();
        for (hook_type, matcher, command) in &specs {
            setup_hooks.insert(
                hook_type.to_string(),
                serde_json::json!([{
                    "matcher": matcher,
                    "hooks": [{"type": "command", "command": command}]
                }]),
            );
        }

        let init_settings = crate::init::default_claude_settings();
        let init_hooks = init_settings["hooks"].as_object().unwrap();

        for key in &["PreToolUse", "PostToolUse", "SessionStart", "SessionEnd"] {
            let setup_arr = setup_hooks.get(*key).unwrap();
            let init_arr = init_hooks.get(*key).unwrap();
            assert_eq!(setup_arr, init_arr, "setup and init diverge for {key}");
        }
    }

    #[test]
    fn test_setup_preserves_existing_settings() {
        let binary = "nucleus-claude-hook";
        let specs = nucleus_hook_specs(binary);
        let mut settings = serde_json::json!({
            "effortLevel": "high",
            "enabledPlugins": {"rust-analyzer": true}
        });

        let hooks = settings
            .as_object_mut()
            .unwrap()
            .entry("hooks")
            .or_insert_with(|| serde_json::json!({}));
        let hooks_obj = hooks.as_object_mut().unwrap();
        for (hook_type, matcher, command) in &specs {
            hooks_obj.insert(
                hook_type.to_string(),
                serde_json::json!([{
                    "matcher": matcher,
                    "hooks": [{"type": "command", "command": command}]
                }]),
            );
        }

        assert_eq!(settings["effortLevel"], "high");
        assert!(settings.get("enabledPlugins").is_some());
        let hooks = settings["hooks"].as_object().unwrap();
        assert!(hooks.contains_key("PreToolUse"));
        assert!(hooks.contains_key("PostToolUse"));
        assert!(hooks.contains_key("SessionStart"));
        assert!(hooks.contains_key("SessionEnd"));
    }

    #[test]
    fn test_migration_detects_old_format() {
        // Old format: only PreToolUse with empty matcher
        let old_hooks: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({
                "PreToolUse": [{
                    "matcher": "",
                    "hooks": [{"type": "command", "command": "nucleus-claude-hook"}]
                }]
            }))
            .unwrap();
        assert!(
            needs_migration(&old_hooks),
            "old PreToolUse-only config should need migration"
        );

        // New format: all 4 hooks with correct matchers
        let new_hooks: serde_json::Map<String, serde_json::Value> = serde_json::from_value(
            serde_json::json!({
                "PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "nucleus-claude-hook"}]}],
                "PostToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "nucleus-claude-hook"}]}],
                "SessionStart": [{"matcher": "", "hooks": [{"type": "command", "command": "nucleus-claude-hook --session-init"}]}],
                "SessionEnd": [{"matcher": "", "hooks": [{"type": "command", "command": "nucleus-claude-hook --session-end"}]}]
            }),
        )
        .unwrap();
        assert!(
            !needs_migration(&new_hooks),
            "new 4-event config should not need migration"
        );
    }

    #[test]
    fn test_migration_detects_empty_matcher_on_tool_hooks() {
        // All 4 types present but PreToolUse has empty matcher instead of ".*"
        let bad: serde_json::Map<String, serde_json::Value> = serde_json::from_value(
            serde_json::json!({
                "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "nucleus-claude-hook"}]}],
                "PostToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "nucleus-claude-hook"}]}],
                "SessionStart": [{"matcher": "", "hooks": [{"type": "command", "command": "nucleus-claude-hook --session-init"}]}],
                "SessionEnd": [{"matcher": "", "hooks": [{"type": "command", "command": "nucleus-claude-hook --session-end"}]}]
            }),
        )
        .unwrap();
        assert!(
            needs_migration(&bad),
            "empty matcher on tool hook should trigger migration"
        );
    }

    #[test]
    fn test_is_nucleus_hook() {
        let yes = serde_json::json!({
            "matcher": ".*",
            "hooks": [{"type": "command", "command": "/usr/bin/nucleus-claude-hook"}]
        });
        assert!(is_nucleus_hook(&yes));

        let no = serde_json::json!({
            "matcher": ".*",
            "hooks": [{"type": "command", "command": "my-custom-linter"}]
        });
        assert!(!is_nucleus_hook(&no));
    }
}
