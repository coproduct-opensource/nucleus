//! Shell completion script generation for `nucleus-claude-hook`.
//!
//! Generates static completion scripts for bash, zsh, and fish shells.
//! No external dependencies — pure string generation from the known flag set.

/// All top-level flags recognised by the CLI.
const FLAGS: &[&str] = &[
    "--setup",
    "--status",
    "--help",
    "--version",
    "--init",
    "--build",
    "--uninstall",
    "--compartment-path",
    "--reset-session",
    "--doctor",
    "--smoke-test",
    "--gc",
    "--show-profile",
    "--receipts",
    "--completions",
    "--exit-codes",
    "--benchmark",
    "--statusline",
];

/// Generate a shell completion script for the given shell name.
///
/// Returns `None` if the shell is not recognised.
pub fn generate_completions(shell: &str) -> Option<String> {
    match shell {
        "bash" => Some(generate_bash()),
        "zsh" => Some(generate_zsh()),
        "fish" => Some(generate_fish()),
        _ => None,
    }
}

fn generate_bash() -> String {
    let words = FLAGS.join(" ");
    format!(
        r#"_nucleus_claude_hook() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    COMPREPLY=($(compgen -W "{words}" -- "$cur"))
}}
complete -F _nucleus_claude_hook nucleus-claude-hook
"#
    )
}

fn generate_zsh() -> String {
    let mut s = String::from(
        r#"#compdef nucleus-claude-hook

_nucleus_claude_hook() {
    local -a flags
    flags=(
"#,
    );
    for flag in FLAGS {
        s.push_str(&format!("        '{flag}'\n"));
    }
    s.push_str(
        r#"    )
    compadd -a flags
}

_nucleus_claude_hook "$@"
"#,
    );
    s
}

fn generate_fish() -> String {
    let mut s = String::new();
    for flag in FLAGS {
        // Strip leading "--" for the fish long-flag name
        let name = flag.trim_start_matches('-');
        s.push_str(&format!("complete -c nucleus-claude-hook -l {name} -f\n"));
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_completions_contain_flags() {
        let out = generate_completions("bash").unwrap();
        assert!(!out.is_empty());
        assert!(out.contains("--setup"));
        assert!(out.contains("--status"));
        assert!(out.contains("--completions"));
        assert!(out.contains("--compartment-path"));
        assert!(out.contains("complete"));
        assert!(out.contains("nucleus-claude-hook"));
    }

    #[test]
    fn zsh_completions_contain_flags() {
        let out = generate_completions("zsh").unwrap();
        assert!(!out.is_empty());
        assert!(out.contains("--setup"));
        assert!(out.contains("--doctor"));
        assert!(out.contains("--completions"));
        assert!(out.contains("compadd"));
        assert!(out.contains("#compdef"));
    }

    #[test]
    fn fish_completions_contain_flags() {
        let out = generate_completions("fish").unwrap();
        assert!(!out.is_empty());
        assert!(out.contains("setup"));
        assert!(out.contains("smoke-test"));
        assert!(out.contains("completions"));
        assert!(out.contains("complete -c nucleus-claude-hook"));
    }

    #[test]
    fn unknown_shell_returns_none() {
        assert!(generate_completions("powershell").is_none());
        assert!(generate_completions("").is_none());
    }

    #[test]
    fn all_cli_flags_present() {
        // Verify that FLAGS covers every flag from the CLI parser.
        let expected = vec![
            "--setup",
            "--status",
            "--help",
            "--version",
            "--init",
            "--build",
            "--uninstall",
            "--compartment-path",
            "--reset-session",
            "--doctor",
            "--smoke-test",
            "--gc",
            "--show-profile",
            "--receipts",
            "--completions",
            "--exit-codes",
            "--statusline",
        ];
        for flag in expected {
            assert!(FLAGS.contains(&flag), "missing flag in completions: {flag}");
        }
    }
}
