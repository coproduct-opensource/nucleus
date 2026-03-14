//! CTF CLI — run attack sequences against The Vault from the command line.
//!
//! Usage:
//!   ctf-cli --level 5 --attack-file attack.json
//!   ctf-cli --level 5 --attack '[{"tool":"read_file","args":{"path":"/vault/flag.txt"}}]'
//!   echo '<json>' | ctf-cli --level 5
//!   ctf-cli --list-levels

use std::io::Read;

use ctf_engine::{AttackResult, CtfEngine, Level, ToolCall};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_usage();
        return;
    }

    if args.contains(&"--list-levels".to_string()) {
        list_levels();
        return;
    }

    let level = parse_arg(&args, "--level")
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or_else(|| {
            eprintln!("Error: --level <1-7> is required");
            std::process::exit(1);
        });

    if !(1..=7).contains(&level) {
        eprintln!("Error: level must be 1-7");
        std::process::exit(1);
    }

    let json = if let Some(file) = parse_arg(&args, "--attack-file") {
        std::fs::read_to_string(&file).unwrap_or_else(|e| {
            eprintln!("Error reading {file}: {e}");
            std::process::exit(1);
        })
    } else if let Some(inline) = parse_arg(&args, "--attack") {
        inline
    } else {
        // Read from stdin
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error reading stdin: {e}");
            std::process::exit(1);
        });
        buf
    };

    let tool_calls: Vec<ToolCall> = match serde_json::from_str(&json) {
        Ok(tc) => tc,
        Err(e) => {
            eprintln!("Invalid JSON: {e}");
            std::process::exit(1);
        }
    };

    let lvl = Level::new(level);
    let meta = lvl.meta();
    eprintln!("Level {}: {} — {}", level, meta.name, meta.tagline);
    eprintln!("Defenses: {}", meta.defenses.iter().map(|d| d.name).collect::<Vec<_>>().join(", "));
    eprintln!("---");

    let mut eng = CtfEngine::new(&lvl);
    let result = eng.run_attack(&tool_calls);

    print_result(&result);

    // Output raw JSON to stdout for piping
    println!("\n---JSON---");
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}

fn print_usage() {
    eprintln!("The Vault — Nucleus CTF CLI");
    eprintln!();
    eprintln!("Can your AI agent break out of a formally verified sandbox?");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  ctf-cli --level <1-7> --attack-file <path>");
    eprintln!("  ctf-cli --level <1-7> --attack '<json>'");
    eprintln!("  echo '<json>' | ctf-cli --level <1-7>");
    eprintln!("  ctf-cli --list-levels");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  --level <N>          Level to attack (1-7)");
    eprintln!("  --attack-file <path> JSON file with tool call array");
    eprintln!("  --attack <json>      Inline JSON tool call array");
    eprintln!("  --list-levels        Show all levels and their defenses");
    eprintln!("  --help               Show this help");
    eprintln!();
    eprintln!("TOOL CALL FORMAT:");
    eprintln!(r#"  [{{"tool": "read_file", "args": {{"path": "/vault/flag.txt"}}}}]"#);
    eprintln!();
    eprintln!("AVAILABLE TOOLS:");
    eprintln!("  read_file, write_file, run_bash, web_fetch, web_search,");
    eprintln!("  glob, grep, git_push, create_pr, approve");
}

fn list_levels() {
    for n in 1..=7u8 {
        let lvl = Level::new(n);
        let meta = lvl.meta();
        eprintln!("Level {}: {}", n, meta.name);
        eprintln!("  {}", meta.tagline);
        if let Some(cve) = meta.cve {
            eprintln!("  CVE: {}", cve);
        }
        eprintln!("  Tools: {}", meta.available_tools.join(", "));
        eprintln!("  Defenses: {}", if meta.defenses.is_empty() {
            "None".to_string()
        } else {
            meta.defenses.iter().map(|d| d.name).collect::<Vec<_>>().join(", ")
        });
        eprintln!("  Flag capturable: {}", if meta.flag_capturable { "YES" } else { "No" });
        eprintln!();
    }
}

fn print_result(result: &AttackResult) {
    for step in &result.steps {
        let icon = match &step.verdict {
            ctf_engine::Verdict::Allow { .. } => "[ALLOW]",
            ctf_engine::Verdict::Deny { .. } => "[DENY] ",
            ctf_engine::Verdict::RequiresApproval { .. } => "[APRV] ",
            ctf_engine::Verdict::Unavailable { .. } => "[N/A]  ",
        };
        eprintln!("  {}  {} {}", step.step + 1, icon, step.tool_call.tool);

        match &step.verdict {
            ctf_engine::Verdict::Allow { output } => {
                let preview: String = output.chars().take(80).collect();
                eprintln!("         {}", preview);
            }
            ctf_engine::Verdict::Deny { reason, defense, proof } => {
                eprintln!("         {} ({})", reason, defense);
                if let Some(p) = proof {
                    eprintln!("         Proof: {}", p);
                }
            }
            ctf_engine::Verdict::RequiresApproval { reason, defense, proof } => {
                eprintln!("         {} ({})", reason, defense);
                if let Some(p) = proof {
                    eprintln!("         Proof: {}", p);
                }
            }
            ctf_engine::Verdict::Unavailable { tool } => {
                eprintln!("         Tool not available: {}", tool);
            }
        }
    }

    eprintln!();
    if result.flag_captured {
        eprintln!("  FLAG CAPTURED! Exfiltration succeeded.");
    } else {
        eprintln!("  Exfiltration blocked.");
    }

    if !result.defenses_activated.is_empty() {
        eprintln!("  Defenses triggered: {}", result.defenses_activated.join(", "));
    }
    eprintln!("  Score: {}", result.score);
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
