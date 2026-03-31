//! `nucleus manifest` subcommand — generate and manage MCP tool manifests.

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub struct ManifestArgs {
    #[command(subcommand)]
    pub command: ManifestCommand,
}

#[derive(Subcommand)]
pub enum ManifestCommand {
    /// Generate a manifest TOML template for an MCP server's tools.
    ///
    /// Reads a JSON tool list (from MCP `tools/list` response or a file)
    /// and generates `.nucleus/manifests/<server>.toml` with placeholder
    /// security annotations.
    Init {
        /// MCP server name (used as the manifest filename).
        #[arg(long)]
        server: String,

        /// Path to a JSON file containing the MCP tools/list response.
        /// If omitted, reads from stdin.
        #[arg(long)]
        tools_json: Option<PathBuf>,

        /// Output directory (default: .nucleus/manifests/).
        #[arg(long, default_value = ".nucleus/manifests")]
        output_dir: PathBuf,
    },
}

/// A tool from the MCP tools/list response.
#[derive(serde::Deserialize)]
struct McpTool {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    input_schema: Option<serde_json::Value>,
}

/// MCP tools/list response wrapper.
#[derive(serde::Deserialize)]
struct McpToolList {
    #[serde(default)]
    tools: Vec<McpTool>,
}

pub fn execute(args: ManifestArgs) {
    match args.command {
        ManifestCommand::Init {
            server,
            tools_json,
            output_dir,
        } => {
            if let Err(e) = run_init(&server, tools_json.as_deref(), &output_dir) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn run_init(
    server: &str,
    tools_json: Option<&std::path::Path>,
    output_dir: &std::path::Path,
) -> Result<(), String> {
    // Read tool list
    let json_content = if let Some(path) = tools_json {
        std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?
    } else {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("failed to read stdin: {e}"))?;
        buf
    };

    // Parse — try as {tools: [...]} first, then as bare [...]
    let tools: Vec<McpTool> = if let Ok(list) = serde_json::from_str::<McpToolList>(&json_content) {
        list.tools
    } else if let Ok(tools) = serde_json::from_str::<Vec<McpTool>>(&json_content) {
        tools
    } else {
        return Err("failed to parse JSON — expected {tools: [...]} or [...]".to_string());
    };

    if tools.is_empty() {
        return Err("no tools found in JSON".to_string());
    }

    // Generate manifest TOML
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create {}: {e}", output_dir.display()))?;

    let output_path = output_dir.join(format!("{server}.toml"));
    let mut output = String::new();

    output.push_str(&format!("# Nucleus manifest for MCP server: {server}\n"));
    output.push_str("#\n");
    output.push_str("# Review and adjust security annotations before deploying.\n");
    output.push_str(&format!(
        "# Generated: {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    for tool in &tools {
        let full_name = format!("{server}__{}", tool.name);
        output.push_str("[[tools]]\n");
        output.push_str(&format!("name = \"{full_name}\"\n"));
        if let Some(desc) = &tool.description {
            let escaped = desc.replace('\"', "\\\"");
            output.push_str(&format!("description = \"{escaped}\"\n"));
        }

        // Classify tool by name heuristic
        let (capabilities, integ, auth) = classify_tool_name(&tool.name);
        output.push_str(&format!("capabilities = {capabilities}\n"));
        output.push_str("remote_fetch = false\n");
        output.push_str("instruction_sources = [\"user_prompt\", \"static\"]\n");
        output.push_str("admissible_sinks = [\"local_memory\", \"human_visible\"]\n");
        output.push_str("max_confidentiality = \"internal\"\n");
        output.push_str(&format!("output_integrity = \"{integ}\"\n"));
        output.push_str(&format!("output_authority = \"{auth}\"\n"));
        output.push_str("# signature = \"\"  # Add Ed25519 signature after review\n");
        output.push('\n');
    }

    std::fs::write(&output_path, &output)
        .map_err(|e| format!("failed to write {}: {e}", output_path.display()))?;

    eprintln!(
        "Generated manifest for {} tools: {}",
        tools.len(),
        output_path.display()
    );
    eprintln!("Review security annotations before deploying.");

    Ok(())
}

/// Heuristic classification of a tool by its name.
/// Returns (capabilities, output_integrity, output_authority).
fn classify_tool_name(name: &str) -> (&'static str, &'static str, &'static str) {
    let lower = name.to_lowercase();

    if lower.contains("read")
        || lower.contains("get")
        || lower.contains("list")
        || lower.contains("search")
        || lower.contains("query")
        || lower.contains("describe")
    {
        ("[\"read_files\"]", "untrusted", "informational")
    } else if lower.contains("write")
        || lower.contains("create")
        || lower.contains("update")
        || lower.contains("delete")
        || lower.contains("set")
        || lower.contains("put")
    {
        ("[\"write_files\"]", "untrusted", "no_authority")
    } else if lower.contains("run")
        || lower.contains("exec")
        || lower.contains("shell")
        || lower.contains("command")
    {
        ("[\"run_bash\"]", "untrusted", "no_authority")
    } else if lower.contains("fetch")
        || lower.contains("download")
        || lower.contains("browse")
        || lower.contains("http")
    {
        ("[\"web_fetch\"]", "adversarial", "no_authority")
    } else {
        // Unknown — conservative defaults
        ("[\"read_files\"]", "untrusted", "informational")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_read_tools() {
        let (caps, _, _) = classify_tool_name("get_user");
        assert!(caps.contains("read_files"));
    }

    #[test]
    fn classify_write_tools() {
        let (caps, _, _) = classify_tool_name("create_issue");
        assert!(caps.contains("write_files"));
    }

    #[test]
    fn classify_exec_tools() {
        let (caps, _, _) = classify_tool_name("run_command");
        assert!(caps.contains("run_bash"));
    }

    #[test]
    fn classify_fetch_tools() {
        let (caps, integ, _) = classify_tool_name("fetch_url");
        assert!(caps.contains("web_fetch"));
        assert_eq!(integ, "adversarial");
    }

    #[test]
    fn parse_mcp_tool_list() {
        let json = r#"{"tools": [
            {"name": "read_file", "description": "Read a file"},
            {"name": "write_file", "description": "Write a file"}
        ]}"#;
        let list: McpToolList = serde_json::from_str(json).unwrap();
        assert_eq!(list.tools.len(), 2);
        assert_eq!(list.tools[0].name, "read_file");
    }

    #[test]
    fn parse_bare_tool_array() {
        let json = r#"[
            {"name": "search_repos"},
            {"name": "create_pr"}
        ]"#;
        let tools: Vec<McpTool> = serde_json::from_str(json).unwrap();
        assert_eq!(tools.len(), 2);
    }
}
