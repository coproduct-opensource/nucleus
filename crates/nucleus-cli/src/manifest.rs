//! `nucleus manifest` subcommand — generate, sign, and verify MCP tool
//! manifests.
//!
//! `sign` fills each entry's `schema_hash` (the descriptor digest the
//! publisher vouches for — from an `mcp-guard --pin-file`, or given
//! explicitly), signs `canonical_bytes()` with the publisher seed, and writes
//! `signature` / `signing_key` back. `verify` loads the file under the trust
//! store exactly as `mcp-guard --manifests` would and says what was admitted.

use clap::{Args, Subcommand};
use portcullis::manifest_registry::{
    ManifestRegistry, TrustStore, parse_manifest_toml, sign_manifest,
};
use portcullis::tool_schema::ToolSchemaRegistry;
use std::path::{Path, PathBuf};

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
    /// Sign a manifest file: set each entry's `schema_hash`, sign it with a
    /// publisher seed (`nucleus trust keygen`), and write the signature back.
    Sign {
        /// The manifest TOML (`[tool]` or `[[tools]]`). Rewritten in place
        /// unless `--out` is given. Comments are not preserved.
        file: PathBuf,
        /// Hex Ed25519 seed file from `nucleus trust keygen`.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        /// An `mcp-guard --pin-file`: the vetted `(name, description,
        /// parameters)` triples whose digests become each entry's `schema_hash`.
        #[arg(long, value_name = "FILE", conflicts_with = "schema_hash")]
        pins: Option<PathBuf>,
        /// The descriptor digest to pin, for a single-tool manifest.
        #[arg(long, value_name = "HEX")]
        schema_hash: Option<String>,
        /// Write here instead of in place.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Emit the approved tool surface for a pod policy (#2485): the extension
    /// entries — one per pinned tool, plus the surface marker — to place under
    /// `policy.lattice.capabilities.extensions` of the pod's inline policy.
    /// The node signs them into the pod certificate; a child pod can only
    /// narrow them, and `mcp-guard` refuses any served tool not on them.
    Surface {
        /// An `mcp-guard --pin-file`: the vetted `(name, description,
        /// parameters)` triples whose digests define the surface.
        #[arg(long, value_name = "FILE")]
        pins: PathBuf,
        /// The pod's compartment (`research` | `draft` | `execute` |
        /// `breakglass`), written as a signed certificate dimension (#2484):
        /// the node clamps the pod's capabilities to its ceiling, a child pod
        /// can only lower it, and tools whose signed manifest lists
        /// `allowed_compartments` are refused outside them.
        #[arg(long, value_name = "NAME")]
        compartment: Option<String>,
    },
    /// Load a manifest file under `<dir>/.nucleus/trust` exactly as
    /// `mcp-guard --manifests` would, and report what was admitted.
    Verify {
        file: PathBuf,
        /// Project directory holding `.nucleus/trust/`.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
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
        ManifestCommand::Sign {
            file,
            key,
            pins,
            schema_hash,
            out,
        } => {
            if let Err(e) = run_sign(
                &file,
                &key,
                pins.as_deref(),
                schema_hash.as_deref(),
                out.as_deref(),
            ) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        ManifestCommand::Surface { pins, compartment } => {
            if let Err(e) = run_surface(&pins, compartment.as_deref()) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        ManifestCommand::Verify { file, dir } => match run_verify(&file, &dir) {
            Ok(true) => {}
            Ok(false) => std::process::exit(1),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
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

/// Descriptor digests from an `mcp-guard --pin-file`: name → hash.
fn digests_from_pins(path: &Path) -> Result<std::collections::BTreeMap<String, String>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let pins: Vec<(String, String, String)> = serde_json::from_str(&content)
        .map_err(|e| format!("{} is not an mcp-guard pin file: {e}", path.display()))?;
    Ok(pins
        .iter()
        .map(|(n, d, s)| (n.clone(), ToolSchemaRegistry::hash_schema(n, d, s)))
        .collect())
}

/// The entries of a manifest document, whichever shape it has.
fn entries_mut(doc: &mut toml::Value) -> Result<Vec<&mut toml::Value>, String> {
    let table = doc.as_table_mut().ok_or("manifest is not a TOML table")?;
    if table.contains_key("tool") {
        return Ok(vec![table.get_mut("tool").expect("checked")]);
    }
    match table.get_mut("tools").and_then(toml::Value::as_array_mut) {
        Some(arr) => Ok(arr.iter_mut().collect()),
        None => Err("no `[tool]` table or `[[tools]]` array found".to_string()),
    }
}

fn run_sign(
    file: &Path,
    key: &Path,
    pins: Option<&Path>,
    schema_hash: Option<&str>,
    out: Option<&Path>,
) -> Result<(), String> {
    let seed_hex = std::fs::read_to_string(key)
        .map_err(|e| format!("failed to read {}: {e}", key.display()))?;
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{} is not a 32-byte hex seed", key.display()))?;

    let content = std::fs::read_to_string(file)
        .map_err(|e| format!("failed to read {}: {e}", file.display()))?;
    let mut manifests = parse_manifest_toml(&content)?;
    let mut doc: toml::Value =
        toml::from_str(&content).map_err(|e| format!("{}: {e}", file.display()))?;
    let entries = entries_mut(&mut doc)?;
    if entries.len() != manifests.len() {
        return Err("manifest entries could not all be converted".to_string());
    }
    if schema_hash.is_some() && manifests.len() != 1 {
        return Err(
            "--schema-hash applies to a single-tool manifest; use --pins for several".to_string(),
        );
    }
    let digests = match pins {
        Some(p) => digests_from_pins(p)?,
        None => std::collections::BTreeMap::new(),
    };

    for (manifest, entry) in manifests.iter_mut().zip(entries) {
        let name = manifest.name.as_str().to_string();
        let digest_hex = match (schema_hash, digests.get(&name)) {
            (Some(h), _) => h.trim().to_ascii_lowercase(),
            (None, Some(h)) => h.clone(),
            (None, None) if manifest.schema_hash != [0u8; 32] => hex::encode(manifest.schema_hash),
            (None, None) => {
                return Err(format!(
                    "tool `{name}`: no descriptor digest — pass --pins (an mcp-guard pin file that \
                     lists it) or --schema-hash; a signed manifest that pins no descriptor vouches \
                     for nothing"
                ));
            }
        };
        let digest: [u8; 32] = hex::decode(&digest_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| format!("tool `{name}`: schema_hash is not 32 hex bytes"))?;
        manifest.schema_hash = digest;
        let public = sign_manifest(manifest, &seed);
        let signature = manifest.signature.expect("just signed");

        let t = entry
            .as_table_mut()
            .ok_or_else(|| format!("tool `{name}`: entry is not a table"))?;
        t.insert("schema_hash".into(), toml::Value::String(digest_hex));
        t.insert(
            "signature".into(),
            toml::Value::String(hex::encode(signature)),
        );
        t.insert(
            "signing_key".into(),
            toml::Value::String(hex::encode(public)),
        );
        eprintln!(
            "signed: {name} (schema_hash {}…)",
            &hex::encode(digest)[..16]
        );
    }

    let rendered =
        toml::to_string_pretty(&doc).map_err(|e| format!("serialising manifest: {e}"))?;
    let dest = out.unwrap_or(file);
    std::fs::write(dest, rendered)
        .map_err(|e| format!("failed to write {}: {e}", dest.display()))?;
    eprintln!("wrote {}", dest.display());
    Ok(())
}

/// Print the surface extension entries as JSON, ready for the pod policy.
fn run_surface(pins: &Path, compartment: Option<&str>) -> Result<(), String> {
    use portcullis::cert_compartment::{Compartment, set_compartment};
    use portcullis::tool_surface::approve_tool;
    let compartment = match compartment {
        Some(name) => Some(Compartment::from_str_opt(name).ok_or_else(|| {
            format!("unknown compartment `{name}` (research | draft | execute | breakglass)")
        })?),
        None => None,
    };
    let digests = digests_from_pins(pins)?;
    if digests.is_empty() {
        return Err(format!(
            "{} pins no tools; a surface of nothing approves nothing",
            pins.display()
        ));
    }
    let mut caps = portcullis::CapabilityLattice::default();
    for (name, digest) in &digests {
        approve_tool(&mut caps, name, digest);
    }
    if let Some(c) = compartment {
        set_compartment(&mut caps, c);
    }
    let json = serde_json::to_string_pretty(&caps.extensions).map_err(|e| e.to_string())?;
    println!("{json}");
    eprintln!(
        "{} tool(s) on the surface; place this map under policy.lattice.capabilities.extensions",
        digests.len()
    );
    Ok(())
}

/// `Ok(true)` when every entry was admitted under the trust store.
fn run_verify(file: &Path, dir: &Path) -> Result<bool, String> {
    let content = std::fs::read_to_string(file)
        .map_err(|e| format!("failed to read {}: {e}", file.display()))?;
    let trust = TrustStore::load_from_dir(dir);
    if trust.is_empty() {
        return Err(format!(
            "no trusted keys in {}/.nucleus/trust; `nucleus trust add` one first (a verifier with no \
             keys would admit everything)",
            dir.display()
        ));
    }
    let expected = parse_manifest_toml(&content)?;
    let mut reg = ManifestRegistry::new();
    reg.load_toml_with_trust(&content, &trust);
    let mut all_ok = true;
    for m in &expected {
        let name = m.name.as_str();
        let status = if reg.get(name).is_some() {
            if m.schema_hash == [0u8; 32] {
                all_ok = false;
                "admitted, but pins NO descriptor (schema_hash absent): vouches for nothing"
            } else {
                "admitted: signature verified, descriptor pinned"
            }
        } else if reg.is_rejected(name).is_some() {
            all_ok = false;
            "REJECTED by admission control"
        } else {
            all_ok = false;
            "UNSIGNED or not signed by a trusted key"
        };
        println!("{name}\t{status}");
    }
    Ok(all_ok)
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

    /// The publisher loop end to end: keygen → sign against guard pins →
    /// trust the public key → verify admits, and the signed digest is the one
    /// the guard computes for the pinned descriptor.
    #[test]
    fn sign_then_verify_round_trip_pins_the_guard_digest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("srv.toml");
        std::fs::write(
            &manifest,
            r#"
[[tools]]
name = "read_file"
capabilities = ["read_files"]
instruction_sources = ["static"]
admissible_sinks = ["local_memory"]

[[tools]]
name = "list_dir"
capabilities = ["read_files"]
instruction_sources = ["static"]
admissible_sinks = ["local_memory"]
"#,
        )
        .unwrap();
        let pins = dir.path().join("pins.json");
        std::fs::write(
            &pins,
            serde_json::to_string(&vec![
                (
                    "read_file",
                    "Read a file",
                    r#"{"inputSchema":{"path":"string"}}"#,
                ),
                ("list_dir", "List", "{}"),
            ])
            .unwrap(),
        )
        .unwrap();
        let seed_hex = hex::encode([5u8; 32]);
        let key = dir.path().join("pub.key");
        std::fs::write(&key, &seed_hex).unwrap();

        // Unsigned and unpinned: nothing to vouch with.
        assert!(run_sign(&manifest, &key, None, None, None).is_err());

        run_sign(&manifest, &key, Some(&pins), None, None).unwrap();
        let signed = std::fs::read_to_string(&manifest).unwrap();
        let expected = ToolSchemaRegistry::hash_schema(
            "read_file",
            "Read a file",
            r#"{"inputSchema":{"path":"string"}}"#,
        );
        assert!(
            signed.contains(&expected),
            "the guard's digest is what was signed"
        );

        // Nobody trusted yet: verify refuses to run rather than admit blindly.
        assert!(run_verify(&manifest, dir.path()).is_err());

        let public = portcullis::manifest_registry::public_key_for_seed(&[5u8; 32]);
        crate::trust::add(dir.path(), &hex::encode(public), Some("pub")).unwrap();
        assert!(
            run_verify(&manifest, dir.path()).unwrap(),
            "both entries admitted"
        );

        // The served-descriptor check the guard performs, against this file.
        let mut reg = ManifestRegistry::new();
        reg.load_toml_with_trust(&signed, &TrustStore::load_from_dir(dir.path()));
        assert_eq!(reg.verify_served_tool("read_file", &expected), Ok(()));

        // A different key is not trusted: verify fails closed.
        std::fs::write(&key, hex::encode([6u8; 32])).unwrap();
        run_sign(&manifest, &key, Some(&pins), None, None).unwrap();
        assert!(!run_verify(&manifest, dir.path()).unwrap());
    }
}
