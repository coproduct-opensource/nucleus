//! Static Kani scheduling inventory. This does not claim proof success or
//! compiler reachability; those still require Kani's per-harness results.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_yaml::Value;
use syn::visit::Visit;

#[derive(Debug)]
struct Harness {
    key: String,
    package: String,
    name: String,
    source_target: bool,
}

#[derive(Default)]
struct Proofs(Vec<String>, Vec<String>);

impl<'ast> Visit<'ast> for Proofs {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        for attr in &item.attrs {
            if attr.path().is_ident("path")
                && let syn::Meta::NameValue(value) = &attr.meta
                && let syn::Expr::Lit(value) = &value.value
                && let syn::Lit::Str(path) = &value.lit
            {
                self.1.push(path.value());
            }
        }
        syn::visit::visit_item_mod(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if item.attrs.iter().any(|a| {
            let segments: Vec<_> = a
                .path()
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            segments == ["kani", "proof"] || segments == ["kani", "proof_for_contract"]
        }) {
            self.0.push(item.sig.ident.to_string());
        }
        syn::visit::visit_item_fn(self, item);
    }
}

fn rust_files(path: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            rust_files(&entry.path(), files)?;
        } else if entry.path().extension().is_some_and(|e| e == "rs") {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn sources(root: &Path) -> Result<Vec<Harness>> {
    let mut harnesses = Vec::new();
    let mut linked_sources = BTreeSet::new();
    for entry in std::fs::read_dir(root.join("crates"))? {
        let path = entry?.path();
        if !path.join("Cargo.toml").exists() {
            continue;
        }
        let manifest: toml::Value =
            toml::from_str(&std::fs::read_to_string(path.join("Cargo.toml"))?)?;
        let package = manifest["package"]["name"]
            .as_str()
            .context("package name is not explicit")?;
        for directory in ["src", "tests", "proofs", "examples", "benches"] {
            let mut files = Vec::new();
            rust_files(&path.join(directory), &mut files)?;
            for file in files {
                let source = std::fs::read_to_string(&file)?;
                let ast = syn::parse_file(&source)
                    .with_context(|| format!("parsing {}", file.display()))?;
                let mut proofs = Proofs::default();
                proofs.visit_file(&ast);
                if directory == "src" {
                    for linked in &proofs.1 {
                        let linked = file.parent().context("source has no parent")?.join(linked);
                        if linked.exists() {
                            linked_sources.insert(linked.canonicalize()?);
                        }
                    }
                }
                for name in proofs.0 {
                    harnesses.push(Harness {
                        key: format!("{}::{name}", file.strip_prefix(root)?.display()),
                        package: package.to_string(),
                        name,
                        source_target: directory == "src",
                    });
                }
            }
        }
    }
    for harness in &mut harnesses {
        let (file, _) = harness
            .key
            .rsplit_once("::")
            .context("invalid harness key")?;
        harness.source_target |= linked_sources.contains(&root.join(file).canonicalize()?);
    }
    harnesses.sort_by(|a, b| a.key.cmp(&b.key));
    if harnesses.is_empty() {
        bail!("no Kani harnesses discovered; inventory would be vacuous");
    }
    Ok(harnesses)
}

#[derive(Debug)]
struct Lane {
    label: String,
    package: String,
    selectors: Vec<String>,
}

fn lane(label: &str, args: &str) -> Result<Lane> {
    if args.contains("${{") || args.contains('$') {
        bail!("{label}: unresolved Kani argument expression: {args}");
    }
    let mut words = args.split_whitespace();
    let mut package = None;
    let mut selectors = Vec::new();
    while let Some(word) = words.next() {
        let value = match word {
            "-p" | "--package" | "--harness" => {
                Some(words.next().context("missing Kani selector value")?)
            }
            _ => word.split_once('=').map(|(_, value)| value),
        };
        let flag = word.split('=').next().unwrap_or(word);
        match flag {
            "-p" | "--package" => {
                if package.is_some() {
                    bail!("{label}: multiple package selectors need explicit inventory support");
                }
                package = value.map(str::to_string);
            }
            "--harness" => selectors.push(value.context("missing harness selector")?.to_string()),
            "--exclude" | "--workspace" => bail!("{label}: unsupported package selection {word}"),
            _ => {}
        }
    }
    Ok(Lane {
        label: label.into(),
        package: package
            .with_context(|| format!("{label}: Kani lane needs an explicit package"))?,
        selectors,
    })
}

fn disabled(value: &Value) -> bool {
    value["if"].as_bool() == Some(false)
        || value["if"]
            .as_str()
            .is_some_and(|s| matches!(s.trim(), "false" | "${{ false }}"))
}

fn workflow_lanes(path: &str, workflow: &Value) -> Result<Vec<Lane>> {
    let mut lanes = Vec::new();
    let jobs = workflow["jobs"]
        .as_mapping()
        .context("workflow has no jobs")?;
    for (id, job) in jobs {
        if disabled(job) {
            continue;
        }
        let Some(steps) = job["steps"].as_sequence() else {
            continue;
        };
        for step in steps {
            if disabled(step)
                || !step["uses"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("model-checking/kani-github-action@"))
            {
                continue;
            }
            if let Some(command) = step["with"]["command"].as_str()
                && !matches!(
                    command,
                    "cargo-kani" | "cargo kani" | "bash scripts/kani-bounded.sh"
                )
            {
                bail!("{path}: unsupported Kani action command {command}");
            }
            let args = step["with"]["args"]
                .as_str()
                .context("Kani action has no args")?;
            let label = format!("{path}::{}", id.as_str().context("job id is not text")?);
            if args.contains("${{ matrix.harness }}") {
                if !job["strategy"]["matrix"]["include"].is_null()
                    || !job["strategy"]["matrix"]["exclude"].is_null()
                {
                    bail!("{label}: matrix include/exclude needs explicit inventory support");
                }
                let matrix = job["strategy"]["matrix"]["harness"]
                    .as_sequence()
                    .context("Kani harness matrix is not explicit")?;
                for value in matrix {
                    lanes.push(lane(
                        &label,
                        &args.replace(
                            "${{ matrix.harness }}",
                            value.as_str().context("matrix harness is not text")?,
                        ),
                    )?);
                }
            } else {
                lanes.push(lane(&label, args)?);
            }
        }
    }
    Ok(lanes)
}

fn covers(lane: &Lane, harness: &Harness) -> bool {
    harness.source_target
        && lane.package == harness.package
        && (lane.selectors.is_empty() || lane.selectors.iter().any(|s| s == &harness.name))
}

fn exceptions(text: &str) -> Result<BTreeMap<String, String>> {
    let mut entries = BTreeMap::new();
    let Some((_, tail)) = text.split_once("<!-- KANI-UNSCHEDULED:BEGIN -->") else {
        return Ok(entries);
    };
    let (body, _) = tail
        .split_once("<!-- KANI-UNSCHEDULED:END -->")
        .context("unclosed Kani exception list")?;
    for line in body.lines().filter(|l| l.starts_with("| `")) {
        let columns: Vec<_> = line.split('|').map(str::trim).collect();
        if columns.len() != 4 || columns[2].is_empty() {
            bail!("exception needs a named harness and reason: {line}");
        }
        let key = columns[1].trim_matches('`').to_string();
        if entries
            .insert(key.clone(), columns[2].to_string())
            .is_some()
        {
            bail!("duplicate exception: {key}");
        }
    }
    Ok(entries)
}

pub fn check(root: &Path) -> Result<()> {
    let harnesses = sources(root)?;
    let mut lanes = Vec::new();
    for entry in std::fs::read_dir(root.join(".github/workflows"))? {
        let path = entry?.path();
        if !path.extension().is_some_and(|s| s == "yml" || s == "yaml") {
            continue;
        }
        let workflow: Value = serde_yaml::from_str(&std::fs::read_to_string(&path)?)?;
        lanes.extend(workflow_lanes(
            &path.strip_prefix(root)?.display().to_string(),
            &workflow,
        )?);
    }
    let exceptions = exceptions(&std::fs::read_to_string(root.join("KANI-STATUS.md"))?)?;
    let keys: BTreeSet<_> = harnesses.iter().map(|h| h.key.as_str()).collect();
    let mut errors = Vec::new();
    for key in exceptions.keys() {
        if !keys.contains(key.as_str()) {
            errors.push(format!("stale exception: {key}"));
        }
    }
    for harness in &harnesses {
        let matching: Vec<_> = lanes.iter().filter(|l| covers(l, harness)).collect();
        if matching.is_empty() {
            if let Some(reason) = exceptions.get(&harness.key) {
                println!("UNSCHEDULED {} — {reason}", harness.key);
            } else {
                errors.push(format!("uncovered harness: {}", harness.key));
            }
        } else if exceptions.contains_key(&harness.key) {
            errors.push(format!("scheduled harness still excepted: {}", harness.key));
        } else {
            println!("scheduled {} — {}", harness.key, matching[0].label);
        }
    }
    if !errors.is_empty() {
        bail!("{}", errors.join("\n"));
    }
    println!(
        "ok: {} named harnesses accounted for ({} explicitly unscheduled); scheduling is not verification",
        harnesses.len(),
        exceptions.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_parser_ignores_strings_and_comments() {
        let file = syn::parse_file(
            "// #[kani::proof]\nconst S: &str = \"#[kani::proof]\"; #[kani::proof] fn actual() {} ",
        )
        .unwrap();
        let mut proofs = Proofs::default();
        proofs.visit_file(&file);
        assert_eq!(proofs.0, ["actual"]);
        let file = syn::parse_file("#[cfg(kani)] #[path = \"../proofs/overflow.rs\"] mod proofs;")
            .unwrap();
        proofs.visit_file(&file);
        assert_eq!(proofs.1, ["../proofs/overflow.rs"]);
    }

    #[test]
    fn selection_is_package_bound_and_does_not_cover_orphan_proofs() {
        let selected = lane("ci", "-p core --harness proof_a").unwrap();
        let mut h = Harness {
            key: "file::proof_a".into(),
            name: "proof_a".into(),
            package: "core".into(),
            source_target: true,
        };
        assert!(covers(&selected, &h));
        h.name = "new_unrun_proof".into();
        assert!(!covers(&selected, &h));
        let all = lane("nightly", "-p core").unwrap();
        assert!(covers(&all, &h));
        h.source_target = false;
        assert!(!covers(&all, &h));
        h.source_target = true;
        h.package = "other".into();
        assert!(!covers(&all, &h));
    }

    #[test]
    fn matrix_entries_are_concrete_and_disabled_jobs_do_not_cover() {
        let yaml: Value = serde_yaml::from_str("jobs:\n  proof:\n    strategy:\n      matrix:\n        harness: [proof_a, proof_b]\n    steps:\n      - uses: model-checking/kani-github-action@pin\n        with:\n          args: '-p core --harness ${{ matrix.harness }}'\n").unwrap();
        let lanes = workflow_lanes("ci", &yaml).unwrap();
        assert_eq!(lanes.len(), 2);
        assert_eq!(lanes[1].selectors, ["proof_b"]);
        let mut non_verifier = yaml.clone();
        non_verifier["jobs"]["proof"]["steps"][0]["with"]["command"] = Value::String("echo".into());
        assert!(workflow_lanes("ci", &non_verifier).is_err());
        let mut disabled_yaml = yaml;
        disabled_yaml["jobs"]["proof"]["if"] = Value::Bool(false);
        assert!(workflow_lanes("ci", &disabled_yaml).unwrap().is_empty());
        assert!(lane("ci", "-p core --harness ${{ matrix.unknown }}").is_err());
    }
}
