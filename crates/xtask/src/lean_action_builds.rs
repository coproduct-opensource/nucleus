//! Read explicit Lean-action build inputs for the library-coverage gate.
use anyhow::{Context, Result, bail};
use serde_yaml::Value;

fn builds(workflow: &Value) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let Some(jobs) = workflow["jobs"].as_mapping() else {
        return Ok(out);
    };
    for job in jobs.values() {
        if job["if"] == Value::Bool(false) {
            continue;
        }
        let Some(steps) = job["steps"].as_sequence() else {
            continue;
        };
        for step in steps {
            if step["if"] == Value::Bool(false) {
                continue;
            }
            if !step["uses"]
                .as_str()
                .is_some_and(|s| s.starts_with("leanprover/lean-action@"))
            {
                continue;
            }
            let inputs = &step["with"];
            let build = inputs["build"]
                .as_str()
                .context("Lean action must explicitly declare build true/false")?;
            if build == "false" {
                continue;
            }
            if build != "true" {
                bail!("unsupported Lean action build input: {build}");
            }
            let directory = inputs["lake-package-directory"]
                .as_str()
                .context("Lean action must declare package directory")?;
            if directory.contains(['$', '\n', '\t', ' ']) {
                bail!("nonliteral Lean package directory");
            }
            let args = match &inputs["build-args"] {
                Value::Null => "",
                value => value
                    .as_str()
                    .context("Lean build-args must be a literal string")?,
            };
            if args.trim().is_empty() {
                out.push(("bare".into(), directory.into()));
            }
            for target in args.split_whitespace() {
                if !target
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    bail!("unsupported Lean build target: {target}");
                }
                out.push(("named".into(), target.into()));
            }
        }
    }
    Ok(out)
}

pub fn run(workflow: Option<&std::path::Path>) -> Result<()> {
    if let Some(path) = workflow {
        if !path.is_file() {
            bail!("workflow does not exist: {}", path.display());
        }
    }
    for entry in std::fs::read_dir(".github/workflows")? {
        let path = entry?.path();
        if workflow.is_some_and(|requested| requested != path) {
            continue;
        }
        if !path.extension().is_some_and(|s| s == "yml" || s == "yaml") {
            continue;
        }
        let yaml: Value = serde_yaml::from_str(&std::fs::read_to_string(&path)?)?;
        for (kind, value) in builds(&yaml).with_context(|| path.display().to_string())? {
            println!("{kind}\t{value}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_folded_targets_and_rejects_dynamic_builds() {
        let mut yaml: Value = serde_yaml::from_str("jobs:\n  proof:\n    steps:\n      - uses: leanprover/lean-action@pin\n        with:\n          build: 'true'\n          lake-package-directory: ci/lean\n          build-args: >-\n            CiSpec\n            CiSpecBite\n").unwrap();
        assert_eq!(
            builds(&yaml).unwrap(),
            [
                ("named".into(), "CiSpec".into()),
                ("named".into(), "CiSpecBite".into())
            ]
        );
        yaml["jobs"]["proof"]["steps"][0]["with"]["build-args"] =
            Value::String("${{ matrix.target }}".into());
        assert!(builds(&yaml).is_err());
        yaml["jobs"]["proof"]["steps"][0]["with"]["build-args"] = Value::String(String::new());
        assert_eq!(builds(&yaml).unwrap(), [("bare".into(), "ci/lean".into())]);
        yaml["jobs"]["proof"]["steps"][0]["with"]["build"] = Value::String("false".into());
        assert!(builds(&yaml).unwrap().is_empty());
        yaml["jobs"]["proof"]["steps"][0]["with"]["build"] = Value::String("default".into());
        assert!(builds(&yaml).is_err());
        yaml["jobs"]["proof"]["if"] = Value::Bool(false);
        assert!(builds(&yaml).unwrap().is_empty());
    }
}
