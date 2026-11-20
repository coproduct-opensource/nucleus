//! Where the bridge's policy comes from: a pod spec, always (ADR 0007 B-2).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use nucleus_spec::PodSpec;
use portcullis::PermissionLattice;

use crate::Args;

/// Where the bridge's policy comes from. Exactly one source, and no variant
/// for "none": a bridge started without a spec used to run its kernel on
/// `PermissionLattice::permissive` and offer every tool, so absence granted
/// everything (ADR 0007 B-2). An unrestricted session is still possible, by
/// naming it: a spec whose policy is `{type: profile, name: permissive}`.
#[derive(Debug)]
pub(crate) enum SpecSource<'a> {
    /// `--spec` / `NUCLEUS_MCP_SPEC`: a pod spec file.
    File(&'a Path),
    /// `--spec-yaml` / `NUCLEUS_MCP_SPEC_YAML`: the pod spec itself.
    Document(&'a str),
}

impl<'a> SpecSource<'a> {
    /// The one source `args` names.
    ///
    /// # Errors
    ///
    /// Neither source is given (the error names both), or both are.
    pub(crate) fn from_args(args: &'a Args) -> Result<Self> {
        match (args.spec.as_deref(), args.spec_yaml.as_deref()) {
            (Some(path), None) => Ok(Self::File(path)),
            (None, Some(doc)) => Ok(Self::Document(doc)),
            (Some(_), Some(_)) => Err(anyhow!(
                "both --spec (NUCLEUS_MCP_SPEC) and --spec-yaml (NUCLEUS_MCP_SPEC_YAML) \
                 are given; give one pod spec"
            )),
            (None, None) => Err(anyhow!(
                "no pod spec: nucleus-mcp needs --spec <path> (NUCLEUS_MCP_SPEC) or \
                 --spec-yaml <document> (NUCLEUS_MCP_SPEC_YAML). Its policy decides which \
                 tools are offered and what the kernel allows, and there is no default \
                 policy. For an unrestricted session, name it in the spec: \
                 `policy: {{type: profile, name: permissive}}`"
            )),
        }
    }

    /// Parse the pod spec and resolve its policy: one parser for both sources.
    ///
    /// # Errors
    ///
    /// The file cannot be read, the spec does not parse, or its policy does
    /// not resolve.
    pub(crate) fn load_policy(&self) -> Result<PermissionLattice> {
        let (contents, from) = match self {
            Self::File(path) => (
                fs::read_to_string(path)
                    .with_context(|| format!("failed to read pod spec from {}", path.display()))?,
                path.display().to_string(),
            ),
            Self::Document(doc) => ((*doc).to_string(), "--spec-yaml".to_string()),
        };
        let spec: PodSpec = nucleus_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse pod spec {from}"))?;
        spec.spec
            .resolve_policy()
            .map_err(|e| anyhow!("policy resolve failed for pod spec {from}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_tool_defs;
    use clap::Parser;

    fn parse(argv: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("nucleus-mcp").chain(argv.iter().copied()))
            .expect("args parse")
    }

    fn spec_doc(profile: &str) -> String {
        format!(
            "apiVersion: nucleus/v1\nkind: Pod\nspec:\n  policy:\n    type: profile\n    name: {profile}\n"
        )
    }

    fn tool_names(policy: &PermissionLattice) -> Vec<String> {
        build_tool_defs(policy)
            .into_iter()
            .map(|t| t.name)
            .collect()
    }

    /// ADR 0007 B-2: no spec is a refusal naming both sources, never a lattice.
    #[test]
    fn no_spec_is_refused_by_name() {
        let args = parse(&[]);
        let err = SpecSource::from_args(&args)
            .expect_err("absence is not a policy")
            .to_string();
        for name in [
            "--spec <path>",
            "NUCLEUS_MCP_SPEC)",
            "--spec-yaml",
            "NUCLEUS_MCP_SPEC_YAML",
        ] {
            assert!(err.contains(name), "{name} not named: {err}");
        }
    }

    #[test]
    fn both_spec_sources_are_refused() {
        let doc = spec_doc("codegen");
        let args = parse(&["--spec", "pod.yaml", "--spec-yaml", &doc]);
        assert!(SpecSource::from_args(&args).is_err());
    }

    /// The one way to an unrestricted session is to name it: a spec that says
    /// `permissive` resolves to that lattice, and offers its tools.
    #[test]
    fn permissive_is_reachable_only_by_naming_it() {
        let doc = spec_doc("permissive");
        let args = parse(&["--spec-yaml", &doc]);
        let policy = SpecSource::from_args(&args)
            .and_then(|s| s.load_policy())
            .expect("a named permissive spec loads");
        assert_eq!(
            tool_names(&policy),
            tool_names(&PermissionLattice::permissive())
        );
    }

    /// A spec file and the same spec as a document resolve through one parser
    /// to one policy, and its tools are the ones the policy grants.
    #[test]
    fn a_spec_file_and_document_decide_the_same_tools() {
        let doc = spec_doc("orchestrator");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pod.yaml");
        std::fs::write(&path, &doc).unwrap();
        let path = path.display().to_string();
        let names = |argv: &[&str]| -> Vec<String> {
            let args = parse(argv);
            let policy = SpecSource::from_args(&args)
                .and_then(|s| s.load_policy())
                .expect("loads");
            tool_names(&policy)
        };
        let from_file = names(&["--spec", &path]);
        assert_eq!(from_file, names(&["--spec-yaml", &doc]));
        assert!(
            !from_file.iter().any(|n| n == "write" || n == "run"),
            "{from_file:?}"
        );
        assert!(from_file.iter().any(|n| n == "create_pod"), "{from_file:?}");
    }
}
