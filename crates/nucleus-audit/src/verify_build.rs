//! SLSA build provenance verification — `nucleus-audit verify-build` (#981).
//!
//! Verifies that a nucleus binary matches a SLSA v1 provenance attestation
//! produced by GitHub Actions. No network calls required for offline checks;
//! Sigstore signature verification is flagged as a separate online step.
//!
//! ## Verification layers
//!
//! 1. **Subject digest**: SHA-256 of the artifact must match the attestation subject.
//! 2. **Builder trust**: builder ID must be a known GitHub Actions runner.
//! 3. **Source repo**: repository in the predicate must match `--expected-repo`.
//! 4. **Workflow ref**: optionally, the git ref must be a protected branch/tag.
//!
//! Layer 5 (Sigstore DSSE envelope signature) requires network access to Rekor
//! and is outside the scope of this offline verifier. The attestation JSON
//! accepted here is the *unwrapped* in-toto statement extracted from the bundle.
//!
//! ## SLSA Provenance v1 JSON structure (GitHub Actions)
//!
//! ```json
//! {
//!   "_type": "https://in-toto.io/Statement/v1",
//!   "subject": [{"name": "nucleus-audit", "digest": {"sha256": "abcdef..."}}],
//!   "predicateType": "https://slsa.dev/provenance/v1",
//!   "predicate": {
//!     "buildDefinition": {
//!       "buildType": "https://actions.github.io/buildtypes/workflow/v1",
//!       "externalParameters": {
//!         "workflow": {
//!           "ref": "refs/heads/main",
//!           "repository": "https://github.com/coproduct-opensource/nucleus",
//!           "path": ".github/workflows/release.yml"
//!         }
//!       }
//!     },
//!     "runDetails": {
//!       "builder": {"id": "https://github.com/actions/runner"},
//!       "metadata": {"invocationId": "...", "startedOn": "...", "finishedOn": "..."}
//!     }
//!   }
//! }
//! ```

use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

fn digest_to_hex(d: impl AsRef<[u8]>) -> String {
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

// ── Trusted builder IDs ────────────────────────────────────────────────────

const TRUSTED_BUILDERS: &[&str] = &[
    "https://github.com/actions/runner",
    "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml",
    "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_generic_slsa3.yml",
];

const SLSA_PREDICATE_V1: &str = "https://slsa.dev/provenance/v1";
const SLSA_PREDICATE_V02: &str = "https://slsa.dev/provenance/v0.2";
const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";

// ── Deserialization types ──────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct InTotoStatement {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: Predicate,
}

#[derive(Deserialize, Debug)]
struct Subject {
    name: String,
    digest: SubjectDigest,
}

#[derive(Deserialize, Debug)]
struct SubjectDigest {
    #[serde(default)]
    sha256: String,
}

#[derive(Deserialize, Debug)]
struct Predicate {
    #[serde(rename = "buildDefinition", default)]
    build_definition: Option<BuildDefinition>,
    #[serde(rename = "runDetails", default)]
    run_details: Option<RunDetails>,
    // SLSA v0.2 fields
    builder: Option<Builder>,
    #[serde(rename = "invocation", default)]
    invocation: Option<Invocation>,
}

#[derive(Deserialize, Debug)]
struct BuildDefinition {
    #[serde(rename = "externalParameters", default)]
    external_parameters: ExternalParameters,
}

#[derive(Deserialize, Debug, Default)]
struct ExternalParameters {
    #[serde(default)]
    workflow: Option<WorkflowRef>,
}

#[derive(Deserialize, Debug)]
struct WorkflowRef {
    #[serde(rename = "ref", default)]
    git_ref: String,
    #[serde(default)]
    repository: String,
    #[serde(default)]
    path: String,
}

#[derive(Deserialize, Debug)]
struct RunDetails {
    builder: Builder,
    #[serde(default)]
    metadata: Option<RunMetadata>,
}

#[derive(Deserialize, Debug)]
struct Builder {
    id: String,
}

#[derive(Deserialize, Debug)]
struct RunMetadata {
    #[serde(rename = "invocationId", default)]
    invocation_id: String,
    #[serde(rename = "startedOn", default)]
    started_on: String,
    #[serde(rename = "finishedOn", default)]
    finished_on: String,
}

// SLSA v0.2 invocation
#[derive(Deserialize, Debug)]
struct Invocation {
    #[serde(rename = "configSource", default)]
    config_source: Option<ConfigSource>,
}

#[derive(Deserialize, Debug)]
struct ConfigSource {
    #[serde(default)]
    uri: String,
    #[serde(rename = "ref", default)]
    git_ref: String,
    #[serde(default)]
    entry_point: String,
}

// ── Verification result ────────────────────────────────────────────────────

/// Outcome of a single verification layer.
#[derive(Debug)]
pub struct LayerResult {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// Full verification report.
#[derive(Debug)]
pub struct BuildVerificationReport {
    pub artifact_name: String,
    pub artifact_sha256: String,
    pub builder_id: String,
    pub source_repo: String,
    pub git_ref: String,
    pub workflow_path: String,
    pub invocation_id: String,
    pub started_on: String,
    pub layers: Vec<LayerResult>,
    pub overall: bool,
}

impl BuildVerificationReport {
    pub fn print(&self) {
        let status = if self.overall { "VERIFIED" } else { "FAILED" };
        println!("nucleus-audit verify-build: {status}");
        println!();
        println!("  Artifact:    {}", self.artifact_name);
        println!("  SHA-256:     {}", self.artifact_sha256);
        println!("  Builder:     {}", self.builder_id);
        println!("  Repository:  {}", self.source_repo);
        println!("  Git ref:     {}", self.git_ref);
        println!("  Workflow:    {}", self.workflow_path);
        if !self.invocation_id.is_empty() {
            println!("  Invocation:  {}", self.invocation_id);
        }
        if !self.started_on.is_empty() {
            println!("  Started:     {}", self.started_on);
        }
        println!();
        println!("  Verification layers:");
        for layer in &self.layers {
            let mark = if layer.passed { "✓" } else { "✗" };
            println!("    {mark} {}: {}", layer.name, layer.detail);
        }
        println!();
        if !self.overall {
            println!("  NOTE: Sigstore DSSE signature verification requires network access.");
            println!("        Run `gh attestation verify` for full online verification.");
        }
    }
}

// ── Main verification function ─────────────────────────────────────────────

/// Verify a SLSA build provenance attestation against an artifact.
///
/// # Arguments
/// - `attestation_path`: Path to the SLSA provenance JSON (in-toto statement).
/// - `artifact_path`: Optional path to the binary. If provided, its SHA-256 is
///   computed and compared against the attestation subject digest.
/// - `expected_repo`: Expected GitHub repository URL or `owner/repo`.
///   Checked against the workflow's repository field.
/// - `expected_ref`: Optional expected git ref (e.g. `refs/heads/main`).
///   If provided, the attestation's ref must match exactly.
pub fn verify_build(
    attestation_path: &Path,
    artifact_path: Option<&Path>,
    expected_repo: Option<&str>,
    expected_ref: Option<&str>,
) -> anyhow::Result<BuildVerificationReport> {
    // Parse the attestation JSON.
    let raw = std::fs::read_to_string(attestation_path)?;
    let stmt: InTotoStatement = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse attestation JSON: {e}"))?;

    let mut layers = Vec::new();

    // ── Layer 1: Statement type ────────────────────────────────────────────
    let type_ok = stmt.statement_type == IN_TOTO_STATEMENT_V1;
    layers.push(LayerResult {
        name: "statement-type",
        passed: type_ok,
        detail: if type_ok {
            "in-toto v1 statement confirmed".to_string()
        } else {
            format!(
                "unexpected _type: {} (want {IN_TOTO_STATEMENT_V1})",
                stmt.statement_type
            )
        },
    });

    // ── Layer 2: Predicate type ────────────────────────────────────────────
    let pred_ok =
        stmt.predicate_type == SLSA_PREDICATE_V1 || stmt.predicate_type == SLSA_PREDICATE_V02;
    layers.push(LayerResult {
        name: "predicate-type",
        passed: pred_ok,
        detail: if pred_ok {
            format!("SLSA provenance predicate: {}", stmt.predicate_type)
        } else {
            format!("unexpected predicateType: {}", stmt.predicate_type)
        },
    });

    // ── Layer 3: Subject digest vs artifact ───────────────────────────────
    let (artifact_name, attested_hash) = stmt
        .subject
        .first()
        .map(|s| (s.name.clone(), s.digest.sha256.clone()))
        .unwrap_or_default();

    let (artifact_sha256, subject_ok, subject_detail) = if let Some(path) = artifact_path {
        let actual = sha256_file(path)?;
        let matches = actual.eq_ignore_ascii_case(&attested_hash);
        let detail = if matches {
            format!("artifact SHA-256 matches attestation subject ({actual})")
        } else {
            format!("SHA-256 mismatch: artifact={actual} attestation={attested_hash}")
        };
        (actual, matches, detail)
    } else {
        // No artifact provided — just surface the attested hash.
        (
            attested_hash.clone(),
            true,
            format!(
                "no artifact provided — attested hash: {attest} (unverified)",
                attest = if attested_hash.is_empty() {
                    "none"
                } else {
                    &attested_hash
                }
            ),
        )
    };

    layers.push(LayerResult {
        name: "subject-digest",
        passed: subject_ok,
        detail: subject_detail,
    });

    // ── Extract builder and workflow info ─────────────────────────────────
    let (builder_id, source_repo, git_ref, workflow_path, invocation_id, started_on, _finished_on) =
        extract_provenance_fields(&stmt);

    // ── Layer 4: Builder trust ────────────────────────────────────────────
    let builder_trusted = TRUSTED_BUILDERS.iter().any(|b| builder_id.starts_with(b))
        || builder_id.contains("github.com/actions")
        || builder_id.contains("slsa-framework");
    layers.push(LayerResult {
        name: "builder-trust",
        passed: builder_trusted,
        detail: if builder_trusted {
            format!("trusted builder: {builder_id}")
        } else {
            format!("untrusted builder: {builder_id}")
        },
    });

    // ── Layer 5: Source repo ──────────────────────────────────────────────
    if let Some(expected) = expected_repo {
        let normalized_expected = normalize_repo(expected);
        let normalized_actual = normalize_repo(&source_repo);
        let repo_ok = normalized_actual.ends_with(&normalized_expected)
            || normalized_expected.ends_with(&normalized_actual);
        layers.push(LayerResult {
            name: "source-repo",
            passed: repo_ok,
            detail: if repo_ok {
                format!("repository matches: {source_repo}")
            } else {
                format!("repository mismatch: got={source_repo} expected={expected}")
            },
        });
    }

    // ── Layer 6: Git ref ──────────────────────────────────────────────────
    if let Some(expected) = expected_ref {
        let ref_ok = git_ref == expected;
        layers.push(LayerResult {
            name: "git-ref",
            passed: ref_ok,
            detail: if ref_ok {
                format!("git ref matches: {git_ref}")
            } else {
                format!("ref mismatch: got={git_ref} expected={expected}")
            },
        });
    }

    let overall = layers.iter().all(|l| l.passed);

    Ok(BuildVerificationReport {
        artifact_name,
        artifact_sha256,
        builder_id,
        source_repo,
        git_ref,
        workflow_path,
        invocation_id,
        started_on,
        layers,
        overall,
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn extract_provenance_fields(
    stmt: &InTotoStatement,
) -> (String, String, String, String, String, String, String) {
    let pred = &stmt.predicate;

    // SLSA v1 path
    if let Some(bd) = &pred.build_definition {
        let builder_id = pred
            .run_details
            .as_ref()
            .map(|rd| rd.builder.id.clone())
            .unwrap_or_default();
        let (source_repo, git_ref, workflow_path) = bd
            .external_parameters
            .workflow
            .as_ref()
            .map(|w| (w.repository.clone(), w.git_ref.clone(), w.path.clone()))
            .unwrap_or_default();
        let (invocation_id, started_on, finished_on) = pred
            .run_details
            .as_ref()
            .and_then(|rd| rd.metadata.as_ref())
            .map(|m| {
                (
                    m.invocation_id.clone(),
                    m.started_on.clone(),
                    m.finished_on.clone(),
                )
            })
            .unwrap_or_default();
        return (
            builder_id,
            source_repo,
            git_ref,
            workflow_path,
            invocation_id,
            started_on,
            finished_on,
        );
    }

    // SLSA v0.2 path
    let builder_id = pred
        .builder
        .as_ref()
        .map(|b| b.id.clone())
        .unwrap_or_default();
    let (source_repo, git_ref, workflow_path) = pred
        .invocation
        .as_ref()
        .and_then(|i| i.config_source.as_ref())
        .map(|cs| (cs.uri.clone(), cs.git_ref.clone(), cs.entry_point.clone()))
        .unwrap_or_default();

    (
        builder_id,
        source_repo,
        git_ref,
        workflow_path,
        String::new(),
        String::new(),
        String::new(),
    )
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(digest_to_hex(Sha256::digest(&bytes)))
}

fn normalize_repo(repo: &str) -> String {
    repo.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_lowercase()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sha256_bytes(data: &[u8]) -> String {
        digest_to_hex(Sha256::digest(data))
    }

    fn write_attestation(json: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f
    }

    fn write_artifact(data: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    fn make_attestation(artifact_name: &str, sha256: &str, repo: &str, git_ref: &str) -> String {
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": artifact_name, "digest": {"sha256": sha256}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "externalParameters": {
                        "workflow": {
                            "ref": git_ref,
                            "repository": repo,
                            "path": ".github/workflows/release.yml"
                        }
                    }
                },
                "runDetails": {
                    "builder": {"id": "https://github.com/actions/runner"},
                    "metadata": {
                        "invocationId": "run/12345/attempt/1",
                        "startedOn": "2026-04-01T00:00:00Z",
                        "finishedOn": "2026-04-01T00:05:00Z"
                    }
                }
            }
        })
        .to_string()
    }

    // ── Subject digest matching ───────────────────────────────────────────

    #[test]
    fn subject_digest_matches_artifact() {
        let artifact_bytes = b"nucleus-audit-binary-v1.0.0";
        let hash = sha256_bytes(artifact_bytes);
        let attest_file = write_attestation(&make_attestation(
            "nucleus-audit",
            &hash,
            "https://github.com/coproduct-opensource/nucleus",
            "refs/tags/v1.0.0",
        ));
        let artifact_file = write_artifact(artifact_bytes);

        let report =
            verify_build(attest_file.path(), Some(artifact_file.path()), None, None).unwrap();
        let subject_layer = report
            .layers
            .iter()
            .find(|l| l.name == "subject-digest")
            .unwrap();
        assert!(
            subject_layer.passed,
            "subject digest should match: {}",
            subject_layer.detail
        );
    }

    #[test]
    fn subject_digest_mismatch_fails() {
        let attest_file = write_attestation(&make_attestation(
            "nucleus-audit",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://github.com/coproduct-opensource/nucleus",
            "refs/tags/v1.0.0",
        ));
        let artifact_file = write_artifact(b"different binary content");

        let report =
            verify_build(attest_file.path(), Some(artifact_file.path()), None, None).unwrap();
        let subject_layer = report
            .layers
            .iter()
            .find(|l| l.name == "subject-digest")
            .unwrap();
        assert!(!subject_layer.passed, "mismatched digest should fail");
        assert!(!report.overall);
    }

    #[test]
    fn no_artifact_provided_subject_layer_passes_with_note() {
        let attest_file = write_attestation(&make_attestation(
            "nucleus-audit",
            "abc123",
            "https://github.com/coproduct-opensource/nucleus",
            "refs/heads/main",
        ));

        let report = verify_build(attest_file.path(), None, None, None).unwrap();
        let subject_layer = report
            .layers
            .iter()
            .find(|l| l.name == "subject-digest")
            .unwrap();
        // Without artifact, layer passes but marks as unverified in detail
        assert!(subject_layer.passed);
        assert!(subject_layer.detail.contains("unverified"));
    }

    // ── Builder trust ─────────────────────────────────────────────────────

    #[test]
    fn github_actions_runner_is_trusted() {
        let attest_file = write_attestation(&make_attestation(
            "nucleus-audit",
            "abc123",
            "https://github.com/coproduct-opensource/nucleus",
            "refs/heads/main",
        ));
        let report = verify_build(attest_file.path(), None, None, None).unwrap();
        let builder_layer = report
            .layers
            .iter()
            .find(|l| l.name == "builder-trust")
            .unwrap();
        assert!(builder_layer.passed);
    }

    #[test]
    fn unknown_builder_fails_trust() {
        let attest = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "bin", "digest": {"sha256": "abc"}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "externalParameters": {"workflow": {"ref": "main", "repository": "https://evil.com/repo", "path": "build.yml"}}
                },
                "runDetails": {
                    "builder": {"id": "https://evil.com/custom-builder"},
                    "metadata": {}
                }
            }
        }).to_string();
        let attest_file = write_attestation(&attest);
        let report = verify_build(attest_file.path(), None, None, None).unwrap();
        let builder_layer = report
            .layers
            .iter()
            .find(|l| l.name == "builder-trust")
            .unwrap();
        assert!(!builder_layer.passed);
    }

    // ── Repo verification ─────────────────────────────────────────────────

    #[test]
    fn repo_matches_expected() {
        let attest_file = write_attestation(&make_attestation(
            "nucleus-audit",
            "abc",
            "https://github.com/coproduct-opensource/nucleus",
            "refs/heads/main",
        ));
        let report = verify_build(
            attest_file.path(),
            None,
            Some("coproduct-opensource/nucleus"),
            None,
        )
        .unwrap();
        let repo_layer = report
            .layers
            .iter()
            .find(|l| l.name == "source-repo")
            .unwrap();
        assert!(repo_layer.passed);
    }

    #[test]
    fn repo_mismatch_fails() {
        let attest_file = write_attestation(&make_attestation(
            "nucleus-audit",
            "abc",
            "https://github.com/evil-org/nucleus-fork",
            "refs/heads/main",
        ));
        let report = verify_build(
            attest_file.path(),
            None,
            Some("coproduct-opensource/nucleus"),
            None,
        )
        .unwrap();
        let repo_layer = report
            .layers
            .iter()
            .find(|l| l.name == "source-repo")
            .unwrap();
        assert!(!repo_layer.passed);
        assert!(!report.overall);
    }

    // ── Git ref verification ──────────────────────────────────────────────

    #[test]
    fn git_ref_matches_expected() {
        let attest_file = write_attestation(&make_attestation(
            "nucleus-audit",
            "abc",
            "https://github.com/coproduct-opensource/nucleus",
            "refs/tags/v1.0.0",
        ));
        let report =
            verify_build(attest_file.path(), None, None, Some("refs/tags/v1.0.0")).unwrap();
        let ref_layer = report.layers.iter().find(|l| l.name == "git-ref").unwrap();
        assert!(ref_layer.passed);
    }

    #[test]
    fn git_ref_mismatch_fails() {
        let attest_file = write_attestation(&make_attestation(
            "nucleus-audit",
            "abc",
            "https://github.com/coproduct-opensource/nucleus",
            "refs/heads/feature-branch",
        ));
        let report =
            verify_build(attest_file.path(), None, None, Some("refs/tags/v1.0.0")).unwrap();
        let ref_layer = report.layers.iter().find(|l| l.name == "git-ref").unwrap();
        assert!(!ref_layer.passed);
    }

    // ── Overall pass/fail ─────────────────────────────────────────────────

    #[test]
    fn full_verification_passes_with_all_checks() {
        let artifact_bytes = b"release-binary";
        let hash = sha256_bytes(artifact_bytes);
        let attest_file = write_attestation(&make_attestation(
            "nucleus-audit",
            &hash,
            "https://github.com/coproduct-opensource/nucleus",
            "refs/tags/v1.0.0",
        ));
        let artifact_file = write_artifact(artifact_bytes);

        let report = verify_build(
            attest_file.path(),
            Some(artifact_file.path()),
            Some("coproduct-opensource/nucleus"),
            Some("refs/tags/v1.0.0"),
        )
        .unwrap();

        assert!(report.overall, "all checks should pass");
        for layer in &report.layers {
            assert!(
                layer.passed,
                "layer {} failed: {}",
                layer.name, layer.detail
            );
        }
    }

    // ── SLSA v0.2 compatibility ───────────────────────────────────────────

    #[test]
    fn slsa_v02_predicate_accepted() {
        let attest = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "nucleus-audit", "digest": {"sha256": "abc"}}],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {"id": "https://github.com/actions/runner"},
                "invocation": {
                    "configSource": {
                        "uri": "https://github.com/coproduct-opensource/nucleus",
                        "ref": "refs/tags/v0.9.0",
                        "entryPoint": ".github/workflows/release.yml"
                    }
                }
            }
        })
        .to_string();
        let attest_file = write_attestation(&attest);
        let report = verify_build(attest_file.path(), None, None, None).unwrap();
        let pred_layer = report
            .layers
            .iter()
            .find(|l| l.name == "predicate-type")
            .unwrap();
        assert!(pred_layer.passed);
        assert!(report.builder_id.contains("github.com/actions"));
    }

    // ── Malformed input ───────────────────────────────────────────────────

    #[test]
    fn invalid_json_returns_error() {
        let attest_file = write_attestation("not valid json {{{{");
        let result = verify_build(attest_file.path(), None, None, None);
        assert!(result.is_err());
    }

    // ── normalize_repo helper ─────────────────────────────────────────────

    #[test]
    fn normalize_repo_strips_scheme() {
        assert_eq!(
            normalize_repo("https://github.com/org/repo"),
            "github.com/org/repo"
        );
        assert_eq!(normalize_repo("org/repo"), "org/repo");
    }
}
