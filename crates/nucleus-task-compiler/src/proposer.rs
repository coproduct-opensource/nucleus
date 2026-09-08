//! Effect proposers: the seam between "what the goal needs" and the
//! deterministic compiler that clamps it.
//!
//! [`RuleProposer`] is the built-in, offline proposer. An orchestrator that
//! wants an LLM's judgement implements the child-process protocol of
//! [`ExternalCommandProposer`] *outside* nucleus; the compiler validates its
//! output against the catalog and meets it with the ceiling, so an external
//! proposer can only narrow or starve a goal, never widen it.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use portcullis::{EffectCatalog, EffectId};
use serde::{Deserialize, Serialize};

use crate::repo_context::RepoContext;

/// A proposer's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Who proposed it.
    pub proposer: String,
    /// The effects.
    pub effects: BTreeSet<EffectId>,
    /// Rule ids (for [`RuleProposer`]) or free-form reasons.
    pub rules_fired: Vec<String>,
}

/// Proposer failures.
#[derive(Debug, thiserror::Error)]
pub enum ProposerError {
    /// The child process could not be run.
    #[error("proposer {program}: {source}")]
    Spawn {
        /// The program.
        program: String,
        /// The error.
        #[source]
        source: std::io::Error,
    },
    /// The child exited non-zero.
    #[error("proposer {program} exited with {status}: {stderr}")]
    Failed {
        /// The program.
        program: String,
        /// Exit status.
        status: String,
        /// Captured stderr (trimmed).
        stderr: String,
    },
    /// The child's output was not the expected JSON.
    #[error("proposer {program} returned malformed output: {detail}")]
    Malformed {
        /// The program.
        program: String,
        /// What was wrong.
        detail: String,
    },
}

/// Something that proposes effects for a goal.
pub trait EffectProposer {
    /// Name recorded in provenance.
    fn name(&self) -> String;
    /// Propose. Unknown effect ids are the compiler's problem, not the
    /// proposer's: return them and they are dropped with a warning.
    fn propose(
        &self,
        goal: &str,
        ctx: &RepoContext,
        catalog: &EffectCatalog,
    ) -> Result<Proposal, ProposerError>;
}

/// The built-in rule table.
#[derive(Debug, Default, Clone, Copy)]
pub struct RuleProposer;

impl EffectProposer for RuleProposer {
    fn name(&self) -> String {
        "rules".into()
    }

    fn propose(
        &self,
        goal: &str,
        ctx: &RepoContext,
        _catalog: &EffectCatalog,
    ) -> Result<Proposal, ProposerError> {
        Ok(crate::rules::apply(goal, ctx))
    }
}

/// What an external proposer reads on stdin.
#[derive(Debug, Serialize)]
struct ExternalRequest<'a> {
    goal: &'a str,
    context: &'a RepoContext,
    /// Every effect the proposer may name, with its title and risk.
    catalog: Vec<ExternalEffect>,
}

#[derive(Debug, Serialize)]
struct ExternalEffect {
    id: String,
    title: String,
    risk: String,
}

/// What an external proposer writes on stdout.
#[derive(Debug, Deserialize)]
struct ExternalResponse {
    #[serde(default)]
    effects: Vec<String>,
    #[serde(default)]
    reasons: Vec<String>,
}

/// A proposer that is a program: JSON request on stdin, JSON response on
/// stdout. The protocol is deliberately tiny so the program can be a shell
/// script, a service client, or anything else that lives outside nucleus.
#[derive(Debug, Clone)]
pub struct ExternalCommandProposer {
    /// The program to run.
    pub program: PathBuf,
}

impl EffectProposer for ExternalCommandProposer {
    fn name(&self) -> String {
        format!("external:{}", self.program.display())
    }

    fn propose(
        &self,
        goal: &str,
        ctx: &RepoContext,
        catalog: &EffectCatalog,
    ) -> Result<Proposal, ProposerError> {
        let program = self.program.display().to_string();
        let request = ExternalRequest {
            goal,
            context: ctx,
            catalog: catalog
                .iter()
                .map(|e| ExternalEffect {
                    id: e.id.to_string(),
                    title: e.title.clone(),
                    risk: e.risk.as_str().to_string(),
                })
                .collect(),
        };
        let input = serde_json::to_vec(&request).map_err(|e| ProposerError::Malformed {
            program: program.clone(),
            detail: format!("could not encode request: {e}"),
        })?;

        let mut child = Command::new(&self.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| ProposerError::Spawn {
                program: program.clone(),
                source,
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(&input)
                .map_err(|source| ProposerError::Spawn {
                    program: program.clone(),
                    source,
                })?;
        }
        let output = child
            .wait_with_output()
            .map_err(|source| ProposerError::Spawn {
                program: program.clone(),
                source,
            })?;
        if !output.status.success() {
            return Err(ProposerError::Failed {
                program,
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        let response: ExternalResponse =
            serde_json::from_slice(&output.stdout).map_err(|e| ProposerError::Malformed {
                program: program.clone(),
                detail: e.to_string(),
            })?;

        // Unknown ids are dropped here, not errors: a proposer that names
        // something the catalog lacks cannot make the grant wider by it.
        let mut effects = BTreeSet::new();
        let mut reasons = response.reasons;
        for raw in response.effects {
            match raw.parse::<EffectId>() {
                Ok(id) if catalog.get(&id).is_some() => {
                    effects.insert(id);
                }
                _ => reasons.push(format!("ignored unknown effect '{raw}'")),
            }
        }
        Ok(Proposal {
            proposer: self.name(),
            effects,
            rules_fired: reasons,
        })
    }
}
