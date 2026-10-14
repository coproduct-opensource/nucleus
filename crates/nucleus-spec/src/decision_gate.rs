//! Effects that run only with a verified owner decision cited, and how a node hands a pod the
//! material to verify one (`docs/permissions.md`, "Decisions").
//!
//! # The requirement
//!
//! A pod spec may list capabilities in `spec.requires_decision`. Each is a
//! [`DecisionCapability`], `<effect>:<upstream>`, for example `create_pr:forge`: a pull request
//! opened through the credentialed upstream named `forge`. The string is exactly the scope
//! capability an owner signs (`nucleus-signed-decision`'s `Scope::capabilities`), so the policy
//! and the decision name the same thing in the same spelling, and nothing translates between
//! them (ADR 0007 G-1).
//!
//! A requirement only ever restricts: a spec that lists one makes an effect it was already
//! allowed need a decision as well. The tool-proxy enforces it at the effect, and a sub-pod
//! inherits every requirement its parent holds for an upstream the child keeps.
//!
//! # The material
//!
//! The node's operator configures the trust roots, the tenant, and the directory the tenant's
//! bundles arrive in. A pod receives them as files at a path outside its workspace and three
//! environment variables naming them ([`TRUST_ROOTS_ENV`], [`BUNDLES_ENV`], [`TENANT_ENV`]),
//! which the tool-proxy reads. The roots are operator configuration. The bundles are untrusted
//! bytes until the tool-proxy verifies them, so nothing on the way checks more than their shape
//! ([`DecisionMaterial::check`]).
//!
//! On Firecracker the material rides the `FETCH_POD_SPEC` reply, beside the spec that declares
//! the requirement: one reply means a guest cannot be handed the requirement without the
//! material to meet it. A guest that predates this ignores the extra field, and a spec that
//! requires a decision is refused by that guest's spec parser, so an older guest fails closed.

use serde::{Deserialize, Serialize};

use crate::EgressOperation;

/// The tool-proxy's trust-roots file variable.
pub const TRUST_ROOTS_ENV: &str = "NUCLEUS_DECISION_TRUST_ROOTS";
/// The tool-proxy's bundle-directory variable.
pub const BUNDLES_ENV: &str = "NUCLEUS_DECISION_BUNDLES";
/// The tool-proxy's tenant variable.
pub const TENANT_ENV: &str = "NUCLEUS_DECISION_TENANT";

/// Where a guest keeps the material: under `/run`, which the workload's Landlock ruleset hides.
macro_rules! guest_decisions {
    ($file:literal) => {
        concat!("/run/nucleus/decisions", $file)
    };
}

/// The directory a Firecracker or container pod's material is placed in.
pub const GUEST_DIR: &str = guest_decisions!("");
/// The trust-roots file inside a pod.
pub const GUEST_TRUST_ROOTS: &str = guest_decisions!("/trust-roots.json");
/// The bundle directory inside a pod.
pub const GUEST_BUNDLES: &str = guest_decisions!("/bundles");

/// The largest trust-roots file a node or proxy reads.
pub const MAX_ROOTS_BYTES: u64 = 64 * 1024;
/// The largest bundle file a node delivers or a proxy reads. A batch is at most 25 decisions of
/// short strings.
pub const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;
/// The most bundles one pod is handed (the proxy's ledger holds at most this many).
pub const MAX_BUNDLES: usize = 256;
/// The most bundle bytes one pod is handed in all. Past it the node refuses the pod rather than
/// choose which decisions to leave out.
pub const MAX_MATERIAL_BYTES: usize = 4 * 1024 * 1024;

/// The console line a tool-proxy prints once it has armed every requirement of its spec. The node
/// requires it of a Firecracker pod that lists one, because it cannot otherwise tell a guest that
/// enforces the requirement from one that predates it.
pub const ARMED_PREFIX: &str = "NUCLEUS_DECISION_GATE: ARMED";

/// An effect a policy may require a decision for. Each is a sink the tool-proxy already
/// classifies; the enum is closed so a requirement can only name one the proxy can gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DecisionGatedEffect {
    /// A push through a credentialed upstream (`EgressOperation::GitPush`).
    GitPush,
    /// A pull request opened through a credentialed upstream (`EgressOperation::CreatePr`).
    CreatePr,
}

impl DecisionGatedEffect {
    /// Every effect.
    pub const ALL: [Self; 2] = [Self::GitPush, Self::CreatePr];

    /// The spelling in a capability string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitPush => "git_push",
            Self::CreatePr => "create_pr",
        }
    }

    /// The effect a credentialed call is, if it is one a decision can be required for.
    /// Exhaustive, so a new operation states whether it can be gated.
    pub const fn of_operation(op: EgressOperation) -> Option<Self> {
        match op {
            EgressOperation::WebFetch => None,
            EgressOperation::GitPush => Some(Self::GitPush),
            EgressOperation::CreatePr => Some(Self::CreatePr),
        }
    }
}

/// `<effect>:<upstream>`: one effect through one credentialed upstream. Serialized as that string,
/// which is the capability an owner's decision must list to cover it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DecisionCapability {
    effect: DecisionGatedEffect,
    upstream: String,
}

/// Why a capability string was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    /// Not `<effect>:<upstream>`.
    #[error("{0:?} is not <effect>:<upstream>")]
    Shape(String),
    /// The effect is not one a decision can be required for.
    #[error("{effect:?} is not a decision-gated effect (expected one of git_push, create_pr)")]
    Effect {
        /// What the string named.
        effect: String,
    },
    /// The upstream name is empty, longer than 64, or not `[A-Za-z0-9._-]`.
    #[error("{0:?} is not an upstream name (1 to 64 of A-Z a-z 0-9 . _ -)")]
    Upstream(String),
}

impl DecisionCapability {
    /// One effect through one upstream.
    ///
    /// # Errors
    /// The upstream name is not 1 to 64 of `[A-Za-z0-9._-]`.
    pub fn new(effect: DecisionGatedEffect, upstream: &str) -> Result<Self, CapabilityError> {
        let ok = !upstream.is_empty()
            && upstream.len() <= 64
            && upstream
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !ok {
            return Err(CapabilityError::Upstream(upstream.to_string()));
        }
        Ok(Self {
            effect,
            upstream: upstream.to_string(),
        })
    }

    /// The effect.
    pub const fn effect(&self) -> DecisionGatedEffect {
        self.effect
    }

    /// The credentialed upstream it goes through.
    pub fn upstream(&self) -> &str {
        &self.upstream
    }
}

impl std::fmt::Display for DecisionCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.effect.as_str(), self.upstream)
    }
}

impl std::str::FromStr for DecisionCapability {
    type Err = CapabilityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (effect, upstream) = s
            .split_once(':')
            .ok_or_else(|| CapabilityError::Shape(s.to_string()))?;
        let effect = DecisionGatedEffect::ALL
            .into_iter()
            .find(|e| e.as_str() == effect)
            .ok_or_else(|| CapabilityError::Effect {
                effect: effect.to_string(),
            })?;
        Self::new(effect, upstream)
    }
}

impl TryFrom<String> for DecisionCapability {
    type Error = CapabilityError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<DecisionCapability> for String {
    fn from(c: DecisionCapability) -> Self {
        c.to_string()
    }
}

/// The console line for an armed set of requirements, in the order given.
pub fn armed_line(required: &[DecisionCapability]) -> String {
    let names: Vec<String> = required.iter().map(ToString::to_string).collect();
    format!("{ARMED_PREFIX} {}", names.join(","))
}

/// Whether `console` carries an armed line naming every capability in `required`.
pub fn armed_in(console: &str, required: &[DecisionCapability]) -> bool {
    console.lines().any(|line| {
        let Some(rest) = line.trim().strip_prefix(ARMED_PREFIX) else {
            return false;
        };
        let armed: Vec<&str> = rest.trim().split(',').collect();
        required
            .iter()
            .all(|c| armed.iter().any(|a| *a == c.to_string()))
    })
}

/// What a node hands a pod so its tool-proxy can verify decisions. Untrusted bytes except
/// `trust_roots`, which the operator configured and the node read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionMaterial {
    /// The trust-roots file's text, as the operator wrote it.
    pub trust_roots: String,
    /// The tenant every decision must name.
    pub tenant: String,
    /// The tenant's bundles, by decision id.
    pub bundles: Vec<DecisionBundleFile>,
}

/// One bundle file: `<id>.json` and its bytes, unverified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBundleFile {
    /// The decision id the file is named for, 64 lowercase hex. The proxy refuses a bundle that
    /// verifies as another id.
    pub id: String,
    /// The file's text.
    pub json: String,
}

/// Why material was refused before any of it was written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MaterialError {
    /// The tenant is empty.
    #[error("decision tenant is empty")]
    EmptyTenant,
    /// The roots are larger than [`MAX_ROOTS_BYTES`].
    #[error("trust roots exceed {MAX_ROOTS_BYTES} bytes")]
    RootsTooLarge,
    /// More than [`MAX_BUNDLES`] bundles.
    #[error("more than {MAX_BUNDLES} decision bundles")]
    TooMany,
    /// More than [`MAX_MATERIAL_BYTES`] of bundles.
    #[error("decision bundles exceed {MAX_MATERIAL_BYTES} bytes in all")]
    TooLarge,
    /// A bundle's id is not 64 lowercase hex, so it cannot be a file name.
    #[error("bundle id {0:?} is not 64 lowercase hex")]
    BadId(String),
    /// Two bundles share an id.
    #[error("bundle id {0} appears twice")]
    DuplicateId(String),
}

/// Whether `s` is a decision id: exactly 64 lowercase hex.
pub fn is_decision_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl DecisionMaterial {
    /// Check the shape both ends rely on: a tenant, bounded sizes, and ids that are safe file
    /// names. Says nothing about whether any bundle verifies.
    ///
    /// # Errors
    /// The first [`MaterialError`] found.
    pub fn check(&self) -> Result<(), MaterialError> {
        if self.tenant.is_empty() {
            return Err(MaterialError::EmptyTenant);
        }
        if !u64::try_from(self.trust_roots.len()).is_ok_and(|n| n <= MAX_ROOTS_BYTES) {
            return Err(MaterialError::RootsTooLarge);
        }
        if self.bundles.len() > MAX_BUNDLES {
            return Err(MaterialError::TooMany);
        }
        let total = self
            .bundles
            .iter()
            .fold(0usize, |n, b| n.saturating_add(b.json.len()));
        if total > MAX_MATERIAL_BYTES {
            return Err(MaterialError::TooLarge);
        }
        let mut seen = std::collections::BTreeSet::new();
        for b in &self.bundles {
            if !is_decision_id(&b.id) {
                return Err(MaterialError::BadId(b.id.clone()));
            }
            if !seen.insert(b.id.as_str()) {
                return Err(MaterialError::DuplicateId(b.id.clone()));
            }
        }
        Ok(())
    }

    /// The tool-proxy's variables for material placed at [`GUEST_DIR`].
    pub fn guest_env(&self) -> [(&'static str, String); 3] {
        [
            (TRUST_ROOTS_ENV, GUEST_TRUST_ROOTS.to_string()),
            (BUNDLES_ENV, GUEST_BUNDLES.to_string()),
            (TENANT_ENV, self.tenant.clone()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capability_is_the_string_an_owner_signs() {
        let c: DecisionCapability = "create_pr:forge".parse().unwrap();
        assert_eq!(c.effect(), DecisionGatedEffect::CreatePr);
        assert_eq!(c.upstream(), "forge");
        assert_eq!(c.to_string(), "create_pr:forge");
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "\"create_pr:forge\"");
        assert_eq!(
            serde_json::from_str::<DecisionCapability>(&json).unwrap(),
            c
        );
        for bad in [
            "create_pr",
            "merge:forge",
            "create_pr:",
            "create_pr:a/b",
            "git_push:a:b",
        ] {
            assert!(bad.parse::<DecisionCapability>().is_err(), "{bad}");
            assert!(serde_json::from_str::<DecisionCapability>(&format!("\"{bad}\"")).is_err());
        }
    }

    #[test]
    fn only_a_push_or_a_pull_request_can_be_gated() {
        assert_eq!(
            DecisionGatedEffect::of_operation(EgressOperation::WebFetch),
            None
        );
        assert_eq!(
            DecisionGatedEffect::of_operation(EgressOperation::GitPush),
            Some(DecisionGatedEffect::GitPush)
        );
        assert_eq!(
            DecisionGatedEffect::of_operation(EgressOperation::CreatePr),
            Some(DecisionGatedEffect::CreatePr)
        );
    }

    #[test]
    fn the_armed_line_must_name_every_requirement() {
        let a: DecisionCapability = "create_pr:forge".parse().unwrap();
        let b: DecisionCapability = "git_push:forge".parse().unwrap();
        let line = armed_line(&[a.clone(), b.clone()]);
        assert!(armed_in(
            &format!("boot\n{line}\n"),
            &[a.clone(), b.clone()]
        ));
        assert!(armed_in(&armed_line(&[a.clone()]), &[a.clone()]));
        assert!(!armed_in(&armed_line(&[a.clone()]), &[a.clone(), b]));
        assert!(!armed_in("NUCLEUS_HOST_SPEC: READY\n", &[a]));
    }

    fn material(ids: &[&str]) -> DecisionMaterial {
        DecisionMaterial {
            trust_roots: "[]".into(),
            tenant: "github~example~repo".into(),
            bundles: ids
                .iter()
                .map(|id| DecisionBundleFile {
                    id: (*id).to_string(),
                    json: "{}".into(),
                })
                .collect(),
        }
    }

    #[test]
    fn material_names_only_safe_files() {
        let id = "ab".repeat(32);
        assert_eq!(material(&[&id]).check(), Ok(()));
        assert_eq!(
            material(&["../../etc/passwd"]).check(),
            Err(MaterialError::BadId("../../etc/passwd".into()))
        );
        assert_eq!(
            material(&[&id, &id]).check(),
            Err(MaterialError::DuplicateId(id.clone()))
        );
        let mut empty = material(&[]);
        empty.tenant.clear();
        assert_eq!(empty.check(), Err(MaterialError::EmptyTenant));
        let mut big = material(&[&id]);
        big.bundles[0].json = "x".repeat(MAX_MATERIAL_BYTES + 1);
        assert_eq!(big.check(), Err(MaterialError::TooLarge));
        let env = material(&[]).guest_env();
        assert_eq!(env[0], (TRUST_ROOTS_ENV, GUEST_TRUST_ROOTS.to_string()));
        assert!(GUEST_BUNDLES.starts_with(GUEST_DIR));
    }
}
