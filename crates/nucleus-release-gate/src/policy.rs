//! The release policy: who holds each role, which tensors a patch may write,
//! and what an evaluation must show. It is the deployer's, and the gate is
//! configured with it; no receipt can supply or replace it.

use std::collections::BTreeSet;

use nucleus_weight_patch::DeclaredWrites;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::body::{Decoding, SuiteId};
use crate::eval::Thresholds;
use crate::keys::{PolicyDigest, RoleKey};

/// The one schema this crate reads and writes.
pub const POLICY_SCHEMA: &str = "nucleus.weight_patch.policy.v1";

const POLICY_DOMAIN: &[u8] = b"nucleus/weight-patch/policy/v1\0";

/// Why a policy was refused.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The schema is not [`POLICY_SCHEMA`].
    #[error("unknown policy schema {got:?}; this reader knows {:?}", POLICY_SCHEMA)]
    UnknownSchema {
        /// The schema the policy declares.
        got: String,
    },
    /// A role has no key. A role nobody holds is not a role anybody may skip.
    #[error("the {role} role has no key")]
    EmptyRole {
        /// The role.
        role: &'static str,
    },
    /// A role lists one key twice.
    #[error("the {role} role lists a key twice")]
    DuplicateKey {
        /// The role.
        role: &'static str,
    },
    /// One key holds two roles.
    #[error("key {key} holds both the {first} and the {second} role")]
    SharedKey {
        /// The key.
        key: RoleKey,
        /// One role it holds.
        first: &'static str,
        /// The other.
        second: &'static str,
    },
    /// The policy names no unrelated task. A patch that is only measured on
    /// what it was meant to improve has not been checked for what it broke.
    #[error("the policy names no unrelated task")]
    NoUnrelatedTask,
    /// The policy could not be put in canonical form.
    #[error("canonical form: {0}")]
    Canonical(#[from] serde_json::Error),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    schema: String,
    deployers: Vec<RoleKey>,
    runners: Vec<RoleKey>,
    evaluators: Vec<RoleKey>,
    permitted: DeclaredWrites,
    suite: SuiteId,
    decoding: Decoding,
    thresholds: Thresholds,
}

/// A validated release policy and its digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawPolicy", into = "RawPolicy")]
pub struct ReleasePolicy {
    deployers: BTreeSet<RoleKey>,
    runners: BTreeSet<RoleKey>,
    evaluators: BTreeSet<RoleKey>,
    permitted: DeclaredWrites,
    suite: SuiteId,
    decoding: Decoding,
    thresholds: Thresholds,
    digest: PolicyDigest,
}

/// What a policy is made from.
#[derive(Clone, Debug)]
pub struct PolicyParts {
    /// Keys that may grant authority to propose, approve, and order rollback.
    pub deployers: Vec<RoleKey>,
    /// Keys that may sign apply receipts.
    pub runners: Vec<RoleKey>,
    /// Keys that may sign evaluation receipts.
    pub evaluators: Vec<RoleKey>,
    /// The tensors a patch may write, by exact name. Never empty.
    pub permitted: DeclaredWrites,
    /// The suite an evaluation must have used.
    pub suite: SuiteId,
    /// The decoding settings an evaluation must have used.
    pub decoding: Decoding,
    /// What the evaluation must show.
    pub thresholds: Thresholds,
}

fn role(name: &'static str, keys: Vec<RoleKey>) -> Result<BTreeSet<RoleKey>, PolicyError> {
    let mut set = BTreeSet::new();
    for key in keys {
        if !set.insert(key) {
            return Err(PolicyError::DuplicateKey { role: name });
        }
    }
    if set.is_empty() {
        return Err(PolicyError::EmptyRole { role: name });
    }
    Ok(set)
}

impl ReleasePolicy {
    /// A policy of `parts`.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] if a role is empty or repeats a key, one key holds two
    /// roles, or no unrelated task is named.
    pub fn new(parts: PolicyParts) -> Result<Self, PolicyError> {
        let PolicyParts {
            deployers,
            runners,
            evaluators,
            permitted,
            suite,
            decoding,
            thresholds,
        } = parts;
        let deployers = role("deployer", deployers)?;
        let runners = role("runner", runners)?;
        let evaluators = role("evaluator", evaluators)?;
        for (first, a, second, b) in [
            ("deployer", &deployers, "runner", &runners),
            ("deployer", &deployers, "evaluator", &evaluators),
            ("runner", &runners, "evaluator", &evaluators),
        ] {
            if let Some(key) = a.intersection(b).next() {
                return Err(PolicyError::SharedKey {
                    key: *key,
                    first,
                    second,
                });
            }
        }
        if thresholds.unrelated.is_empty() {
            return Err(PolicyError::NoUnrelatedTask);
        }
        // Sets serialize in key order and the struct holds no map, so the
        // JSON has one byte sequence.
        let canonical = serde_json::to_vec(&RawPolicy {
            schema: POLICY_SCHEMA.to_owned(),
            deployers: deployers.iter().copied().collect(),
            runners: runners.iter().copied().collect(),
            evaluators: evaluators.iter().copied().collect(),
            permitted: permitted.clone(),
            suite: suite.clone(),
            decoding: decoding.clone(),
            thresholds: thresholds.clone(),
        })?;
        let mut h = Sha256::new();
        h.update(POLICY_DOMAIN);
        h.update(&canonical);
        Ok(Self {
            deployers,
            runners,
            evaluators,
            permitted,
            suite,
            decoding,
            thresholds,
            digest: PolicyDigest::from_bytes(h.finalize().into()),
        })
    }

    /// The digest grants, approvals and orders bind.
    #[must_use]
    pub const fn digest(&self) -> PolicyDigest {
        self.digest
    }

    /// Whether `key` is a deployer.
    #[must_use]
    pub fn is_deployer(&self, key: RoleKey) -> bool {
        self.deployers.contains(&key)
    }

    /// Whether `key` is a runner.
    #[must_use]
    pub fn is_runner(&self, key: RoleKey) -> bool {
        self.runners.contains(&key)
    }

    /// Whether `key` is an evaluator.
    #[must_use]
    pub fn is_evaluator(&self, key: RoleKey) -> bool {
        self.evaluators.contains(&key)
    }

    /// Whether `key` holds any role the policy assigns.
    #[must_use]
    pub fn holds_a_role(&self, key: RoleKey) -> bool {
        self.is_deployer(key) || self.is_runner(key) || self.is_evaluator(key)
    }

    /// The tensors a patch may write.
    #[must_use]
    pub const fn permitted(&self) -> &DeclaredWrites {
        &self.permitted
    }

    /// The suite an evaluation must have used.
    #[must_use]
    pub const fn suite(&self) -> &SuiteId {
        &self.suite
    }

    /// The decoding settings an evaluation must have used.
    #[must_use]
    pub const fn decoding(&self) -> &Decoding {
        &self.decoding
    }

    /// What an evaluation must show.
    #[must_use]
    pub const fn thresholds(&self) -> &Thresholds {
        &self.thresholds
    }
}

impl TryFrom<RawPolicy> for ReleasePolicy {
    type Error = PolicyError;

    fn try_from(raw: RawPolicy) -> Result<Self, Self::Error> {
        let RawPolicy {
            schema,
            deployers,
            runners,
            evaluators,
            permitted,
            suite,
            decoding,
            thresholds,
        } = raw;
        if schema != POLICY_SCHEMA {
            return Err(PolicyError::UnknownSchema { got: schema });
        }
        Self::new(PolicyParts {
            deployers,
            runners,
            evaluators,
            permitted,
            suite,
            decoding,
            thresholds,
        })
    }
}

impl From<ReleasePolicy> for RawPolicy {
    fn from(policy: ReleasePolicy) -> Self {
        let ReleasePolicy {
            deployers,
            runners,
            evaluators,
            permitted,
            suite,
            decoding,
            thresholds,
            digest: _,
        } = policy;
        Self {
            schema: POLICY_SCHEMA.to_owned(),
            deployers: deployers.into_iter().collect(),
            runners: runners.into_iter().collect(),
            evaluators: evaluators.into_iter().collect(),
            permitted,
            suite,
            decoding,
            thresholds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{World, key};

    #[test]
    fn a_policy_round_trips_and_keeps_its_digest() {
        let policy = World::new().policy;
        let json = serde_json::to_string(&policy).unwrap();
        let back: ReleasePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, policy);
        assert_eq!(back.digest(), policy.digest());
    }

    #[test]
    fn the_digest_binds_the_permitted_tensors_and_the_roles() {
        let world = World::new();
        let mut narrower = world.parts();
        narrower.permitted = DeclaredWrites::new(["layer.0.bias"]).unwrap();
        let mut other_runner = world.parts();
        other_runner.runners = vec![RoleKey::of(&key(99))];
        let base = world.policy.digest();
        assert_ne!(base, ReleasePolicy::new(narrower).unwrap().digest());
        assert_ne!(base, ReleasePolicy::new(other_runner).unwrap().digest());
    }

    #[test]
    fn a_role_nobody_holds_is_refused() {
        let mut parts = World::new().parts();
        parts.evaluators = Vec::new();
        assert!(matches!(
            ReleasePolicy::new(parts),
            Err(PolicyError::EmptyRole { role: "evaluator" })
        ));
    }

    #[test]
    fn one_key_in_two_roles_is_refused() {
        let world = World::new();
        let mut parts = world.parts();
        parts.evaluators = parts.runners.clone();
        assert!(matches!(
            ReleasePolicy::new(parts),
            Err(PolicyError::SharedKey {
                first: "runner",
                second: "evaluator",
                ..
            })
        ));
    }

    #[test]
    fn a_policy_with_no_unrelated_task_is_refused() {
        let mut parts = World::new().parts();
        parts.thresholds.unrelated = Vec::new();
        assert!(matches!(
            ReleasePolicy::new(parts),
            Err(PolicyError::NoUnrelatedTask)
        ));
    }
}
