//! Deterministic replay engine for verified writes (DPI spec sections 15, 17.7).
//!
//! This module implements **verification replay** — given a [`WitnessBundle`]
//! and an expected output hash, the replay engine checks that:
//!
//! 1. The witness chain is internally consistent (hash chain integrity).
//! 2. Every parser and transform referenced in the chain is registered in
//!    the [`ParserRegistry`] and declared as deterministic.
//! 3. The witness bundle's `final_output_hash` matches the expected output.
//!
//! This is *verification*, not *re-execution*: we validate the witness
//! evidence, not re-run the actual parser/transform code. Re-execution
//! replay (sandboxed deterministic re-computation) is a separate concern
//! that builds on top of this verification layer.
//!
//! ## Usage
//!
//! ```ignore
//! let input = ReplayInput {
//!     witness: bundle,
//!     expected_output_hash: expected,
//! };
//! let report = replay(&input, &registry);
//! assert!(matches!(report.result, ReplayResult::Match));
//! ```

use crate::parser_registry::ParserRegistry;
use crate::witness::{ChainVerifyError, WitnessBundle};
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════════════════
// ReplayInput — what the caller provides
// ═══════════════════════════════════════════════════════════════════════════

/// Input to the replay verification engine.
///
/// Contains the witness bundle to verify and the expected output hash
/// that the caller believes the derivation chain should produce.
#[derive(Debug, Clone)]
pub struct ReplayInput {
    /// The witness bundle recording the full derivation chain.
    pub witness: WitnessBundle,
    /// The expected SHA-256 hash of the final output.
    pub expected_output_hash: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayResult — outcome of replay verification
// ═══════════════════════════════════════════════════════════════════════════

/// Outcome of a deterministic replay verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayResult {
    /// Replay verification succeeded: the witness chain is valid, all
    /// parsers/transforms are registered and deterministic, and the
    /// final output hash matches the expected value.
    Match,

    /// The witness bundle's `final_output_hash` does not match the
    /// caller's `expected_output_hash`.
    Mismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// The witness bundle's internal hash chain is broken.
    ChainBroken { step_index: usize, detail: String },

    /// A parser referenced in the witness chain is not registered
    /// in the [`ParserRegistry`], or is registered but not deterministic.
    MissingParser { parser_id: String },

    /// A transform referenced in the witness chain is not registered
    /// in the [`ParserRegistry`], or is registered but not deterministic.
    MissingTransform { transform_id: String },

    /// A validation step in the witness bundle did not pass.
    ValidationFailed { validator_id: String },
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayReport — detailed output
// ═══════════════════════════════════════════════════════════════════════════

/// Detailed report from a replay verification run.
///
/// Contains the verification result plus metadata about what was checked,
/// useful for audit logging and debugging.
#[derive(Debug, Clone)]
pub struct ReplayReport {
    /// The verification result.
    pub result: ReplayResult,
    /// Number of chain steps (parsers + transforms) that were verified
    /// before the result was determined.
    pub steps_verified: usize,
    /// IDs of all parsers and transforms that were checked against the
    /// registry during verification.
    pub parsers_checked: Vec<String>,
    /// Wall-clock time elapsed during verification, in milliseconds.
    pub elapsed_ms: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// replay() — the core verification function
// ═══════════════════════════════════════════════════════════════════════════

/// Run deterministic replay verification on a witness bundle.
///
/// This function verifies:
/// 1. **Chain integrity**: The witness bundle's hash chain is continuous
///    (each step's output feeds the next step's input).
/// 2. **Registry coverage**: Every parser and transform in the chain is
///    registered in the `registry` and declared as deterministic.
/// 3. **Validation passing**: All validation results in the bundle passed.
/// 4. **Output match**: The bundle's `final_output_hash` equals the
///    caller's `expected_output_hash`.
///
/// Returns a [`ReplayReport`] with the result and audit metadata.
pub fn replay(input: &ReplayInput, registry: &ParserRegistry) -> ReplayReport {
    let start = Instant::now();
    let mut steps_verified: usize = 0;
    let mut parsers_checked: Vec<String> = Vec::new();

    // Step 1: Verify the witness chain integrity.
    if let Err(chain_err) = input.witness.verify_chain() {
        let (step_index, detail) = chain_error_to_step(&chain_err);
        return ReplayReport {
            result: ReplayResult::ChainBroken { step_index, detail },
            steps_verified,
            parsers_checked,
            elapsed_ms: start.elapsed().as_millis() as u64,
        };
    }

    // Step 2: Check all parsers are registered and deterministic.
    for step in &input.witness.parser_chain {
        parsers_checked.push(step.parser_id.clone());

        let Some(decl) = registry.get_parser(&step.parser_id) else {
            return ReplayReport {
                result: ReplayResult::MissingParser {
                    parser_id: step.parser_id.clone(),
                },
                steps_verified,
                parsers_checked,
                elapsed_ms: start.elapsed().as_millis() as u64,
            };
        };

        if !decl.is_deterministic {
            return ReplayReport {
                result: ReplayResult::MissingParser {
                    parser_id: step.parser_id.clone(),
                },
                steps_verified,
                parsers_checked,
                elapsed_ms: start.elapsed().as_millis() as u64,
            };
        }

        steps_verified += 1;
    }

    // Step 3: Check all transforms are registered and deterministic.
    for step in &input.witness.transform_chain {
        parsers_checked.push(step.transform_id.clone());

        let Some(decl) = registry.get_transform(&step.transform_id) else {
            return ReplayReport {
                result: ReplayResult::MissingTransform {
                    transform_id: step.transform_id.clone(),
                },
                steps_verified,
                parsers_checked,
                elapsed_ms: start.elapsed().as_millis() as u64,
            };
        };

        if !decl.is_deterministic {
            return ReplayReport {
                result: ReplayResult::MissingTransform {
                    transform_id: step.transform_id.clone(),
                },
                steps_verified,
                parsers_checked,
                elapsed_ms: start.elapsed().as_millis() as u64,
            };
        }

        steps_verified += 1;
    }

    // Step 4: Check all validations passed.
    for v in &input.witness.validation_results {
        if !v.passed {
            return ReplayReport {
                result: ReplayResult::ValidationFailed {
                    validator_id: v.validator_id.clone(),
                },
                steps_verified,
                parsers_checked,
                elapsed_ms: start.elapsed().as_millis() as u64,
            };
        }
    }

    // Step 5: Compare final output hash.
    if input.witness.final_output_hash != input.expected_output_hash {
        return ReplayReport {
            result: ReplayResult::Mismatch {
                expected: input.expected_output_hash,
                actual: input.witness.final_output_hash,
            },
            steps_verified,
            parsers_checked,
            elapsed_ms: start.elapsed().as_millis() as u64,
        };
    }

    // All checks passed.
    ReplayReport {
        result: ReplayResult::Match,
        steps_verified,
        parsers_checked,
        elapsed_ms: start.elapsed().as_millis() as u64,
    }
}

/// Map a [`ChainVerifyError`] to a `(step_index, detail)` pair for
/// [`ReplayResult::ChainBroken`].
fn chain_error_to_step(err: &ChainVerifyError) -> (usize, String) {
    match err {
        ChainVerifyError::EmptyInputBlobs => (0, err.to_string()),
        ChainVerifyError::UnlinkedParser { step_index, .. } => (*step_index, err.to_string()),
        ChainVerifyError::UnlinkedTransform { step_index, .. } => (*step_index, err.to_string()),
        ChainVerifyError::EmptyTransformInputs { step_index, .. } => (*step_index, err.to_string()),
        ChainVerifyError::FinalHashMismatch => (usize::MAX, err.to_string()),
        ChainVerifyError::AmbiguousPassthrough => (0, err.to_string()),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser_registry::{ParserDeclaration, TransformDeclaration};
    use crate::witness::{InputBlob, ParserStep, TransformStep, ValidationResult, WitnessBundle};
    use sha2::{Digest, Sha256};

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Build a valid witness bundle: input -> parser -> transform -> output.
    fn make_valid_bundle() -> WitnessBundle {
        let input_hash = sha256(b"raw api response");
        let parser_output = sha256(b"parsed json");
        let transform_output = sha256(b"normalized record");

        WitnessBundle {
            witness_id: "wb-replay-001".to_string(),
            input_blobs: vec![InputBlob {
                source_class: "api".to_string(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "fetcher-agent".to_string(),
                raw_content: None,
            }],
            parser_chain: vec![ParserStep {
                parser_id: "json_parser".to_string(),
                parser_version: "1.0.0".to_string(),
                parser_hash: sha256(b"json_parser_v1_binary"),
                input_hash,
                output_hash: parser_output,
            }],
            transform_chain: vec![TransformStep {
                transform_id: "normalizer".to_string(),
                version: "2.1.0".to_string(),
                input_hashes: vec![parser_output],
                output_hash: transform_output,
            }],
            validation_results: vec![ValidationResult {
                validator_id: "schema_check".to_string(),
                version: "1.0.0".to_string(),
                passed: true,
            }],
            final_output_hash: transform_output,
            signature: None,
            created_at: 2000,
        }
    }

    /// Build a registry that has the parsers/transforms used by make_valid_bundle().
    fn make_matching_registry() -> ParserRegistry {
        let mut reg = ParserRegistry::new();
        reg.register_parser(ParserDeclaration {
            parser_id: "json_parser".to_string(),
            version: "1.0.0".to_string(),
            build_hash: sha256(b"json_parser_v1_binary"),
            input_format: "json".to_string(),
            output_schema: "company_record".to_string(),
            is_deterministic: true,
            test_corpus_hash: None,
        })
        .unwrap();
        reg.register_transform(TransformDeclaration {
            transform_id: "normalizer".to_string(),
            version: "2.1.0".to_string(),
            build_hash: sha256(b"normalizer_v2_binary"),
            input_format: "company_record".to_string(),
            output_schema: "normalized_company".to_string(),
            is_deterministic: true,
            test_corpus_hash: None,
        })
        .unwrap();
        reg
    }

    // ── Valid replay matches ──────────────────────────────────────────────

    #[test]
    fn valid_replay_produces_match() {
        let bundle = make_valid_bundle();
        let expected_hash = bundle.final_output_hash;
        let input = ReplayInput {
            witness: bundle,
            expected_output_hash: expected_hash,
        };
        let registry = make_matching_registry();

        let report = replay(&input, &registry);

        assert_eq!(report.result, ReplayResult::Match);
        assert_eq!(report.steps_verified, 2); // 1 parser + 1 transform
        assert_eq!(report.parsers_checked, vec!["json_parser", "normalizer"]);
    }

    // ── Tampered output hash produces mismatch ───────────────────────────

    #[test]
    fn tampered_expected_hash_produces_mismatch() {
        let bundle = make_valid_bundle();
        let actual_hash = bundle.final_output_hash;
        let tampered_hash = [0xDE; 32];

        let input = ReplayInput {
            witness: bundle,
            expected_output_hash: tampered_hash,
        };
        let registry = make_matching_registry();

        let report = replay(&input, &registry);

        assert_eq!(
            report.result,
            ReplayResult::Mismatch {
                expected: tampered_hash,
                actual: actual_hash,
            }
        );
        // All steps were still verified before the mismatch was detected.
        assert_eq!(report.steps_verified, 2);
    }

    // ── Unregistered parser fails ────────────────────────────────────────

    #[test]
    fn unregistered_parser_fails() {
        let bundle = make_valid_bundle();
        let input = ReplayInput {
            expected_output_hash: bundle.final_output_hash,
            witness: bundle,
        };
        // Empty registry — no parsers or transforms registered.
        let registry = ParserRegistry::new();

        let report = replay(&input, &registry);

        assert_eq!(
            report.result,
            ReplayResult::MissingParser {
                parser_id: "json_parser".to_string(),
            }
        );
        assert_eq!(report.steps_verified, 0);
    }

    // ── Non-deterministic parser fails ───────────────────────────────────

    #[test]
    fn non_deterministic_parser_fails() {
        let bundle = make_valid_bundle();
        let input = ReplayInput {
            expected_output_hash: bundle.final_output_hash,
            witness: bundle,
        };

        let mut registry = ParserRegistry::new();
        registry
            .register_parser(ParserDeclaration {
                parser_id: "json_parser".to_string(),
                version: "1.0.0".to_string(),
                build_hash: sha256(b"json_parser_v1_binary"),
                input_format: "json".to_string(),
                output_schema: "company_record".to_string(),
                is_deterministic: false, // Non-deterministic!
                test_corpus_hash: None,
            })
            .unwrap();

        let report = replay(&input, &registry);

        assert_eq!(
            report.result,
            ReplayResult::MissingParser {
                parser_id: "json_parser".to_string(),
            }
        );
    }

    // ── Unregistered transform fails ─────────────────────────────────────

    #[test]
    fn unregistered_transform_fails() {
        let bundle = make_valid_bundle();
        let input = ReplayInput {
            expected_output_hash: bundle.final_output_hash,
            witness: bundle,
        };

        // Register only the parser, not the transform.
        let mut registry = ParserRegistry::new();
        registry
            .register_parser(ParserDeclaration {
                parser_id: "json_parser".to_string(),
                version: "1.0.0".to_string(),
                build_hash: sha256(b"json_parser_v1_binary"),
                input_format: "json".to_string(),
                output_schema: "company_record".to_string(),
                is_deterministic: true,
                test_corpus_hash: None,
            })
            .unwrap();

        let report = replay(&input, &registry);

        assert_eq!(
            report.result,
            ReplayResult::MissingTransform {
                transform_id: "normalizer".to_string(),
            }
        );
        assert_eq!(report.steps_verified, 1); // Parser verified, transform missing.
    }

    // ── Broken chain detected ────────────────────────────────────────────

    #[test]
    fn broken_chain_detected() {
        let mut bundle = make_valid_bundle();
        // Break the chain: transform references a hash that was never produced.
        bundle.transform_chain[0].input_hashes = vec![[0xBA; 32]];

        let input = ReplayInput {
            expected_output_hash: bundle.final_output_hash,
            witness: bundle,
        };
        let registry = make_matching_registry();

        let report = replay(&input, &registry);

        match &report.result {
            ReplayResult::ChainBroken { step_index, detail } => {
                assert_eq!(*step_index, 0);
                assert!(detail.contains("normalizer"));
            }
            other => panic!("expected ChainBroken, got: {other:?}"),
        }
        assert_eq!(report.steps_verified, 0); // Chain check happens first.
    }

    // ── Empty input blobs detected as chain break ────────────────────────

    #[test]
    fn empty_input_blobs_is_chain_broken() {
        let mut bundle = make_valid_bundle();
        bundle.input_blobs.clear();

        let input = ReplayInput {
            expected_output_hash: bundle.final_output_hash,
            witness: bundle,
        };
        let registry = make_matching_registry();

        let report = replay(&input, &registry);

        match &report.result {
            ReplayResult::ChainBroken { detail, .. } => {
                assert!(detail.contains("no input blobs"));
            }
            other => panic!("expected ChainBroken, got: {other:?}"),
        }
    }

    // ── Failed validation detected ───────────────────────────────────────

    #[test]
    fn failed_validation_detected() {
        let mut bundle = make_valid_bundle();
        bundle.validation_results[0].passed = false;

        let input = ReplayInput {
            expected_output_hash: bundle.final_output_hash,
            witness: bundle,
        };
        let registry = make_matching_registry();

        let report = replay(&input, &registry);

        assert_eq!(
            report.result,
            ReplayResult::ValidationFailed {
                validator_id: "schema_check".to_string(),
            }
        );
    }

    // ── Passthrough bundle (no parsers, no transforms) ───────────────────

    #[test]
    fn passthrough_bundle_matches() {
        let input_hash = sha256(b"direct data");
        let bundle = WitnessBundle {
            witness_id: "wb-passthrough".to_string(),
            input_blobs: vec![InputBlob {
                source_class: "file".to_string(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "agent".to_string(),
                raw_content: None,
            }],
            parser_chain: vec![],
            transform_chain: vec![],
            validation_results: vec![],
            final_output_hash: input_hash,
            signature: None,
            created_at: 1000,
        };

        let input = ReplayInput {
            witness: bundle,
            expected_output_hash: input_hash,
        };
        let registry = ParserRegistry::new();

        let report = replay(&input, &registry);

        assert_eq!(report.result, ReplayResult::Match);
        assert_eq!(report.steps_verified, 0);
        assert!(report.parsers_checked.is_empty());
    }

    // ── Report metadata is populated ─────────────────────────────────────

    #[test]
    fn report_tracks_elapsed_time() {
        let bundle = make_valid_bundle();
        let input = ReplayInput {
            expected_output_hash: bundle.final_output_hash,
            witness: bundle,
        };
        let registry = make_matching_registry();

        let report = replay(&input, &registry);

        // elapsed_ms should be non-negative (it's u64, so always true,
        // but this documents the intent).
        assert!(report.elapsed_ms < 1000, "verification should be fast");
    }

    // ── Non-deterministic transform fails ────────────────────────────────

    #[test]
    fn non_deterministic_transform_fails() {
        let bundle = make_valid_bundle();
        let input = ReplayInput {
            expected_output_hash: bundle.final_output_hash,
            witness: bundle,
        };

        let mut registry = ParserRegistry::new();
        registry
            .register_parser(ParserDeclaration {
                parser_id: "json_parser".to_string(),
                version: "1.0.0".to_string(),
                build_hash: sha256(b"json_parser_v1_binary"),
                input_format: "json".to_string(),
                output_schema: "company_record".to_string(),
                is_deterministic: true,
                test_corpus_hash: None,
            })
            .unwrap();
        registry
            .register_transform(TransformDeclaration {
                transform_id: "normalizer".to_string(),
                version: "2.1.0".to_string(),
                build_hash: sha256(b"normalizer_v2_binary"),
                input_format: "company_record".to_string(),
                output_schema: "normalized_company".to_string(),
                is_deterministic: false, // Non-deterministic!
                test_corpus_hash: None,
            })
            .unwrap();

        let report = replay(&input, &registry);

        assert_eq!(
            report.result,
            ReplayResult::MissingTransform {
                transform_id: "normalizer".to_string(),
            }
        );
        assert_eq!(report.steps_verified, 1); // Parser passed, transform failed.
    }
}
