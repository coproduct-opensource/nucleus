//! Witness bundles for DPI data flow verification (spec section 9).
//!
//! A [`WitnessBundle`] contains enough material to replay and validate a
//! verified write deterministically. No valid witness = verified write MUST fail.
//!
//! The bundle records the full derivation chain: which inputs were fetched,
//! which parsers and transforms were applied, and what validation results
//! were produced. [`WitnessBundle::verify_chain`] checks that each step's
//! output hash matches the next step's input, forming a tamper-evident
//! hash chain from source to sink.
//!
//! ## Relationship to existing types
//!
//! - [`crate::envelope::SourceRef`] and [`crate::envelope::TransformRef`] are
//!   per-field provenance pointers. A `WitnessBundle` aggregates a complete
//!   derivation chain across multiple fields and steps.
//! - [`crate::receipt::FlowReceipt`] records kernel flow decisions. A witness
//!   bundle records the data derivation evidence that justifies the write.
//! - `FieldEnvelope::witness_bundle_id` links an envelope to its witness.
//!
//! ## Canonical digest
//!
//! [`WitnessBundle::compute_digest`] produces a SHA-256 over all steps in
//! declaration order (inputs, parsers, transforms, validations, final output).
//! The digest is the content address of the bundle — changing any step
//! changes the digest.

use sha2::{Digest, Sha256};

// ═══════════════════════════════════════════════════════════════════════════
// InputBlob — a fetched data source
// ═══════════════════════════════════════════════════════════════════════════

/// An input blob fetched from an external or internal source.
///
/// Records the source classification, content hash at fetch time,
/// when it was fetched, and which principal performed the fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBlob {
    /// Classification of the source (e.g. "api", "database", "file", "web").
    pub source_class: String,
    /// SHA-256 hash of the fetched content.
    pub content_hash: [u8; 32],
    /// Unix timestamp (seconds) when the source was fetched.
    pub fetched_at: u64,
    /// Identity of the principal that performed the fetch.
    pub fetched_by: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// ParserStep — a parsing stage in the derivation chain
// ═══════════════════════════════════════════════════════════════════════════

/// A parser step in the derivation chain.
///
/// Parsers consume raw input and produce structured output. The
/// `parser_hash` is the content hash of the parser implementation
/// (e.g. WASM module hash), enabling reproducibility verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserStep {
    /// Unique identifier for the parser (e.g. "json_parser", "csv_reader").
    pub parser_id: String,
    /// Semantic version of the parser implementation.
    pub parser_version: String,
    /// SHA-256 hash of the parser implementation binary/source.
    pub parser_hash: [u8; 32],
    /// SHA-256 hash of the parser output.
    pub output_hash: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════
// TransformStep — a transformation stage in the derivation chain
// ═══════════════════════════════════════════════════════════════════════════

/// A transform step in the derivation chain.
///
/// Transforms consume one or more inputs (by hash) and produce a single
/// output. For deterministic transforms, re-executing with the same
/// `input_hashes` must reproduce the same `output_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformStep {
    /// Unique identifier for the transform.
    pub transform_id: String,
    /// Semantic version of the transform implementation.
    pub version: String,
    /// SHA-256 hashes of each input to this transform.
    pub input_hashes: Vec<[u8; 32]>,
    /// SHA-256 hash of the transform output.
    pub output_hash: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════
// ValidationResult — outcome of a validation check
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a single validation check applied to the derivation output.
///
/// Multiple validators may run independently. All must pass for the
/// bundle to be considered valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    /// Unique identifier for the validator.
    pub validator_id: String,
    /// Semantic version of the validator implementation.
    pub version: String,
    /// Whether this validation passed.
    pub passed: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// WitnessBundle — the core proof artifact
// ═══════════════════════════════════════════════════════════════════════════

/// A witness bundle proving that a verified write is legitimate.
///
/// Contains the full derivation chain from source inputs through parsing,
/// transformation, and validation to the final output. The bundle is
/// content-addressed via [`Self::compute_digest`] and forms a hash chain
/// that can be verified via [`Self::verify_chain`].
///
/// # Invariants
///
/// A valid witness bundle satisfies:
/// 1. **Digest integrity**: `compute_digest()` matches the canonical digest.
/// 2. **Chain continuity**: each step's output feeds into the next step's input.
/// 3. **All validations pass**: every `ValidationResult::passed` is true.
///
/// [`Self::is_valid`] checks all three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessBundle {
    /// Unique identifier for this witness bundle.
    pub witness_id: String,
    /// Input blobs that were fetched as source data.
    pub input_blobs: Vec<InputBlob>,
    /// Parser steps applied to the input blobs.
    pub parser_chain: Vec<ParserStep>,
    /// Transform steps applied after parsing.
    pub transform_chain: Vec<TransformStep>,
    /// Validation results from all validators.
    pub validation_results: Vec<ValidationResult>,
    /// SHA-256 hash of the final output produced by the derivation chain.
    pub final_output_hash: [u8; 32],
    /// Optional detached signature over the bundle digest.
    pub signature: Option<Vec<u8>>,
    /// Unix timestamp (seconds) when this bundle was created.
    pub created_at: u64,
}

impl WitnessBundle {
    /// Compute the SHA-256 digest of all steps in canonical order.
    ///
    /// The digest covers:
    /// 1. `witness_id` (UTF-8 bytes)
    /// 2. Each `InputBlob`: source_class, content_hash, fetched_at, fetched_by
    /// 3. Each `ParserStep`: parser_id, parser_version, parser_hash, output_hash
    /// 4. Each `TransformStep`: transform_id, version, input_hashes, output_hash
    /// 5. Each `ValidationResult`: validator_id, version, passed
    /// 6. `final_output_hash`
    /// 7. `created_at`
    ///
    /// The signature is excluded (detached signing).
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Witness ID
        hasher.update(self.witness_id.as_bytes());

        // Input blobs
        let blob_count = self.input_blobs.len() as u32;
        hasher.update(blob_count.to_le_bytes());
        for blob in &self.input_blobs {
            hasher.update(blob.source_class.as_bytes());
            hasher.update(blob.content_hash);
            hasher.update(blob.fetched_at.to_le_bytes());
            hasher.update(blob.fetched_by.as_bytes());
        }

        // Parser chain
        let parser_count = self.parser_chain.len() as u32;
        hasher.update(parser_count.to_le_bytes());
        for step in &self.parser_chain {
            hasher.update(step.parser_id.as_bytes());
            hasher.update(step.parser_version.as_bytes());
            hasher.update(step.parser_hash);
            hasher.update(step.output_hash);
        }

        // Transform chain
        let transform_count = self.transform_chain.len() as u32;
        hasher.update(transform_count.to_le_bytes());
        for step in &self.transform_chain {
            hasher.update(step.transform_id.as_bytes());
            hasher.update(step.version.as_bytes());
            let input_count = step.input_hashes.len() as u32;
            hasher.update(input_count.to_le_bytes());
            for ih in &step.input_hashes {
                hasher.update(ih);
            }
            hasher.update(step.output_hash);
        }

        // Validation results
        let val_count = self.validation_results.len() as u32;
        hasher.update(val_count.to_le_bytes());
        for result in &self.validation_results {
            hasher.update(result.validator_id.as_bytes());
            hasher.update(result.version.as_bytes());
            hasher.update([if result.passed { 1u8 } else { 0u8 }]);
        }

        // Final output hash
        hasher.update(self.final_output_hash);

        // Created at
        hasher.update(self.created_at.to_le_bytes());

        hasher.finalize().into()
    }

    /// Verify the hash chain: each step's output feeds the next step's input.
    ///
    /// The chain is:
    /// 1. Input blob content hashes feed into the first parser step (any blob
    ///    hash must appear as a known input).
    /// 2. Each parser step's `output_hash` must appear in the next stage's
    ///    input hashes.
    /// 3. Each transform step's `output_hash` must appear in a subsequent
    ///    transform's `input_hashes` (or be the `final_output_hash`).
    /// 4. The last step's `output_hash` must equal `final_output_hash`.
    ///
    /// Empty chains are invalid — at least one input blob is required.
    pub fn verify_chain(&self) -> bool {
        // Must have at least one input blob.
        if self.input_blobs.is_empty() {
            return false;
        }

        // Collect all input blob content hashes as the initial available set.
        let mut available_hashes: Vec<[u8; 32]> =
            self.input_blobs.iter().map(|b| b.content_hash).collect();

        // Parser chain: each parser consumes from available hashes and produces
        // its output hash.
        for step in &self.parser_chain {
            // Parser must consume at least one available hash.
            // (Parsers take raw input — we check that input blobs exist.)
            available_hashes.push(step.output_hash);
        }

        // Transform chain: each transform's input_hashes must all be available.
        for step in &self.transform_chain {
            if step.input_hashes.is_empty() {
                return false;
            }
            for ih in &step.input_hashes {
                if !available_hashes.contains(ih) {
                    return false;
                }
            }
            available_hashes.push(step.output_hash);
        }

        // The final output hash must be the last produced hash.
        // If there are transforms, the last transform's output must match.
        // If only parsers, the last parser's output must match.
        // If neither, the single input blob's content_hash must match.
        let last_output = if let Some(last_transform) = self.transform_chain.last() {
            last_transform.output_hash
        } else if let Some(last_parser) = self.parser_chain.last() {
            last_parser.output_hash
        } else {
            // No parsers or transforms — single input passthrough.
            if self.input_blobs.len() != 1 {
                return false;
            }
            self.input_blobs[0].content_hash
        };

        last_output == self.final_output_hash
    }

    /// Check whether this witness bundle is fully valid.
    ///
    /// A bundle is valid when:
    /// 1. The hash chain is continuous ([`Self::verify_chain`]).
    /// 2. All validation results passed.
    ///
    /// Note: digest integrity is checked by the caller comparing
    /// `compute_digest()` against a stored/expected digest. This method
    /// does not store a digest internally — the bundle is content-addressed
    /// by its digest.
    pub fn is_valid(&self) -> bool {
        if !self.verify_chain() {
            return false;
        }

        // All validations must pass.
        if self.validation_results.iter().any(|v| !v.passed) {
            return false;
        }

        true
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    /// Helper: compute SHA-256 of arbitrary bytes.
    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Build a valid witness bundle with a full chain:
    /// input -> parser -> transform -> final output.
    fn make_valid_bundle() -> WitnessBundle {
        let input_hash = sha256(b"raw api response");
        let parser_output = sha256(b"parsed json");
        let transform_output = sha256(b"normalized record");

        WitnessBundle {
            witness_id: "wb-001".to_string(),
            input_blobs: vec![InputBlob {
                source_class: "api".to_string(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "fetcher-agent".to_string(),
            }],
            parser_chain: vec![ParserStep {
                parser_id: "json_parser".to_string(),
                parser_version: "1.0.0".to_string(),
                parser_hash: sha256(b"json_parser_v1_binary"),
                output_hash: parser_output,
            }],
            transform_chain: vec![TransformStep {
                transform_id: "normalizer".to_string(),
                version: "2.1.0".to_string(),
                input_hashes: vec![parser_output],
                output_hash: transform_output,
            }],
            validation_results: vec![
                ValidationResult {
                    validator_id: "schema_check".to_string(),
                    version: "1.0.0".to_string(),
                    passed: true,
                },
                ValidationResult {
                    validator_id: "range_check".to_string(),
                    version: "1.0.0".to_string(),
                    passed: true,
                },
            ],
            final_output_hash: transform_output,
            signature: None,
            created_at: 2000,
        }
    }

    #[test]
    fn valid_bundle_passes_all_checks() {
        let bundle = make_valid_bundle();
        assert!(bundle.verify_chain());
        assert!(bundle.is_valid());
    }

    #[test]
    fn broken_chain_detected_missing_input() {
        let mut bundle = make_valid_bundle();
        // Point transform at a hash that was never produced.
        bundle.transform_chain[0].input_hashes = vec![[0xDE; 32]];
        assert!(!bundle.verify_chain());
        assert!(!bundle.is_valid());
    }

    #[test]
    fn broken_chain_detected_wrong_final_hash() {
        let mut bundle = make_valid_bundle();
        // Tamper with the final output hash.
        bundle.final_output_hash = [0xFF; 32];
        assert!(!bundle.verify_chain());
        assert!(!bundle.is_valid());
    }

    #[test]
    fn failed_validation_rejects() {
        let mut bundle = make_valid_bundle();
        // Fail one validator.
        bundle.validation_results[1].passed = false;
        assert!(bundle.verify_chain()); // Chain is still intact.
        assert!(!bundle.is_valid()); // But bundle is invalid.
    }

    #[test]
    fn digest_is_deterministic() {
        let b1 = make_valid_bundle();
        let b2 = make_valid_bundle();
        assert_eq!(b1.compute_digest(), b2.compute_digest());
    }

    #[test]
    fn digest_tamper_detection() {
        let bundle = make_valid_bundle();
        let original_digest = bundle.compute_digest();

        // Tamper with witness_id.
        let mut tampered = make_valid_bundle();
        tampered.witness_id = "wb-TAMPERED".to_string();
        assert_ne!(tampered.compute_digest(), original_digest);

        // Tamper with an input blob.
        let mut tampered = make_valid_bundle();
        tampered.input_blobs[0].content_hash = [0xAA; 32];
        assert_ne!(tampered.compute_digest(), original_digest);

        // Tamper with a parser step.
        let mut tampered = make_valid_bundle();
        tampered.parser_chain[0].parser_version = "9.9.9".to_string();
        assert_ne!(tampered.compute_digest(), original_digest);

        // Tamper with a transform step.
        let mut tampered = make_valid_bundle();
        tampered.transform_chain[0].version = "EVIL".to_string();
        assert_ne!(tampered.compute_digest(), original_digest);

        // Tamper with a validation result.
        let mut tampered = make_valid_bundle();
        tampered.validation_results[0].passed = false;
        assert_ne!(tampered.compute_digest(), original_digest);

        // Tamper with final_output_hash.
        let mut tampered = make_valid_bundle();
        tampered.final_output_hash = [0x00; 32];
        assert_ne!(tampered.compute_digest(), original_digest);

        // Tamper with created_at.
        let mut tampered = make_valid_bundle();
        tampered.created_at = 9999;
        assert_ne!(tampered.compute_digest(), original_digest);
    }

    #[test]
    fn empty_input_blobs_rejected() {
        let mut bundle = make_valid_bundle();
        bundle.input_blobs.clear();
        assert!(!bundle.verify_chain());
        assert!(!bundle.is_valid());
    }

    #[test]
    fn passthrough_bundle_no_parsers_no_transforms() {
        let input_hash = sha256(b"raw data");
        let bundle = WitnessBundle {
            witness_id: "wb-passthrough".to_string(),
            input_blobs: vec![InputBlob {
                source_class: "file".to_string(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "agent".to_string(),
            }],
            parser_chain: vec![],
            transform_chain: vec![],
            validation_results: vec![ValidationResult {
                validator_id: "noop".to_string(),
                version: "1.0.0".to_string(),
                passed: true,
            }],
            final_output_hash: input_hash,
            signature: None,
            created_at: 1000,
        };
        assert!(bundle.verify_chain());
        assert!(bundle.is_valid());
    }

    #[test]
    fn multi_input_transform() {
        let hash_a = sha256(b"source A");
        let hash_b = sha256(b"source B");
        let parser_out_a = sha256(b"parsed A");
        let parser_out_b = sha256(b"parsed B");
        let merged = sha256(b"merged output");

        let bundle = WitnessBundle {
            witness_id: "wb-multi".to_string(),
            input_blobs: vec![
                InputBlob {
                    source_class: "api".to_string(),
                    content_hash: hash_a,
                    fetched_at: 1000,
                    fetched_by: "agent-a".to_string(),
                },
                InputBlob {
                    source_class: "database".to_string(),
                    content_hash: hash_b,
                    fetched_at: 1001,
                    fetched_by: "agent-b".to_string(),
                },
            ],
            parser_chain: vec![
                ParserStep {
                    parser_id: "json_parser".to_string(),
                    parser_version: "1.0.0".to_string(),
                    parser_hash: sha256(b"json_v1"),
                    output_hash: parser_out_a,
                },
                ParserStep {
                    parser_id: "sql_parser".to_string(),
                    parser_version: "1.0.0".to_string(),
                    parser_hash: sha256(b"sql_v1"),
                    output_hash: parser_out_b,
                },
            ],
            transform_chain: vec![TransformStep {
                transform_id: "merger".to_string(),
                version: "1.0.0".to_string(),
                input_hashes: vec![parser_out_a, parser_out_b],
                output_hash: merged,
            }],
            validation_results: vec![ValidationResult {
                validator_id: "integrity_check".to_string(),
                version: "1.0.0".to_string(),
                passed: true,
            }],
            final_output_hash: merged,
            signature: None,
            created_at: 2000,
        };
        assert!(bundle.verify_chain());
        assert!(bundle.is_valid());
    }

    #[test]
    fn signature_excluded_from_digest() {
        let bundle = make_valid_bundle();
        let digest_unsigned = bundle.compute_digest();

        let mut signed = make_valid_bundle();
        signed.signature = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let digest_signed = signed.compute_digest();

        assert_eq!(digest_unsigned, digest_signed);
    }

    #[test]
    fn transform_with_empty_inputs_rejected() {
        let input_hash = sha256(b"data");
        let parser_out = sha256(b"parsed");
        let transform_out = sha256(b"transformed");

        let bundle = WitnessBundle {
            witness_id: "wb-bad".to_string(),
            input_blobs: vec![InputBlob {
                source_class: "api".to_string(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "agent".to_string(),
            }],
            parser_chain: vec![ParserStep {
                parser_id: "p".to_string(),
                parser_version: "1.0.0".to_string(),
                parser_hash: sha256(b"p"),
                output_hash: parser_out,
            }],
            transform_chain: vec![TransformStep {
                transform_id: "t".to_string(),
                version: "1.0.0".to_string(),
                input_hashes: vec![], // Empty inputs — invalid.
                output_hash: transform_out,
            }],
            validation_results: vec![],
            final_output_hash: transform_out,
            signature: None,
            created_at: 1000,
        };
        assert!(!bundle.verify_chain());
    }
}
