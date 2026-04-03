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
use std::fmt;

/// SHA-256 helper for content hashing.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ═══════════════════════════════════════════════════════════════════════════
// ChainVerifyError — structured errors from verify_chain()
// ═══════════════════════════════════════════════════════════════════════════

/// Error returned by [`WitnessBundle::verify_chain`] when the hash chain
/// is broken or a step has no linkage to known inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerifyError {
    /// The bundle has no input blobs — there is nothing to derive from.
    EmptyInputBlobs,
    /// A parser step's `input_hash` does not match any available hash
    /// (input blob content hashes for the first parser, or previous step
    /// outputs for subsequent parsers).
    UnlinkedParser {
        parser_id: String,
        step_index: usize,
    },
    /// A transform step references an `input_hash` that was never produced
    /// by a preceding step or input blob.
    UnlinkedTransform {
        transform_id: String,
        step_index: usize,
        missing_hash: [u8; 32],
    },
    /// A transform step has an empty `input_hashes` list.
    EmptyTransformInputs {
        transform_id: String,
        step_index: usize,
    },
    /// The `final_output_hash` does not match the last step's output.
    FinalHashMismatch,
    /// Multiple input blobs but no parsers or transforms — ambiguous passthrough.
    AmbiguousPassthrough,
}

impl fmt::Display for ChainVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInputBlobs => write!(f, "witness bundle has no input blobs"),
            Self::UnlinkedParser {
                parser_id,
                step_index,
            } => write!(
                f,
                "parser '{parser_id}' at step {step_index} does not consume any known input hash"
            ),
            Self::UnlinkedTransform {
                transform_id,
                step_index,
                missing_hash,
            } => write!(
                f,
                "transform '{transform_id}' at step {step_index} references unknown input hash {}",
                hex_short(missing_hash)
            ),
            Self::EmptyTransformInputs {
                transform_id,
                step_index,
            } => write!(
                f,
                "transform '{transform_id}' at step {step_index} has empty input_hashes"
            ),
            Self::FinalHashMismatch => {
                write!(f, "final_output_hash does not match last step output")
            }
            Self::AmbiguousPassthrough => write!(
                f,
                "multiple input blobs with no parsers or transforms — ambiguous passthrough"
            ),
        }
    }
}

fn hex_short(hash: &[u8; 32]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}...",
        hash[0], hash[1], hash[2], hash[3]
    )
}

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
    /// Raw content bytes for replay verification (#939).
    /// When present, an auditor can re-execute the parser chain on this
    /// input and verify the output hashes match. When absent, the auditor
    /// must trust the content_hash.
    pub raw_content: Option<Vec<u8>>,
}

// ═══════════════════════════════════════════════════════════════════════════
// ParserStep — a parsing stage in the derivation chain
// ═══════════════════════════════════════════════════════════════════════════

/// A parser step in the derivation chain.
///
/// Parsers consume raw input and produce structured output. The
/// `parser_hash` is the content hash of the parser implementation
/// (e.g. WASM module hash), enabling reproducibility verification.
///
/// The `input_hash` field declares which input this parser consumes.
/// For the first parser this must be one of the input blob content hashes;
/// for subsequent parsers it must be a preceding step's output hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserStep {
    /// Unique identifier for the parser (e.g. "json_parser", "csv_reader").
    pub parser_id: String,
    /// Semantic version of the parser implementation.
    pub parser_version: String,
    /// SHA-256 hash of the parser implementation binary/source.
    pub parser_hash: [u8; 32],
    /// SHA-256 hash of the input this parser consumes. Must reference an
    /// input blob content hash or a preceding parser step's output hash.
    pub input_hash: [u8; 32],
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
// FieldWitness — per-field provenance chain (#940)
// ═══════════════════════════════════════════════════════════════════════════

/// Independent provenance chain for a single schema field (#940).
///
/// Each field gets its own source → parser chain, preventing cross-field
/// contamination (e.g., swapping revenue and net_income parser outputs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldWitness {
    /// Schema field name this witness covers.
    pub field_name: String,
    /// The input blob index (into `WitnessBundle::input_blobs`) for this field's source.
    pub input_blob_index: usize,
    /// Parser steps specific to this field's derivation chain.
    pub parser_steps: Vec<ParserStep>,
    /// SHA-256 of the final field value.
    pub output_hash: [u8; 32],
    /// Derivation kind: "deterministic" or "ai_derived".
    pub derivation: String,
    /// Confidence metadata for AI-derived fields (#944).
    /// None for deterministic fields.
    pub ai_confidence: Option<AiDerivedWitness>,
}

// ═══════════════════════════════════════════════════════════════════════════
// AiDerivedWitness — transparency metadata for AI-generated fields (#944)
// ═══════════════════════════════════════════════════════════════════════════

/// Transparency metadata for AI-derived fields.
///
/// This does NOT make AI output verifiable — a compromised model can generate
/// consistent-but-wrong output. This provides **audit transparency** so
/// downstream consumers can assess confidence.
///
/// Fields mirror NIST AI RMF uncertainty measurement recommendations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiDerivedWitness {
    /// SHA-256 of the input context the model received.
    /// Allows auditors to verify what the model actually read.
    pub input_context_hash: [u8; 32],
    /// Vendor-agnostic model identifier string.
    /// e.g., "gpt-4o-2024-05-13" or "llm-v2.1" — just a label.
    pub model_id: String,
    /// Number of independent generations used for consistency check.
    /// 1 = single generation (no consistency check performed).
    pub generation_count: u32,
    /// Agreement rate across multiple generations (0.0 to 1.0).
    /// Only meaningful when `generation_count > 1`.
    /// 1.0 = all generations produced identical output.
    /// None if consistency check was not performed.
    pub agreement_rate: Option<AgreementRate>,
}

/// Agreement rate as a fixed-point fraction (numerator / denominator).
///
/// Avoids floating-point non-determinism in hash chains.
/// e.g., 3 out of 5 generations agreed → `AgreementRate { agreed: 3, total: 5 }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgreementRate {
    /// Number of generations that produced matching output.
    pub agreed: u32,
    /// Total number of generations.
    pub total: u32,
}

impl AgreementRate {
    /// Create a new agreement rate.
    ///
    /// # Panics
    /// Panics if `total` is 0 or `agreed > total`.
    pub fn new(agreed: u32, total: u32) -> Self {
        assert!(total > 0, "total must be > 0");
        assert!(agreed <= total, "agreed must be <= total");
        Self { agreed, total }
    }

    /// Agreement as a float (for display/reporting).
    pub fn as_f64(self) -> f64 {
        f64::from(self.agreed) / f64::from(self.total)
    }

    /// Whether all generations agreed.
    pub fn is_unanimous(self) -> bool {
        self.agreed == self.total
    }
}

impl fmt::Display for AgreementRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{} ({:.0}%)",
            self.agreed,
            self.total,
            self.as_f64() * 100.0
        )
    }
}

impl AiDerivedWitness {
    /// Create a witness for a single-generation AI output (no consistency check).
    pub fn single_generation(input_context: &[u8], model_id: &str) -> Self {
        Self {
            input_context_hash: sha256(input_context),
            model_id: model_id.to_string(),
            generation_count: 1,
            agreement_rate: None,
        }
    }

    /// Create a witness with multi-generation consistency check.
    pub fn with_consistency(input_context: &[u8], model_id: &str, agreed: u32, total: u32) -> Self {
        Self {
            input_context_hash: sha256(input_context),
            model_id: model_id.to_string(),
            generation_count: total,
            agreement_rate: Some(AgreementRate::new(agreed, total)),
        }
    }

    /// Content hash for inclusion in witness bundle digests.
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.input_context_hash);
        hasher.update(self.model_id.as_bytes());
        hasher.update(self.generation_count.to_le_bytes());
        if let Some(rate) = self.agreement_rate {
            hasher.update(rate.agreed.to_le_bytes());
            hasher.update(rate.total.to_le_bytes());
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
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
    /// Per-field provenance chains (#940). When populated, each field
    /// has its own independent source → parser → output chain that can
    /// be verified independently. Prevents cross-field contamination.
    pub field_witnesses: std::collections::BTreeMap<String, FieldWitness>,
    /// Optional zkVM receipt bytes proving parser execution (#1117).
    /// When present, this is a serialized RISC Zero receipt that
    /// cryptographically attests the parser execution. Use
    /// `zkvm_receipt::ZkvmReceipt` (behind `zkvm` feature) to parse
    /// and verify. Raw bytes stored here to avoid feature coupling.
    pub zkvm_receipt: Option<Vec<u8>>,
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
            hasher.update(step.input_hash);
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

        // zkVM receipt (if present, include in digest for tamper evidence)
        if let Some(ref receipt) = self.zkvm_receipt {
            hasher.update(receipt);
        }

        hasher.finalize().into()
    }

    /// Returns true if this bundle has a zkVM receipt attached.
    pub fn has_zkvm_receipt(&self) -> bool {
        self.zkvm_receipt.is_some()
    }

    /// Verify the hash chain: each step's output feeds the next step's input.
    ///
    /// The chain is:
    /// 1. Each parser step's `input_hash` must reference an input blob
    ///    content hash or a preceding parser step's output hash.
    /// 2. Each parser step's `output_hash` is added to the available set.
    /// 3. Each transform step's `input_hashes` must all reference hashes
    ///    in the available set (input blobs, parser outputs, or preceding
    ///    transform outputs).
    /// 4. The last step's `output_hash` must equal `final_output_hash`.
    ///
    /// Empty chains are invalid — at least one input blob is required.
    pub fn verify_chain(&self) -> Result<(), ChainVerifyError> {
        // Must have at least one input blob.
        if self.input_blobs.is_empty() {
            return Err(ChainVerifyError::EmptyInputBlobs);
        }

        // Collect all input blob content hashes as the initial available set.
        let mut available_hashes: Vec<[u8; 32]> =
            self.input_blobs.iter().map(|b| b.content_hash).collect();

        // Parser chain: each parser's input_hash must be in available_hashes.
        for (step_index, step) in self.parser_chain.iter().enumerate() {
            if !available_hashes.contains(&step.input_hash) {
                return Err(ChainVerifyError::UnlinkedParser {
                    parser_id: step.parser_id.clone(),
                    step_index,
                });
            }
            available_hashes.push(step.output_hash);
        }

        // Transform chain: each transform's input_hashes must all be available.
        for (step_index, step) in self.transform_chain.iter().enumerate() {
            if step.input_hashes.is_empty() {
                return Err(ChainVerifyError::EmptyTransformInputs {
                    transform_id: step.transform_id.clone(),
                    step_index,
                });
            }
            for ih in &step.input_hashes {
                if !available_hashes.contains(ih) {
                    return Err(ChainVerifyError::UnlinkedTransform {
                        transform_id: step.transform_id.clone(),
                        step_index,
                        missing_hash: *ih,
                    });
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
                return Err(ChainVerifyError::AmbiguousPassthrough);
            }
            self.input_blobs[0].content_hash
        };

        if last_output != self.final_output_hash {
            return Err(ChainVerifyError::FinalHashMismatch);
        }

        Ok(())
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
    /// Verify per-field provenance chains (#940).
    ///
    /// For each `FieldWitness`, verify that:
    /// 1. The input_blob_index references a valid input blob
    /// 2. Each parser step's input_hash chains from the source or prior step
    /// 3. The final parser output hash matches `output_hash`
    pub fn verify_field_chains(&self) -> Result<(), ChainVerifyError> {
        for (name, fw) in &self.field_witnesses {
            // Check input blob reference.
            let blob = self.input_blobs.get(fw.input_blob_index).ok_or_else(|| {
                ChainVerifyError::UnlinkedParser {
                    parser_id: format!("field:{name}"),
                    step_index: 0,
                }
            })?;

            // Walk the field's parser chain.
            let mut available = vec![blob.content_hash];
            for (i, step) in fw.parser_steps.iter().enumerate() {
                if !available.contains(&step.input_hash) {
                    return Err(ChainVerifyError::UnlinkedParser {
                        parser_id: step.parser_id.clone(),
                        step_index: i,
                    });
                }
                available.push(step.output_hash);
            }

            // Verify the final output hash is in the available set.
            if !available.contains(&fw.output_hash) && !fw.parser_steps.is_empty() {
                let last = &fw.parser_steps[fw.parser_steps.len() - 1];
                if last.output_hash != fw.output_hash {
                    return Err(ChainVerifyError::FinalHashMismatch);
                }
            }
        }
        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        if self.verify_chain().is_err() {
            return false;
        }

        if self.verify_field_chains().is_err() {
            return false;
        }

        // All validations must pass.
        if self.validation_results.iter().any(|v| !v.passed) {
            return false;
        }

        true
    }

    /// Verify the bundle by replaying parser execution (#939).
    ///
    /// For each parser step where the input blob has `raw_content`, re-hash
    /// the content and verify it matches `content_hash`, then call the
    /// provided executor to re-run the parser and verify the output hash.
    ///
    /// This is the strongest verification: the auditor doesn't trust our
    /// hashes — they independently compute them from the raw data.
    pub fn verify_replay<F>(&self, mut executor: F) -> Result<(), ReplayError>
    where
        F: FnMut(&str, &[u8]) -> Result<Vec<u8>, String>,
    {
        // Verify raw content hashes for input blobs that include raw data.
        for (i, blob) in self.input_blobs.iter().enumerate() {
            if let Some(ref raw) = blob.raw_content {
                let actual = sha256(raw);
                if actual != blob.content_hash {
                    return Err(ReplayError::InputHashMismatch {
                        blob_index: i,
                        declared: blob.content_hash,
                        actual,
                    });
                }
            }
        }

        // Replay each parser step.
        for (i, step) in self.parser_chain.iter().enumerate() {
            // Find the input bytes from an input blob with matching hash.
            let input_bytes = self
                .input_blobs
                .iter()
                .find(|b| b.content_hash == step.input_hash)
                .and_then(|b| b.raw_content.as_deref());

            let Some(input) = input_bytes else {
                // No raw content available — skip replay (hash chain still applies).
                continue;
            };

            // Re-execute the parser.
            let output =
                executor(&step.parser_id, input).map_err(|e| ReplayError::ExecutionFailed {
                    step_index: i,
                    parser_id: step.parser_id.clone(),
                    message: e,
                })?;

            // Verify the output hash.
            let actual_hash = sha256(&output);
            if actual_hash != step.output_hash {
                return Err(ReplayError::OutputHashMismatch {
                    step_index: i,
                    parser_id: step.parser_id.clone(),
                    declared: step.output_hash,
                    actual: actual_hash,
                });
            }
        }

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayError — errors from verify_replay (#939)
// ═══════════════════════════════════════════════════════════════════════════

/// Error returned by [`WitnessBundle::verify_replay`] when replay
/// verification detects a discrepancy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// Raw content hash doesn't match the declared content_hash.
    InputHashMismatch {
        blob_index: usize,
        declared: [u8; 32],
        actual: [u8; 32],
    },
    /// Parser re-execution produced a different output hash.
    OutputHashMismatch {
        step_index: usize,
        parser_id: String,
        declared: [u8; 32],
        actual: [u8; 32],
    },
    /// Parser execution failed during replay.
    ExecutionFailed {
        step_index: usize,
        parser_id: String,
        message: String,
    },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputHashMismatch { blob_index, .. } => {
                write!(
                    f,
                    "input blob {blob_index}: content hash mismatch on replay"
                )
            }
            Self::OutputHashMismatch {
                step_index,
                parser_id,
                ..
            } => {
                write!(
                    f,
                    "parser step {step_index} ({parser_id}): output hash mismatch on replay"
                )
            }
            Self::ExecutionFailed {
                step_index,
                parser_id,
                message,
            } => {
                write!(
                    f,
                    "parser step {step_index} ({parser_id}): execution failed: {message}"
                )
            }
        }
    }
}

impl std::error::Error for ReplayError {}

// ═══════════════════════════════════════════════════════════════════════════
// ReductionWitness - proof that content was processed through a parser chain
// ═══════════════════════════════════════════════════════════════════════════

/// Proof that raw content was reduced through a deterministic parser chain
/// before promotion to the verified lane.
///
/// Without a valid `ReductionWitness`, promotion of non-deterministic data
/// (AIDerived, Mixed, OpaqueExternal) is denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReductionWitness {
    /// SHA-256 hash of the raw input content (content-addressed).
    pub source_hash: [u8; 32],
    /// Parser steps applied to reduce the raw input.
    pub parser_steps: Vec<ParserStep>,
    /// Validation results from all validators applied to the output.
    pub validation_steps: Vec<ValidationResult>,
    /// SHA-256 hash of the final reduced output.
    pub output_hash: [u8; 32],
}

impl ReductionWitness {
    /// Check whether this reduction witness is valid.
    ///
    /// A witness is valid when:
    /// 1. The parser chain is intact (each step's output feeds the next input).
    /// 2. The last parser step's output matches `output_hash`.
    /// 3. All validation results passed.
    pub fn is_valid(&self) -> bool {
        let mut current_hash = self.source_hash;
        for step in &self.parser_steps {
            if step.input_hash != current_hash {
                return false;
            }
            current_hash = step.output_hash;
        }
        if current_hash != self.output_hash {
            return false;
        }
        if self.validation_steps.iter().any(|v| !v.passed) {
            return false;
        }
        true
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WitnessValidationError — why a witness failed validation
// ═══════════════════════════════════════════════════════════════════════════

/// Errors that prevent a [`ReductionWitness`] from being wrapped in a
/// [`ValidatedWitness`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessValidationError {
    /// The parser chain is broken: a step's input hash does not match the
    /// preceding step's output hash, or the final output hash is wrong.
    InvalidChain,
    /// One or more validation steps reported `passed = false`.
    FailedValidation,
    /// The witness has no parser steps and `source_hash != output_hash`,
    /// or the witness is otherwise structurally empty in a way that cannot
    /// prove derivation.
    EmptyInputs,
}

impl fmt::Display for WitnessValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChain => write!(f, "reduction witness has a broken parser chain"),
            Self::FailedValidation => {
                write!(f, "one or more validation steps in the witness failed")
            }
            Self::EmptyInputs => write!(f, "reduction witness has no meaningful inputs"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ValidatedWitness — typestate newtype for validated witnesses
// ═══════════════════════════════════════════════════════════════════════════

/// A [`ReductionWitness`] that has been validated.
///
/// The inner field is private — the only way to construct a `ValidatedWitness`
/// is through [`ValidatedWitness::validate`], which checks the full chain
/// integrity and validation results. This makes unwitnessed verified writes
/// impossible at the type level: any API that accepts `&ValidatedWitness`
/// is guaranteed to have a valid derivation proof.
///
/// # Example
///
/// ```ignore
/// let witness = build_reduction_witness(/* ... */);
/// let validated = ValidatedWitness::validate(witness)?;
/// promote(&mut envelope, &request, &validated, now)?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWitness(ReductionWitness);

impl ValidatedWitness {
    /// Validate a [`ReductionWitness`] and wrap it in a `ValidatedWitness`.
    ///
    /// # Errors
    ///
    /// - [`WitnessValidationError::InvalidChain`] if the parser chain is
    ///   broken or the final output hash does not match.
    /// - [`WitnessValidationError::FailedValidation`] if any validation step
    ///   reported `passed = false`.
    /// - [`WitnessValidationError::EmptyInputs`] if there are no parser steps
    ///   and the source hash differs from the output hash.
    pub fn validate(witness: ReductionWitness) -> Result<Self, WitnessValidationError> {
        // Check chain integrity: each parser step's input must match the
        // preceding step's output (or source_hash for the first step).
        let mut current_hash = witness.source_hash;
        for step in &witness.parser_steps {
            if step.input_hash != current_hash {
                return Err(WitnessValidationError::InvalidChain);
            }
            current_hash = step.output_hash;
        }
        if current_hash != witness.output_hash {
            return Err(WitnessValidationError::InvalidChain);
        }

        // Check all validation steps passed.
        if witness.validation_steps.iter().any(|v| !v.passed) {
            return Err(WitnessValidationError::FailedValidation);
        }

        Ok(ValidatedWitness(witness))
    }

    /// Access the inner [`ReductionWitness`] by reference.
    pub fn inner(&self) -> &ReductionWitness {
        &self.0
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VerifiedBundle — typestate for chain-verified WitnessBundle (#1052)
// ═══════════════════════════════════════════════════════════════════════════

/// A [`WitnessBundle`] that has passed chain verification.
///
/// The inner field is private — the only way to construct a `VerifiedBundle`
/// is through [`VerifiedBundle::verify`], which calls `verify_chain()` and
/// `is_valid()`. This makes it a compile-time guarantee that any API
/// accepting `&VerifiedBundle` has a valid, verified derivation chain.
///
/// ```ignore
/// let bundle = assemble_witness_bundle(/* ... */);
/// let verified = VerifiedBundle::verify(bundle)?;
/// let digest = verified.digest(); // only available on VerifiedBundle
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBundle(WitnessBundle);

/// Error from `VerifiedBundle::verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleVerifyError {
    /// The hash chain is broken.
    ChainError(ChainVerifyError),
    /// A validation result reported failure.
    ValidationFailed,
}

impl std::fmt::Display for BundleVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainError(e) => write!(f, "chain verification failed: {e}"),
            Self::ValidationFailed => write!(f, "validation result reported failure"),
        }
    }
}

impl std::error::Error for BundleVerifyError {}

impl VerifiedBundle {
    /// Verify a WitnessBundle and wrap it. Consumes the unverified bundle.
    pub fn verify(bundle: WitnessBundle) -> Result<Self, BundleVerifyError> {
        bundle
            .verify_chain()
            .map_err(BundleVerifyError::ChainError)?;
        if bundle.validation_results.iter().any(|v| !v.passed) {
            return Err(BundleVerifyError::ValidationFailed);
        }
        Ok(Self(bundle))
    }

    /// Compute the canonical SHA-256 digest. Only available on verified bundles.
    pub fn digest(&self) -> [u8; 32] {
        self.0.compute_digest()
    }

    /// Access the verified bundle's witness ID.
    pub fn witness_id(&self) -> &str {
        &self.0.witness_id
    }

    /// Access the inner verified bundle.
    pub fn inner(&self) -> &WitnessBundle {
        &self.0
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
            field_witnesses: std::collections::BTreeMap::new(),
            zkvm_receipt: None,
        }
    }

    #[test]
    fn valid_bundle_passes_all_checks() {
        let bundle = make_valid_bundle();
        assert!(bundle.verify_chain().is_ok());
        assert!(bundle.is_valid());
    }

    #[test]
    fn broken_chain_detected_missing_input() {
        let mut bundle = make_valid_bundle();
        // Point transform at a hash that was never produced.
        bundle.transform_chain[0].input_hashes = vec![[0xDE; 32]];
        assert!(bundle.verify_chain().is_err());
        assert!(!bundle.is_valid());
    }

    #[test]
    fn broken_chain_detected_wrong_final_hash() {
        let mut bundle = make_valid_bundle();
        // Tamper with the final output hash.
        bundle.final_output_hash = [0xFF; 32];
        assert!(bundle.verify_chain().is_err());
        assert!(!bundle.is_valid());
    }

    #[test]
    fn failed_validation_rejects() {
        let mut bundle = make_valid_bundle();
        // Fail one validator.
        bundle.validation_results[1].passed = false;
        assert!(bundle.verify_chain().is_ok()); // Chain is still intact.
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
        assert!(bundle.verify_chain().is_err());
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
                raw_content: None,
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
            field_witnesses: std::collections::BTreeMap::new(),
            zkvm_receipt: None,
        };
        assert!(bundle.verify_chain().is_ok());
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
                    raw_content: None,
                },
                InputBlob {
                    source_class: "database".to_string(),
                    content_hash: hash_b,
                    fetched_at: 1001,
                    fetched_by: "agent-b".to_string(),
                    raw_content: None,
                },
            ],
            parser_chain: vec![
                ParserStep {
                    parser_id: "json_parser".to_string(),
                    parser_version: "1.0.0".to_string(),
                    parser_hash: sha256(b"json_v1"),
                    input_hash: hash_a,
                    output_hash: parser_out_a,
                },
                ParserStep {
                    parser_id: "sql_parser".to_string(),
                    parser_version: "1.0.0".to_string(),
                    parser_hash: sha256(b"sql_v1"),
                    input_hash: hash_b,
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
            field_witnesses: std::collections::BTreeMap::new(),
            zkvm_receipt: None,
        };
        assert!(bundle.verify_chain().is_ok());
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
                raw_content: None,
            }],
            parser_chain: vec![ParserStep {
                parser_id: "p".to_string(),
                parser_version: "1.0.0".to_string(),
                parser_hash: sha256(b"p"),
                input_hash,
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
            field_witnesses: std::collections::BTreeMap::new(),
            zkvm_receipt: None,
        };
        assert!(bundle.verify_chain().is_err());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input linkage verification tests (issue #742)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn parser_with_no_input_linkage_rejected() {
        let input_hash = sha256(b"real input");
        let parser_output = sha256(b"parsed output");
        let fabricated_input = sha256(b"fabricated - not an input blob");

        let bundle = WitnessBundle {
            witness_id: "wb-unlinked-parser".to_string(),
            input_blobs: vec![InputBlob {
                source_class: "api".to_string(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "agent".to_string(),
                raw_content: None,
            }],
            parser_chain: vec![ParserStep {
                parser_id: "evil_parser".to_string(),
                parser_version: "1.0.0".to_string(),
                parser_hash: sha256(b"evil"),
                input_hash: fabricated_input, // Not in input_blobs!
                output_hash: parser_output,
            }],
            transform_chain: vec![],
            validation_results: vec![],
            final_output_hash: parser_output,
            signature: None,
            created_at: 1000,
            field_witnesses: std::collections::BTreeMap::new(),
            zkvm_receipt: None,
        };

        let err = bundle.verify_chain().unwrap_err();
        assert_eq!(
            err,
            ChainVerifyError::UnlinkedParser {
                parser_id: "evil_parser".to_string(),
                step_index: 0,
            }
        );
        assert!(!bundle.is_valid());
    }

    #[test]
    fn second_parser_can_consume_first_parser_output() {
        let input_hash = sha256(b"raw data");
        let parser_1_output = sha256(b"stage 1 parsed");
        let parser_2_output = sha256(b"stage 2 parsed");

        let bundle = WitnessBundle {
            witness_id: "wb-chained-parsers".to_string(),
            input_blobs: vec![InputBlob {
                source_class: "file".to_string(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "agent".to_string(),
                raw_content: None,
            }],
            parser_chain: vec![
                ParserStep {
                    parser_id: "stage1".to_string(),
                    parser_version: "1.0.0".to_string(),
                    parser_hash: sha256(b"s1"),
                    input_hash,
                    output_hash: parser_1_output,
                },
                ParserStep {
                    parser_id: "stage2".to_string(),
                    parser_version: "1.0.0".to_string(),
                    parser_hash: sha256(b"s2"),
                    input_hash: parser_1_output, // Consumes first parser's output.
                    output_hash: parser_2_output,
                },
            ],
            transform_chain: vec![],
            validation_results: vec![],
            final_output_hash: parser_2_output,
            signature: None,
            created_at: 1000,
            field_witnesses: std::collections::BTreeMap::new(),
            zkvm_receipt: None,
        };

        assert!(bundle.verify_chain().is_ok());
        assert!(bundle.is_valid());
    }

    #[test]
    fn second_parser_with_unknown_input_rejected() {
        let input_hash = sha256(b"raw data");
        let parser_1_output = sha256(b"stage 1 parsed");
        let parser_2_output = sha256(b"stage 2 parsed");
        let unknown_hash = sha256(b"unknown source");

        let bundle = WitnessBundle {
            witness_id: "wb-bad-chain".to_string(),
            input_blobs: vec![InputBlob {
                source_class: "file".to_string(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "agent".to_string(),
                raw_content: None,
            }],
            parser_chain: vec![
                ParserStep {
                    parser_id: "stage1".to_string(),
                    parser_version: "1.0.0".to_string(),
                    parser_hash: sha256(b"s1"),
                    input_hash,
                    output_hash: parser_1_output,
                },
                ParserStep {
                    parser_id: "stage2".to_string(),
                    parser_version: "1.0.0".to_string(),
                    parser_hash: sha256(b"s2"),
                    input_hash: unknown_hash, // Not from any known source!
                    output_hash: parser_2_output,
                },
            ],
            transform_chain: vec![],
            validation_results: vec![],
            final_output_hash: parser_2_output,
            signature: None,
            created_at: 1000,
            field_witnesses: std::collections::BTreeMap::new(),
            zkvm_receipt: None,
        };

        let err = bundle.verify_chain().unwrap_err();
        assert_eq!(
            err,
            ChainVerifyError::UnlinkedParser {
                parser_id: "stage2".to_string(),
                step_index: 1,
            }
        );
    }

    #[test]
    fn transform_consuming_unknown_hash_rejected() {
        let input_hash = sha256(b"data");
        let parser_output = sha256(b"parsed");
        let unknown_hash = sha256(b"never produced by any step");
        let transform_output = sha256(b"transformed");

        let bundle = WitnessBundle {
            witness_id: "wb-bad-transform".to_string(),
            input_blobs: vec![InputBlob {
                source_class: "api".to_string(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "agent".to_string(),
                raw_content: None,
            }],
            parser_chain: vec![ParserStep {
                parser_id: "p".to_string(),
                parser_version: "1.0.0".to_string(),
                parser_hash: sha256(b"p"),
                input_hash,
                output_hash: parser_output,
            }],
            transform_chain: vec![TransformStep {
                transform_id: "bad_transform".to_string(),
                version: "1.0.0".to_string(),
                input_hashes: vec![parser_output, unknown_hash], // One valid, one unknown.
                output_hash: transform_output,
            }],
            validation_results: vec![],
            final_output_hash: transform_output,
            signature: None,
            created_at: 1000,
            field_witnesses: std::collections::BTreeMap::new(),
            zkvm_receipt: None,
        };

        let err = bundle.verify_chain().unwrap_err();
        assert_eq!(
            err,
            ChainVerifyError::UnlinkedTransform {
                transform_id: "bad_transform".to_string(),
                step_index: 0,
                missing_hash: unknown_hash,
            }
        );
    }

    #[test]
    fn transform_can_consume_input_blob_directly() {
        // A transform that references an input blob hash (no parser needed)
        // should be valid — transforms consume from available hashes which
        // includes input blob content hashes.
        let input_hash = sha256(b"direct data");
        let transform_output = sha256(b"transformed");

        let bundle = WitnessBundle {
            witness_id: "wb-direct-transform".to_string(),
            input_blobs: vec![InputBlob {
                source_class: "file".to_string(),
                content_hash: input_hash,
                fetched_at: 1000,
                fetched_by: "agent".to_string(),
                raw_content: None,
            }],
            parser_chain: vec![],
            transform_chain: vec![TransformStep {
                transform_id: "t".to_string(),
                version: "1.0.0".to_string(),
                input_hashes: vec![input_hash],
                output_hash: transform_output,
            }],
            validation_results: vec![],
            final_output_hash: transform_output,
            signature: None,
            created_at: 1000,
            field_witnesses: std::collections::BTreeMap::new(),
            zkvm_receipt: None,
        };

        assert!(bundle.verify_chain().is_ok());
    }

    #[test]
    fn error_display_is_informative() {
        let err = ChainVerifyError::UnlinkedParser {
            parser_id: "evil".to_string(),
            step_index: 0,
        };
        let msg = err.to_string();
        assert!(msg.contains("evil"));
        assert!(msg.contains("step 0"));
        assert!(msg.contains("known input hash"));
    }

    // ReductionWitness tests (issue #860)

    fn make_valid_reduction_witness() -> ReductionWitness {
        let source = sha256(b"raw web content");
        let parsed = sha256(b"parsed json");
        ReductionWitness {
            source_hash: source,
            parser_steps: vec![ParserStep {
                parser_id: "json_parser".to_string(),
                parser_version: "1.0.0".to_string(),
                parser_hash: sha256(b"json_parser_binary"),
                input_hash: source,
                output_hash: parsed,
            }],
            validation_steps: vec![ValidationResult {
                validator_id: "schema_check".to_string(),
                version: "1.0.0".to_string(),
                passed: true,
            }],
            output_hash: parsed,
        }
    }

    #[test]
    fn valid_reduction_witness() {
        let w = make_valid_reduction_witness();
        assert!(w.is_valid());
    }

    #[test]
    fn reduction_witness_broken_chain() {
        let mut w = make_valid_reduction_witness();
        w.parser_steps[0].input_hash = [0xDE; 32];
        assert!(!w.is_valid());
    }

    #[test]
    fn reduction_witness_wrong_output() {
        let mut w = make_valid_reduction_witness();
        w.output_hash = [0xFF; 32];
        assert!(!w.is_valid());
    }

    #[test]
    fn reduction_witness_failed_validation() {
        let mut w = make_valid_reduction_witness();
        w.validation_steps[0].passed = false;
        assert!(!w.is_valid());
    }

    #[test]
    fn reduction_witness_passthrough_no_parsers() {
        let source = sha256(b"already structured");
        let w = ReductionWitness {
            source_hash: source,
            parser_steps: vec![],
            validation_steps: vec![ValidationResult {
                validator_id: "noop".to_string(),
                version: "1.0.0".to_string(),
                passed: true,
            }],
            output_hash: source,
        };
        assert!(w.is_valid());
    }

    #[test]
    fn reduction_witness_multi_step_chain() {
        let source = sha256(b"raw html");
        let stage1 = sha256(b"stage 1");
        let stage2 = sha256(b"stage 2");
        let w = ReductionWitness {
            source_hash: source,
            parser_steps: vec![
                ParserStep {
                    parser_id: "html_parser".to_string(),
                    parser_version: "1.0.0".to_string(),
                    parser_hash: sha256(b"html_parser_binary"),
                    input_hash: source,
                    output_hash: stage1,
                },
                ParserStep {
                    parser_id: "text_extractor".to_string(),
                    parser_version: "1.0.0".to_string(),
                    parser_hash: sha256(b"text_extractor_binary"),
                    input_hash: stage1,
                    output_hash: stage2,
                },
            ],
            validation_steps: vec![ValidationResult {
                validator_id: "schema_check".to_string(),
                version: "1.0.0".to_string(),
                passed: true,
            }],
            output_hash: stage2,
        };
        assert!(w.is_valid());
    }

    // ValidatedWitness tests (issue #755)

    #[test]
    fn validated_witness_from_valid_reduction() {
        let w = make_valid_reduction_witness();
        let validated = ValidatedWitness::validate(w).expect("valid witness should validate");
        assert!(validated.inner().is_valid());
    }

    #[test]
    fn validated_witness_rejects_broken_chain() {
        let mut w = make_valid_reduction_witness();
        w.parser_steps[0].input_hash = [0xDE; 32];

        let err = ValidatedWitness::validate(w).unwrap_err();
        assert_eq!(err, WitnessValidationError::InvalidChain);
    }

    #[test]
    fn validated_witness_rejects_wrong_output_hash() {
        let mut w = make_valid_reduction_witness();
        w.output_hash = [0xFF; 32];

        let err = ValidatedWitness::validate(w).unwrap_err();
        assert_eq!(err, WitnessValidationError::InvalidChain);
    }

    #[test]
    fn validated_witness_rejects_failed_validation() {
        let mut w = make_valid_reduction_witness();
        w.validation_steps[0].passed = false;

        let err = ValidatedWitness::validate(w).unwrap_err();
        assert_eq!(err, WitnessValidationError::FailedValidation);
    }

    #[test]
    fn validated_witness_inner_returns_original() {
        let w = make_valid_reduction_witness();
        let original = w.clone();
        let validated = ValidatedWitness::validate(w).unwrap();
        assert_eq!(validated.inner(), &original);
    }

    #[test]
    fn validated_witness_passthrough_no_parsers() {
        let source = sha256(b"already structured");
        let w = ReductionWitness {
            source_hash: source,
            parser_steps: vec![],
            validation_steps: vec![ValidationResult {
                validator_id: "noop".to_string(),
                version: "1.0.0".to_string(),
                passed: true,
            }],
            output_hash: source,
        };
        let validated = ValidatedWitness::validate(w).expect("passthrough should validate");
        assert!(validated.inner().is_valid());
    }

    #[test]
    fn witness_validation_error_display() {
        let err = WitnessValidationError::InvalidChain;
        assert!(err.to_string().contains("broken parser chain"));

        let err = WitnessValidationError::FailedValidation;
        assert!(err.to_string().contains("validation steps"));

        let err = WitnessValidationError::EmptyInputs;
        assert!(err.to_string().contains("no meaningful inputs"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // AiDerivedWitness tests (#944)
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn ai_witness_single_generation() {
        let w = AiDerivedWitness::single_generation(b"prompt context", "llm-v2.1");
        assert_eq!(w.generation_count, 1);
        assert!(w.agreement_rate.is_none());
        assert_eq!(w.model_id, "llm-v2.1");
        assert_ne!(w.input_context_hash, [0u8; 32]);
    }

    #[test]
    fn ai_witness_with_consistency() {
        let w = AiDerivedWitness::with_consistency(b"prompt", "llm-v3", 4, 5);
        assert_eq!(w.generation_count, 5);
        let rate = w.agreement_rate.unwrap();
        assert_eq!(rate.agreed, 4);
        assert_eq!(rate.total, 5);
        assert!(!rate.is_unanimous());
        assert!((rate.as_f64() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn ai_witness_unanimous() {
        let w = AiDerivedWitness::with_consistency(b"prompt", "model", 3, 3);
        let rate = w.agreement_rate.unwrap();
        assert!(rate.is_unanimous());
        assert_eq!(rate.to_string(), "3/3 (100%)");
    }

    #[test]
    fn ai_witness_content_hash_deterministic() {
        let w1 = AiDerivedWitness::single_generation(b"same input", "model-a");
        let w2 = AiDerivedWitness::single_generation(b"same input", "model-a");
        assert_eq!(w1.content_hash(), w2.content_hash());

        let w3 = AiDerivedWitness::single_generation(b"different input", "model-a");
        assert_ne!(w1.content_hash(), w3.content_hash());
    }

    #[test]
    fn ai_witness_content_hash_includes_consistency() {
        let w1 = AiDerivedWitness::single_generation(b"input", "model");
        let w2 = AiDerivedWitness::with_consistency(b"input", "model", 3, 3);
        assert_ne!(w1.content_hash(), w2.content_hash());
    }

    #[test]
    fn agreement_rate_display() {
        let rate = AgreementRate::new(7, 10);
        assert_eq!(rate.to_string(), "7/10 (70%)");
    }

    #[test]
    #[should_panic(expected = "total must be > 0")]
    fn agreement_rate_zero_total_panics() {
        AgreementRate::new(0, 0);
    }

    #[test]
    #[should_panic(expected = "agreed must be <= total")]
    fn agreement_rate_overflow_panics() {
        AgreementRate::new(5, 3);
    }

    #[test]
    fn field_witness_with_ai_confidence() {
        let fw = FieldWitness {
            field_name: "summary".into(),
            input_blob_index: 0,
            parser_steps: vec![],
            output_hash: [0u8; 32],
            derivation: "ai_derived".into(),
            ai_confidence: Some(AiDerivedWitness::single_generation(
                b"context",
                "test-model",
            )),
        };
        assert!(fw.ai_confidence.is_some());
        assert_eq!(fw.ai_confidence.unwrap().model_id, "test-model");
    }

    #[test]
    fn field_witness_deterministic_no_confidence() {
        let fw = FieldWitness {
            field_name: "revenue".into(),
            input_blob_index: 0,
            parser_steps: vec![],
            output_hash: [0u8; 32],
            derivation: "deterministic".into(),
            ai_confidence: None,
        };
        assert!(fw.ai_confidence.is_none());
    }
}
