//! Deterministic parser and transform registry (DPI spec section 10).
//!
//! This module provides a registry of deterministic parsers and transforms --
//! functions that are guaranteed to produce identical output from identical
//! input. These are the building blocks that allow data to carry
//! [`crate::DerivationClass::Deterministic`]: if every step in a derivation
//! chain is a registered deterministic transform, the output is deterministic.
//!
//! ## Key invariant
//!
//! A parser or transform that uses an LLM internally **MUST NOT** be registered
//! as deterministic (`is_deterministic = false`). LLM outputs are inherently
//! non-reproducible; registering them as deterministic would violate the
//! verification guarantee.
//!
//! ## Content-addressing
//!
//! Each declaration carries a `build_hash` -- a 32-byte digest of the parser
//! or transform binary (WASM module, native shared library, etc.). This
//! content-addresses the exact code that will execute, ensuring that
//! "same parser ID + same version" always means "same code".
//!
//! ## TOML loading
//!
//! When the `serde` feature is enabled, declarations can be loaded from
//! `.nucleus/parsers/*.toml` files on disk via [`ParserRegistry::load_from_dir`].

use core::fmt;
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════════════════
// Sigstore supply chain verification (#943)
// ═══════════════════════════════════════════════════════════════════════════

/// Sigstore bundle attached to a parser or transform declaration.
///
/// Carries the cryptographic evidence that a specific binary was signed by
/// a trusted identity and recorded in the Rekor transparency log. Offline
/// verification confirms that `signed_artifact_hash == hex(build_hash)`.
/// Full Rekor verification (checking the log entry is present and unrevoked)
/// must be done by the application layer with network access.
///
/// ## TOML format
///
/// ```toml
/// [parser.sigstore_bundle]
/// certificate_pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
/// signature_b64 = "MEUCIQDx..."
/// rekor_log_id = "24296fb24b8ad77a88acdd4b8fca..."
/// signed_artifact_hash = "abcdef0123456789..."
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SigstoreBundle {
    /// PEM-encoded Fulcio certificate chain for the signing identity.
    pub certificate_pem: String,
    /// Base64-encoded signature over the artifact (DSSE or raw).
    pub signature_b64: String,
    /// Rekor transparency log entry UUID (for audit / online verification).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub rekor_log_id: Option<String>,
    /// Hex-encoded SHA-256 of the artifact that was signed.
    /// Must match `build_hash` for offline verification to pass.
    pub signed_artifact_hash: String,
}

impl SigstoreBundle {
    /// Offline verification: confirm the bundle covers the declared `build_hash`.
    ///
    /// This does NOT verify the cryptographic signature or check Rekor.
    /// It only asserts that the bundle's `signed_artifact_hash` field
    /// matches the declared binary hash — preventing a bundle from one
    /// binary being attached to a different binary.
    ///
    /// Full Sigstore verification (certificate chain + Rekor) requires
    /// network access and must be performed by the application layer.
    pub fn verify_covers_hash(&self, build_hash: &[u8; 32]) -> Result<(), SignatureError> {
        let declared = hex_encode(build_hash);
        if self.signed_artifact_hash.to_lowercase() == declared.to_lowercase() {
            Ok(())
        } else {
            Err(SignatureError::HashMismatch {
                bundle_hash: self.signed_artifact_hash.clone(),
                declared_hash: declared,
            })
        }
    }
}

/// Policy controlling whether a Sigstore bundle is required for registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SignaturePolicy {
    /// No signature required (default). Bundle is stored if present but not verified.
    #[default]
    Ignore,
    /// A bundle must be present and its `signed_artifact_hash` must match `build_hash`.
    /// Full Rekor verification is recommended but not enforced here.
    Require,
}

/// Errors from Sigstore bundle verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// No bundle was provided but the policy requires one.
    BundleRequired { parser_id: String },
    /// The bundle's `signed_artifact_hash` does not match the declared `build_hash`.
    HashMismatch {
        bundle_hash: String,
        declared_hash: String,
    },
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BundleRequired { parser_id } => {
                write!(f, "sigstore bundle required but missing for '{parser_id}'")
            }
            Self::HashMismatch {
                bundle_hash,
                declared_hash,
            } => {
                write!(
                    f,
                    "sigstore bundle covers {bundle_hash} but declaration has {declared_hash}"
                )
            }
        }
    }
}

impl std::error::Error for SignatureError {}

// ═══════════════════════════════════════════════════════════════════════════
// ParserDeclaration
// ═══════════════════════════════════════════════════════════════════════════

/// A registered parser: a content-addressed, versioned function that converts
/// one data format into a typed schema.
///
/// Example: a JSON parser that reads raw bytes and produces `company_record`
/// structs. The `build_hash` pins the exact binary so replay verification can
/// re-execute the identical code path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ParserDeclaration {
    /// Unique identifier for this parser (e.g. `"json_company_parser"`).
    pub parser_id: String,
    /// Semantic version string (e.g. `"1.2.0"`).
    pub version: String,
    /// Content-addressed digest of the parser binary (BLAKE3 or SHA-256).
    #[cfg_attr(feature = "serde", serde(with = "hex_bytes"))]
    pub build_hash: [u8; 32],
    /// Input format this parser accepts (e.g. `"json"`, `"html"`, `"csv"`).
    pub input_format: String,
    /// Output schema this parser produces (e.g. `"company_record"`).
    pub output_schema: String,
    /// Whether this parser is deterministic. **Must be `false` if the parser
    /// uses an LLM internally.** Only parsers with `is_deterministic = true`
    /// may be used in the verified (deterministic) lane.
    pub is_deterministic: bool,
    /// Optional digest of a test corpus used to validate determinism.
    /// When present, the registry can verify that re-running the parser
    /// on the test corpus produces bit-identical output.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "option_hex_bytes"
        )
    )]
    pub test_corpus_hash: Option<[u8; 32]>,
    /// Optional Sigstore bundle providing supply-chain provenance for this binary.
    /// See [`SigstoreBundle`] and [`SignaturePolicy`].
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub sigstore_bundle: Option<SigstoreBundle>,
    /// Whether a Sigstore bundle must be present and cover `build_hash`.
    /// Defaults to [`SignaturePolicy::Ignore`].
    #[cfg_attr(feature = "serde", serde(default))]
    pub signature_policy: SignaturePolicy,
}

impl ParserDeclaration {
    /// Verify the Sigstore bundle against the declared `build_hash`.
    ///
    /// - `SignaturePolicy::Ignore`: always returns `Ok(())`.
    /// - `SignaturePolicy::Require`: bundle must be present and cover the hash.
    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        match self.signature_policy {
            SignaturePolicy::Ignore => Ok(()),
            SignaturePolicy::Require => match &self.sigstore_bundle {
                None => Err(SignatureError::BundleRequired {
                    parser_id: self.parser_id.clone(),
                }),
                Some(bundle) => bundle.verify_covers_hash(&self.build_hash),
            },
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TransformDeclaration
// ═══════════════════════════════════════════════════════════════════════════

/// A registered transform: a content-addressed, versioned pure function
/// that maps one schema to another.
///
/// Structurally identical to [`ParserDeclaration`] but semantically distinct:
/// parsers convert raw formats to typed schemas, transforms map between schemas.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransformDeclaration {
    /// Unique identifier for this transform (e.g. `"normalize_address"`).
    pub transform_id: String,
    /// Semantic version string.
    pub version: String,
    /// Content-addressed digest of the transform binary.
    #[cfg_attr(feature = "serde", serde(with = "hex_bytes"))]
    pub build_hash: [u8; 32],
    /// Input schema this transform accepts.
    pub input_format: String,
    /// Output schema this transform produces.
    pub output_schema: String,
    /// Whether this transform is deterministic. **Must be `false` if the
    /// transform uses an LLM internally.**
    pub is_deterministic: bool,
    /// Optional test corpus hash for determinism verification.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "option_hex_bytes"
        )
    )]
    pub test_corpus_hash: Option<[u8; 32]>,
    /// Optional Sigstore bundle providing supply-chain provenance for this binary.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub sigstore_bundle: Option<SigstoreBundle>,
    /// Whether a Sigstore bundle must be present and cover `build_hash`.
    #[cfg_attr(feature = "serde", serde(default))]
    pub signature_policy: SignaturePolicy,
}

impl TransformDeclaration {
    /// Verify the Sigstore bundle against the declared `build_hash`.
    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        match self.signature_policy {
            SignaturePolicy::Ignore => Ok(()),
            SignaturePolicy::Require => match &self.sigstore_bundle {
                None => Err(SignatureError::BundleRequired {
                    parser_id: self.transform_id.clone(),
                }),
                Some(bundle) => bundle.verify_covers_hash(&self.build_hash),
            },
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════════════

/// Errors that can occur when registering parsers or transforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// A parser/transform with the same ID is already registered with a
    /// different `build_hash`. This prevents silent mutation of registered
    /// code.
    ConflictingHash {
        id: String,
        existing: [u8; 32],
        incoming: [u8; 32],
    },
    /// TOML file could not be parsed.
    #[cfg(feature = "serde")]
    ParseError { path: String, message: String },
    /// I/O error reading a directory or file.
    #[cfg(feature = "serde")]
    IoError { path: String, message: String },
    /// Sigstore signature policy violation — bundle missing or hash mismatch.
    SignatureInvalid(SignatureError),
    /// WASM compilation or pre-compilation lookup failed.
    #[cfg(feature = "wasm-sandbox")]
    CompileError(String),
    /// WASM execution failed.
    #[cfg(feature = "wasm-sandbox")]
    ExecutionError(String),
    /// The actual content hash of WASM bytes doesn't match the declared
    /// `build_hash` — the binary has been tampered with or is the wrong version.
    #[cfg(feature = "wasm-sandbox")]
    HashMismatch {
        id: String,
        declared: [u8; 32],
        actual: [u8; 32],
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingHash {
                id,
                existing,
                incoming,
            } => {
                write!(
                    f,
                    "conflicting build_hash for '{id}': existing {} vs incoming {}",
                    hex_encode(existing),
                    hex_encode(incoming),
                )
            }
            Self::SignatureInvalid(e) => write!(f, "signature verification failed: {e}"),
            #[cfg(feature = "serde")]
            Self::ParseError { path, message } => {
                write!(f, "failed to parse '{path}': {message}")
            }
            #[cfg(feature = "serde")]
            Self::IoError { path, message } => {
                write!(f, "I/O error at '{path}': {message}")
            }
            #[cfg(feature = "wasm-sandbox")]
            Self::CompileError(msg) => write!(f, "compile error: {msg}"),
            #[cfg(feature = "wasm-sandbox")]
            Self::ExecutionError(msg) => write!(f, "execution error: {msg}"),
            #[cfg(feature = "wasm-sandbox")]
            Self::HashMismatch {
                id,
                declared,
                actual,
            } => {
                write!(
                    f,
                    "hash mismatch for '{id}': declared {} vs actual {}",
                    hex_encode(declared),
                    hex_encode(actual),
                )
            }
        }
    }
}

impl std::error::Error for RegistryError {}

// ═══════════════════════════════════════════════════════════════════════════
// ParserRegistry
// ═══════════════════════════════════════════════════════════════════════════

/// Registry of deterministic parsers and transforms.
///
/// Parsers and transforms are keyed by their unique ID. Attempting to register
/// a declaration whose ID already exists with a *different* `build_hash` is
/// an error -- this enforces content-addressing integrity.
///
/// Re-registering the exact same declaration (same ID, same hash) is a no-op,
/// which makes the registry idempotent.
#[cfg_attr(not(feature = "wasm-sandbox"), derive(Clone))]
#[derive(Debug, Default)]
pub struct ParserRegistry {
    parsers: BTreeMap<String, ParserDeclaration>,
    transforms: BTreeMap<String, TransformDeclaration>,
    /// Compiled WASM parsers, keyed by parser ID. Only populated when
    /// the `wasm-sandbox` feature is enabled and `compile_parser` is called.
    #[cfg(feature = "wasm-sandbox")]
    compiled_parsers: BTreeMap<String, LiveParser>,
}

impl ParserRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    // -- Parser operations --------------------------------------------------

    /// Register a parser declaration.
    ///
    /// Returns `Ok(())` if:
    /// - The parser ID is new, or
    /// - The parser ID already exists with the **same** `build_hash` (idempotent).
    ///
    /// Returns `Err` if:
    /// - The ID exists with a different `build_hash` ([`RegistryError::ConflictingHash`])
    /// - The `signature_policy` is [`SignaturePolicy::Require`] and the bundle
    ///   is missing or doesn't cover `build_hash` ([`RegistryError::SignatureInvalid`])
    pub fn register_parser(&mut self, decl: ParserDeclaration) -> Result<(), RegistryError> {
        if let Some(existing) = self.parsers.get(&decl.parser_id) {
            if existing.build_hash != decl.build_hash {
                return Err(RegistryError::ConflictingHash {
                    id: decl.parser_id.clone(),
                    existing: existing.build_hash,
                    incoming: decl.build_hash,
                });
            }
            // Same hash -- idempotent, do nothing.
            return Ok(());
        }
        decl.verify_signature()
            .map_err(RegistryError::SignatureInvalid)?;
        self.parsers.insert(decl.parser_id.clone(), decl);
        Ok(())
    }

    /// Look up a parser by ID.
    pub fn get_parser(&self, parser_id: &str) -> Option<&ParserDeclaration> {
        self.parsers.get(parser_id)
    }

    /// Returns `true` if the parser with the given ID is registered **and**
    /// declared as deterministic.
    ///
    /// Returns `false` if the parser is not registered or if it is registered
    /// but `is_deterministic` is `false`.
    pub fn verify_parser_deterministic(&self, parser_id: &str) -> bool {
        self.parsers
            .get(parser_id)
            .is_some_and(|p| p.is_deterministic)
    }

    /// Number of registered parsers.
    pub fn parser_count(&self) -> usize {
        self.parsers.len()
    }

    /// Iterate over all registered parsers.
    pub fn parsers(&self) -> impl Iterator<Item = (&String, &ParserDeclaration)> {
        self.parsers.iter()
    }

    // -- Transform operations -----------------------------------------------

    /// Register a transform declaration.
    ///
    /// Same idempotency, conflict, and signature-policy semantics as
    /// [`Self::register_parser`].
    pub fn register_transform(&mut self, decl: TransformDeclaration) -> Result<(), RegistryError> {
        if let Some(existing) = self.transforms.get(&decl.transform_id) {
            if existing.build_hash != decl.build_hash {
                return Err(RegistryError::ConflictingHash {
                    id: decl.transform_id.clone(),
                    existing: existing.build_hash,
                    incoming: decl.build_hash,
                });
            }
            return Ok(());
        }
        decl.verify_signature()
            .map_err(RegistryError::SignatureInvalid)?;
        self.transforms.insert(decl.transform_id.clone(), decl);
        Ok(())
    }

    /// Look up a transform by ID.
    pub fn get_transform(&self, transform_id: &str) -> Option<&TransformDeclaration> {
        self.transforms.get(transform_id)
    }

    /// Returns `true` if the transform is registered and deterministic.
    pub fn verify_transform_deterministic(&self, transform_id: &str) -> bool {
        self.transforms
            .get(transform_id)
            .is_some_and(|t| t.is_deterministic)
    }

    /// Number of registered transforms.
    pub fn transform_count(&self) -> usize {
        self.transforms.len()
    }

    /// Iterate over all registered transforms.
    pub fn transforms(&self) -> impl Iterator<Item = (&String, &TransformDeclaration)> {
        self.transforms.iter()
    }

    // -- TOML loading (serde feature) ----------------------------------------

    /// Load parser and transform declarations from a directory.
    ///
    /// Reads all `*.toml` files in the given directory. Each file should
    /// contain either a `[parser]` or `[transform]` table (or both).
    ///
    /// ```toml
    /// [parser]
    /// parser_id = "json_company_parser"
    /// version = "1.0.0"
    /// build_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    /// input_format = "json"
    /// output_schema = "company_record"
    /// is_deterministic = true
    /// ```
    #[cfg(feature = "serde")]
    pub fn load_from_dir(&mut self, dir: &std::path::Path) -> Result<usize, RegistryError> {
        let entries = std::fs::read_dir(dir).map_err(|e| RegistryError::IoError {
            path: dir.display().to_string(),
            message: e.to_string(),
        })?;

        let mut count = 0;
        for entry in entries {
            let entry = entry.map_err(|e| RegistryError::IoError {
                path: dir.display().to_string(),
                message: e.to_string(),
            })?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }

            let contents = std::fs::read_to_string(&path).map_err(|e| RegistryError::IoError {
                path: path.display().to_string(),
                message: e.to_string(),
            })?;

            let doc: TomlDocument =
                toml::from_str(&contents).map_err(|e| RegistryError::ParseError {
                    path: path.display().to_string(),
                    message: e.to_string(),
                })?;

            if let Some(parser) = doc.parser {
                self.register_parser(parser)?;
                count += 1;
            }
            if let Some(transform) = doc.transform {
                self.register_transform(transform)?;
                count += 1;
            }
        }

        Ok(count)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WASM-backed registry (wasm-sandbox feature)
// ═══════════════════════════════════════════════════════════════════════════

/// A compiled, content-addressed parser ready for execution.
///
/// Bridges [`ParserDeclaration`] (metadata) with
/// [`crate::wasm_sandbox::CompiledParser`] (executable code).
#[cfg(feature = "wasm-sandbox")]
pub struct LiveParser {
    /// The declaration this compiled parser corresponds to.
    pub declaration: ParserDeclaration,
    /// The compiled WASM module, ready for execution.
    pub compiled: crate::wasm_sandbox::CompiledParser,
}

#[cfg(feature = "wasm-sandbox")]
impl fmt::Debug for LiveParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveParser")
            .field("parser_id", &self.declaration.parser_id)
            .field("version", &self.declaration.version)
            .field("content_hash", &self.declaration.build_hash)
            .finish()
    }
}

#[cfg(feature = "wasm-sandbox")]
impl ParserRegistry {
    /// Compile and register a parser from raw WASM bytes.
    ///
    /// 1. SHA-256 hashes the bytes (via [`crate::wasm_sandbox::ParserSandbox`])
    /// 2. Verifies the hash matches the declaration's `build_hash`
    /// 3. Caches the compiled module for subsequent `execute_parser` calls
    ///
    /// Returns the content hash on success.
    pub fn compile_parser(
        &mut self,
        sandbox: &crate::wasm_sandbox::ParserSandbox,
        parser_id: &str,
        wasm_bytes: &[u8],
    ) -> Result<[u8; 32], RegistryError> {
        let decl = self.parsers.get(parser_id).ok_or_else(|| {
            RegistryError::CompileError(format!("parser '{parser_id}' not registered"))
        })?;

        let compiled = sandbox.compile(wasm_bytes).map_err(|e| {
            RegistryError::CompileError(format!("WASM compile failed for '{parser_id}': {e}"))
        })?;

        let actual_hash = *compiled.content_hash();
        if actual_hash != decl.build_hash {
            return Err(RegistryError::HashMismatch {
                id: parser_id.to_string(),
                declared: decl.build_hash,
                actual: actual_hash,
            });
        }

        let live = LiveParser {
            declaration: decl.clone(),
            compiled,
        };
        self.compiled_parsers.insert(parser_id.to_string(), live);

        Ok(actual_hash)
    }

    /// Execute a previously compiled parser on the given input.
    ///
    /// Returns the raw output bytes. The caller is responsible for hashing
    /// the output and recording it in a [`crate::witness::WitnessBundle`].
    pub fn execute_parser(
        &self,
        sandbox: &crate::wasm_sandbox::ParserSandbox,
        parser_id: &str,
        input: &[u8],
        fuel_limit: u64,
    ) -> Result<Vec<u8>, RegistryError> {
        let live = self.compiled_parsers.get(parser_id).ok_or_else(|| {
            RegistryError::CompileError(format!(
                "parser '{parser_id}' not compiled — call compile_parser first"
            ))
        })?;

        sandbox
            .execute(&live.compiled, input, fuel_limit)
            .map_err(|e| {
                RegistryError::ExecutionError(format!(
                    "WASM execution failed for '{parser_id}': {e}"
                ))
            })
    }

    /// Look up a compiled (live) parser by ID.
    #[cfg(feature = "wasm-sandbox")]
    pub fn get_live_parser(&self, parser_id: &str) -> Option<&LiveParser> {
        self.compiled_parsers.get(parser_id)
    }

    /// Number of compiled (live) parsers ready for execution.
    pub fn live_parser_count(&self) -> usize {
        self.compiled_parsers.len()
    }
}

/// Internal TOML document structure for loading from files.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct TomlDocument {
    parser: Option<ParserDeclaration>,
    transform: Option<TransformDeclaration>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Hex serialization helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Encode a 32-byte array as a hex string.
fn hex_encode(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string into a 32-byte array.
#[cfg(any(feature = "serde", test))]
fn hex_decode(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hex: {e}"))?;
    }
    Ok(out)
}

/// Serde helper for `[u8; 32]` <-> hex string.
#[cfg(feature = "serde")]
mod hex_bytes {
    use super::{hex_decode, hex_encode};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex_decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Serde helper for `Option<[u8; 32]>` <-> optional hex string.
#[cfg(feature = "serde")]
mod option_hex_bytes {
    use super::{hex_decode, hex_encode};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&hex_encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => hex_decode(&s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash_a() -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = 0xAA;
        h[31] = 0xFF;
        h
    }

    fn sample_hash_b() -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = 0xBB;
        h[31] = 0xEE;
        h
    }

    fn make_parser(id: &str, hash: [u8; 32], deterministic: bool) -> ParserDeclaration {
        ParserDeclaration {
            parser_id: id.to_string(),
            version: "1.0.0".to_string(),
            build_hash: hash,
            input_format: "json".to_string(),
            output_schema: "company_record".to_string(),
            is_deterministic: deterministic,
            test_corpus_hash: None,
            sigstore_bundle: None,
            signature_policy: SignaturePolicy::Ignore,
        }
    }

    fn make_transform(id: &str, hash: [u8; 32], deterministic: bool) -> TransformDeclaration {
        TransformDeclaration {
            transform_id: id.to_string(),
            version: "1.0.0".to_string(),
            build_hash: hash,
            input_format: "company_record".to_string(),
            output_schema: "normalized_company".to_string(),
            is_deterministic: deterministic,
            test_corpus_hash: None,
            sigstore_bundle: None,
            signature_policy: SignaturePolicy::Ignore,
        }
    }

    fn make_bundle(build_hash: &[u8; 32]) -> SigstoreBundle {
        SigstoreBundle {
            certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
                .to_string(),
            signature_b64: "MEUCIQDxtest==".to_string(),
            rekor_log_id: Some("24296fb24b8ad77a".to_string()),
            signed_artifact_hash: hex_encode(build_hash),
        }
    }

    #[test]
    fn register_and_get_parser() {
        let mut reg = ParserRegistry::new();
        let decl = make_parser("json_parser", sample_hash_a(), true);
        reg.register_parser(decl.clone()).unwrap();

        let got = reg.get_parser("json_parser").unwrap();
        assert_eq!(got.parser_id, "json_parser");
        assert_eq!(got.build_hash, sample_hash_a());
        assert_eq!(reg.parser_count(), 1);
    }

    #[test]
    fn register_and_get_transform() {
        let mut reg = ParserRegistry::new();
        let decl = make_transform("normalize_addr", sample_hash_a(), true);
        reg.register_transform(decl.clone()).unwrap();

        let got = reg.get_transform("normalize_addr").unwrap();
        assert_eq!(got.transform_id, "normalize_addr");
        assert_eq!(reg.transform_count(), 1);
    }

    #[test]
    fn idempotent_register_same_hash() {
        let mut reg = ParserRegistry::new();
        let decl = make_parser("json_parser", sample_hash_a(), true);
        reg.register_parser(decl.clone()).unwrap();
        // Re-register with same hash -- should succeed (idempotent).
        reg.register_parser(decl).unwrap();
        assert_eq!(reg.parser_count(), 1);
    }

    #[test]
    fn reject_conflicting_hash() {
        let mut reg = ParserRegistry::new();
        reg.register_parser(make_parser("json_parser", sample_hash_a(), true))
            .unwrap();

        let err = reg
            .register_parser(make_parser("json_parser", sample_hash_b(), true))
            .unwrap_err();

        match err {
            RegistryError::ConflictingHash {
                id,
                existing,
                incoming,
            } => {
                assert_eq!(id, "json_parser");
                assert_eq!(existing, sample_hash_a());
                assert_eq!(incoming, sample_hash_b());
            }
            #[allow(unreachable_patterns)]
            other => panic!("expected ConflictingHash, got: {other:?}"),
        }
    }

    #[test]
    fn reject_conflicting_transform_hash() {
        let mut reg = ParserRegistry::new();
        reg.register_transform(make_transform("norm", sample_hash_a(), true))
            .unwrap();

        let err = reg
            .register_transform(make_transform("norm", sample_hash_b(), true))
            .unwrap_err();

        assert!(matches!(err, RegistryError::ConflictingHash { .. }));
    }

    #[test]
    fn verify_deterministic_true() {
        let mut reg = ParserRegistry::new();
        reg.register_parser(make_parser("det_parser", sample_hash_a(), true))
            .unwrap();
        assert!(reg.verify_parser_deterministic("det_parser"));
    }

    #[test]
    fn verify_deterministic_false_when_nondeterministic() {
        let mut reg = ParserRegistry::new();
        // A parser that internally uses an LLM -- MUST NOT be deterministic.
        reg.register_parser(make_parser("llm_parser", sample_hash_a(), false))
            .unwrap();
        assert!(!reg.verify_parser_deterministic("llm_parser"));
    }

    #[test]
    fn verify_deterministic_false_when_missing() {
        let reg = ParserRegistry::new();
        assert!(!reg.verify_parser_deterministic("nonexistent"));
    }

    #[test]
    fn verify_transform_deterministic() {
        let mut reg = ParserRegistry::new();
        reg.register_transform(make_transform("det_xform", sample_hash_a(), true))
            .unwrap();
        reg.register_transform(make_transform("llm_xform", sample_hash_b(), false))
            .unwrap();

        assert!(reg.verify_transform_deterministic("det_xform"));
        assert!(!reg.verify_transform_deterministic("llm_xform"));
        assert!(!reg.verify_transform_deterministic("missing"));
    }

    #[test]
    fn get_missing_returns_none() {
        let reg = ParserRegistry::new();
        assert!(reg.get_parser("nope").is_none());
        assert!(reg.get_transform("nope").is_none());
    }

    #[test]
    fn iterate_parsers_and_transforms() {
        let mut reg = ParserRegistry::new();
        reg.register_parser(make_parser("a", sample_hash_a(), true))
            .unwrap();
        reg.register_parser(make_parser("b", sample_hash_b(), false))
            .unwrap();
        reg.register_transform(make_transform("x", sample_hash_a(), true))
            .unwrap();

        let parser_ids: Vec<_> = reg.parsers().map(|(k, _)| k.as_str()).collect();
        assert_eq!(parser_ids, vec!["a", "b"]); // BTreeMap is sorted

        let transform_ids: Vec<_> = reg.transforms().map(|(k, _)| k.as_str()).collect();
        assert_eq!(transform_ids, vec!["x"]);
    }

    #[test]
    fn hex_encode_decode_roundtrip() {
        let hash = sample_hash_a();
        let encoded = hex_encode(&hash);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(hash, decoded);
    }

    #[test]
    fn hex_decode_rejects_bad_length() {
        assert!(hex_decode("abcd").is_err());
    }

    #[test]
    fn hex_decode_rejects_bad_chars() {
        let bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(hex_decode(bad).is_err());
    }

    #[test]
    fn error_display_conflicting_hash() {
        let err = RegistryError::ConflictingHash {
            id: "test".to_string(),
            existing: sample_hash_a(),
            incoming: sample_hash_b(),
        };
        let msg = err.to_string();
        assert!(msg.contains("conflicting build_hash"));
        assert!(msg.contains("test"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn load_from_dir_reads_toml_files() {
        let dir = std::env::temp_dir().join("nucleus_parser_registry_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Write a parser TOML.
        let parser_toml = r#"
[parser]
parser_id = "csv_parser"
version = "2.1.0"
build_hash = "aa000000000000000000000000000000000000000000000000000000000000ff"
input_format = "csv"
output_schema = "tabular_data"
is_deterministic = true
"#;
        std::fs::write(dir.join("csv_parser.toml"), parser_toml).unwrap();

        // Write a transform TOML.
        let transform_toml = r#"
[transform]
transform_id = "flatten_nested"
version = "1.0.0"
build_hash = "bb000000000000000000000000000000000000000000000000000000000000ee"
input_format = "nested_json"
output_schema = "flat_json"
is_deterministic = true
"#;
        std::fs::write(dir.join("flatten.toml"), transform_toml).unwrap();

        // Write a non-toml file (should be skipped).
        std::fs::write(dir.join("readme.txt"), "ignored").unwrap();

        let mut reg = ParserRegistry::new();
        let count = reg.load_from_dir(&dir).unwrap();

        assert_eq!(count, 2);
        assert!(reg.get_parser("csv_parser").is_some());
        assert!(reg.get_transform("flatten_nested").is_some());

        let parser = reg.get_parser("csv_parser").unwrap();
        assert_eq!(parser.version, "2.1.0");
        assert_eq!(parser.input_format, "csv");
        assert!(parser.is_deterministic);
        assert_eq!(parser.build_hash, sample_hash_a());

        let transform = reg.get_transform("flatten_nested").unwrap();
        assert_eq!(transform.version, "1.0.0");
        assert!(transform.is_deterministic);
        assert_eq!(transform.build_hash, sample_hash_b());

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn load_from_dir_rejects_conflicting_hash() {
        let dir = std::env::temp_dir().join("nucleus_parser_registry_conflict_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Two files declaring the same parser_id with different hashes.
        let toml_a = r#"
[parser]
parser_id = "dup_parser"
version = "1.0.0"
build_hash = "aa000000000000000000000000000000000000000000000000000000000000ff"
input_format = "json"
output_schema = "record"
is_deterministic = true
"#;
        let toml_b = r#"
[parser]
parser_id = "dup_parser"
version = "1.0.0"
build_hash = "bb000000000000000000000000000000000000000000000000000000000000ee"
input_format = "json"
output_schema = "record"
is_deterministic = true
"#;
        std::fs::write(dir.join("a.toml"), toml_a).unwrap();
        std::fs::write(dir.join("b.toml"), toml_b).unwrap();

        let mut reg = ParserRegistry::new();
        let err = reg.load_from_dir(&dir).unwrap_err();
        assert!(matches!(err, RegistryError::ConflictingHash { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn load_from_dir_nonexistent_returns_error() {
        let mut reg = ParserRegistry::new();
        let err = reg
            .load_from_dir(std::path::Path::new("/nonexistent/path"))
            .unwrap_err();
        assert!(matches!(err, RegistryError::IoError { .. }));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn toml_roundtrip_with_test_corpus_hash() {
        let decl = ParserDeclaration {
            parser_id: "roundtrip_test".to_string(),
            version: "1.0.0".to_string(),
            build_hash: sample_hash_a(),
            input_format: "json".to_string(),
            output_schema: "test".to_string(),
            is_deterministic: true,
            test_corpus_hash: Some(sample_hash_b()),
            sigstore_bundle: None,
            signature_policy: SignaturePolicy::Ignore,
        };

        let serialized = toml::to_string(&decl).unwrap();
        let deserialized: ParserDeclaration = toml::from_str(&serialized).unwrap();
        assert_eq!(decl, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn toml_roundtrip_without_test_corpus_hash() {
        let decl = ParserDeclaration {
            parser_id: "no_corpus".to_string(),
            version: "1.0.0".to_string(),
            build_hash: sample_hash_a(),
            input_format: "csv".to_string(),
            output_schema: "rows".to_string(),
            is_deterministic: false,
            test_corpus_hash: None,
            sigstore_bundle: None,
            signature_policy: SignaturePolicy::Ignore,
        };

        let serialized = toml::to_string(&decl).unwrap();
        assert!(!serialized.contains("test_corpus_hash"));
        let deserialized: ParserDeclaration = toml::from_str(&serialized).unwrap();
        assert_eq!(decl, deserialized);
    }

    // -----------------------------------------------------------------
    // Sigstore supply-chain verification tests (#943)
    // -----------------------------------------------------------------

    #[test]
    fn ignore_policy_allows_registration_without_bundle() {
        let mut reg = ParserRegistry::new();
        let decl = make_parser("no_sig", sample_hash_a(), true);
        assert_eq!(decl.signature_policy, SignaturePolicy::Ignore);
        reg.register_parser(decl).unwrap();
    }

    #[test]
    fn require_policy_rejects_missing_bundle() {
        let mut reg = ParserRegistry::new();
        let decl = ParserDeclaration {
            signature_policy: SignaturePolicy::Require,
            ..make_parser("needs_sig", sample_hash_a(), true)
        };
        let err = reg.register_parser(decl).unwrap_err();
        assert!(matches!(
            err,
            RegistryError::SignatureInvalid(SignatureError::BundleRequired { .. })
        ));
    }

    #[test]
    fn require_policy_accepts_matching_bundle() {
        let mut reg = ParserRegistry::new();
        let hash = sample_hash_a();
        let decl = ParserDeclaration {
            signature_policy: SignaturePolicy::Require,
            sigstore_bundle: Some(make_bundle(&hash)),
            ..make_parser("signed_parser", hash, true)
        };
        reg.register_parser(decl).unwrap();
        assert!(reg.get_parser("signed_parser").is_some());
    }

    #[test]
    fn require_policy_rejects_bundle_covering_wrong_hash() {
        let mut reg = ParserRegistry::new();
        let declaration_hash = sample_hash_a();
        let bundle_hash = sample_hash_b(); // covers a different binary
        let decl = ParserDeclaration {
            signature_policy: SignaturePolicy::Require,
            sigstore_bundle: Some(make_bundle(&bundle_hash)),
            ..make_parser("mismatch_parser", declaration_hash, true)
        };
        let err = reg.register_parser(decl).unwrap_err();
        assert!(matches!(
            err,
            RegistryError::SignatureInvalid(SignatureError::HashMismatch { .. })
        ));
    }

    #[test]
    fn transform_require_policy_rejects_missing_bundle() {
        let mut reg = ParserRegistry::new();
        let decl = TransformDeclaration {
            signature_policy: SignaturePolicy::Require,
            ..make_transform("needs_sig", sample_hash_a(), true)
        };
        let err = reg.register_transform(decl).unwrap_err();
        assert!(matches!(
            err,
            RegistryError::SignatureInvalid(SignatureError::BundleRequired { .. })
        ));
    }

    #[test]
    fn transform_require_policy_accepts_matching_bundle() {
        let mut reg = ParserRegistry::new();
        let hash = sample_hash_a();
        let decl = TransformDeclaration {
            signature_policy: SignaturePolicy::Require,
            sigstore_bundle: Some(make_bundle(&hash)),
            ..make_transform("signed_xform", hash, true)
        };
        reg.register_transform(decl).unwrap();
    }

    #[test]
    fn bundle_covers_hash_ok() {
        let hash = sample_hash_a();
        let bundle = make_bundle(&hash);
        assert!(bundle.verify_covers_hash(&hash).is_ok());
    }

    #[test]
    fn bundle_covers_hash_mismatch() {
        let bundle = make_bundle(&sample_hash_a());
        let err = bundle.verify_covers_hash(&sample_hash_b()).unwrap_err();
        assert!(matches!(err, SignatureError::HashMismatch { .. }));
        assert!(err.to_string().contains("sigstore bundle covers"));
    }

    #[test]
    fn bundle_with_rekor_log_id_roundtrips() {
        let hash = sample_hash_a();
        let bundle = SigstoreBundle {
            certificate_pem: "cert".to_string(),
            signature_b64: "sig".to_string(),
            rekor_log_id: Some("abc123".to_string()),
            signed_artifact_hash: hex_encode(&hash),
        };
        assert_eq!(bundle.rekor_log_id.as_deref(), Some("abc123"));
    }

    #[test]
    fn signature_error_display() {
        let e = SignatureError::BundleRequired {
            parser_id: "my_parser".to_string(),
        };
        assert!(e.to_string().contains("my_parser"));

        let e2 = SignatureError::HashMismatch {
            bundle_hash: "aaa".to_string(),
            declared_hash: "bbb".to_string(),
        };
        assert!(e2.to_string().contains("aaa"));
        assert!(e2.to_string().contains("bbb"));
    }

    // -----------------------------------------------------------------
    // WASM-backed registry tests (#914)
    // -----------------------------------------------------------------

    #[cfg(feature = "wasm-sandbox")]
    mod wasm_tests {
        use super::*;
        use crate::wasm_sandbox::ParserSandbox;
        use sha2::{Digest, Sha256};

        /// Identity parser WAT — copies input to output unchanged.
        fn identity_wat() -> &'static str {
            r#"
            (module
                (memory (export "memory") 1)
                (global $bump (mut i32) (i32.const 1024))
                (func (export "alloc") (param $len i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $bump))
                    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
                    (local.get $ptr))
                (func (export "parse") (param $ptr i32) (param $len i32) (result i64)
                    (local $out i32)
                    (local.set $out (global.get $bump))
                    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
                    (memory.copy (local.get $out) (local.get $ptr) (local.get $len))
                    (i64.or
                        (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
                        (i64.extend_i32_u (local.get $len))))
            )
            "#
        }

        fn wasm_hash(wasm_bytes: &[u8]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(wasm_bytes);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        }

        #[test]
        fn compile_and_execute_via_registry() {
            let sandbox = ParserSandbox::new();
            let wasm = wat::parse_str(identity_wat()).unwrap();
            let hash = wasm_hash(&wasm);

            let mut reg = ParserRegistry::new();
            reg.register_parser(ParserDeclaration {
                parser_id: "identity".into(),
                version: "1.0.0".into(),
                build_hash: hash,
                input_format: "bytes".into(),
                output_schema: "bytes".into(),
                is_deterministic: true,
                ..Default::default()
            })
            .unwrap();

            let returned_hash = reg.compile_parser(&sandbox, "identity", &wasm).unwrap();
            assert_eq!(returned_hash, hash);
            assert_eq!(reg.live_parser_count(), 1);

            let output = reg
                .execute_parser(&sandbox, "identity", b"hello", 100_000)
                .unwrap();
            assert_eq!(output, b"hello");
        }

        #[test]
        fn compile_rejects_hash_mismatch() {
            let sandbox = ParserSandbox::new();
            let wasm = wat::parse_str(identity_wat()).unwrap();

            let mut reg = ParserRegistry::new();
            reg.register_parser(ParserDeclaration {
                parser_id: "tampered".into(),
                version: "1.0.0".into(),
                build_hash: [0xAA; 32], // wrong hash
                input_format: "bytes".into(),
                output_schema: "bytes".into(),
                is_deterministic: true,
                ..Default::default()
            })
            .unwrap();

            let err = reg.compile_parser(&sandbox, "tampered", &wasm).unwrap_err();
            assert!(
                matches!(err, RegistryError::HashMismatch { .. }),
                "expected HashMismatch, got: {err}"
            );
        }

        #[test]
        fn compile_rejects_unregistered_parser() {
            let sandbox = ParserSandbox::new();
            let wasm = wat::parse_str(identity_wat()).unwrap();

            let mut reg = ParserRegistry::new();
            let err = reg
                .compile_parser(&sandbox, "nonexistent", &wasm)
                .unwrap_err();
            assert!(
                matches!(err, RegistryError::CompileError(_)),
                "expected CompileError, got: {err}"
            );
        }

        #[test]
        fn execute_rejects_uncompiled_parser() {
            let sandbox = ParserSandbox::new();
            let reg = ParserRegistry::new();
            let err = reg
                .execute_parser(&sandbox, "missing", b"input", 100_000)
                .unwrap_err();
            assert!(
                matches!(err, RegistryError::CompileError(_)),
                "expected CompileError, got: {err}"
            );
        }

        #[test]
        fn determinism_via_registry() {
            let sandbox = ParserSandbox::new();
            let wasm = wat::parse_str(identity_wat()).unwrap();
            let hash = wasm_hash(&wasm);

            let mut reg = ParserRegistry::new();
            reg.register_parser(ParserDeclaration {
                parser_id: "det_test".into(),
                version: "1.0.0".into(),
                build_hash: hash,
                input_format: "bytes".into(),
                output_schema: "bytes".into(),
                is_deterministic: true,
                ..Default::default()
            })
            .unwrap();
            reg.compile_parser(&sandbox, "det_test", &wasm).unwrap();

            let out1 = reg
                .execute_parser(&sandbox, "det_test", b"abc", 100_000)
                .unwrap();
            let out2 = reg
                .execute_parser(&sandbox, "det_test", b"abc", 100_000)
                .unwrap();
            assert_eq!(out1, out2, "same input must produce identical output");
        }
    }
}
