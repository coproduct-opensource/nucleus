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
// ParserDeclaration
// ═══════════════════════════════════════════════════════════════════════════

/// A registered parser: a content-addressed, versioned function that converts
/// one data format into a typed schema.
///
/// Example: a JSON parser that reads raw bytes and produces `company_record`
/// structs. The `build_hash` pins the exact binary so replay verification can
/// re-execute the identical code path.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

// ═══════════════════════════════════════════════════════════════════════════
// TransformDeclaration
// ═══════════════════════════════════════════════════════════════════════════

/// A registered transform: a content-addressed, versioned pure function
/// that maps one schema to another.
///
/// Structurally identical to [`ParserDeclaration`] but semantically distinct:
/// parsers convert raw formats to typed schemas, transforms map between schemas.
#[derive(Debug, Clone, PartialEq, Eq)]
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
            #[cfg(feature = "serde")]
            Self::ParseError { path, message } => {
                write!(f, "failed to parse '{path}': {message}")
            }
            #[cfg(feature = "serde")]
            Self::IoError { path, message } => {
                write!(f, "I/O error at '{path}': {message}")
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
#[derive(Debug, Clone, Default)]
pub struct ParserRegistry {
    parsers: BTreeMap<String, ParserDeclaration>,
    transforms: BTreeMap<String, TransformDeclaration>,
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
    /// Returns `Err(RegistryError::ConflictingHash)` if the ID exists with a
    /// different `build_hash`.
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
    /// Same idempotency and conflict semantics as [`Self::register_parser`].
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
        };

        let serialized = toml::to_string(&decl).unwrap();
        assert!(!serialized.contains("test_corpus_hash"));
        let deserialized: ParserDeclaration = toml::from_str(&serialized).unwrap();
        assert_eq!(decl, deserialized);
    }
}
