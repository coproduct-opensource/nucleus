//! A pod manifest's content hash: the `manifest_hash` a v3 pod receipt carries.
//!
//! # Why not the YAML
//!
//! Receipts up to v2 hashed `serde_yaml::to_string(spec)`. That made a YAML
//! emitter's quoting and float formatting part of a signed wire format: the
//! hash moved whenever the emitter did, and no one outside the node could
//! recompute it without that exact emitter. Replacing serde_yaml (its
//! `unsafe-libyaml` is unmaintained) changes those bytes for almost every real
//! spec, so the hash is moved to an encoding that is canonical by definition:
//!
//! ```text
//! manifest_hash = hex(SHA-256( MANIFEST_HASH_DOMAIN || RFC 8785 JSON of the PodSpec ))
//! ```
//!
//! The domain tag means a v3 hash is never the SHA-256 of some document's bytes,
//! so it cannot collide with a v2 hash of a YAML file that happens to be valid
//! JSON. The YAML-bytes path is gone, not kept beside this one (G-1).
//!
//! # Fails closed
//!
//! A spec that has no canonical JSON has no manifest hash, and that is an error
//! the caller must handle. The v2 path hashed `""` in that case
//! (`unwrap_or_default`), so two unserialisable specs shared one hash (ADR 0007
//! A-2, B-4).
//!
//! A non-finite float is the case that would otherwise slip through: serde_json
//! writes NaN and ±infinity as `null`, so `base_cost_usd: .nan` and `.inf`
//! would share a hash. [`finite::check`] refuses them first, over the whole
//! value, so a float field added later is covered without being named.

use sha2::{Digest, Sha256};

use crate::PodSpec;

/// The prefix absorbed before the canonical JSON. Changing it is a receipt
/// version bump.
pub const MANIFEST_HASH_DOMAIN: &[u8] = b"nucleus.pod-manifest.v3\0";

/// A pod manifest's v3 content hash, lowercase hex. Minted only by
/// [`PodSpec::manifest_hash`] (C-1): there is no constructor from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestHash(String);

impl ManifestHash {
    /// The hex digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The hex digest, owned (for a receipt's wire field).
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for ManifestHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a spec has no manifest hash.
#[derive(Debug, thiserror::Error)]
#[error("pod spec has no canonical JSON form: {0}")]
pub struct ManifestHashError(String);

impl PodSpec {
    /// This spec's v3 manifest hash. See the [module docs](self).
    ///
    /// # Errors
    ///
    /// [`ManifestHashError`] when the spec has no RFC 8785 form. Never a hash of
    /// nothing.
    pub fn manifest_hash(&self) -> Result<ManifestHash, ManifestHashError> {
        finite::check(self).map_err(|e| ManifestHashError(e.to_string()))?;
        let canonical =
            serde_json_canonicalizer::to_vec(self).map_err(|e| ManifestHashError(e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_HASH_DOMAIN);
        hasher.update(&canonical);
        Ok(ManifestHash(hex::encode(hasher.finalize())))
    }
}

/// A serializer that writes nothing and refuses every non-finite float.
mod finite {
    use serde::Serialize;
    use serde::ser::{self, Serializer};

    #[derive(Debug)]
    pub(super) struct NonFinite(String);

    impl std::fmt::Display for NonFinite {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for NonFinite {}

    impl ser::Error for NonFinite {
        fn custom<T: std::fmt::Display>(msg: T) -> Self {
            Self(msg.to_string())
        }
    }

    pub(super) fn check<T: Serialize + ?Sized>(value: &T) -> Result<(), NonFinite> {
        value.serialize(Finite)
    }

    #[derive(Clone, Copy)]
    struct Finite;

    fn float(v: f64) -> Result<(), NonFinite> {
        if v.is_finite() {
            Ok(())
        } else {
            Err(NonFinite(format!(
                "a non-finite float ({v}) has no canonical JSON form"
            )))
        }
    }

    macro_rules! ok {
        ($($name:ident($ty:ty)),* $(,)?) => {
            $(fn $name(self, _: $ty) -> Result<(), NonFinite> { Ok(()) })*
        };
    }

    impl Serializer for Finite {
        type Ok = ();
        type Error = NonFinite;
        type SerializeSeq = Self;
        type SerializeTuple = Self;
        type SerializeTupleStruct = Self;
        type SerializeTupleVariant = Self;
        type SerializeMap = Self;
        type SerializeStruct = Self;
        type SerializeStructVariant = Self;

        ok!(
            serialize_bool(bool),
            serialize_i8(i8),
            serialize_i16(i16),
            serialize_i32(i32),
            serialize_i64(i64),
            serialize_i128(i128),
            serialize_u8(u8),
            serialize_u16(u16),
            serialize_u32(u32),
            serialize_u64(u64),
            serialize_u128(u128),
            serialize_char(char),
            serialize_str(&str),
            serialize_bytes(&[u8]),
            serialize_unit_struct(&'static str),
        );

        fn serialize_f32(self, v: f32) -> Result<(), NonFinite> {
            float(f64::from(v))
        }
        fn serialize_f64(self, v: f64) -> Result<(), NonFinite> {
            float(v)
        }
        fn serialize_none(self) -> Result<(), NonFinite> {
            Ok(())
        }
        fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> Result<(), NonFinite> {
            v.serialize(self)
        }
        fn serialize_unit(self) -> Result<(), NonFinite> {
            Ok(())
        }
        fn serialize_unit_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
        ) -> Result<(), NonFinite> {
            Ok(())
        }
        fn serialize_newtype_struct<T: Serialize + ?Sized>(
            self,
            _: &'static str,
            v: &T,
        ) -> Result<(), NonFinite> {
            v.serialize(self)
        }
        fn serialize_newtype_variant<T: Serialize + ?Sized>(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            v: &T,
        ) -> Result<(), NonFinite> {
            v.serialize(self)
        }
        fn serialize_seq(self, _: Option<usize>) -> Result<Self, NonFinite> {
            Ok(self)
        }
        fn serialize_tuple(self, _: usize) -> Result<Self, NonFinite> {
            Ok(self)
        }
        fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self, NonFinite> {
            Ok(self)
        }
        fn serialize_tuple_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self, NonFinite> {
            Ok(self)
        }
        fn serialize_map(self, _: Option<usize>) -> Result<Self, NonFinite> {
            Ok(self)
        }
        fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self, NonFinite> {
            Ok(self)
        }
        fn serialize_struct_variant(
            self,
            _: &'static str,
            _: u32,
            _: &'static str,
            _: usize,
        ) -> Result<Self, NonFinite> {
            Ok(self)
        }
    }

    macro_rules! compound {
        ($($tr:ident :: $method:ident),* $(,)?) => {
            $(impl ser::$tr for Finite {
                type Ok = ();
                type Error = NonFinite;
                fn $method<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), NonFinite> {
                    v.serialize(*self)
                }
                fn end(self) -> Result<(), NonFinite> {
                    Ok(())
                }
            })*
        };
    }

    compound!(
        SerializeSeq::serialize_element,
        SerializeTuple::serialize_element,
        SerializeTupleStruct::serialize_field,
        SerializeTupleVariant::serialize_field,
    );

    impl ser::SerializeMap for Finite {
        type Ok = ();
        type Error = NonFinite;
        fn serialize_key<T: Serialize + ?Sized>(&mut self, k: &T) -> Result<(), NonFinite> {
            k.serialize(*self)
        }
        fn serialize_value<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), NonFinite> {
            v.serialize(*self)
        }
        fn end(self) -> Result<(), NonFinite> {
            Ok(())
        }
    }

    impl ser::SerializeStruct for Finite {
        type Ok = ();
        type Error = NonFinite;
        fn serialize_field<T: Serialize + ?Sized>(
            &mut self,
            _: &'static str,
            v: &T,
        ) -> Result<(), NonFinite> {
            v.serialize(*self)
        }
        fn end(self) -> Result<(), NonFinite> {
            Ok(())
        }
    }

    impl ser::SerializeStructVariant for Finite {
        type Ok = ();
        type Error = NonFinite;
        fn serialize_field<T: Serialize + ?Sized>(
            &mut self,
            _: &'static str,
            v: &T,
        ) -> Result<(), NonFinite> {
            v.serialize(*self)
        }
        fn end(self) -> Result<(), NonFinite> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = "apiVersion: nucleus/v1
kind: Pod
metadata:
  name: golden
  labels:
    team: platform
    mode: \"0755\"
spec:
  work_dir: .
  timeout_seconds: 600
  policy:
    type: profile
    name: codegen
  budget_model:
    base_cost_usd: 0.000001
    cost_per_second_usd: 0.0001
  network:
    dns_allow:
      - example.org
  credentials:
    env:
      LLM_API_TOKEN: test-token-123
";

    fn spec() -> PodSpec {
        nucleus_yaml::from_str(SPEC).expect("golden spec parses")
    }

    /// The golden value. If this moves, every v3 receipt's manifest hash moved:
    /// that is a receipt version bump, not a test update.
    #[test]
    fn golden_manifest_hash() {
        assert_eq!(
            spec().manifest_hash().unwrap().as_str(),
            "0d3c43d6422aee0ceb8c5235538380b2ac0ed8f757ba400ce4c8a048908f3d00"
        );
    }

    /// The hash is of the spec, not of how it was written: reordered keys,
    /// different quoting and a flow mapping are the same manifest.
    #[test]
    fn hash_ignores_yaml_presentation() {
        let respelled: PodSpec = nucleus_yaml::from_str(
            "kind: Pod\napiVersion: 'nucleus/v1'\nspec: {timeout_seconds: 600, work_dir: '.', \
             policy: {name: codegen, type: profile}, \
             budget_model: {cost_per_second_usd: 1.0e-4, base_cost_usd: 1e-6}, \
             network: {dns_allow: [example.org]}, \
             credentials: {env: {LLM_API_TOKEN: \"test-token-123\"}}}\n\
             metadata: {labels: {mode: '0755', team: platform}, name: golden}\n",
        )
        .unwrap();
        assert_eq!(
            respelled.manifest_hash().unwrap(),
            spec().manifest_hash().unwrap()
        );
    }

    /// Any change to the spec moves the hash.
    #[test]
    fn hash_moves_with_the_spec() {
        let mut other = spec();
        other
            .metadata
            .labels
            .insert("team".into(), "platform2".into());
        assert_ne!(
            other.manifest_hash().unwrap(),
            spec().manifest_hash().unwrap()
        );
    }

    /// The v2 rule — SHA-256 of the YAML text — is gone (G-1): the v3 hash is
    /// neither that, nor the bare SHA-256 of the canonical JSON (the domain tag
    /// is absorbed).
    #[test]
    fn v2_yaml_bytes_hash_is_not_the_manifest_hash() {
        let spec = spec();
        let v3 = spec.manifest_hash().unwrap();
        let yaml = nucleus_yaml::to_string(&spec).unwrap();
        assert_ne!(v3.as_str(), hex::encode(Sha256::digest(yaml.as_bytes())));
        assert_ne!(v3.as_str(), hex::encode(Sha256::digest(SPEC.as_bytes())));
        let jcs = serde_json_canonicalizer::to_vec(&spec).unwrap();
        assert_ne!(v3.as_str(), hex::encode(Sha256::digest(&jcs)));
        let mut tagged = MANIFEST_HASH_DOMAIN.to_vec();
        tagged.extend(jcs);
        assert_eq!(v3.as_str(), hex::encode(Sha256::digest(&tagged)));
    }

    /// A spec with no canonical JSON has no hash. The v2 path hashed "" here,
    /// and serde_json alone would write every non-finite float as `null`, so NaN
    /// and infinity would share one.
    #[test]
    fn unserialisable_spec_is_an_error_not_an_empty_hash() {
        for bad_value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut bad = spec();
            bad.spec
                .budget_model
                .as_mut()
                .expect("golden spec has a budget")
                .base_cost_usd = bad_value;
            assert!(bad.manifest_hash().is_err(), "{bad_value} must not hash");
        }
        // Reached through YAML too: `.nan` is a valid f64 spelling.
        let from_yaml: PodSpec = nucleus_yaml::from_str(&SPEC.replace("0.000001", ".nan")).unwrap();
        assert!(from_yaml.manifest_hash().is_err());
    }
}
