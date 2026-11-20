//! One entry point for every standard attestation format.
//!
//! [`ExportFormat`] is the single decider for the format names a caller may
//! ask for — the `nucleus envelope-export --format` flag and the
//! control-plane's `GET /v1/jobs/{id}/attestation?format=` both parse
//! through it — and [`Bundle::export_attestation`] is the single dispatch
//! from a name to the adapter that produces it.

use std::str::FromStr;

use nucleus_lineage::EdgeSigner;
use serde::{Deserialize, Serialize};

use crate::bundle::Bundle;
use crate::interop::in_toto::{DsseEnvelope, InTotoError};
use crate::interop::sigstore::SigstoreBundle;

/// A standard attestation format a [`Bundle`] can be exported as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum ExportFormat {
    /// DSSE envelope over an in-toto Statement with the nucleus
    /// agent-provenance predicate.
    InToto,
    /// DSSE envelope over an in-toto Statement with a SLSA Provenance v1
    /// predicate.
    Slsa,
    /// Sigstore Bundle v0.3 carrying the [`ExportFormat::InToto`] envelope.
    Sigstore,
    /// Sigstore Bundle v0.3 carrying the [`ExportFormat::Slsa`] envelope.
    SigstoreSlsa,
}

impl ExportFormat {
    /// Every format, in the order they are listed to a user.
    pub const ALL: [Self; 4] = [Self::InToto, Self::Slsa, Self::Sigstore, Self::SigstoreSlsa];

    /// The format's wire name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::InToto => "in-toto",
            Self::Slsa => "slsa",
            Self::Sigstore => "sigstore",
            Self::SigstoreSlsa => "sigstore-slsa",
        }
    }
}

/// A format name that is not one of [`ExportFormat::ALL`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownExportFormat(pub String);

impl std::fmt::Display for UnknownExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown attestation format {:?}; expected one of:",
            self.0
        )?;
        for (i, format) in ExportFormat::ALL.iter().enumerate() {
            let sep = if i == 0 { " " } else { ", " };
            write!(f, "{sep}{}", format.name())?;
        }
        Ok(())
    }
}

impl std::error::Error for UnknownExportFormat {}

impl FromStr for ExportFormat {
    type Err = UnknownExportFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|f| f.name() == s)
            .ok_or_else(|| UnknownExportFormat(s.to_string()))
    }
}

impl TryFrom<String> for ExportFormat {
    type Error = UnknownExportFormat;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// An exported attestation, serialized as its format's own JSON document.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Attestation {
    /// A bare DSSE envelope ([`ExportFormat::InToto`], [`ExportFormat::Slsa`]).
    Dsse(DsseEnvelope),
    /// A Sigstore Bundle ([`ExportFormat::Sigstore`], [`ExportFormat::SigstoreSlsa`]).
    Sigstore(SigstoreBundle),
}

impl Bundle {
    /// Export this bundle as `format`, signed by `signer`.
    ///
    /// Does not verify the bundle — verify it against an out-of-band trust
    /// anchor first, or attest only bundles this process produced.
    pub fn export_attestation(
        &self,
        format: ExportFormat,
        signer: &dyn EdgeSigner,
    ) -> Result<Attestation, InTotoError> {
        Ok(match format {
            ExportFormat::InToto => Attestation::Dsse(self.to_in_toto_dsse(signer)?),
            ExportFormat::Slsa => Attestation::Dsse(self.to_slsa_dsse(signer)?),
            ExportFormat::Sigstore => {
                Attestation::Sigstore(self.to_sigstore_bundle_intoto(signer)?)
            }
            ExportFormat::SigstoreSlsa => {
                Attestation::Sigstore(self.to_sigstore_bundle_slsa(signer)?)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_parses_back_to_its_format() {
        for f in ExportFormat::ALL {
            assert_eq!(f.name().parse::<ExportFormat>(), Ok(f));
            let via_serde: ExportFormat =
                serde_json::from_value(serde_json::json!(f.name())).unwrap();
            assert_eq!(via_serde, f);
        }
    }

    #[test]
    fn the_error_lists_the_known_names() {
        let msg = "c2pa".parse::<ExportFormat>().unwrap_err().to_string();
        assert!(
            msg.ends_with("expected one of: in-toto, slsa, sigstore, sigstore-slsa"),
            "{msg}"
        );
    }

    #[test]
    fn unknown_names_are_refused() {
        for bad in ["", "c2pa", "In-Toto", "slsa ", "sigstore_slsa"] {
            assert!(bad.parse::<ExportFormat>().is_err(), "{bad:?}");
            assert!(serde_json::from_value::<ExportFormat>(serde_json::json!(bad)).is_err());
        }
    }
}
