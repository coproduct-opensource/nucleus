//! `EgressProxyTrust` (ADR 0015 §4/§8, step E3, guest side): the trust bundle
//! the workload's TLS clients use, so the pod's egress proxy can terminate
//! their TLS with a leaf its pod CA minted.
//!
//! guest-init fetches the pod CA's **certificate** over `FETCH_EGRESS_CA`
//! (never a key: the node hands the key only to the pod's proxy), and writes
//! [`TRUST_BUNDLE`]: the guest's own CA bundle with the pod CA appended. The
//! path is exported to the tool-proxy as [`TRUST_BUNDLE_ENV`]; pointing the
//! workload's clients at it is the tool-proxy's (its workload environment is
//! declared, not inherited).
//!
//! The bundle lives on `/run`, a fresh tmpfs every boot, so a snapshot base
//! never carries one pod's CA into another (`FETCH_EGRESS_CA` personalises the
//! VM for the same reason).

/// Where the trust bundle is written. `/run` is a tmpfs created at each boot.
pub const TRUST_BUNDLE: &str = "/run/nucleus/egress-trust.pem";

/// The variable that names [`TRUST_BUNDLE`] to the tool-proxy.
pub const TRUST_BUNDLE_ENV: &str = "NUCLEUS_EGRESS_TRUST_BUNDLE";

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// Why a served CA was not trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// Not exactly one PEM certificate block, and nothing else.
    NotOneCertificate,
    /// Key material where only a certificate belongs. The node never sends
    /// one; a reply that carries one is refused rather than installed.
    CarriesAKey,
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TrustError::NotOneCertificate => {
                "the served egress CA is not exactly one PEM certificate"
            }
            TrustError::CarriesAKey => "the served egress CA carries key material",
        })
    }
}

/// The served CA, checked: exactly one `CERTIFICATE` block and no key.
///
/// # Errors
/// [`TrustError`], named.
pub fn checked_ca(pem: &str) -> Result<&str, TrustError> {
    if pem.contains("PRIVATE KEY") {
        return Err(TrustError::CarriesAKey);
    }
    let pem = pem.trim();
    let one_block = pem.starts_with(BEGIN)
        && pem.ends_with(END)
        && pem.matches(BEGIN).count() == 1
        && pem.matches(END).count() == 1;
    if one_block {
        Ok(pem)
    } else {
        Err(TrustError::NotOneCertificate)
    }
}

/// The bundle to write: the guest's own roots (if it has any) followed by the
/// pod CA. Appending keeps every root the image trusts; the pod CA adds the
/// names its constraints permit, and nothing beyond them.
///
/// # Errors
/// [`TrustError`] for a served CA that is not one clean certificate.
pub fn trust_bundle(system_roots: Option<&str>, pod_ca_pem: &str) -> Result<String, TrustError> {
    let ca = checked_ca(pod_ca_pem)?;
    let mut out = String::new();
    if let Some(roots) = system_roots {
        out.push_str(roots.trim_end());
        out.push('\n');
    }
    out.push_str(ca);
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    #[test]
    fn the_pod_ca_is_appended_to_the_guest_roots() {
        let roots = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----";
        let b = trust_bundle(Some(roots), CA).unwrap();
        assert!(b.starts_with(roots));
        assert!(b.trim_end().ends_with("AAAA\n-----END CERTIFICATE-----"));
        assert_eq!(b.matches(BEGIN).count(), 2);
    }

    #[test]
    fn without_guest_roots_the_bundle_is_the_pod_ca() {
        assert_eq!(trust_bundle(None, CA).unwrap(), CA);
    }

    #[test]
    fn a_reply_carrying_a_key_is_refused() {
        let with_key =
            format!("{CA}-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n");
        assert_eq!(trust_bundle(None, &with_key), Err(TrustError::CarriesAKey));
    }

    #[test]
    fn anything_but_one_certificate_is_refused() {
        for bad in [
            "",
            "not pem",
            &format!("{CA}{CA}"),
            "-----BEGIN CERTIFICATE-----\nAAAA",
        ] {
            assert_eq!(
                trust_bundle(None, bad),
                Err(TrustError::NotOneCertificate),
                "{bad:?}"
            );
        }
    }
}
