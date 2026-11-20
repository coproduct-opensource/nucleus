//! The per-pod egress CA (ADR 0015 §4, step E3, node side), built to
//! `TlsTermination.lean`.
//!
//! At admission the node mints, for an eval cell with an egress proxy, one CA:
//!
//! * ECDSA P-256;
//! * `nameConstraints` whose permitted DNS subtrees are exactly the registry's
//!   `https://` hosts plus the link namespace [`LINK_SUBTREE`] (ADR 0017);
//! * `notAfter` no later than the pod's deadline (admission + its timeout).
//!
//! The CA **key** goes to exactly one place: that pod's proxy, as the first
//! bytes on the proxy's decision channel ([`MintedCa::hand_over`]), the model's
//! `ca_key_stays_in_proxy`. It is never put in `PodMaterial`, a workload-API
//! reply, argv, the environment or a file. The guest gets the **certificate**
//! only ([`MintedCa::certificate_pem`]), through `FETCH_EGRESS_CA`.
//!
//! # Why the decision channel and not an inherited descriptor
//!
//! The proxy was built to read `--tls-ca-fd N` (`70aeecf13`). That cannot work
//! for a confined child: the confinement hook marks every descriptor from 3 up
//! close-on-exec (`nucleus::hardening`, `harden_child`, the
//! `CLOSE_RANGE_CLOEXEC` sweep), so no descriptor above stderr survives the
//! exec, and stdin and stdout are already the guest listener and the decision
//! channel. The decision channel is a socket pair whose other end only this
//! node holds, so the key crosses exactly the boundary the fd would have. The
//! proxy must read the bundle from it before its first `Decide`
//! (`--tls-ca-channel`); that read is the proxy's half and lands with it.
//!
//! # How the node's copy is dropped
//!
//! [`MintedCa`] holds the key DER in a [`Zeroizing`] buffer and is not
//! `Clone`. [`MintedCa::hand_over`] takes it **by value** (ADR 0007 C-4): the
//! bundle is built into another `Zeroizing` buffer, written, and both are
//! wiped when the function returns, on success or error. No other method
//! exposes the key.

// Reached from `egress_proxy::mint_for_pod` and `start`, which are linux-only.
#![cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]

use std::fmt;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, GeneralSubtree, IsCa, KeyPair,
    KeyUsagePurpose, NameConstraints, PKCS_ECDSA_P256_SHA256,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The DNS subtree every ADR 0017 link name lives under. `.invalid` (RFC
/// 6761) never resolves publicly, so a link name cannot be mistaken for, or
/// fronted as, a real host. The proxy's constant, so the CA the node mints and
/// the subtree the link proxy requires are one fact (ADR 0007 G-1).
pub(crate) use nucleus_egress_proxy::link::LINK_SUBTREE;

/// One pod's CA as the node holds it, between admission and the handover.
pub(crate) struct MintedCa {
    cert_der: Vec<u8>,
    key_der: Zeroizing<Vec<u8>>,
    permitted: Vec<String>,
    not_after: u64,
}

impl fmt::Debug for MintedCa {
    // The key is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedCa")
            .field("permitted", &self.permitted)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

/// Why no CA was minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MintError {
    /// A permitted name that is not a DNS name the constraint can carry.
    BadName(String),
    /// The deadline is not a representable instant.
    Deadline,
    /// rcgen refused.
    Mint(String),
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MintError::BadName(n) => {
                write!(f, "{n:?} is not a DNS name a CA can be constrained to")
            }
            MintError::Deadline => f.write_str("the pod deadline is not a representable instant"),
            MintError::Mint(e) => write!(f, "minting the pod CA: {e}"),
        }
    }
}

/// A DNS name the constraint may carry: lower-case LDH labels, no wildcard.
fn dns_name(name: &str) -> Option<String> {
    let name = name.to_ascii_lowercase();
    let ok = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    ok.then_some(name)
}

/// The permitted subtrees for a pod: the registry's https hosts, then
/// [`LINK_SUBTREE`], de-duplicated, in that order.
///
/// # Errors
/// [`MintError::BadName`] for a host that is not a DNS name.
pub(crate) fn permitted_names(https_hosts: &[String]) -> Result<Vec<String>, MintError> {
    let mut out: Vec<String> = Vec::new();
    for h in https_hosts.iter().map(String::as_str).chain([LINK_SUBTREE]) {
        let n = dns_name(h).ok_or_else(|| MintError::BadName(h.to_string()))?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok(out)
}

impl MintedCa {
    /// Mint pod `pod`'s CA for `https_hosts` (plus the link namespace), valid
    /// from `now` (unix seconds) until `now + timeout_seconds`.
    ///
    /// # Errors
    /// [`MintError`], named.
    pub(crate) fn mint(
        pod: Uuid,
        https_hosts: &[String],
        now: u64,
        timeout_seconds: u64,
    ) -> Result<MintedCa, MintError> {
        let permitted = permitted_names(https_hosts)?;
        let not_after = now
            .checked_add(timeout_seconds)
            .ok_or(MintError::Deadline)?;
        let to_time = |secs: u64| {
            i64::try_from(secs)
                .ok()
                .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
                .ok_or(MintError::Deadline)
        };
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| MintError::Mint(e.to_string()))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| MintError::Mint(e.to_string()))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("nucleus pod egress CA {pod}"));
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted
                .iter()
                .map(|n| GeneralSubtree::DnsName(n.clone()))
                .collect(),
            excluded_subtrees: Vec::new(),
        });
        params.not_before = to_time(now.saturating_sub(60))?;
        params.not_after = to_time(not_after)?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| MintError::Mint(e.to_string()))?;
        Ok(MintedCa {
            cert_der: cert.der().to_vec(),
            key_der: Zeroizing::new(key.serialize_der()),
            permitted,
            not_after,
        })
    }

    /// The CA certificate, DER. Public: this is what the guest trusts.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The CA certificate as PEM, for `FETCH_EGRESS_CA`. Never the key.
    #[must_use]
    pub(crate) fn certificate_pem(&self) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&self.cert_der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    /// The permitted subtrees the certificate carries.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn permitted(&self) -> &[String] {
        &self.permitted
    }

    /// The CA's deadline, unix seconds.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Split one CA into two holders, consuming it: one for the pod's egress
    /// proxy and one for its link proxy (ADR 0017 L4b). Both are the same
    /// pod's proxies, which is what `ca_key_stays_in_proxy` allows (its
    /// `Holder.proxy p` names the pod, not a process). Each half is still
    /// handed over by value and wiped; there is no `Clone`.
    #[must_use]
    pub(crate) fn split(self) -> (MintedCa, MintedCa) {
        let twin = MintedCa {
            cert_der: self.cert_der.clone(),
            key_der: Zeroizing::new(self.key_der.to_vec()),
            permitted: self.permitted.clone(),
            not_after: self.not_after,
        };
        (self, twin)
    }

    /// Write the `nucleus-pod-ca/1` bundle (the proxy's
    /// `PodCa::from_bundle` format) to `channel`, consuming the CA: the node's
    /// copy of the key is wiped when this returns, whatever the outcome.
    ///
    /// # Errors
    /// The write's I/O error.
    pub(crate) async fn hand_over<W>(self, channel: &mut W) -> std::io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let bundle = Zeroizing::new(nucleus_egress_proxy::tls::PodCa::to_bundle(
            &self.cert_der,
            &self.key_der,
        ));
        channel.write_all(&bundle).await?;
        channel.flush().await
        // `bundle` and `self.key_der` are dropped (and wiped) here.
    }
}

#[cfg(test)]
#[path = "pod_ca_tests.rs"]
mod tests;
