//! The bare tier is a declared insecure mode (Program C, phase C0).
//!
//! # What the bare tier is
//!
//! `--driver local --allow-local-driver` runs each pod's tool-proxy as a plain
//! host process, and on a non-root node every child it runs is at the node's
//! own uid (`nucleus::hardening`, `Posture::Unsandboxed`). Such a child can
//! read every file the node can: the 0700 state directory with the node's
//! signing keys, the identity CA, the federation issuer key. So it can sign
//! anything the node can sign, including an execution claim saying
//! `backend = firecracker, uid_isolated = true`.
//!
//! There is no isolation between a bare-tier workload and the node. C0 does
//! not repair that (that is phase C2, subordinate host ids); it makes it
//! honest:
//!
//! 1. **No trusted authority.** A node in this mode refuses to start, naming
//!    the flag, when anything is configured whose trust would outlive the
//!    node's own process: a federation issuer or exchange, credentialed
//!    upstreams, external certificate anchors, TPM / node evidence, the public
//!    evidence listener, owner-decision trust roots, audit sinks or their
//!    credential minter, or the external trust API
//!    ([`refuse_trusted_authorities`]).
//! 2. **A separate signing domain.** Everything the node signs as evidence
//!    (execution receipts, pod receipts, Article 12 attestations) is signed
//!    with an insecure key under a kid with
//!    [`INSECURE_SHARED_UID_KID_PREFIX`], and marked
//!    [`INSECURE_RECEIPT_TIER`] / [`SandboxTier::InsecureSharedUid`]. The
//!    executor key is never created, and a state directory holding one is
//!    refused ([`prepare_state_dir`]). Every verifier in this repository
//!    refuses that kid and that mark by name, so a child signing with the key
//!    it can read gains nothing a verifier accepts.
//! 3. **A state directory used this way stays this way.** Its keys were
//!    readable by workloads, so a node that separates its workloads refuses
//!    to start on it.
//!
//! What it does not do: the node's other keys (certificate root, approval,
//! task issuer, identity CA) remain readable by its workloads, so a workload
//! can impersonate the operator TO THIS NODE. They anchor nothing outside it,
//! which is what (1) guarantees.
//!
//! Not refused, by decision: `--root-minter-spiffe-id`. It names which caller
//! the node treats as its operator; it is an input to this node's own
//! authorization, trusted by nothing outside it, and the C1/C2 live-path gates
//! set it.

use std::path::{Path, PathBuf};

pub(crate) use nucleus_ci_verdict::execution::{INSECURE_SHARED_UID_KID_PREFIX, SandboxTier};

/// The pod receipt's `sandbox_tier` on a node in declared insecure mode.
pub(crate) const INSECURE_RECEIPT_TIER: &str = "insecure-shared-uid";

/// The file a node in declared insecure mode leaves in its state directory.
const INSECURE_MODE_MARKER: &str = "insecure-shared-uid.marker";

/// Which signing domain this node's evidence is in, decided once from the
/// operator's flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceTier {
    /// The driver keeps workloads away from the node's keys (a microVM, a
    /// container): evidence is signed with the executor key.
    Separated,
    /// The bare tier: workloads share the node's uid. See the module docs.
    InsecureSharedUid,
}

impl EvidenceTier {
    /// The one decider: the bare-tier opt-in is the insecure mode.
    ///
    /// Decided from the operator's flags, not from the node's uid. A root
    /// node's bare-tier children drop to an unprivileged uid, but they still
    /// run with no namespace, no seccomp and no VM; the flag that said "no VM
    /// isolation" is what declares the mode.
    pub(crate) fn of(opt_in: nucleus::UnsandboxedOptIn) -> Self {
        match opt_in {
            nucleus::UnsandboxedOptIn::Explicit => Self::InsecureSharedUid,
            nucleus::UnsandboxedOptIn::Absent => Self::Separated,
        }
    }

    /// The declaration an execution claim carries.
    pub(crate) fn claim_tier(self) -> SandboxTier {
        match self {
            Self::Separated => SandboxTier::Driver,
            Self::InsecureSharedUid => SandboxTier::InsecureSharedUid,
        }
    }

    /// The pod receipt's `sandbox_tier`. Empty for a separating driver, as it
    /// has been since #2512.
    pub(crate) fn receipt_label(self) -> &'static str {
        match self {
            Self::Separated => "",
            Self::InsecureSharedUid => INSECURE_RECEIPT_TIER,
        }
    }
}

/// The kid of a node's insecure evidence key.
pub(crate) fn insecure_kid(key: &ed25519_dalek::SigningKey) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(key.verifying_key().as_bytes());
    format!(
        "{INSECURE_SHARED_UID_KID_PREFIX}{}",
        hex::encode(&digest[..8])
    )
}

/// Everything whose trust would outlive the node's process, as configured.
///
/// Each variant is one operator setting, named by its flag or variable in
/// [`TrustedAuthority::setting`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustedAuthority {
    /// `--federation-issuer`: assertions upstreams accept as this node.
    FederationIssuer,
    /// `--federation-listen`: the inbound federation exchange.
    FederationExchange,
    /// `--upstreams`: credentialed upstreams whose credentials the node holds.
    CredentialedUpstreams,
    /// `--cert-trust-anchors`: external roots of caller certificate chains.
    CertTrustAnchors,
    /// `--node-evidence-tpm`.
    NodeEvidenceTpm,
    /// `--node-evidence-software-tpm`.
    NodeEvidenceSoftwareTpm,
    /// `--node-evidence-reference`.
    NodeEvidenceReference,
    /// `--node-evidence-ak-pin`.
    NodeEvidenceAkPin,
    /// `--public-evidence-addr`: publishes the node's evidence key.
    PublicEvidence,
    /// `--decision-trust-roots`: owner-decision roots.
    DecisionTrustRoots,
    /// `--audit-sinks`.
    AuditSinks,
    /// `--audit-minter-socket`: mints scoped audit credentials.
    AuditMinter,
    /// `TRUST_API_URL`: the external trust API receipts are reported to.
    TrustApiUrl,
    /// `TRUST_RECEIPT_SECRET`: that API's shared secret.
    TrustReceiptSecret,
    /// `TRUST_EXECUTOR_ID`: an executor identity that would replace the
    /// insecure kid.
    TrustExecutorId,
}

impl TrustedAuthority {
    /// The flag or variable that configures it, as the refusal names it.
    pub(crate) fn setting(self) -> &'static str {
        match self {
            Self::FederationIssuer => "--federation-issuer",
            Self::FederationExchange => "--federation-listen",
            Self::CredentialedUpstreams => "--upstreams",
            Self::CertTrustAnchors => "--cert-trust-anchors",
            Self::NodeEvidenceTpm => "--node-evidence-tpm",
            Self::NodeEvidenceSoftwareTpm => "--node-evidence-software-tpm",
            Self::NodeEvidenceReference => "--node-evidence-reference",
            Self::NodeEvidenceAkPin => "--node-evidence-ak-pin",
            Self::PublicEvidence => "--public-evidence-addr",
            Self::DecisionTrustRoots => "--decision-trust-roots",
            Self::AuditSinks => "--audit-sinks",
            Self::AuditMinter => "--audit-minter-socket",
            Self::TrustApiUrl => "TRUST_API_URL",
            Self::TrustReceiptSecret => "TRUST_RECEIPT_SECRET",
            Self::TrustExecutorId => "TRUST_EXECUTOR_ID",
        }
    }
}

/// The trusted authorities the node's flags and environment configure.
///
/// Each flattened argument struct is destructured without `..` (ADR 0007
/// E-1), so a flag added to one of them does not compile until it is
/// classified here.
pub(crate) fn configured(
    args: &crate::Args,
    env: impl Fn(&str) -> Option<String>,
) -> Vec<TrustedAuthority> {
    use TrustedAuthority as T;
    let mut out = Vec::new();
    let mut when = |set: bool, authority: T| {
        if set {
            out.push(authority);
        }
    };

    let crate::pod_authority::AuthorityArgs {
        // This node's own operator identity; trusted by nothing outside it.
        root_minter_spiffe_id: _,
        cert_trust_anchors,
        max_children_per_pod: _,
        upstreams,
        federation_issuer,
        ingress,
        approvals: _,
    } = &args.authority;
    when(!cert_trust_anchors.is_empty(), T::CertTrustAnchors);
    when(upstreams.is_some(), T::CredentialedUpstreams);
    when(federation_issuer.is_some(), T::FederationIssuer);
    let crate::federation_ingress::FederationArgs {
        // Proof requirements on callers: they narrow, never extend, trust.
        request_proof_api_origin: _,
        request_proof_exchange_origin: _,
        federation_listen,
        federation_max_concurrent: _,
        federation_tls_cert: _,
        federation_tls_key: _,
    } = ingress;
    when(federation_listen.is_some(), T::FederationExchange);

    for authority in args.node_evidence.trusted_authorities() {
        when(true, authority);
    }
    let crate::public_evidence::PublicEvidenceArgs {
        addr,
        tls_cert: _,
        tls_key: _,
        requests_per_sec: _,
    } = &args.node_evidence.public;
    when(addr.is_some(), T::PublicEvidence);

    when(args.decisions.configured(), T::DecisionTrustRoots);

    let crate::audit_sink::AuditSinkArgs {
        audit_minter_socket,
        audit_sinks,
    } = &args.audit_sinks;
    when(audit_sinks.is_some(), T::AuditSinks);
    when(audit_minter_socket.is_some(), T::AuditMinter);

    when(
        env("TRUST_API_URL").is_some_and(|v| !v.is_empty()),
        T::TrustApiUrl,
    );
    when(env("TRUST_RECEIPT_SECRET").is_some(), T::TrustReceiptSecret);
    when(env("TRUST_EXECUTOR_ID").is_some(), T::TrustExecutorId);
    out
}

/// Refuse to start in insecure mode with any trusted authority configured,
/// naming every one.
///
/// # Errors
/// The node is in [`EvidenceTier::InsecureSharedUid`] and `configured` is not
/// empty.
pub(crate) fn refuse_trusted_authorities(
    tier: EvidenceTier,
    configured: &[TrustedAuthority],
) -> Result<(), String> {
    match tier {
        EvidenceTier::Separated => Ok(()),
        EvidenceTier::InsecureSharedUid => match configured {
            [] => Ok(()),
            some => Err(format!(
                "--allow-local-driver runs workloads at the node's own uid, where they can read \
                 every key this node holds (the bare tier is insecure; see \
                 docs/bare-tier-insecure.md). A node in that mode is trusted by nothing outside \
                 it, so it refuses to start with: {}",
                some.iter()
                    .map(|a| a.setting())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        },
    }
}

/// Check, and mark, the state directory for `tier`.
///
/// * Insecure: a state directory holding an executor key is refused (the
///   node would hand its workloads a key verifiers trust), and the directory
///   is marked.
/// * Separated: a marked directory is refused: its keys were readable by
///   workloads.
///
/// # Errors
/// As above, or the marker cannot be written.
pub(crate) fn prepare_state_dir(tier: EvidenceTier, state_dir: &Path) -> Result<(), String> {
    let marker = state_dir.join(INSECURE_MODE_MARKER);
    match tier {
        EvidenceTier::Separated => match marker.symlink_metadata() {
            Ok(_) => Err(format!(
                "{} was used by a node in insecure mode (--allow-local-driver): every key in it \
                 was readable by that node's workloads. A node that separates its workloads \
                 does not start on it; use a fresh --state-dir",
                state_dir.display()
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", marker.display())),
        },
        EvidenceTier::InsecureSharedUid => {
            let held: Vec<PathBuf> = crate::keys::executor_key_files(state_dir);
            if !held.is_empty() {
                return Err(format!(
                    "--allow-local-driver: {} holds this node's executor key ({}), which \
                     verifiers trust; in insecure mode its workloads could read it. Use a fresh \
                     --state-dir for the bare tier",
                    state_dir.display(),
                    held.iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            std::fs::write(
                &marker,
                "This state directory was used by a nucleus-node in declared insecure mode \
                 (--allow-local-driver): its workloads could read every key in it.\n",
            )
            .map_err(|e| format!("{}: {e}", marker.display()))
        }
    }
}

#[cfg(test)]
#[path = "insecure_mode_tests.rs"]
mod tests;
