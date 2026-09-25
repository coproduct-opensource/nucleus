//! The execution receipt: what a pod did, as a value both transports serve.
//!
//! # Why this exists as a module
//!
//! The receipt was assembled inline in the gRPC handler, which made gRPC the only way to get one.
//! `Operation::GetReceipt` had existed in the authorization enum the whole time, and the Python
//! SDK has been calling `GET /v1/pods/{id}/receipt` — a route that did not exist, so the call
//! 404'd. A receipt that is produced and cannot be read is not evidence of anything.
//!
//! So the assembly moves here and both transports call it. One implementation rather than two
//! spellings, which is the shape that drifts: the whole reason the receipt is a content hash is
//! that two parties should be able to compute the same value, and that argument dies immediately
//! if the node itself has two ways of computing it.
//!
//! # The reporting side effect stays on gRPC, deliberately
//!
//! Building a receipt over gRPC also fires an *external* report to the trust API. That is a real
//! oddity — a read with an outward-facing side effect, so asking twice reports twice — and it
//! belongs at pod exit rather than at read time. It is not changed here: something outside this
//! repository may depend on it, and quietly dropping an outward-facing call is not a refactor.
//!
//! What this does refuse to do is *propagate* it. The HTTP route reads and does not report, which
//! is what a GET should be. The asymmetry is the bug being contained rather than spread, and it is
//! written down here so the next person finds a decision instead of an inconsistency.

// Declared HERE, not in main.rs, because this is the only thing that needs it:
// the read-back exists so a receipt can be built for a microVM. It also keeps
// `main.rs` off its line ceiling, which it was sitting exactly on.
#[path = "scratch_readback.rs"]
mod scratch_readback;

use std::sync::Arc;

use serde::Serialize;

use crate::{NodeState, PodHandle, PodState};

/// The receipt as served. Field-for-field the proto message, so the two transports cannot
/// disagree about what a receipt IS — `main.rs` converts, it does not re-derive.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Receipt {
    pub pod_id: String,
    pub workspace_hash: String,
    pub audit_tail_hash: String,
    pub audit_entry_count: u64,
    pub timestamp_unix: u64,
    pub manifest_hash: String,
    pub sandbox_tier: String,
    pub spiffe_id: String,
    pub version: u32,
    pub v1_content_hash: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cost_usd: f64,
    /// The node's signature over [`Receipt::preimage`], and the key that made
    /// it. Empty when this node could not sign — never a receipt that looks
    /// signed and is not.
    pub signature: String,
    pub signer_pubkey: String,
}

impl Receipt {
    /// The bytes the node signs.
    ///
    /// EXHAUSTIVELY DESTRUCTURED, so a field added to `Receipt` is an E0027
    /// here until someone says whether it is committed to. The silent failure
    /// of a digest is a field that quietly stopped counting, and this struct is
    /// the thing a receipt is ABOUT.
    ///
    /// Each part is absorbed tag-separated and length-prefixed, so no two
    /// distinct receipts share a preimage by concatenation, and nothing goes
    /// through `Debug` — `scripts/check-preimage-dylint.sh` gates that.
    ///
    /// `signature` and `signer_pubkey` are deliberately NOT in it: a signature
    /// cannot cover itself.
    pub fn preimage(&self) -> Vec<u8> {
        let Receipt {
            pod_id,
            workspace_hash,
            audit_tail_hash,
            audit_entry_count,
            timestamp_unix,
            manifest_hash,
            sandbox_tier,
            spiffe_id,
            version,
            v1_content_hash,
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cost_usd,
            signature: _,
            signer_pubkey: _,
        } = self;

        let mut out = Vec::new();
        let mut absorb = |tag: &str, bytes: &[u8]| {
            out.extend_from_slice(tag.as_bytes());
            out.push(0);
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        };
        absorb("pod_id", pod_id.as_bytes());
        absorb("workspace_hash", workspace_hash.as_bytes());
        absorb("audit_tail_hash", audit_tail_hash.as_bytes());
        absorb("audit_entry_count", &audit_entry_count.to_be_bytes());
        absorb("timestamp_unix", &timestamp_unix.to_be_bytes());
        absorb("manifest_hash", manifest_hash.as_bytes());
        absorb("sandbox_tier", sandbox_tier.as_bytes());
        absorb("spiffe_id", spiffe_id.as_bytes());
        absorb("version", &version.to_be_bytes());
        absorb("v1_content_hash", v1_content_hash.as_bytes());
        absorb("input_tokens", &input_tokens.to_be_bytes());
        absorb("output_tokens", &output_tokens.to_be_bytes());
        absorb("cache_read_tokens", &cache_read_tokens.to_be_bytes());
        // `to_bits` rather than `to_string`: a float's decimal rendering is a
        // formatting decision, and this is a digest preimage.
        absorb("cost_usd", &cost_usd.to_bits().to_be_bytes());
        out
    }
}

/// Why a receipt could not be produced.
///
/// Three cases rather than one string, because they mean different things to a caller: wait, look
/// elsewhere, and something is broken.
#[derive(Debug)]
pub(crate) enum ReceiptError {
    /// The pod is still running. Not an error so much as "not yet".
    NotExited,
    /// The pod exited without leaving an exit report — the tool proxy writes it at shutdown, so
    /// its absence usually means the pod died before shutdown ran.
    NoExitReport(String),
    /// The report is there and unreadable.
    Malformed(String),
    /// A report was found where the workload could have written it, and it does
    /// not carry this pod's supervisor signature. See `nucleus_spec::exit_report_auth`.
    Unauthenticated(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotExited => write!(f, "pod has not exited yet; receipt not available"),
            Self::NoExitReport(why) => write!(f, "exit report not found: {why}"),
            Self::Malformed(why) => write!(f, "failed to parse exit report: {why}"),
            Self::Unauthenticated(why) => {
                write!(f, "exit report is not the supervisor's: {why}")
            }
        }
    }
}

/// Everything the receipt was built from, kept so the trust report does not recompute any of it.
pub(crate) struct Built {
    pub receipt: Receipt,
    pub report: nucleus_spec::ExitReport,
    pub agent_identity: String,
    pub exit_code: i32,
}

/// Assemble the receipt for an exited pod.
///
/// # Errors
///
/// [`ReceiptError`] — still running, no exit report, or an unreadable one.
pub(crate) async fn build(
    handle: &Arc<PodHandle>,
    authority: &crate::pod_authority::PodAuthority,
) -> Result<Built, ReceiptError> {
    let id = handle.id;
    let state = handle.status().await;
    let PodState::Exited { code, .. } = state else {
        return Err(ReceiptError::NotExited);
    };

    let report = match &handle.driver_state {
        crate::DriverState::Firecracker(pod) => {
            let json = firecracker_report_json(pod).await?;
            parse_report(
                &json,
                &ReportSource::WorkloadOwnedImage {
                    pod_dir: pod.pod_dir.clone(),
                },
            )?
        }
        #[cfg(feature = "local-driver")]
        crate::DriverState::Local(_) => shared_directory_report(handle).await?,
        crate::DriverState::Container(_) => shared_directory_report(handle).await?,
    };

    let spec_yaml = serde_yaml::to_string(&handle.spec).unwrap_or_default();
    let manifest_hash =
        nucleus_identity::approval_bundle::compute_manifest_hash(spec_yaml.as_bytes());
    let v1_content_hash =
        crate::trust_gate::compute_v1_content_hash(&id.to_string(), &manifest_hash, &report);

    let labels = &handle.spec.metadata.labels;
    let agent_identity = labels
        .get("trust.coproduct.one/agent-id")
        .or_else(|| labels.get("spiffe.io/identity"))
        .cloned()
        .or_else(|| handle.spec.metadata.name.clone())
        .unwrap_or_else(|| id.to_string());
    let spiffe_id = labels
        .get("spiffe.io/identity")
        .cloned()
        .unwrap_or_default();

    let mut receipt = Receipt {
        pod_id: id.to_string(),
        workspace_hash: report.workspace_hash.clone(),
        audit_tail_hash: report.audit_tail_hash.clone(),
        audit_entry_count: report.audit_entry_count,
        timestamp_unix: report.timestamp_unix,
        manifest_hash,
        // EMPTY, and deliberately so since #2512. This field's only producer
        // was `trust.coproduct.one/profile`, a label the deleted reputation
        // lookup wrote from an external service's letter bracket. With that
        // path gone nothing produces a tier, and an empty string is the honest
        // report of that — the alternative was leaving a label read that can
        // never match, which reads like a live source.
        //
        // The field stays in the signed content (`absorb("sandbox_tier", …)`)
        // rather than being removed: it is in `nucleus-sdk`'s public `Receipt`
        // and dropping it is a wire change this issue did not scope. Feeding it
        // from the isolation level the pod ACTUALLY got would be better data
        // and is the natural follow-up; it is new behaviour, not a deletion.
        sandbox_tier: String::new(),
        spiffe_id,
        version: 1,
        v1_content_hash,
        input_tokens: report.input_tokens,
        output_tokens: report.output_tokens,
        cache_read_tokens: report.cache_read_tokens,
        cost_usd: report.cost_usd,
        // Filled below: the preimage is over the OTHER fields, so the
        // receipt has to exist before it can be signed.
        signature: String::new(),
        signer_pubkey: String::new(),
    };
    // The node signs, not the pod. See `PodAuthority::sign_pod_receipt` for why
    // this is the one place the MediationReceipt pattern is deliberately not
    // followed.
    receipt.signature = authority.sign_pod_receipt(&receipt.preimage());
    receipt.signer_pubkey = authority.root_pubkey_hex();

    Ok(Built {
        receipt,
        report,
        agent_identity,
        exit_code: code.unwrap_or(-1),
    })
}

/// Report the receipt to the external trust API, in the background.
///
/// Unchanged in behaviour from when this lived inline in the gRPC handler, including that it is
/// fire-and-forget: a trust API that is down must not make a receipt unreadable.
pub(crate) fn report_to_trust_gate(state: &NodeState, built: &Built) {
    let id = built.receipt.pod_id.clone();
    let r = &built.report;
    let receipt_report = crate::trust_gate::ReceiptReport {
        agent_id: built.agent_identity.clone(),
        session_id: id.clone(),
        success: built.exit_code == 0,
        cost_usd: r.cost_usd,
        tool_call_count: r.audit_entry_count,
        workspace_hash: r.workspace_hash.clone(),
        audit_tail_hash: r.audit_tail_hash.clone(),
        // Verified exposure from the tool proxy's GradedExposureGuard, written to
        // .nucleus-exit-report.json at shutdown.
        observed_exposure_labels: r.observed_exposure_labels.clone(),
        observed_risk_tier: if r.observed_risk_tier.is_empty() {
            "unknown".to_string()
        } else {
            r.observed_risk_tier.clone()
        },
        uninhabitable_reached: r.uninhabitable_reached,
        // Runtime-verification findings from the tool proxy's TraceMonitor.
        monitor_violations: r.monitor_violations.clone(),
        monitor_violations_dropped: r.monitor_violations_dropped,
        // Signed with the executor key, which the pod never sees. Taken at pod exit — after the
        // pod has stopped — so the head it binds is one the pod can no longer move.
        art12_attestation: crate::trust_gate::attest_art12(
            r,
            // What the HOST received, not what the pod reported.
            crate::art12_collector::observed_chain(&state.state_dir, &id).as_ref(),
            &id,
            &state.trust_gate.executor_id,
            &state.trust_gate.executor_signing_key,
        ),
        // Cryptographic session identity — required for the SandboxAttested upgrade path in the
        // trust-service session-complete handler.
        sandbox_identity: if built.receipt.spiffe_id.is_empty() {
            built.agent_identity.clone()
        } else {
            built.receipt.spiffe_id.clone()
        },
        v1_content_hash: built.receipt.v1_content_hash.clone(),
    };
    let trust_config = state.trust_gate.clone();
    let http_client = state.http_client.clone();
    tokio::spawn(async move {
        // In secure mode, pre-register the v1_content_hash so the handler can validate it when
        // observed_exposure_labels are present. Without this, session-complete returns 422 and the
        // NameHeuristic -> SandboxAttested upgrade is silently dropped.
        crate::trust_gate::register_receipt_hash(&trust_config, &receipt_report, &http_client)
            .await;
        crate::trust_gate::report_receipt(&trust_config, &receipt_report, &http_client).await;
    });
}

/// The gRPC shape, beside the type it is a shape OF.
///
/// This lived inline in `main.rs`'s `get_receipt`, which is why adding two
/// fields to `Receipt` pushed that file over its line ceiling. A mapping
/// between a type and its wire form belongs with the type: the two lists have
/// to stay equal, and `the_http_body_names_the_same_fields_the_proto_does`
/// checks exactly that — from here, where both are visible.
impl From<Receipt> for crate::proto::ExecutionReceipt {
    fn from(r: Receipt) -> Self {
        Self {
            pod_id: r.pod_id,
            workspace_hash: r.workspace_hash,
            audit_tail_hash: r.audit_tail_hash,
            audit_entry_count: r.audit_entry_count,
            timestamp_unix: r.timestamp_unix,
            manifest_hash: r.manifest_hash,
            sandbox_tier: r.sandbox_tier,
            spiffe_id: r.spiffe_id,
            version: r.version,
            v1_content_hash: r.v1_content_hash,
            extensions: std::collections::HashMap::new(),
            input_tokens: r.input_tokens,
            output_tokens: r.output_tokens,
            cache_read_tokens: r.cache_read_tokens,
            cost_usd: r.cost_usd,
            signature: r.signature,
            signer_pubkey: r.signer_pubkey,
        }
    }
}

/// Where the preserved copy of a Firecracker pod's report lives, in the host-owned pod dir.
const PRESERVED_REPORT: &str = "exit-report.json";

/// Read a local or container pod's report from the directory it shares with the host.
///
/// Unchanged in what it accepts: these drivers share the work dir with the workload
/// outright and have no per-pod mediation key to sign with, so this path never
/// claimed more than "the file in the pod's directory". A signed report found here
/// is unwrapped, not verified.
async fn shared_directory_report(
    handle: &Arc<PodHandle>,
) -> Result<nucleus_spec::ExitReport, ReceiptError> {
    let path = handle
        .spec
        .spec
        .work_dir
        .join(nucleus_spec::exit_report_auth::EXIT_REPORT_FILE);
    let json = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| ReceiptError::NoExitReport(format!("{}: {e}", path.display())))?;
    parse_report(&json, &ReportSource::SharedDirectory)
}

/// The Firecracker pod's report bytes: the copy preserved at teardown, else a
/// read-back from the jail's scratch image if the jail still exists.
///
/// The host's `work_dir` path is NOT consulted any more. A microVM shares no
/// directory with the host, so a file at that host path was never the guest's
/// report — and it was accepted unsigned.
async fn firecracker_report_json(pod: &crate::FirecrackerPod) -> Result<String, ReceiptError> {
    let preserved = pod.pod_dir.join(PRESERVED_REPORT);
    if let Ok(json) = tokio::fs::read_to_string(&preserved).await {
        return Ok(json);
    }
    let jail = pod.jail.lock().await;
    let Some(layout) = jail.as_ref() else {
        return Err(ReceiptError::NoExitReport(format!(
            "{}: not preserved, and the pod's jail is already gone",
            preserved.display()
        )));
    };
    read_from_image(layout)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .map_err(|e| ReceiptError::NoExitReport(format!("scratch image: {e}")))
}

fn read_from_image(
    layout: &crate::firecracker_config::JailLayout,
) -> Result<Vec<u8>, scratch_readback::ReadbackError> {
    let image = layout
        .jail_root
        .join(crate::firecracker_config::in_jail::SCRATCH.trim_start_matches('/'));
    // The guest mounts the image at `/work`, so `/work/<file>` is `/<file>` here.
    scratch_readback::read_file(
        &image,
        &format!("/{}", nucleus_spec::exit_report_auth::EXIT_REPORT_FILE),
    )
}

/// Copy the exit report out of the jail's scratch image into the pod dir.
///
/// Called after the VMM is killed and before the jail is removed. Without it the
/// report existed only inside the jail, and every way a Firecracker pod ends —
/// cancel, or the reaper — removed the jail first, so no receipt could ever be
/// built. Best effort by design: a missing report is reported when a receipt is
/// asked for, where the reason can be read.
pub(crate) fn preserve_exit_report(
    layout: &crate::firecracker_config::JailLayout,
    pod_dir: &std::path::Path,
) {
    match read_from_image(layout) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(pod_dir.join(PRESERVED_REPORT), bytes) {
                tracing::warn!(error = %e, "could not preserve the exit report before teardown");
            }
        }
        Err(e) => tracing::debug!(reason = %e, "no exit report to preserve"),
    }
}

/// Where a report was read from, which decides what it has to prove.
pub(crate) enum ReportSource {
    /// A directory the host shares with the pod (local and container drivers).
    SharedDirectory,
    /// An image the workload can write (Firecracker): only the supervisor's
    /// signature, checked against the key the node minted, makes it a report.
    WorkloadOwnedImage { pod_dir: std::path::PathBuf },
}

/// Parse and, where the source requires it, authenticate a report.
pub(crate) fn parse_report(
    json: &str,
    source: &ReportSource,
) -> Result<nucleus_spec::ExitReport, ReceiptError> {
    use nucleus_spec::exit_report_auth::{SignedExitReport, signing_bytes};
    match source {
        ReportSource::SharedDirectory => {
            if let Ok(signed) = serde_json::from_str::<SignedExitReport>(json) {
                return Ok(signed.report);
            }
            serde_json::from_str(json).map_err(|e| ReceiptError::Malformed(e.to_string()))
        }
        ReportSource::WorkloadOwnedImage { pod_dir } => {
            let signed: SignedExitReport = serde_json::from_str(json).map_err(|e| {
                if serde_json::from_str::<nucleus_spec::ExitReport>(json).is_ok() {
                    ReceiptError::Unauthenticated("the report is unsigned".into())
                } else {
                    ReceiptError::Malformed(e.to_string())
                }
            })?;
            let recorded =
                std::fs::read_to_string(pod_dir.join("mediator-pubkey.hex")).map_err(|e| {
                    ReceiptError::Unauthenticated(format!(
                        "the node has no record of this pod's mediation key: {e}"
                    ))
                })?;
            let recorded = recorded.trim();
            // The report's own copy of the key is a claim; the node's record decides.
            if !signed.signer_pubkey.eq_ignore_ascii_case(recorded) {
                return Err(ReceiptError::Unauthenticated(
                    "signed by a key other than the one the node minted for this pod".into(),
                ));
            }
            let key_bytes: [u8; 32] = hex::decode(recorded)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| {
                    ReceiptError::Unauthenticated("the recorded key is malformed".into())
                })?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
                .map_err(|e| ReceiptError::Unauthenticated(format!("the recorded key: {e}")))?;
            let sig_bytes: [u8; 64] = hex::decode(&signed.signature)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| {
                    ReceiptError::Unauthenticated("the signature is malformed".into())
                })?;
            let bytes = signing_bytes(&signed.report)
                .map_err(|e| ReceiptError::Malformed(e.to_string()))?;
            key.verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
                .map_err(|_| {
                    ReceiptError::Unauthenticated("the signature does not verify".into())
                })?;
            Ok(signed.report)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Receipt {
        Receipt {
            pod_id: "11111111-1111-1111-1111-111111111111".into(),
            workspace_hash: "ws".into(),
            audit_tail_hash: "tail".into(),
            audit_entry_count: 3,
            timestamp_unix: 1_757_000_000,
            manifest_hash: "mf".into(),
            sandbox_tier: "restricted".into(),
            spiffe_id: "spiffe://nucleus.local/ns/pods/sa/1".into(),
            version: 1,
            v1_content_hash: "v1".into(),
            input_tokens: 10,
            output_tokens: 20,
            cache_read_tokens: 5,
            cost_usd: 0.5,
            signature: String::new(),
            signer_pubkey: String::new(),
        }
    }

    /// The HTTP body names exactly the fields the proto does.
    ///
    /// The two transports serve one value, and this is the half a compiler cannot check: the
    /// gRPC conversion in `main.rs` is a struct literal, so a missing field there is a compile
    /// error, but nothing stops the JSON from drifting into a different vocabulary. A client
    /// reading `workspace_hash` over gRPC must find `workspace_hash` over HTTP.
    #[test]
    fn the_http_body_names_the_same_fields_the_proto_does() {
        let json = serde_json::to_value(sample()).expect("a receipt serializes");
        let keys: std::collections::BTreeSet<&str> = json
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        // `extensions` is deliberately absent: it is a proto-level escape hatch the node always
        // sends empty, and an empty map in JSON would be noise a client has to ignore.
        let expected: std::collections::BTreeSet<&str> = [
            "pod_id",
            "workspace_hash",
            "audit_tail_hash",
            "audit_entry_count",
            "timestamp_unix",
            "manifest_hash",
            "sandbox_tier",
            "spiffe_id",
            "version",
            "v1_content_hash",
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cost_usd",
            "signature",
            "signer_pubkey",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            keys, expected,
            "the HTTP body and the proto must name one vocabulary"
        );
    }

    /// The three refusals stay distinguishable, because they ask the caller for different things.
    ///
    /// "Not finished yet" means retry, "no exit report" means look at why the pod died, and
    /// "malformed" means something is broken. Collapsing them into one string — which is what the
    /// inline version effectively did, since it built `Status` messages ad hoc — makes a caller
    /// unable to tell waiting from failing.
    #[test]
    fn each_reason_a_receipt_is_unavailable_reads_differently() {
        let rendered: Vec<String> = [
            ReceiptError::NotExited,
            ReceiptError::NoExitReport("/w/.nucleus-exit-report.json: ENOENT".into()),
            ReceiptError::Malformed("expected value at line 1".into()),
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert!(rendered[0].contains("has not exited"), "{rendered:?}");
        assert!(
            rendered[1].contains("exit report not found"),
            "{rendered:?}"
        );
        assert!(rendered[2].contains("failed to parse"), "{rendered:?}");
        let unique: std::collections::BTreeSet<&String> = rendered.iter().collect();
        assert_eq!(unique.len(), 3, "each must read differently: {rendered:?}");
    }

    // ── `build`, against a real exited pod ──────────────────────────────────
    //
    // Everything above tests the value and the refusals' wording. `build` — the
    // function that turns a pod into a receipt — was reached by nothing, because
    // it needs a `PodHandle`, which needs a live `DriverState`. Under the local
    // driver that is a real child process, so these spawn one and let it exit.
    //
    // `local-driver` is not a default feature; CI's coverage job runs
    // `--all-features`, which compiles it.

    #[cfg(feature = "local-driver")]
    mod against_a_real_pod {
        use super::*;
        use std::collections::BTreeMap;

        /// A pod handle whose child has actually run and exited, or is still
        /// running when `exit` is false.
        /// A real `PodAuthority` over a temp state dir, so `build` signs for
        /// real in these tests rather than against a stub. The key is generated
        /// per-test, which is also what makes "another key does not verify"
        /// meaningful.
        fn authority(dir: &std::path::Path) -> crate::pod_authority::PodAuthority {
            crate::pod_authority::PodAuthority::new(
                &crate::pod_authority::AuthorityArgs {
                    root_minter_spiffe_id: None,
                    cert_trust_anchors: Vec::new(),
                    max_children_per_pod: 8,
                    upstreams: None,
                },
                "nucleus.local",
                dir,
            )
            .expect("no registry to fail to load")
        }

        /// **The claim, end to end.** Every other signature test builds a `Receipt`
        /// by hand and signs a preimage itself, which tests the primitives and not
        /// the composition: until this existed, nothing checked that a receipt
        /// `build` actually produced carries a signature that verifies.
        ///
        /// That is the same shape as `FETCH_POD_SPEC` shipping with a handler, a
        /// helper and tests and nothing sending it. A claim is about the assembled
        /// thing.
        #[tokio::test]
        async fn a_receipt_build_produced_verifies_against_the_nodes_key() {
            use crate::pod_authority::verify_pod_receipt;
            let dir = tempfile::tempdir().expect("tempdir");
            write_report(dir.path(), REPORT);
            let auth = authority(dir.path());
            let built = build(&pod(dir.path(), true, &[]).await, &auth)
                .await
                .expect("built");
            let r = &built.receipt;

            assert!(
                !r.signature.is_empty(),
                "build produced an unsigned receipt"
            );
            assert_eq!(
                r.signer_pubkey,
                auth.root_pubkey_hex(),
                "the receipt names a key other than the one that signed it"
            );
            assert!(
                verify_pod_receipt(&r.signer_pubkey, &r.preimage(), &r.signature),
                "a receipt this node built does not verify against this node's key"
            );

            // And it is bound to its content: move one field and the signature no
            // longer covers it.
            let mut tampered = r.clone();
            tampered.workspace_hash = "rewritten-in-flight".into();
            assert!(
                !verify_pod_receipt(
                    &tampered.signer_pubkey,
                    &tampered.preimage(),
                    &tampered.signature
                ),
                "a rewritten workspace hash still verified — the signature is not binding the content"
            );
        }

        async fn pod(
            work_dir: &std::path::Path,
            exit: bool,
            labels: &[(&str, &str)],
        ) -> Arc<crate::PodHandle> {
            let mut spec: nucleus_spec::PodSpec =
                serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
                    .expect("a minimal PodSpec deserializes");
            spec.spec.work_dir = work_dir.to_path_buf();
            spec.metadata.name = Some("probe".to_string());
            spec.metadata.labels = labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<BTreeMap<_, _>>();

            // Resolved through `PATH` rather than by absolute path: `true` lives in
            // `/usr/bin` on macOS and `/bin` on most Linux distributions, and the
            // hardcoded `/bin/true` made these five tests fail to spawn on a Mac
            // the moment the crate became compilable there.
            let child = tokio::process::Command::new(if exit { "true" } else { "sleep" })
                .args(if exit { vec![] } else { vec!["30"] })
                .spawn()
                .expect("a child spawns");

            let handle = Arc::new(crate::PodHandle {
                id: uuid::Uuid::new_v4(),
                spec,
                created_at: 1_757_000_000,
                log_path: work_dir.join("pod.log"),
                proxy_addr: tokio::sync::Mutex::new(None),
                driver_state: crate::DriverState::Local(Box::new(crate::LocalPod {
                    child: tokio::sync::Mutex::new(child),
                    signed_proxy: tokio::sync::Mutex::new(None),
                })),
                parent_pod_id: None,
                posture_stamp: None,
            });

            if exit {
                // Poll rather than `wait()`: `status()` reads `try_wait`, and the
                // point is to reach the state the real code will see.
                for _ in 0..200 {
                    if matches!(handle.status().await, crate::PodState::Exited { .. }) {
                        return handle;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                panic!("/bin/true did not exit");
            }
            handle
        }

        fn write_report(work_dir: &std::path::Path, json: &str) {
            std::fs::write(work_dir.join(".nucleus-exit-report.json"), json)
                .expect("the exit report is written");
        }

        const REPORT: &str = r#"{
            "workspace_hash":"ws-abc","audit_tail_hash":"tail-def",
            "audit_entry_count":7,"timestamp_unix":1757000123,
            "input_tokens":11,"output_tokens":22,"cache_read_tokens":33,"cost_usd":1.5
        }"#;

        /// A pod still running is "not yet", not a failure — the caller should
        /// retry rather than go looking at why the pod died.
        #[tokio::test]
        async fn a_running_pod_has_no_receipt_yet() {
            let dir = tempfile::tempdir().expect("tempdir");
            let handle = pod(dir.path(), false, &[]).await;
            // `let Err(..) else` rather than `expect_err`: `Built` has no
            // `Debug`, and a test is not a reason to add one to a production type.
            let Err(err) = build(&handle, &authority(dir.path())).await else {
                panic!("a running pod must not produce a receipt");
            };
            assert!(matches!(err, ReceiptError::NotExited), "{err:?}");
            let _ = handle.cancel().await;
        }

        /// The proxy writes the report at shutdown, so its absence means the pod
        /// died before shutdown ran — a different thing to go and look at.
        #[tokio::test]
        async fn an_exited_pod_with_no_report_says_which_file_is_missing() {
            let dir = tempfile::tempdir().expect("tempdir");
            let handle = pod(dir.path(), true, &[]).await;
            let Err(err) = build(&handle, &authority(dir.path())).await else {
                panic!("no report on disk, so no receipt");
            };
            let ReceiptError::NoExitReport(why) = err else {
                panic!("expected NoExitReport, got {err:?}");
            };
            assert!(
                why.contains(".nucleus-exit-report.json"),
                "the path is the actionable part: {why}"
            );
        }

        /// A report that is there and unreadable is "something is broken",
        /// distinct from "it is not there".
        #[tokio::test]
        async fn an_unreadable_report_is_reported_as_malformed() {
            let dir = tempfile::tempdir().expect("tempdir");
            write_report(dir.path(), "{not json");
            let handle = pod(dir.path(), true, &[]).await;
            let Err(err) = build(&handle, &authority(dir.path())).await else {
                panic!("malformed json must not produce a receipt");
            };
            assert!(matches!(err, ReceiptError::Malformed(_)), "{err:?}");
        }

        /// The whole assembly: every number the proxy reported reaches the
        /// receipt unchanged, and the pod's own id identifies it.
        #[tokio::test]
        async fn a_receipt_carries_the_reports_numbers_and_the_pods_id() {
            let dir = tempfile::tempdir().expect("tempdir");
            write_report(dir.path(), REPORT);
            let handle = pod(dir.path(), true, &[]).await;
            let built = build(&handle, &authority(dir.path()))
                .await
                .expect("a receipt is produced");

            let r = &built.receipt;
            assert_eq!(r.pod_id, handle.id.to_string());
            assert_eq!(r.workspace_hash, "ws-abc");
            assert_eq!(r.audit_tail_hash, "tail-def");
            assert_eq!(r.audit_entry_count, 7);
            assert_eq!(r.timestamp_unix, 1_757_000_123);
            assert_eq!(r.input_tokens, 11);
            assert_eq!(r.output_tokens, 22);
            assert_eq!(r.cache_read_tokens, 33);
            assert!((r.cost_usd - 1.5).abs() < f64::EPSILON);
            assert_eq!(r.version, 1);
            assert_eq!(built.exit_code, 0, "/bin/true exits 0");
            assert!(!r.manifest_hash.is_empty(), "the spec must be hashed");
            assert!(
                !r.v1_content_hash.is_empty(),
                "the content hash is the point"
            );
        }

        /// The content hash is a hash OF something: two pods with different
        /// specs must not produce the same one, or the "two parties compute the
        /// same value" argument the module opens with is empty.
        #[tokio::test]
        async fn two_different_pods_do_not_share_a_content_hash() {
            let a = tempfile::tempdir().expect("tempdir");
            let b = tempfile::tempdir().expect("tempdir");
            write_report(a.path(), REPORT);
            write_report(b.path(), REPORT);
            let one = build(&pod(a.path(), true, &[]).await, &authority(a.path()))
                .await
                .expect("built");
            let two = build(&pod(b.path(), true, &[]).await, &authority(b.path()))
                .await
                .expect("built");

            assert_ne!(
                one.receipt.v1_content_hash, two.receipt.v1_content_hash,
                "distinct pods with distinct specs must hash differently"
            );
            assert_ne!(one.receipt.manifest_hash, two.receipt.manifest_hash);
        }

        /// Trust labels are read from the spec, and the SPIFFE id is the
        /// sandbox's cryptographic identity — the upgrade path in the trust
        /// service keys on it, so a receipt that dropped it would silently
        /// downgrade the session.
        #[tokio::test]
        async fn identity_labels_reach_the_receipt_and_reputation_ones_do_not() {
            let dir = tempfile::tempdir().expect("tempdir");
            write_report(dir.path(), REPORT);
            let handle = pod(
                dir.path(),
                true,
                &[
                    ("trust.coproduct.one/bracket", "B2"),
                    ("trust.coproduct.one/profile", "restricted"),
                    ("trust.coproduct.one/agent-id", "agent-7"),
                    ("spiffe.io/identity", "spiffe://nucleus.local/ns/pods/sa/7"),
                ],
            )
            .await;
            let built = build(&handle, &authority(dir.path())).await.expect("built");

            assert_eq!(built.agent_identity, "agent-7");
            assert_eq!(
                built.receipt.spiffe_id,
                "spiffe://nucleus.local/ns/pods/sa/7"
            );
            assert!(
                built.receipt.sandbox_tier.is_empty(),
                "since #2512 no reputation label feeds the tier, even when one \
                 is present on the spec — the producer is gone, not ignored"
            );
        }

        /// With no labels at all the receipt still identifies the pod rather
        /// than carrying an empty agent. The fallback chain is agent-id, then
        /// the SPIFFE id, then the pod name, then the id.
        #[tokio::test]
        async fn an_unlabelled_pod_still_names_itself() {
            let dir = tempfile::tempdir().expect("tempdir");
            write_report(dir.path(), REPORT);
            let built = build(&pod(dir.path(), true, &[]).await, &authority(dir.path()))
                .await
                .expect("built");
            assert_eq!(
                built.agent_identity, "probe",
                "the spec's name is the next-best identity"
            );
            assert!(
                built.receipt.spiffe_id.is_empty(),
                "no SPIFFE label means no SPIFFE id, not a fabricated one"
            );
            assert!(built.receipt.sandbox_tier.is_empty());
        }
    }
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    use crate::pod_authority::verify_pod_receipt;

    fn sample() -> Receipt {
        Receipt {
            pod_id: "11111111-1111-1111-1111-111111111111".into(),
            workspace_hash: "ws".into(),
            audit_tail_hash: "tail".into(),
            audit_entry_count: 3,
            timestamp_unix: 1_700_000_000,
            manifest_hash: "mh".into(),
            sandbox_tier: "tier2".into(),
            spiffe_id: "spiffe://nucleus.local/ns/default/sa/x".into(),
            version: 1,
            v1_content_hash: "v1".into(),
            input_tokens: 10,
            output_tokens: 20,
            cache_read_tokens: 30,
            cost_usd: 0.5,
            signature: String::new(),
            signer_pubkey: String::new(),
        }
    }

    /// **Every committed field must move the preimage.** A field the signature
    /// does not cover can be rewritten in flight while the signature still
    /// verifies — the tamper a signature exists to prevent.
    #[test]
    fn every_field_reaches_the_preimage() {
        let base = sample().preimage();
        let cases: Vec<(&str, Receipt)> = vec![
            (
                "pod_id",
                Receipt {
                    pod_id: "other".into(),
                    ..sample()
                },
            ),
            (
                "workspace_hash",
                Receipt {
                    workspace_hash: "other".into(),
                    ..sample()
                },
            ),
            (
                "audit_tail_hash",
                Receipt {
                    audit_tail_hash: "other".into(),
                    ..sample()
                },
            ),
            (
                "audit_entry_count",
                Receipt {
                    audit_entry_count: 4,
                    ..sample()
                },
            ),
            (
                "timestamp_unix",
                Receipt {
                    timestamp_unix: 1_700_000_001,
                    ..sample()
                },
            ),
            (
                "manifest_hash",
                Receipt {
                    manifest_hash: "other".into(),
                    ..sample()
                },
            ),
            (
                "sandbox_tier",
                Receipt {
                    sandbox_tier: "tier1".into(),
                    ..sample()
                },
            ),
            (
                "spiffe_id",
                Receipt {
                    spiffe_id: "spiffe://other".into(),
                    ..sample()
                },
            ),
            (
                "version",
                Receipt {
                    version: 2,
                    ..sample()
                },
            ),
            (
                "v1_content_hash",
                Receipt {
                    v1_content_hash: "other".into(),
                    ..sample()
                },
            ),
            (
                "input_tokens",
                Receipt {
                    input_tokens: 11,
                    ..sample()
                },
            ),
            (
                "output_tokens",
                Receipt {
                    output_tokens: 21,
                    ..sample()
                },
            ),
            (
                "cache_read_tokens",
                Receipt {
                    cache_read_tokens: 31,
                    ..sample()
                },
            ),
            (
                "cost_usd",
                Receipt {
                    cost_usd: 0.6,
                    ..sample()
                },
            ),
        ];
        for (field, perturbed) in cases {
            assert_ne!(
                base,
                perturbed.preimage(),
                "{field} does not reach the preimage: it can be rewritten with the signature \
                 still verifying"
            );
        }
    }

    /// The signature cannot cover itself, so those two fields must NOT move it —
    /// otherwise signing would invalidate what it just signed.
    #[test]
    fn the_signature_fields_are_not_in_their_own_preimage() {
        let base = sample().preimage();
        let signed = Receipt {
            signature: "deadbeef".into(),
            signer_pubkey: "cafe".into(),
            ..sample()
        };
        assert_eq!(base, signed.preimage());
    }

    /// **Framing must be injective.** Without the length prefixes, moving a
    /// character across a field boundary would be the same bytes — two
    /// different receipts under one signature.
    #[test]
    fn a_field_boundary_cannot_move_without_changing_the_preimage() {
        let a = Receipt {
            workspace_hash: "ab".into(),
            audit_tail_hash: String::new(),
            ..sample()
        };
        let b = Receipt {
            workspace_hash: "a".into(),
            audit_tail_hash: "b".into(),
            ..sample()
        };
        assert_ne!(a.preimage(), b.preimage());
    }

    /// A signature made by a DIFFERENT key must not verify. This is what makes
    /// the host-held key meaningful: a guest, which never sees it, cannot
    /// produce one.
    #[test]
    fn another_key_cannot_sign_a_receipt_this_node_would_accept() {
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let mk = || {
            let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("gen");
            ring::signature::Ed25519KeyPair::from_pkcs8(doc.as_ref()).expect("parse")
        };
        let node = mk();
        let impostor = mk();
        let node_pub = hex::encode(node.public_key().as_ref());
        let preimage = sample().preimage();

        // Same domain tag the authority uses; a signature over the bare
        // preimage must not verify either.
        let mut msg = b"nucleus/pod-receipt/v1\0".to_vec();
        msg.extend_from_slice(&preimage);

        let theirs = hex::encode(impostor.sign(&msg).as_ref());
        assert!(
            !verify_pod_receipt(&node_pub, &preimage, &theirs),
            "a receipt signed by another key verified against this node's"
        );

        let ours = hex::encode(node.sign(&msg).as_ref());
        assert!(
            verify_pod_receipt(&node_pub, &preimage, &ours),
            "the node's own did not verify"
        );
    }

    /// **The domain tag is load-bearing.** A signature over the untagged
    /// preimage must not verify, or a signature minted in another of the root
    /// key's roles could be replayed as a receipt.
    #[test]
    fn a_signature_over_the_untagged_preimage_does_not_verify() {
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("gen");
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(doc.as_ref()).expect("parse");
        let preimage = sample().preimage();
        let untagged = hex::encode(key.sign(&preimage).as_ref());
        assert!(!verify_pod_receipt(
            &hex::encode(key.public_key().as_ref()),
            &preimage,
            &untagged
        ));
    }

    /// Malformed input is `false`, never a panic: a verifier is handed
    /// attacker-controlled text by definition.
    #[test]
    fn malformed_signatures_are_refused_rather_than_fatal() {
        let p = sample().preimage();
        assert!(!verify_pod_receipt("nothex", &p, "nothex"));
        assert!(!verify_pod_receipt("", &p, ""));
        assert!(!verify_pod_receipt("aabb", &p, "ccdd"));
    }
}

/// What a report read out of a workload-owned image has to prove.
///
/// The forged-report case is the one a live node measured as reachable in
/// principle: the scratch root is the workload's uid, so the workload can put
/// any bytes at the report's path. These pin that only a report signed with the
/// key the NODE minted for this pod is accepted there.
#[cfg(test)]
mod authenticated_reports {
    use super::*;
    use ed25519_dalek::Signer;
    use nucleus_spec::exit_report_auth::{SignedExitReport, signing_bytes};

    const REPORT: &str = r#"{"workspace_hash":"ws","audit_tail_hash":"tail","audit_entry_count":4,"timestamp_unix":7}"#;

    fn report() -> nucleus_spec::ExitReport {
        serde_json::from_str(REPORT).unwrap()
    }

    fn signed_by(
        key: &ed25519_dalek::SigningKey,
        report: nucleus_spec::ExitReport,
    ) -> SignedExitReport {
        SignedExitReport {
            signature: hex::encode(key.sign(&signing_bytes(&report).unwrap()).to_bytes()),
            signer_pubkey: hex::encode(key.verifying_key().to_bytes()),
            report,
        }
    }

    /// A pod dir holding the node's record of `key`.
    fn pod_dir(key: &ed25519_dalek::SigningKey) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("mediator-pubkey.hex"),
            hex::encode(key.verifying_key().to_bytes()),
        )
        .unwrap();
        dir
    }

    fn image(dir: &tempfile::TempDir) -> ReportSource {
        ReportSource::WorkloadOwnedImage {
            pod_dir: dir.path().to_path_buf(),
        }
    }

    fn pod_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// Control first: the supervisor's own report is accepted, with its numbers.
    #[test]
    fn a_report_signed_with_the_pods_key_is_accepted() {
        let dir = pod_dir(&pod_key());
        let json = serde_json::to_string(&signed_by(&pod_key(), report())).unwrap();
        let got = parse_report(&json, &image(&dir)).expect("the supervisor's report verifies");
        assert_eq!(got.workspace_hash, "ws");
        assert_eq!(got.audit_entry_count, 4);
    }

    #[test]
    fn an_unsigned_report_in_the_image_is_refused_by_name() {
        let dir = pod_dir(&pod_key());
        let Err(ReceiptError::Unauthenticated(why)) = parse_report(REPORT, &image(&dir)) else {
            panic!("an unsigned report must not become a receipt");
        };
        assert!(why.contains("unsigned"), "{why}");
    }

    /// The workload's own key, honestly named: not the key the node minted.
    #[test]
    fn a_report_signed_by_another_key_is_refused() {
        let dir = pod_dir(&pod_key());
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let json = serde_json::to_string(&signed_by(&other, report())).unwrap();
        assert!(matches!(
            parse_report(&json, &image(&dir)),
            Err(ReceiptError::Unauthenticated(_))
        ));
    }

    /// The report's claimed key is a claim: naming the right key does not make
    /// another key's signature verify.
    #[test]
    fn claiming_the_pods_key_does_not_make_a_foreign_signature_verify() {
        let dir = pod_dir(&pod_key());
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut forged = signed_by(&other, report());
        forged.signer_pubkey = hex::encode(pod_key().verifying_key().to_bytes());
        let json = serde_json::to_string(&forged).unwrap();
        let Err(ReceiptError::Unauthenticated(why)) = parse_report(&json, &image(&dir)) else {
            panic!("a foreign signature must not verify");
        };
        assert!(why.contains("does not verify"), "{why}");
    }

    /// A genuine signature over different numbers: the workload edits the
    /// supervisor's report in place.
    #[test]
    fn editing_a_signed_report_breaks_it() {
        let dir = pod_dir(&pod_key());
        let mut edited = signed_by(&pod_key(), report());
        edited.report.workspace_hash = "forged-by-the-guest".into();
        let json = serde_json::to_string(&edited).unwrap();
        assert!(matches!(
            parse_report(&json, &image(&dir)),
            Err(ReceiptError::Unauthenticated(_))
        ));
    }

    /// "Could not look" is not "looked and it was fine" (ADR 0007 A-1).
    #[test]
    fn with_no_record_of_the_key_nothing_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let json = serde_json::to_string(&signed_by(&pod_key(), report())).unwrap();
        let Err(ReceiptError::Unauthenticated(why)) = parse_report(&json, &image(&dir)) else {
            panic!("no key record must refuse");
        };
        assert!(why.contains("no record"), "{why}");
    }

    /// The shared-directory drivers keep what they accepted.
    #[test]
    fn a_shared_directory_accepts_a_plain_or_a_signed_report() {
        assert!(parse_report(REPORT, &ReportSource::SharedDirectory).is_ok());
        let json = serde_json::to_string(&signed_by(&pod_key(), report())).unwrap();
        assert!(parse_report(&json, &ReportSource::SharedDirectory).is_ok());
    }
}
