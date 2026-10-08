//! The live boot's operation-coverage pod (ADR 0014 S2): honest traffic, one
//! permitted and one refused call per workload-door route and per
//! credentialed upstream, so every operation in the shadow coverage set
//! (`nucleus_spec::host_decide_telemetry::COVERAGE`) is decided by the guest
//! and compared by the host in every run.
//!
//! Ordinary, policy-expected calls only: a file in the workspace and a
//! credentials file the pod's path policy blocks, a search for each, a fetch
//! and a search, one memory write and recall, one credentialed call. Nothing
//! here probes the guest or the host for a way out.
//!
//! The calls go to the pod's proxy from the host, through the same handlers the
//! workload door binds (`workload_door::handler`, pinned by
//! `the_door_binds_the_main_listeners_handlers`), so each is decided by the same
//! kernel session and shadowed by the same client a workload's call is. That
//! works on every admitted guest, 2.4.0 on, with no new in-guest binary.
//!
//! What each call got is recorded beside what it was meant to get
//! ([`CoverageCall`]); this module asserts neither. The reader judges coverage
//! from the host's own per-operation counts.

use anyhow::{Context, Result};
use nucleus_spec::live_boot::{CoverageCall, CoverageIntent};
use serde_json::{Value, json};
use std::time::Duration;

/// The credentialed upstream the coverage pod declares: the effect pod's, the
/// one upstream the fixture node's operator registry grants.
const UPSTREAM: &str = "receipt-fixture";

/// One call: a route, a JSON body (or a raw body for egress), and what the
/// policy is meant to answer.
struct Call {
    route: String,
    body: Body,
    intent: CoverageIntent,
}

enum Body {
    Json(Value),
    Text(&'static str),
}

fn call(route: &str, body: Value, intent: CoverageIntent) -> Call {
    Call {
        route: route.to_string(),
        body: Body::Json(body),
        intent,
    }
}

/// A memory write body the handler accepts: a value ingested from a local
/// file, labelled as its derivation says it must be.
fn memory_write() -> Result<Value> {
    use nucleus_provenance_memory::{ContentHash, MemoryDerivation, SchemaType, SourceClass};
    let value = "coverage";
    let derivation = MemoryDerivation::RawIngest {
        source_class: SourceClass::LocalFile,
        source_hash: ContentHash::of_canonical_bytes(value.as_bytes()),
    };
    let label = nucleus_provenance_memory::recompute::derive_label(&derivation, &[]);
    Ok(json!({
        "value": value,
        "schema": serde_json::to_value(SchemaType::String)?,
        "derivation": serde_json::to_value(&derivation)?,
        "label": serde_json::to_value(&label)?,
    }))
}

/// The traffic, in order. The order matters to the flow graph: the clean
/// session's fetch and search come before any read, the writes before the
/// credentialed reply taints the session, and a second fetch, search and
/// credentialed call after the reads, where the session's label is meant to
/// refuse them; the last write follows the credentialed reply.
fn calls() -> Result<Vec<Call>> {
    use CoverageIntent::{Permitted, Refused};
    let egress = format!("/v1/egress/{UPSTREAM}/echo");
    Ok(vec![
        call(
            "/v1/web_fetch",
            json!({"url": "https://example.com/coverage"}),
            Permitted,
        ),
        // Refused by DLC admission (`DLC_REFUSED`), in the guest and on the host.
        call("/v1/web_search", json!({"query": "coverage"}), Refused),
        call(
            "/v1/write",
            json!({"path": "coverage-a.txt", "contents": "coverage\n"}),
            Permitted,
        ),
        call(
            "/v1/write",
            json!({"path": ".env", "contents": "X=1\n"}),
            Refused,
        ),
        call("/v1/memory/write", memory_write()?, Permitted),
        call("/v1/read", json!({"path": "coverage-a.txt"}), Permitted),
        call("/v1/read", json!({"path": ".env"}), Refused),
        call("/v1/glob", json!({"pattern": "coverage-*.txt"}), Permitted),
        call("/v1/glob", json!({"pattern": ".env*"}), Refused),
        call("/v1/grep", json!({"pattern": "coverage"}), Permitted),
        call("/v1/grep", json!({"pattern": ".env"}), Refused),
        call(
            "/v1/memory/recall",
            json!({"content_hash": "00".repeat(32)}),
            Permitted,
        ),
        call(
            "/v1/web_fetch",
            json!({"url": "https://example.com/coverage-after-read"}),
            Refused,
        ),
        call(
            "/v1/web_search",
            json!({"query": "coverage after read"}),
            Refused,
        ),
        Call {
            route: egress,
            body: Body::Text("coverage"),
            intent: Refused,
        },
        call(
            "/v1/write",
            json!({"path": "coverage-b.txt", "contents": "after the reply\n"}),
            Refused,
        ),
    ])
}

/// The coverage pod: the effect pod's shape (a permissive lattice, one
/// credentialed upstream) under a path policy that blocks credentials files,
/// so each path route has a call it refuses.
pub(crate) fn pod_spec(upstream: &str) -> Value {
    let mut spec = crate::host_evidence_live::effect_pod_spec(upstream);
    spec["metadata"]["name"] = "live-boot-coverage".into();
    // DLC admission on every coverage operation but one: the guest's DLC gate
    // and the host's (ADR 0014, host DLC admission) then both admit five
    // operations, so the lattice still decides them, and both refuse
    // `web_search`. Before the host read the labels, the guest refused what
    // the host allowed: run 37833208274 measured six guest-stricter
    // disagreements, the class §10 bounds at zero.
    spec["metadata"]["labels"] = json!(dlc().labels());
    let mut lattice = portcullis::PermissionLattice::permissive();
    lattice.paths = portcullis::PathLattice::block_sensitive();
    spec["spec"]["policy"]["lattice"] = serde_json::to_value(&lattice).unwrap_or(Value::Null);
    spec
}

/// The one coverage operation the pod's DLC credentials leave out.
pub(crate) const DLC_REFUSED: portcullis::Operation = portcullis::Operation::WebSearch;

/// The coverage pod's DLC provisioning: an issuer-signed credential for every
/// operation in the coverage set but [`DLC_REFUSED`].
fn dlc() -> nucleus_spec::dlc_admission::DlcProvisioning {
    let seed = [29u8; 32];
    let mut issuer = [0u8; 32];
    let mut credentials = Vec::new();
    for op in nucleus_spec::host_decide_telemetry::COVERAGE {
        if op == DLC_REFUSED {
            continue;
        }
        let name = portcullis::grant_usage::operation_name(op);
        let (pk, sig) = portcullis::says_admission::mint_credential(&seed, name);
        issuer = pk;
        credentials.push(format!("{name}={}", hex::encode(sig.bytes)));
    }
    nucleus_spec::dlc_admission::DlcProvisioning {
        trusted_keys: hex::encode(issuer),
        issuer: hex::encode(issuer),
        credentials: credentials.join(","),
    }
}

/// Make every call against the pod's proxy and record what each got. A call
/// the proxy could not be reached for fails the collection: that is not a
/// refusal.
pub(crate) async fn drive(proxy_addr: &str) -> Result<Vec<CoverageCall>> {
    let proxy = if proxy_addr.starts_with("http://") {
        proxy_addr.to_owned()
    } else {
        format!("http://{proxy_addr}")
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    let mut made = Vec::new();
    for c in calls()? {
        let request = client
            .post(format!("{proxy}{}", c.route))
            .header("x-nucleus-approval-wait-seconds", "0");
        let request = match &c.body {
            Body::Json(v) => request.json(v),
            Body::Text(t) => request.header("content-type", "text/plain").body(*t),
        };
        let response = request
            .send()
            .await
            .with_context(|| format!("POST {}", c.route))?;
        made.push(CoverageCall {
            route: c.route,
            intent: c.intent,
            status: response.status().as_u16(),
        });
    }
    Ok(made)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every door route's path is called, and each path route is called once
    /// meant to be permitted and once meant to be refused.
    #[test]
    fn the_traffic_reaches_every_route() {
        let calls = calls().expect("bodies build");
        for route in [
            "/v1/read",
            "/v1/write",
            "/v1/web_fetch",
            "/v1/glob",
            "/v1/grep",
            "/v1/web_search",
            "/v1/memory/write",
            "/v1/memory/recall",
            "/v1/egress/",
        ] {
            assert!(
                calls.iter().any(|c| c.route.starts_with(route)),
                "{route} is never called"
            );
        }
        for route in ["/v1/read", "/v1/write", "/v1/glob", "/v1/grep"] {
            for intent in [CoverageIntent::Permitted, CoverageIntent::Refused] {
                assert!(
                    calls.iter().any(|c| c.route == route && c.intent == intent),
                    "{route} {intent:?}"
                );
            }
        }
    }

    /// The path policy the refused calls rely on is the pod's.
    #[test]
    fn the_pod_blocks_credentials_files() {
        let spec = pod_spec("http://127.0.0.1:1");
        let lattice: portcullis::PermissionLattice =
            serde_json::from_value(spec["spec"]["policy"]["lattice"].clone()).expect("lattice");
        assert!(!lattice.paths.can_access(std::path::Path::new(".env")));
        assert!(
            lattice
                .paths
                .can_access(std::path::Path::new("coverage-a.txt"))
        );
        assert_eq!(spec["spec"]["credentialed_egress"][0]["name"], UPSTREAM);
    }

    /// The pod provisions DLC admission for every coverage operation but one,
    /// and the credentials it carries admit exactly those.
    #[test]
    fn the_pod_admits_every_coverage_operation_but_one() {
        use nucleus_spec::dlc_admission::{DlcField, DlcProvisioning};
        let spec = pod_spec("http://127.0.0.1:1");
        let labels: std::collections::BTreeMap<String, String> =
            serde_json::from_value(spec["metadata"]["labels"].clone()).expect("labels");
        let p = DlcProvisioning::from_labels(&labels).expect("DLC labels");
        let admission = portcullis::says_admission::DlcAdmission::provision(
            p.get(DlcField::TrustedKeys),
            p.get(DlcField::Issuer),
            p.get(DlcField::Credentials),
        )
        .expect("provisioned");
        for op in nucleus_spec::host_decide_telemetry::COVERAGE {
            let name = portcullis::grant_usage::operation_name(op);
            assert_eq!(
                admission.decide_operation(name).is_admit(),
                op != DLC_REFUSED,
                "{name}"
            );
        }
    }
}
