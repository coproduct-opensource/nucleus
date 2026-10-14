//! #3219: the runtime-injected `NUCLEUS_EGRESS_<NAME>_URL` entries are bound in
//! the receipt's `environment_inputs_sha256`, and a verifier derives them from
//! the admission record instead of restating the runtime's spelling of them.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::SigningKey;
use nucleus_ci_verdict::execution::{Backend, ExecutionClaim, ExecutionSchema, NodePlatform};
use nucleus_receipt::{Receipt, Session};
use nucleus_spec::workload_result::EnvironmentIdentity;

const POD: &str = "attempt-1";
const DOOR: &str = "unix:///run/nucleus-door/workload.sock";
const UPSTREAM: &str = "NUCLEUS_EGRESS_CODING_MODEL_URL";

fn now() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}

/// What the operator wrote: the workload spec's env and the resolved defaults.
fn declared() -> BTreeMap<String, String> {
    [("HOME", "/work/.home"), ("PATH", "/usr/bin:/bin")]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
}

/// What the runtime added, by the function the launcher calls.
fn injected() -> BTreeMap<String, String> {
    let egress = nucleus_spec::CredentialedEgressSpec {
        name: "coding-model".into(),
        upstream: "https://model.invalid/".into(),
        credential_env: "LLM_API_TOKEN".into(),
        header: "authorization".into(),
        value_prefix: "Bearer ".into(),
        effects: nucleus_spec::EffectTable::unclassified(),
    };
    let injected = nucleus_spec::workload_egress::injected_env(&[egress], DOOR);
    // The spelling seen live in #3219.
    assert_eq!(
        injected,
        BTreeMap::from([(
            UPSTREAM.to_string(),
            "unix:///run/nucleus-door/workload.sock/v1/egress/coding-model".to_string(),
        )])
    );
    injected
}

struct Fixture {
    dir: tempfile::TempDir,
    key: SigningKey,
    receipt: PathBuf,
}

impl Fixture {
    /// A receipt over the environment the launcher actually built: declared,
    /// injected, and the per-attempt door binding the inputs digest omits.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut launched = declared();
        launched.extend(injected());
        launched.insert("NUCLEUS_TOOL_PROXY_URL".into(), DOOR.into());
        let environment = EnvironmentIdentity::of(&launched);
        let digest = "a".repeat(64);
        let claim = ExecutionClaim {
            schema: ExecutionSchema::V1,
            pod_id: POD.into(),
            source_commit: String::new(),
            source_tree: String::new(),
            gate: String::new(),
            program_digest: digest.clone(),
            architecture: "aarch64".into(),
            backend: Backend::Firecracker,
            uid_isolated: true,
            exit_code: Some(0),
            stdout_sha256: digest.clone(),
            stderr_sha256: digest.clone(),
            launch_hash: digest,
            environment_inputs_sha256: environment.inputs_sha256,
            environment_complete_sha256: environment.complete_sha256,
            artifacts: BTreeMap::new(),
            node_platform: NodePlatform::Unattested {
                reason: "test node".into(),
            },
        };
        let receipt = Receipt::sign(
            Session {
                session_id: POD.into(),
                issuer_kid: "node".into(),
                issued_at_micros: now(),
                parent_chain: Vec::new(),
            },
            vec![claim.to_projection().unwrap()],
            &key,
        );
        let path = dir.path().join("receipt.json");
        std::fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        Self {
            dir,
            key,
            receipt: path,
        }
    }

    /// The node's admission record, with `runtime` as its injected set, or
    /// without the field when `runtime` is `None`.
    fn admission(&self, runtime: Option<BTreeMap<String, String>>) -> serde_json::Value {
        let mut admission = serde_json::json!({
            "pod_id": POD,
            "created_at_unix": now() / 1_000_000 - 60,
            "source_commit": "",
            "source_tree": "",
            "gate": "",
            "program_digest": "a".repeat(64),
            "architecture": "aarch64",
            "artifacts": {},
            "session_id": POD,
            "issuer_kid": "node",
            "verifying_key": self.key.verifying_key().to_bytes(),
        });
        if let Some(runtime) = runtime {
            admission["runtime_environment_inputs"] = serde_json::to_value(runtime).unwrap();
        }
        admission
    }

    fn write(&self, name: &str, value: &impl serde::Serialize) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }

    fn prepare(&self, admission: &serde_json::Value, inputs: &BTreeMap<String, String>) -> Output {
        Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
            .arg("prepare-execution")
            .arg("--admission")
            .arg(self.write("admission.json", admission))
            .args([
                "--signer-key-hex",
                &hex::encode(self.key.verifying_key().to_bytes()),
            ])
            .arg("--environment-inputs")
            .arg(self.write("inputs.json", inputs))
            .args(["--valid-until-micros", &(now() + 60_000_000).to_string()])
            .output()
            .unwrap()
    }

    /// Prepare, then verify the receipt against what was prepared.
    fn verify(&self, admission: &serde_json::Value, inputs: &BTreeMap<String, String>) -> Output {
        let prepared = self.prepare(admission, inputs);
        assert!(prepared.status.success(), "{}", stderr(&prepared));
        verify_execution(
            &self.receipt,
            &self.write("expected.json", &json(&prepared)),
        )
    }
}

fn verify_execution(receipt: &Path, expectations: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
        .arg("verify-execution")
        .arg("--receipt")
        .arg(receipt)
        .arg("--expectations")
        .arg(expectations)
        .output()
        .unwrap()
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn declared_inputs_and_the_admission_record_verify_an_egress_pod() {
    let fx = Fixture::new();
    let out = fx.verify(&fx.admission(Some(injected())), &declared());
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(json(&out)["execution_verified"], true);
}

#[test]
fn a_tampered_injected_value_in_the_admission_record_refuses_the_binding() {
    let fx = Fixture::new();
    let mut tampered = injected();
    tampered.insert(UPSTREAM.into(), format!("{DOOR}/v1/egress/elsewhere"));
    let out = fx.verify(&fx.admission(Some(tampered)), &declared());
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("environment_inputs_sha256"),
        "{}",
        stderr(&out)
    );
    // An injected entry dropped from the record is refused the same way.
    let out = fx.verify(&fx.admission(Some(BTreeMap::new())), &declared());
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("environment_inputs_sha256"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn an_admission_record_without_the_injected_set_is_refused_by_name() {
    let fx = Fixture::new();
    let out = fx.prepare(&fx.admission(None), &declared());
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("runtime_environment_inputs"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn restating_an_injected_value_is_refused_by_name() {
    let fx = Fixture::new();
    let mut restated = declared();
    restated.extend(injected());
    let out = fx.prepare(&fx.admission(Some(injected())), &restated);
    assert!(!out.status.success());
    assert!(stderr(&out).contains(UPSTREAM), "{}", stderr(&out));
}
