use super::*;

use nucleus_identity::dpop::DpopProofBuilder;

const ORIGIN: &str = "https://jobs.broker.nucleus.invalid/";

/// Two GCP-shaped upstreams, one per job, with the credential minted per call on the host (a
/// federated exchange at GCP STS), and one static upstream.
const UPSTREAMS: &str = r#"
[[upstream]]
name = "gcp-console"
base_url = "https://compute.googleapis.com/"
header = "authorization"
value_prefix = "Bearer "
[upstream.credential.federated]
token_endpoint = "https://sts.googleapis.com/v1/token"
grant = "token-exchange"
encoding = "form"
audience = "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/ops/providers/node"
request_audience = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/ops/providers/node"
scope = "https://www.googleapis.com/auth/cloud-platform"

[[upstream]]
name = "gcp-lane-ops"
base_url = "https://compute.googleapis.com/"
header = "authorization"
value_prefix = "Bearer "
[upstream.credential.federated]
token_endpoint = "https://sts.googleapis.com/v1/token"
grant = "token-exchange"
encoding = "form"
audience = "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/ops/providers/node"
request_audience = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/ops/providers/node"
scope = "https://www.googleapis.com/auth/cloud-platform"

[[upstream]]
name = "vertex-console"
base_url = "https://us-central1-aiplatform.googleapis.com/"
header = "authorization"
value_prefix = "Bearer "
[upstream.credential.env]
var = "UNUSED_IN_TESTS"
"#;

const JOBS: &str = r#"
[[job]]
name = "console"
holder = { service = "console" }
upstreams = ["gcp-console", "vertex-console"]

[[job]]
name = "lane-ops"
holder = { service = "lane-ops" }
upstreams = ["gcp-lane-ops"]
"#;

fn upstreams() -> UpstreamRegistry {
    UpstreamRegistry::from_toml_str(UPSTREAMS).expect("upstreams parse")
}

fn registry() -> JobRegistry {
    JobRegistry::from_toml_str(JOBS, &upstreams()).expect("jobs parse")
}

/// A guest: its SVID (a P-256 certificate) and the SVID's private key, which only it holds.
struct Guest {
    pod: Uuid,
    der: Vec<u8>,
    key: Vec<u8>,
    service: &'static str,
}

impl Guest {
    fn new(service: &'static str) -> Self {
        let pod = Uuid::new_v4();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(format!("spiffe://node.test/ns/pods/sa/{pod}"))
                .unwrap(),
        )];
        let cert = params.self_signed(&key).unwrap();
        Self {
            pod,
            der: cert.der().to_vec(),
            key: key.serialize_der(),
            service,
        }
    }

    /// The channel the HOST knows this guest by.
    fn channel(&self) -> GuestChannel {
        GuestChannel::new(
            self.pod,
            &self.der,
            now() + 3600,
            Some(ServiceName::new(self.service).unwrap()),
        )
    }

    fn proof(&self, gate: &JobGate, method: &str, path: &str, token: Option<&str>) -> String {
        sign(&self.key, gate, method, path, token)
    }
}

fn sign(key: &[u8], gate: &JobGate, method: &str, path: &str, token: Option<&str>) -> String {
    let mut b = DpopProofBuilder::new(method, &gate.htu(path));
    if let Some(t) = token {
        b = b.with_access_token(t);
    }
    b.build(key).unwrap()
}

fn now() -> u64 {
    nucleus_request_proof::unix_now()
}

fn gate() -> (JobGate, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("jobs");
    (
        JobGate::open(registry(), ORIGIN, &ledger).expect("gate opens with the test ledger"),
        dir,
    )
}

/// A capability for `job` issued to `g`, the positive path.
fn issued(gate: &JobGate, g: &Guest, job: &str) -> String {
    let p = g.proof(gate, "POST", &issue_path(job), None);
    gate.issue(&g.channel(), &g.der, &p, job, now())
        .expect("issued")
}

fn perform(
    gate: &JobGate,
    g: &Guest,
    ch: &GuestChannel,
    cap: &str,
    job: &str,
) -> Result<AdmittedJob, JobRefusal> {
    let path = perform_path(job);
    let p = g.proof(gate, "POST", &path, Some(cap));
    gate.admit(ch, cap, &p, "POST", &path, now())
}

// ----- The positive witness ----------------------------------------------------------------

#[test]
fn a_guest_proves_its_svid_and_receives_only_its_own_jobs_capability() {
    let (gate, _d) = gate();
    let console = Guest::new("console");
    let cap = issued(&gate, &console, "console");
    let admitted = perform(&gate, &console, &console.channel(), &cap, "console").expect("admitted");
    assert_eq!(admitted.job(), "console");
    assert_eq!(
        admitted.upstreams().collect::<Vec<_>>(),
        ["gcp-console", "vertex-console"]
    );
    assert_eq!(admitted.upstream("gcp-console"), Ok("gcp-console"));
    // The guest holds a capability and proofs. It never holds a GCP token: that is minted on
    // the host per call, for the upstream this clamp admits (`federated_credential`).
    assert!(
        !cap.contains("ya29."),
        "a capability is not a provider token"
    );
}

// ----- Another guest's SVID ----------------------------------------------------------------

#[test]
fn another_guests_svid_is_refused_even_with_its_key() {
    let (gate, _d) = gate();
    let console = Guest::new("console");
    let agent = Guest::new("lane-ops");
    // The agent stole the console's SVID AND its key, and asks on its own channel.
    let p = console.proof(&gate, "POST", &issue_path("console"), None);
    assert_eq!(
        gate.issue(&agent.channel(), &console.der, &p, "console", now()),
        Err(JobRefusal::NotThisGuest)
    );
    // Non-vacuity: the same SVID and proof on the console's own channel are admitted.
    assert!(
        gate.issue(&console.channel(), &console.der, &p, "console", now())
            .is_ok()
    );
}

// ----- A copied token without the guest's key (DPoP) -----------------------------------------

#[test]
fn a_copied_capability_without_the_guests_key_is_refused() {
    let (gate, _d) = gate();
    let console = Guest::new("console");
    let cap = issued(&gate, &console, "console");
    let path = perform_path("console");
    let attacker = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .serialize_der();
    // A proof by another key, on the right channel, method, URI and token.
    let forged = sign(&attacker, &gate, "POST", &path, Some(&cap));
    assert_eq!(
        gate.admit(&console.channel(), &cap, &forged, "POST", &path, now()),
        Err(JobRefusal::ProofRefused)
    );
    // No proof at all.
    assert_eq!(
        gate.admit(&console.channel(), &cap, "", "POST", &path, now()),
        Err(JobRefusal::ProofRefused)
    );
    // The guest's own proof, but bound to a different token (no `ath`, then another token's).
    let unbound = console.proof(&gate, "POST", &path, None);
    assert_eq!(
        gate.admit(&console.channel(), &cap, &unbound, "POST", &path, now()),
        Err(JobRefusal::ProofRefused)
    );
    let other = console.proof(&gate, "POST", &path, Some("njc1.other.token"));
    assert_eq!(
        gate.admit(&console.channel(), &cap, &other, "POST", &path, now()),
        Err(JobRefusal::ProofRefused)
    );
}

#[test]
fn a_replayed_proof_and_a_proof_for_another_uri_are_refused() {
    let (gate, _d) = gate();
    let console = Guest::new("console");
    let cap = issued(&gate, &console, "console");
    let path = perform_path("console");
    let p = console.proof(&gate, "POST", &path, Some(&cap));
    assert!(
        gate.admit(&console.channel(), &cap, &p, "POST", &path, now())
            .is_ok()
    );
    assert_eq!(
        gate.admit(&console.channel(), &cap, &p, "POST", &path, now()),
        Err(JobRefusal::ProofRefused),
        "a proof is spent once"
    );
    // A proof made for the issue route is not a proof for the perform route.
    let wrong_uri = console.proof(&gate, "POST", &issue_path("console"), Some(&cap));
    assert_eq!(
        gate.admit(&console.channel(), &cap, &wrong_uri, "POST", &path, now()),
        Err(JobRefusal::ProofRefused)
    );
    let wrong_method = console.proof(&gate, "GET", &path, Some(&cap));
    assert_eq!(
        gate.admit(
            &console.channel(),
            &cap,
            &wrong_method,
            "POST",
            &path,
            now()
        ),
        Err(JobRefusal::ProofRefused)
    );
}

#[test]
fn a_capability_copied_with_its_key_to_another_channel_is_refused() {
    let (gate, _d) = gate();
    let console = Guest::new("console");
    let agent = Guest::new("lane-ops");
    let cap = issued(&gate, &console, "console");
    // Both copied, and presented from the agent's channel.
    assert_eq!(
        perform(&gate, &console, &agent.channel(), &cap, "console"),
        Err(JobRefusal::NotThisGuest)
    );
}

#[test]
fn an_expired_or_altered_capability_is_refused() {
    let (gate, _d) = gate();
    let console = Guest::new("console");
    let cap = issued(&gate, &console, "console");
    let path = perform_path("console");
    let p = console.proof(&gate, "POST", &path, Some(&cap));
    assert_eq!(
        gate.admit(
            &console.channel(),
            &cap,
            &p,
            "POST",
            &path,
            now() + CAPABILITY_TTL_SECS
        ),
        Err(JobRefusal::Expired)
    );
    // Rewrite the job in the claims and keep the tag: the MAC refuses it.
    let (signed, tag) = cap.rsplit_once('.').unwrap();
    let body = signed.split_once('.').unwrap().1;
    let mut claims: serde_json::Value = serde_json::from_slice(&B64.decode(body).unwrap()).unwrap();
    claims["job"] = "lane-ops".into();
    let altered = format!(
        "njc1.{}.{tag}",
        B64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let p = console.proof(&gate, "POST", &perform_path("lane-ops"), Some(&altered));
    assert_eq!(
        gate.admit(
            &console.channel(),
            &altered,
            &p,
            "POST",
            &perform_path("lane-ops"),
            now()
        ),
        Err(JobRefusal::Malformed)
    );
}

/// A capability never outlives the SVID it was issued under.
#[test]
fn a_capability_ends_with_its_svid() {
    let (gate, _d) = gate();
    let console = Guest::new("console");
    let short = GuestChannel::new(
        console.pod,
        &console.der,
        now() + 10,
        Some(ServiceName::new("console").unwrap()),
    );
    let p = console.proof(&gate, "POST", &issue_path("console"), None);
    let cap = gate
        .issue(&short, &console.der, &p, "console", now())
        .unwrap();
    let path = perform_path("console");
    let p = console.proof(&gate, "POST", &path, Some(&cap));
    assert_eq!(
        gate.admit(&short, &cap, &p, "POST", &path, now() + 11),
        Err(JobRefusal::Expired)
    );
    let p = console.proof(&gate, "POST", &issue_path("console"), None);
    assert_eq!(
        gate.issue(&short, &console.der, &p, "console", now() + 11),
        Err(JobRefusal::Expired)
    );
}

// ----- Another job's credentials -------------------------------------------------------------

#[test]
fn a_guest_cannot_fetch_another_jobs_credentials() {
    let (gate, _d) = gate();
    let console = Guest::new("console");
    // Ask for the other job's capability, with a valid proof of its own SVID.
    let p = console.proof(&gate, "POST", &issue_path("lane-ops"), None);
    assert_eq!(
        gate.issue(&console.channel(), &console.der, &p, "lane-ops", now()),
        Err(JobRefusal::NotGranted)
    );
    // Use its own capability on the other job's route.
    let cap = issued(&gate, &console, "console");
    assert_eq!(
        perform(&gate, &console, &console.channel(), &cap, "lane-ops"),
        Err(JobRefusal::NotGranted)
    );
    // Within its own job, target the other job's upstream.
    let admitted = perform(&gate, &console, &console.channel(), &cap, "console").unwrap();
    assert_eq!(
        admitted.upstream("gcp-lane-ops"),
        Err(JobRefusal::NotGranted)
    );
    // A guest launched as no service holds no job at all.
    let plain = Guest::new("console");
    let ch = GuestChannel::new(plain.pod, &plain.der, now() + 3600, None);
    let p = plain.proof(&gate, "POST", &issue_path("console"), None);
    assert_eq!(
        gate.issue(&ch, &plain.der, &p, "console", now()),
        Err(JobRefusal::NotGranted)
    );
}

// ----- The registry --------------------------------------------------------------------------

#[test]
fn the_job_registry_refuses_each_malformed_entry() {
    let ups = upstreams();
    let cases: &[(&str, &str, &str)] = &[
        ("name = \"console\"", "name = \"Console\"", "job name"),
        ("name = \"lane-ops\"", "name = \"console\"", "defined twice"),
        (
            "upstreams = [\"gcp-lane-ops\"]",
            "upstreams = []",
            "names no upstream",
        ),
        (
            "upstreams = [\"gcp-lane-ops\"]",
            "upstreams = [\"gcp-everything\"]",
            "not in the node's upstream registry",
        ),
        (
            "upstreams = [\"gcp-lane-ops\"]",
            "upstreams = [\"gcp-console\"]",
            "already belongs to job console",
        ),
        (
            "holder = { service = \"lane-ops\" }",
            "holder = { service = \"../x\" }",
            "holder",
        ),
        (
            "holder = { service = \"lane-ops\" }",
            "holder = { spiffe = \"spiffe://x\" }",
            "unknown variant",
        ),
    ];
    for (from, to, want) in cases {
        let text = JOBS.replacen(from, to, 1);
        assert_ne!(text, JOBS, "the case {to:?} changed nothing");
        let err = JobRegistry::from_toml_str(&text, &ups).expect_err(to);
        assert!(err.contains(want), "{to:?}: {err}");
    }
}

/// The public build ships no durable replay ledger. A gate must then refuse to open rather than
/// run on one that forgets spent proofs, and the test build's volatile ledger must be the only
/// reason it opens here.
#[test]
fn the_gate_opens_only_where_a_replay_ledger_exists() {
    let dir = tempfile::tempdir().unwrap();
    let opened = JobGate::open(registry(), ORIGIN, &dir.path().join("j"));
    assert_eq!(
        opened.is_ok(),
        nucleus_request_proof::replay_ledger_available()
    );
    // A plaintext origin is refused whatever the ledger.
    assert!(JobGate::open(registry(), "http://jobs.example/", &dir.path().join("k")).is_err());
}
