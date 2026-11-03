//! Job grants: a guest proves its SVID and receives a capability for its own job, and nothing
//! else; the capability is bound to the guest's key, so a copy of it is worth nothing.
//!
//! # The problem this closes
//!
//! An operator job today ("deploy controld", "start a lane", "stop the metal host") is a
//! service-account token in a file that every process of the operator's login can read. Moving
//! the job into a guest only helps if the guest never holds the token either, and if a guest
//! can act as ITS job and no other. This module is the second half. The first is the broker,
//! which already attaches an upstream's credential on the host per call and never hands it to
//! the guest (`broker`, `broker_perform`, `federated_credential`).
//!
//! # The model
//!
//! * **The operator defines jobs** (`[[job]]`): a name, the one holder that may act as it, and
//!   the upstreams (operator registry names, `upstreams.rs`) its calls may reach. An upstream
//!   belongs to at most one job, so what an upstream's own IAM grants (for GCP, the binding on
//!   the federated principal whose `nucleus_upstream` claim names it) is exactly that job's
//!   authority and no other's.
//! * **The host knows who is on the channel** ([`GuestChannel`]): the pod whose broker socket
//!   this is, the SVID the node issued to it, and the service (`service_guest`) it was launched
//!   as. Nothing in it comes from the guest.
//! * **Issue** (`POST /v1/jobs/{job}/capability`): the guest presents its SVID and a fresh DPoP
//!   proof signed by the SVID's key. The node checks the SVID is the one it issued to THIS
//!   channel, the proof is fresh, unreplayed and for this method and URI, and that this guest's
//!   service holds the job. It answers with a capability naming that one job, this pod, and the
//!   SVID's public key, for at most [`CAPABILITY_TTL_SECS`] and never past the SVID.
//! * **Admit** (`POST /v1/jobs/{job}/perform`): every call carries the capability and a fresh
//!   proof by the same key over this method and URI, bound to the capability by `ath`. The node
//!   checks the MAC, the expiry, that the capability names this channel's pod and SVID, that the
//!   path names the capability's job, and that the job is still granted. The result,
//!   [`AdmittedJob`], is what the broker then clamps the call's target with.
//!
//! The key the proofs are checked against is the SVID's. **Today the HOST generates that key** and
//! serves it to guest-init once (`workload_api_vsock`, "served once across connections"), so the
//! host held it before the guest did. The host is inside the trust base either way; what changes
//! when the guest generates the key and sends a CSR (stage 2) is that no host file or memory
//! ever holds it. A copied capability, a copied SVID, or both, without
//! that key, fail at the proof. Both copied WITH the key, but presented on another guest's
//! channel, fail at the channel check. That is what "bound to the guest" means here.
//!
//! # What this does not establish
//!
//! * It is not wired to a transport yet (stage 2 adds the two routes to the broker socket).
//! * Replay protection is only as durable as [`nucleus_request_proof::ProofGate`]'s ledger. The
//!   public build ships none, so [`JobGate::open`] refuses in a public release build: the gate
//!   fails closed rather than run on a ledger that forgets spent proofs on restart.
//! * The capability's MAC key lives in the node process and dies with it. A node restart
//!   invalidates every capability; guests ask again. That is deliberate (no key at rest).

// Not wired to a transport yet (stage 2), so outside tests every item is dead.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, Mac as _, digest::KeyInit as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::pod_launch::service_guest::ServiceName;
use crate::upstreams::UpstreamRegistry;

/// The longest a capability lives. Short, because it is re-issued for the cost of one proof.
pub const CAPABILITY_TTL_SECS: u64 = 300;

/// The issue route for job `job`.
#[must_use]
pub fn issue_path(job: &str) -> String {
    format!("/v1/jobs/{job}/capability")
}

/// The perform route for job `job`.
#[must_use]
pub fn perform_path(job: &str) -> String {
    format!("/v1/jobs/{job}/perform")
}

/// Who may act as a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    /// The guest the node launched as this service (`service_guest`).
    Service(ServiceName),
}

/// One job, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    name: String,
    holder: Holder,
    upstreams: BTreeSet<String>,
}

/// The operator's `[[job]]` tables.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JobRegistry {
    jobs: Vec<Job>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobsFile {
    #[serde(default)]
    job: Vec<JobFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobFile {
    name: String,
    holder: HolderFile,
    upstreams: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum HolderFile {
    Service(String),
}

fn job_name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 48
        && n.as_bytes()[0].is_ascii_lowercase()
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl JobRegistry {
    /// Parse and validate, against the node's upstream registry.
    ///
    /// Refuses: a bad or repeated job name; a job with no upstreams; an upstream the node's
    /// registry does not define; an upstream named by two jobs (it would give both jobs one
    /// IAM principal); an unknown field.
    ///
    /// # Errors
    /// The first refusal, naming the job.
    pub fn from_toml_str(text: &str, upstreams: &UpstreamRegistry) -> Result<Self, String> {
        let file: JobsFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let known: BTreeSet<&str> = upstreams
            .entries()
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        let mut owner: BTreeMap<String, String> = BTreeMap::new();
        let mut jobs: Vec<Job> = Vec::with_capacity(file.job.len());
        for j in file.job {
            if !job_name_ok(&j.name) {
                return Err(format!(
                    "job name {:?} must be 1-48 of [a-z0-9-], starting with a letter",
                    j.name
                ));
            }
            if jobs.iter().any(|k| k.name == j.name) {
                return Err(format!("job {} is defined twice", j.name));
            }
            if j.upstreams.is_empty() {
                return Err(format!("job {} names no upstream", j.name));
            }
            let mut ups = BTreeSet::new();
            for u in j.upstreams {
                if !known.contains(u.as_str()) {
                    return Err(format!(
                        "job {}: upstream {u:?} is not in the node's upstream registry",
                        j.name
                    ));
                }
                if let Some(other) = owner.insert(u.clone(), j.name.clone()) {
                    return Err(format!(
                        "job {}: upstream {u:?} already belongs to job {other}; an upstream is \
                         one job's authority",
                        j.name
                    ));
                }
                ups.insert(u);
            }
            let holder = match j.holder {
                HolderFile::Service(s) => Holder::Service(
                    ServiceName::new(&s).map_err(|e| format!("job {}: holder: {e}", j.name))?,
                ),
            };
            jobs.push(Job {
                name: j.name,
                holder,
                upstreams: ups,
            });
        }
        Ok(Self { jobs })
    }

    fn granted(&self, job: &str, ch: &GuestChannel) -> Option<&Job> {
        self.jobs.iter().find(|j| {
            j.name == job
                && match &j.holder {
                    Holder::Service(s) => ch.service.as_ref() == Some(s),
                }
        })
    }
}

/// What the HOST knows about the guest at the other end of a broker channel. The node builds it
/// from its own records (the pod whose socket this is, the SVID it issued, the service it
/// launched); nothing in it is read from the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestChannel {
    pod: Uuid,
    svid_sha256: [u8; 32],
    svid_not_after: u64,
    service: Option<ServiceName>,
}

impl GuestChannel {
    /// The channel of pod `pod`, which the node issued the SVID `svid_der` (valid until
    /// `svid_not_after`, Unix seconds) and launched as `service`, if it is a service guest.
    #[must_use]
    pub fn new(
        pod: Uuid,
        svid_der: &[u8],
        svid_not_after: u64,
        service: Option<ServiceName>,
    ) -> Self {
        Self {
            pod,
            svid_sha256: Sha256::digest(svid_der).into(),
            svid_not_after,
            service,
        }
    }
}

/// Why a request was refused. Deliberately coarse on the wire (stage 2 maps every variant but
/// `Unavailable` to one 403): the reason is for the node's log, not for a probing guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobRefusal {
    /// The SVID or capability presented is not the one this channel's guest holds.
    NotThisGuest,
    /// The DPoP proof is missing, malformed, stale, replayed, for another method or URI, not
    /// bound to the capability, or not signed by the key the capability or SVID names.
    ProofRefused,
    /// This guest does not hold the job, or the target is outside it.
    NotGranted,
    /// The capability or the SVID it was issued under has expired.
    Expired,
    /// The capability does not parse or its MAC does not verify.
    Malformed,
    /// The replay ledger could not be read or written; fail closed.
    Unavailable,
}

/// A job's admitted call: the job and the upstreams its call may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct AdmittedJob {
    job: String,
    upstreams: BTreeSet<String>,
}

impl AdmittedJob {
    /// The job.
    #[must_use]
    pub fn job(&self) -> &str {
        &self.job
    }

    /// The upstreams.
    pub fn upstreams(&self) -> impl Iterator<Item = &str> {
        self.upstreams.iter().map(String::as_str)
    }

    /// Clamp a call's target: `name` only if it is one of this job's upstreams.
    ///
    /// # Errors
    /// [`JobRefusal::NotGranted`] for any other upstream, including another job's.
    pub fn upstream<'a>(&self, name: &'a str) -> Result<&'a str, JobRefusal> {
        if self.upstreams.contains(name) {
            Ok(name)
        } else {
            Err(JobRefusal::NotGranted)
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    v: u8,
    job: String,
    pod: Uuid,
    svid: String,
    x: String,
    y: String,
    iat: u64,
    exp: u64,
}

const CAPABILITY_PREFIX: &str = "njc1";

/// Issues and admits job capabilities. One per node.
pub struct JobGate {
    registry: JobRegistry,
    proofs: nucleus_request_proof::ProofGate,
    origin: String,
    mac_key: [u8; 32],
}

impl JobGate {
    /// A gate over `registry`, whose routes live at `origin` (an `https://` origin; on the broker
    /// socket it names the channel, not a network host), with its replay ledger in `ledger_dir`
    /// (a `0700` directory).
    ///
    /// # Errors
    /// The origin is not one `ProofGate` accepts, or this build has no durable replay ledger
    /// (every public release build): [`JobRefusal::Unavailable`].
    pub fn open(
        registry: JobRegistry,
        origin: &str,
        ledger_dir: &Path,
    ) -> Result<Self, JobRefusal> {
        let proofs = nucleus_request_proof::ProofGate::open(origin, ledger_dir)
            .map_err(|_| JobRefusal::Unavailable)?;
        // `ProofGate::open` has refused anything but a bare https origin ending in `/`.
        let origin = origin.trim_end_matches('/').to_owned();
        let mut mac_key = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut mac_key)
            .map_err(|_| JobRefusal::Unavailable)?;
        Ok(Self {
            registry,
            proofs,
            origin,
            mac_key,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.origin, path)
    }

    /// The URI a proof for `path` on this gate must name (`htu`).
    #[must_use]
    pub fn htu(&self, path: &str) -> String {
        self.url(path)
    }

    fn verify_proof(
        &self,
        proof: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        key: &nucleus_identity::did::JsonWebKey,
    ) -> Result<(), JobRefusal> {
        use nucleus_request_proof::Error;
        match self.proofs.verify(proof, method, path, token, key) {
            Ok(v) => v
                .into_thumbprint(nucleus_request_proof::unix_now())
                .map(|_| ())
                .map_err(|_| JobRefusal::ProofRefused),
            Err(Error::Refused) => Err(JobRefusal::ProofRefused),
            Err(_) => Err(JobRefusal::Unavailable),
        }
    }

    fn mac(&self, signed: &str) -> Hmac<Sha256> {
        let mut m = <Hmac<Sha256>>::new_from_slice(&self.mac_key).expect("any key length");
        m.update(b"nucleus-job-capability-v1\n");
        m.update(signed.as_bytes());
        m
    }

    /// Issue a capability for `job` to the guest on `ch`, which presents `svid_der` and a DPoP
    /// `proof` over `POST {issue_path(job)}` signed by that SVID's key, at `now`.
    ///
    /// # Errors
    /// [`JobRefusal::NotThisGuest`] for an SVID this channel's guest was not issued;
    /// [`JobRefusal::Expired`] past the SVID's end; [`JobRefusal::ProofRefused`] for any proof
    /// defect; [`JobRefusal::NotGranted`] when this guest does not hold `job`.
    pub fn issue(
        &self,
        ch: &GuestChannel,
        svid_der: &[u8],
        proof: &str,
        job: &str,
        now: u64,
    ) -> Result<String, JobRefusal> {
        let presented: [u8; 32] = Sha256::digest(svid_der).into();
        if presented != ch.svid_sha256 {
            return Err(JobRefusal::NotThisGuest);
        }
        if now >= ch.svid_not_after {
            return Err(JobRefusal::Expired);
        }
        let key = nucleus_request_proof::certificate_key(svid_der)
            .map_err(|_| JobRefusal::NotThisGuest)?;
        // The proof before the grant: an unauthenticated caller learns nothing about which jobs
        // exist from the order of refusals.
        self.verify_proof(proof, "POST", &issue_path(job), None, &key)?;
        self.registry
            .granted(job, ch)
            .ok_or(JobRefusal::NotGranted)?;
        let claims = Claims {
            v: 1,
            job: job.to_owned(),
            pod: ch.pod,
            svid: hex::encode(ch.svid_sha256),
            x: key.x.clone(),
            y: key.y.clone().ok_or(JobRefusal::NotThisGuest)?,
            iat: now,
            exp: now
                .saturating_add(CAPABILITY_TTL_SECS)
                .min(ch.svid_not_after),
        };
        let body = B64.encode(serde_json::to_vec(&claims).map_err(|_| JobRefusal::Unavailable)?);
        let signed = format!("{CAPABILITY_PREFIX}.{body}");
        let tag = B64.encode(self.mac(&signed).finalize().into_bytes());
        Ok(format!("{signed}.{tag}"))
    }

    /// Admit one call: `capability`, with a DPoP `proof` over `method` and `path` bound to it,
    /// from the guest on `ch`, at `now`.
    ///
    /// # Errors
    /// [`JobRefusal::Malformed`] for a capability that does not parse or verify;
    /// [`JobRefusal::Expired`] past its `exp`; [`JobRefusal::NotThisGuest`] when it was issued to
    /// another pod or SVID; [`JobRefusal::NotGranted`] when the path is not this job's perform
    /// route or the job is no longer granted; [`JobRefusal::ProofRefused`] for any proof defect.
    pub fn admit(
        &self,
        ch: &GuestChannel,
        capability: &str,
        proof: &str,
        method: &str,
        path: &str,
        now: u64,
    ) -> Result<AdmittedJob, JobRefusal> {
        let claims = self.open_capability(capability)?;
        if now >= claims.exp {
            return Err(JobRefusal::Expired);
        }
        if claims.pod != ch.pod || claims.svid != hex::encode(ch.svid_sha256) {
            return Err(JobRefusal::NotThisGuest);
        }
        if method != "POST" || path != perform_path(&claims.job) {
            return Err(JobRefusal::NotGranted);
        }
        let key = nucleus_identity::did::JsonWebKey::ec_p256(&claims.x, &claims.y);
        self.verify_proof(proof, method, path, Some(capability), &key)?;
        let job = self
            .registry
            .granted(&claims.job, ch)
            .ok_or(JobRefusal::NotGranted)?;
        Ok(AdmittedJob {
            job: job.name.clone(),
            upstreams: job.upstreams.clone(),
        })
    }

    fn open_capability(&self, capability: &str) -> Result<Claims, JobRefusal> {
        let (signed, tag) = capability.rsplit_once('.').ok_or(JobRefusal::Malformed)?;
        let (prefix, body) = signed.split_once('.').ok_or(JobRefusal::Malformed)?;
        if prefix != CAPABILITY_PREFIX {
            return Err(JobRefusal::Malformed);
        }
        let tag = B64.decode(tag).map_err(|_| JobRefusal::Malformed)?;
        self.mac(signed)
            .verify_slice(&tag)
            .map_err(|_| JobRefusal::Malformed)?;
        let claims: Claims =
            serde_json::from_slice(&B64.decode(body).map_err(|_| JobRefusal::Malformed)?)
                .map_err(|_| JobRefusal::Malformed)?;
        if claims.v != 1 {
            return Err(JobRefusal::Malformed);
        }
        Ok(claims)
    }
}

#[cfg(test)]
#[path = "job_grant_tests.rs"]
mod tests;
