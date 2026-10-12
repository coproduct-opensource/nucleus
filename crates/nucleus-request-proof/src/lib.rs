//! Sender-constrained request verification with native Olog replay persistence.
//! The caller supplies a key from independently verified mTLS or issuer+CSR.
#![forbid(unsafe_code)]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use nucleus_identity::{did::JsonWebKey, dpop::DpopVerifier};
use olog_ledger::{Actor, Ledgered};
use olog_store::Batch;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Mutex};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("request proof refused")]
    Refused,
    #[error("request proof persistence unavailable")]
    Unavailable,
    #[error("invalid request proof configuration")]
    Configuration,
}
type Result<T> = std::result::Result<T, Error>;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    crv: String,
    kty: String,
    x: String,
    y: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    typ: String,
    alg: String,
    jwk: PublicKey,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    ath: Option<String>,
}
/// Evidence that verification and durable replay consumption both succeeded.
/// Not cloneable; adapters must consume the result when authorizing the request.
#[must_use]
pub struct VerifiedRequest {
    thumbprint: String,
}
impl VerifiedRequest {
    pub fn into_thumbprint(self) -> String {
        self.thumbprint
    }
}
struct Replay {
    db: Ledgered,
    poisoned: bool,
}
pub struct ProofGate {
    origin: url::Url,
    replay: Mutex<Replay>,
}

/// Immutable host-provisioned authority for one loopback listener. No key or
/// expiry may be selected from the incoming request. Each proof also binds the
/// exact body through ath(SHA256(body) encoded as lowercase hexadecimal).
pub struct LoopbackGate {
    gate: ProofGate,
    key: JsonWebKey,
    health_key: Option<JsonWebKey>,
    observation_key: Option<JsonWebKey>,
    expires: u64,
}
impl LoopbackGate {
    pub fn open(origin: &str, path: &Path, key: JsonWebKey, expires: u64) -> Result<Self> {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        if expires <= now || expires.saturating_sub(now) > 3600 {
            return Err(Error::Configuration);
        }
        thumbprint(&key)?;
        Ok(Self {
            gate: ProofGate::open_loopback(origin, path)?,
            key,
            health_key: None,
            observation_key: None,
            expires,
        })
    }

    /// Host-owned boot probe authority. This key is never accepted for an
    /// approval, file operation, or a nonempty health request.
    pub fn with_health_key(mut self, key: JsonWebKey) -> Result<Self> {
        let identity = thumbprint(&key)?;
        if self
            .observation_key
            .as_ref()
            .map(thumbprint)
            .transpose()?
            .as_ref()
            == Some(&identity)
        {
            return Err(Error::Configuration);
        }
        self.health_key = Some(key);
        Ok(self)
    }

    /// Separate node-owned authority for fixed supervisor observations. It does
    /// not authorize health probes, tools, approvals, bodies, or other routes.
    pub fn with_observation_key(mut self, key: JsonWebKey) -> Result<Self> {
        let identity = thumbprint(&key)?;
        if identity == thumbprint(&self.key)?
            || self
                .health_key
                .as_ref()
                .map(thumbprint)
                .transpose()?
                .as_ref()
                == Some(&identity)
        {
            return Err(Error::Configuration);
        }
        self.observation_key = Some(key);
        Ok(self)
    }

    pub fn verify(
        &self,
        proof: &str,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<VerifiedRequest> {
        if chrono::Utc::now().timestamp().max(0) as u64 >= self.expires {
            return Err(Error::Refused);
        }
        let binding = hex::encode(Sha256::digest(body));
        let key = if method == "GET" && path == "/v1/health" && body.is_empty() {
            self.health_key.as_ref().unwrap_or(&self.key)
        } else if method == "GET" && is_supervisor_observation(path) && body.is_empty() {
            self.observation_key.as_ref().unwrap_or(&self.key)
        } else {
            &self.key
        };
        let verified = self.gate.verify(proof, method, path, Some(&binding), key)?;
        if chrono::Utc::now().timestamp().max(0) as u64 >= self.expires {
            return Err(Error::Refused);
        }
        Ok(verified)
    }
}

/// Exact paths only: no query strings, suffixes, aliases, or arbitrary file reads.
pub fn is_supervisor_observation(path: &str) -> bool {
    matches!(
        path,
        "/v1/workload/result" | "/v1/workload/logs/stdout" | "/v1/workload/logs/stderr"
    )
}

#[cfg(test)]
mod observation_tests;
impl ProofGate {
    pub fn open(origin: &str, path: &Path) -> Result<Self> {
        Self::open_origin(origin, path, false)
    }

    /// Explicit host-local HTTP transport. Never accepts DNS names, unspecified
    /// addresses, default/absent ports, or arbitrary plaintext origins. The
    /// embedding listener must independently configure the authorized key.
    pub fn open_loopback(origin: &str, path: &Path) -> Result<Self> {
        Self::open_origin(origin, path, true)
    }

    fn open_origin(origin: &str, path: &Path, loopback: bool) -> Result<Self> {
        let origin = url::Url::parse(origin).map_err(|_| Error::Configuration)?;
        let transport = if loopback {
            origin.scheme() == "http"
                && origin.port().is_some_and(|port| port != 0)
                && origin.host().is_some_and(|host| match host {
                    url::Host::Ipv4(ip) => ip.is_loopback(),
                    url::Host::Ipv6(ip) => ip.is_loopback(),
                    url::Host::Domain(_) => false,
                })
        } else {
            origin.scheme() == "https"
        };
        if !transport
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(Error::Configuration);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            if !path.exists() {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(path)
                    .map_err(|_| Error::Unavailable)?;
            }
            let m = std::fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
            if !m.is_dir() || m.file_type().is_symlink() || m.permissions().mode() & 0o077 != 0 {
                return Err(Error::Configuration);
            }
        }
        let mut db = Ledgered::open(path, "request-proof").map_err(|_| Error::Unavailable)?;
        db.verify().map_err(|_| Error::Unavailable)?;
        match db
            .store()
            .try_get(b"format")
            .map_err(|_| Error::Unavailable)?
        {
            Some(v) if v == b"nucleus-request-proof-v1" => {}
            Some(_) => return Err(Error::Configuration),
            None => {
                if !db.is_empty() {
                    return Err(Error::Configuration);
                }
                let mut batch = Batch::new();
                batch.put(b"format", b"nucleus-request-proof-v1");
                db.write(
                    Actor {
                        principal: "node".into(),
                        credential: "local-initialize".into(),
                    },
                    |s| s.commit(batch),
                )
                .map_err(|_| Error::Unavailable)?;
            }
        }
        Ok(Self {
            origin,
            replay: Mutex::new(Replay {
                db,
                poisoned: false,
            }),
        })
    }
    pub fn verify(
        &self,
        proof: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        expected: &JsonWebKey,
    ) -> Result<VerifiedRequest> {
        self.verify_inner(proof, method, path, token, expected, None)
    }
    /// Also retire an issuer-validated single-use assertion in the same commit.
    pub fn verify_assertion(
        &self,
        proof: &str,
        path: &str,
        token: &str,
        expected: &JsonWebKey,
        expires: u64,
    ) -> Result<VerifiedRequest> {
        self.verify_inner(proof, "POST", path, Some(token), expected, Some(expires))
    }
    fn verify_inner(
        &self,
        proof: &str,
        method: &str,
        path: &str,
        token: Option<&str>,
        expected: &JsonWebKey,
        assertion_expiry: Option<u64>,
    ) -> Result<VerifiedRequest> {
        if proof.len() > 8192 || !path.starts_with('/') {
            return Err(Error::Refused);
        }
        let target = self.origin.join(path).map_err(|_| Error::Refused)?;
        if target.origin() != self.origin.origin()
            || !target.username().is_empty()
            || target.password().is_some()
        {
            return Err(Error::Refused);
        }
        let target = format!("{}{}", target.origin().ascii_serialization(), target.path());
        let parts: Vec<_> = proof.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::Refused);
        }
        let header: Header =
            serde_json::from_slice(&B64.decode(parts[0]).map_err(|_| Error::Refused)?)
                .map_err(|_| Error::Refused)?;
        let claims: Claims =
            serde_json::from_slice(&B64.decode(parts[1]).map_err(|_| Error::Refused)?)
                .map_err(|_| Error::Refused)?;
        if header.typ != "dpop+jwt"
            || header.alg != "ES256"
            || claims.jti.is_empty()
            || claims.jti.len() > 128
            || claims.htm != method
            || claims.htu != target
        {
            return Err(Error::Refused);
        }
        let embedded = JsonWebKey::ec_p256(&header.jwk.x, &header.jwk.y);
        if header.jwk.crv != "P-256"
            || header.jwk.kty != "EC"
            || thumbprint(&embedded)? != thumbprint(expected)?
        {
            return Err(Error::Refused);
        }
        let expected_ath = token.map(|t| B64.encode(Sha256::digest(t.as_bytes())));
        if claims.ath != expected_ath {
            return Err(Error::Refused);
        }
        DpopVerifier::new()
            .with_max_age(chrono::Duration::seconds(60))
            .with_max_clock_skew(chrono::Duration::seconds(5))
            .verify(proof, expected, method, &target)
            .map_err(|_| Error::Refused)?;
        let now = chrono::Utc::now().timestamp();
        let now = u64::try_from(now).map_err(|_| Error::Unavailable)?;
        let expires = claims.iat.checked_add(60).ok_or(Error::Refused)?;
        if expires < now {
            return Err(Error::Refused);
        }
        let thumbprint = thumbprint(expected)?;
        let key = format!(
            "seen/proof/{}",
            hex::encode(Sha256::digest(
                serde_json::to_vec(&(&thumbprint, &claims.jti)).map_err(|_| Error::Refused)?
            ))
        );
        let mut replay = self.replay.lock().map_err(|_| Error::Unavailable)?;
        if replay.poisoned {
            return Err(Error::Unavailable);
        }
        if replay
            .db
            .store()
            .try_get(key.as_bytes())
            .map_err(|_| Error::Unavailable)?
            .is_some()
        {
            return Err(Error::Refused);
        }
        let assertion_key = if let Some(expiry) = assertion_expiry {
            if expiry < now {
                return Err(Error::Refused);
            }
            let signed = token
                .and_then(|t| t.rsplit_once('.'))
                .map(|(signed, _)| signed)
                .ok_or(Error::Refused)?;
            let k = format!(
                "seen/assertion/{}",
                hex::encode(Sha256::digest(signed.as_bytes()))
            );
            if replay
                .db
                .store()
                .try_get(k.as_bytes())
                .map_err(|_| Error::Unavailable)?
                .is_some()
            {
                return Err(Error::Refused);
            }
            Some((k, expiry))
        } else {
            None
        };
        let rows = replay
            .db
            .store()
            .try_scan_prefix(b"seen/")
            .map_err(|_| Error::Unavailable)?;
        let mut live = 0;
        let mut batch = Batch::new();
        for (k, v) in rows {
            let expiry: u64 = serde_json::from_slice(&v).map_err(|_| Error::Unavailable)?;
            if expiry < now {
                batch.delete(&k);
            } else {
                live += 1;
            }
        }
        if live + 1 + usize::from(assertion_key.is_some()) > 4096 {
            return Err(Error::Unavailable);
        }
        if let Some((k, expiry)) = assertion_key {
            batch.put(
                k.as_bytes(),
                &serde_json::to_vec(&expiry).map_err(|_| Error::Unavailable)?,
            );
        }
        batch.put(
            key.as_bytes(),
            &serde_json::to_vec(&expires).map_err(|_| Error::Unavailable)?,
        );
        if replay
            .db
            .write(
                Actor {
                    principal: thumbprint.clone(),
                    credential: "verified-request-proof".into(),
                },
                |s| s.commit(batch),
            )
            .is_err()
        {
            replay.poisoned = true;
            return Err(Error::Unavailable);
        }
        Ok(VerifiedRequest { thumbprint })
    }
}
pub fn thumbprint(key: &JsonWebKey) -> Result<String> {
    if key.kty != "EC" || key.crv != "P-256" {
        return Err(Error::Refused);
    }
    let y = key.y.as_ref().ok_or(Error::Refused)?;
    for v in [&key.x, y] {
        let bytes = B64.decode(v).map_err(|_| Error::Refused)?;
        if bytes.len() != 32 || B64.encode(&bytes) != *v {
            return Err(Error::Refused);
        }
    }
    let public = PublicKey {
        crv: key.crv.clone(),
        kty: key.kty.clone(),
        x: key.x.clone(),
        y: y.clone(),
    };
    Ok(B64.encode(Sha256::digest(
        serde_json::to_vec(&public).map_err(|_| Error::Refused)?,
    )))
}
/// Caller must have validated this certificate's TLS chain before using its key.
pub fn certificate_key(der: &[u8]) -> Result<JsonWebKey> {
    nucleus_identity::did_crypto::extract_ec_p256_jwk(
        &nucleus_identity::certificate::Certificate::from_der(der.to_vec()),
    )
    .map_err(|_| Error::Refused)
}
/// Caller must verify the issuer JWT before supplying its cnf.jkt. CSR signature
/// and identity policy remain the CA's responsibility before issuance.
pub fn csr_key(pem: &str, verified_jkt: &str) -> Result<JsonWebKey> {
    use x509_parser::prelude::FromDer;
    let (rest, pem) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_| Error::Refused)?;
    if rest.iter().any(|b| !b.is_ascii_whitespace()) || pem.label != "CERTIFICATE REQUEST" {
        return Err(Error::Refused);
    }
    let (rest, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
            .map_err(|_| Error::Refused)?;
    if !rest.is_empty() {
        return Err(Error::Refused);
    }
    let key = nucleus_identity::did_crypto::ec_p256_jwk_from_spki(
        &csr.certification_request_info.subject_pki,
    )
    .map_err(|_| Error::Refused)?;
    if thumbprint(&key)? != verified_jkt {
        return Err(Error::Refused);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_identity::{CsrOptions, dpop::DpopProofBuilder};
    fn fixture() -> (nucleus_identity::csr::CertSign, Vec<u8>, JsonWebKey) {
        let csr = CsrOptions::new("spiffe://example.test/ns/app/sa/test")
            .generate()
            .unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
        let (_, csr_pem) = x509_parser::pem::parse_x509_pem(csr.csr().as_bytes()).unwrap();
        use x509_parser::prelude::FromDer;
        let (_, parsed) = x509_parser::certification_request::X509CertificationRequest::from_der(
            &csr_pem.contents,
        )
        .unwrap();
        let key = nucleus_identity::did_crypto::ec_p256_jwk_from_spki(
            &parsed.certification_request_info.subject_pki,
        )
        .unwrap();
        (csr, pem.contents, key)
    }
    #[test]
    fn bound_csr_and_requests_refuse_copies_mismatches_and_restart_replay() {
        let (csr, private, key) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay");
        assert_eq!(
            thumbprint(&csr_key(csr.csr(), &thumbprint(&key).unwrap()).unwrap()).unwrap(),
            thumbprint(&key).unwrap()
        );
        assert!(csr_key(csr.csr(), &thumbprint(&fixture().2).unwrap()).is_err());
        let gate = ProofGate::open("https://node.test", &path).unwrap();
        let proof = DpopProofBuilder::new("POST", "https://node.test/v1/pods")
            .with_access_token("bound-test-token")
            .build(&private)
            .unwrap();
        assert!(
            gate.verify("", "POST", "/v1/pods", Some("bound-test-token"), &key)
                .is_err()
        );
        for (method, path, token) in [
            ("GET", "/v1/pods", Some("bound-test-token")),
            ("POST", "/else", Some("bound-test-token")),
            ("POST", "/v1/pods", Some("copied-other-token")),
            ("POST", "/v1/pods", None),
        ] {
            assert!(gate.verify(&proof, method, path, token, &key).is_err());
        }
        assert!(
            gate.verify(
                &proof,
                "POST",
                "/v1/pods",
                Some("bound-test-token"),
                &fixture().2
            )
            .is_err()
        );
        assert_eq!(
            gate.verify(
                &proof,
                "POST",
                "/v1/pods?query=ignored",
                Some("bound-test-token"),
                &key
            )
            .unwrap()
            .into_thumbprint(),
            thumbprint(&key).unwrap()
        );
        drop(gate);
        let gate = ProofGate::open("https://node.test", &path).unwrap();
        assert!(matches!(
            gate.verify(&proof, "POST", "/v1/pods", Some("bound-test-token"), &key),
            Err(Error::Refused)
        ));
    }
    #[test]
    fn concurrent_replay_grants_exactly_one_request() {
        let (_, private, key) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let gate = std::sync::Arc::new(
            ProofGate::open("https://node.test", &dir.path().join("replay")).unwrap(),
        );
        let proof = DpopProofBuilder::new("GET", "https://node.test/v1/health")
            .build(&private)
            .unwrap();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let gate = gate.clone();
                let proof = proof.clone();
                let key = key.clone();
                std::thread::spawn(move || {
                    gate.verify(&proof, "GET", "/v1/health", None, &key).is_ok()
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|t| usize::from(t.join().unwrap()))
                .sum::<usize>(),
            1
        );
    }
    #[test]
    fn configuration_and_exclusive_writer_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay");
        for origin in [
            "http://node.test",
            "https://node.test/path",
            "https://user@node.test",
            "https://node.test/?query",
        ] {
            assert!(ProofGate::open(origin, &path).is_err());
        }
        let gate = ProofGate::open("https://node.test", &path).unwrap();
        assert!(ProofGate::open("https://node.test", &path).is_err());
        drop(gate);
    }
}

#[cfg(test)]
mod assertion_tests {
    use super::*;
    use nucleus_identity::dpop::DpopProofBuilder;
    #[test]
    fn single_use_assertions_cannot_gain_fresh_authority_after_restart() {
        let csr = nucleus_identity::CsrOptions::new("spiffe://example.test/ns/app/sa/test")
            .generate()
            .unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
        // The adapter supplies a JWT it already verified; this unit test checks
        // replay storage, not issuer validation (covered by the HTTP exchange).
        let token = "signed-header.signed-claims.signature";
        let make = || {
            DpopProofBuilder::new("POST", "https://node.test/exchange")
                .with_access_token(token)
                .build(&pem.contents)
                .unwrap()
        };
        let proof = make();
        let header: nucleus_identity::dpop::DpopHeader =
            serde_json::from_slice(&B64.decode(proof.split('.').next().unwrap()).unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay");
        let expiry = chrono::Utc::now().timestamp() as u64 + 300;
        let gate = ProofGate::open("https://node.test", &path).unwrap();
        gate.verify_assertion(&proof, "/exchange", token, &header.jwk, expiry)
            .unwrap()
            .into_thumbprint();
        drop(gate);
        let gate = ProofGate::open("https://node.test", &path).unwrap();
        assert!(
            gate.verify_assertion(&make(), "/exchange", token, &header.jwk, expiry)
                .is_err()
        );
        let malleated = "signed-header.signed-claims.other-signature";
        let fresh = DpopProofBuilder::new("POST", "https://node.test/exchange")
            .with_access_token(malleated)
            .build(&pem.contents)
            .unwrap();
        assert!(
            gate.verify_assertion(&fresh, "/exchange", malleated, &header.jwk, expiry)
                .is_err()
        );
    }
}

#[cfg(test)]
mod strict_tests {
    use super::*;
    #[test]
    fn health_key_cannot_authorize_tools_or_nonempty_probes() {
        use nucleus_identity::dpop::{DpopHeader, DpopProofBuilder};
        fn material() -> (Vec<u8>, JsonWebKey) {
            let csr = nucleus_identity::CsrOptions::new("spiffe://test/ns/probe/sa/health")
                .generate()
                .unwrap();
            let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
            let proof = DpopProofBuilder::new("GET", "http://127.0.0.1:1234/v1/health")
                .build(&pem.contents)
                .unwrap();
            let header: DpopHeader =
                serde_json::from_slice(&B64.decode(proof.split('.').next().unwrap()).unwrap())
                    .unwrap();
            (pem.contents, header.jwk)
        }
        let (_, client) = material();
        let (secret, health) = material();
        let dir = tempfile::tempdir().unwrap();
        let gate = LoopbackGate::open(
            "http://127.0.0.1:1234",
            &dir.path().join("proof"),
            client,
            chrono::Utc::now().timestamp() as u64 + 300,
        )
        .unwrap()
        .with_health_key(health)
        .unwrap();
        for (method, path, body) in [
            ("POST", "/v1/approve", "{}"),
            ("POST", "/v1/read", "{}"),
            ("POST", "/v1/health", ""),
            ("GET", "/v1/health", "unexpected"),
            ("GET", "/v1/health", ""),
        ] {
            let proof = DpopProofBuilder::new(method, &format!("http://127.0.0.1:1234{path}"))
                .with_access_token(&hex::encode(Sha256::digest(body.as_bytes())))
                .build(&secret)
                .unwrap();
            let result = gate.verify(&proof, method, path, body.as_bytes());
            if method == "GET" && body.is_empty() {
                result.unwrap().into_thumbprint();
                assert!(gate.verify(&proof, method, path, body.as_bytes()).is_err());
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn loopback_authority_binds_body_key_and_lifetime() {
        let csr = nucleus_identity::CsrOptions::new("spiffe://example.test/ns/app/sa/test")
            .generate()
            .unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
        let body = b"{\"path\":\"source\"}";
        let target = "http://127.0.0.1:1234/v1/read";
        let make = |body: &[u8]| {
            nucleus_identity::dpop::DpopProofBuilder::new("POST", target)
                .with_access_token(&hex::encode(Sha256::digest(body)))
                .build(&pem.contents)
                .unwrap()
        };
        let proof = make(body);
        let header: nucleus_identity::dpop::DpopHeader =
            serde_json::from_slice(&B64.decode(proof.split('.').next().unwrap()).unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now().timestamp() as u64;
        for expires in [now, now + 3601] {
            assert!(
                LoopbackGate::open(
                    "http://127.0.0.1:1234",
                    &dir.path().join("bad"),
                    header.jwk.clone(),
                    expires
                )
                .is_err()
            );
        }
        let gate = LoopbackGate::open(
            "http://127.0.0.1:1234",
            &dir.path().join("proof"),
            header.jwk,
            now + 300,
        )
        .unwrap();
        assert!(gate.verify(&proof, "POST", "/v1/read", b"changed").is_err());
        assert!(gate.verify(&proof, "POST", "/v1/write", body).is_err());
        gate.verify(&proof, "POST", "/v1/read", body)
            .unwrap()
            .into_thumbprint();
        assert!(gate.verify(&proof, "POST", "/v1/read", body).is_err());
    }

    #[test]
    fn loopback_is_explicit_bound_to_port_and_replay_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loopback");
        for origin in [
            "http://localhost:1234",
            "http://0.0.0.0:1234",
            "http://192.0.2.1:1234",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:1234/path",
            "http://user@127.0.0.1:1234",
            "https://127.0.0.1:1234",
        ] {
            assert!(ProofGate::open_loopback(origin, &path).is_err(), "{origin}");
            assert!(!path.exists());
        }
        assert!(ProofGate::open("http://127.0.0.1:1234", &path).is_err());
        let csr = nucleus_identity::CsrOptions::new("spiffe://example.test/ns/app/sa/test")
            .generate()
            .unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
        let proof =
            nucleus_identity::dpop::DpopProofBuilder::new("POST", "http://127.0.0.1:1234/v1/read")
                .build(&pem.contents)
                .unwrap();
        let header: nucleus_identity::dpop::DpopHeader =
            serde_json::from_slice(&B64.decode(proof.split('.').next().unwrap()).unwrap()).unwrap();
        let wrong_port = ProofGate::open_loopback("http://127.0.0.1:1235", &path).unwrap();
        assert!(
            wrong_port
                .verify(&proof, "POST", "/v1/read", None, &header.jwk)
                .is_err()
        );
        drop(wrong_port);
        let gate = ProofGate::open_loopback("http://127.0.0.1:1234", &path).unwrap();
        gate.verify(&proof, "POST", "/v1/read", None, &header.jwk)
            .unwrap()
            .into_thumbprint();
        drop(gate);
        let gate = ProofGate::open_loopback("http://127.0.0.1:1234", &path).unwrap();
        assert!(
            gate.verify(&proof, "POST", "/v1/read", None, &header.jwk)
                .is_err()
        );
        drop(gate);
        assert!(ProofGate::open_loopback("http://[::1]:1234", &dir.path().join("ipv6")).is_ok());
    }

    #[test]
    fn expired_future_private_jwk_and_unexpected_claims_are_refused() {
        let csr = nucleus_identity::CsrOptions::new("spiffe://example.test/ns/app/sa/test")
            .generate()
            .unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
        let sample = nucleus_identity::dpop::DpopProofBuilder::new("GET", "https://node.test/test")
            .build(&pem.contents)
            .unwrap();
        let header: nucleus_identity::dpop::DpopHeader =
            serde_json::from_slice(&B64.decode(sample.split('.').next().unwrap()).unwrap())
                .unwrap();
        let key = header.jwk;
        let dir = tempfile::tempdir().unwrap();
        let gate = ProofGate::open("https://node.test", &dir.path().join("replay")).unwrap();
        let now = chrono::Utc::now().timestamp();
        for case in ["expired", "future", "private", "nonce", "empty-jti"] {
            let mut header = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":key});
            let mut claims = serde_json::json!({"jti":case,"htm":"GET","htu":"https://node.test/test","iat":now});
            match case {
                "expired" => claims["iat"] = (now - 120).into(),
                "future" => claims["iat"] = (now + 30).into(),
                "private" => header["jwk"]["d"] = "forbidden-private-member".into(),
                "nonce" => claims["nonce"] = "unexpected".into(),
                "empty-jti" => claims["jti"] = "".into(),
                _ => unreachable!(),
            }
            let signed = nucleus_identity::did_crypto::jws_sign_es256_with_protected_header(
                &header.to_string(),
                claims.to_string().as_bytes(),
                &pem.contents,
            )
            .unwrap();
            assert!(
                gate.verify(&signed, "GET", "/test", None, &key).is_err(),
                "{case}"
            );
        }
    }
}
