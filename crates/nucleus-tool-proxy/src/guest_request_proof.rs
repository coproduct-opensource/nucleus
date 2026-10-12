//! Host proof is an additional condition, never a replacement for transport or
//! approval authority. Workload-door identities have a separate provisioning path.
use crate::{ApiError, PodSpec};
use nucleus_identity::did::JsonWebKey;
use serde::Deserialize;
use std::path::Path;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    kty: String,
    crv: String,
    x: String,
    y: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    origin: String,
    key: PublicKey,
    expires: u64,
}
pub(crate) struct Gate {
    gate: nucleus_request_proof::ProofGate,
    key: JsonWebKey,
    expires: u64,
}
fn refused() -> ApiError {
    ApiError::Auth(crate::auth::AuthError::InvalidHeader("dpop"))
}
impl Config {
    pub(crate) fn from_spec(spec: &PodSpec) -> Result<Option<Self>, ApiError> {
        let Some(raw) = spec.metadata.labels.get("nucleus.guest-proof") else {
            if spec.metadata.labels.contains_key("nucleus.tool-proof") {
                return Err(refused());
            }
            return Ok(None);
        };
        if raw.len() > 2048 {
            return Err(refused());
        }
        let config: Self = serde_json::from_str(raw).map_err(|_| refused())?;
        let origin = url::Url::parse(&config.origin).map_err(|_| refused())?;
        let id = origin
            .host_str()
            .and_then(|s| s.strip_suffix(".tools.nucleus.invalid"))
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(refused)?;
        if config.origin != format!("https://{id}.tools.nucleus.invalid")
            || config.key.kty != "EC"
            || config.key.crv != "P-256"
        {
            return Err(refused());
        }
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        if config.expires <= now || config.expires - now > 3600 {
            return Err(refused());
        }
        Ok(Some(config))
    }
    pub(crate) fn open(self, path: &Path) -> Result<Gate, ApiError> {
        let key = JsonWebKey::ec_p256(self.key.x, self.key.y);
        nucleus_request_proof::thumbprint(&key).map_err(|_| refused())?;
        Ok(Gate {
            gate: nucleus_request_proof::ProofGate::open(&self.origin, path)
                .map_err(|_| refused())?,
            key,
            expires: self.expires,
        })
    }
}
impl Gate {
    pub(crate) fn verify(
        &self,
        headers: &axum::http::HeaderMap,
        method: &str,
        uri: &axum::http::Uri,
        body: &[u8],
    ) -> Result<(), ApiError> {
        use sha2::{Digest, Sha256};
        if chrono::Utc::now().timestamp().max(0) as u64 >= self.expires || uri.query().is_some() {
            return Err(refused());
        }
        if headers.get_all("dpop").iter().count() != 1 {
            return Err(refused());
        }
        let proof = headers
            .get("dpop")
            .and_then(|s| s.to_str().ok())
            .ok_or_else(refused)?;
        let digest = hex::encode(Sha256::digest(body));
        self.gate
            .verify(proof, method, uri.path(), Some(&digest), &self.key)
            .map_err(|_| refused())?
            .into_thumbprint();
        if chrono::Utc::now().timestamp().max(0) as u64 >= self.expires {
            return Err(refused());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    #[test]
    fn host_proof_is_required_body_bound_and_replay_durable() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec: PodSpec = serde_json::from_value(serde_json::json!({
            "apiVersion":"nucleus/v1","kind":"Pod","metadata":{},"spec":{}
        }))
        .unwrap();
        assert!(Config::from_spec(&spec).unwrap().is_none());
        spec.metadata
            .labels
            .insert("nucleus.tool-proof".into(), "{}".into());
        assert!(Config::from_spec(&spec).is_err());
        let origin = format!("https://{}.tools.nucleus.invalid", uuid::Uuid::new_v4());
        let csr = nucleus_identity::CsrOptions::new("spiffe://test/ns/node/sa/host")
            .generate()
            .unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
        let body = b"exact body";
        let digest = hex::encode(Sha256::digest(body));
        let proof =
            nucleus_identity::dpop::DpopProofBuilder::new("POST", &format!("{origin}/v1/read"))
                .with_access_token(&digest)
                .build(&pem.contents)
                .unwrap();
        let header: nucleus_identity::dpop::DpopHeader = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(proof.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        let config = serde_json::json!({"origin":origin,"key":{"kty":"EC","crv":"P-256","x":header.jwk.x,"y":header.jwk.y},"expires":chrono::Utc::now().timestamp()+300});
        spec.metadata
            .labels
            .insert("nucleus.guest-proof".into(), config.to_string());
        let path = dir.path().join("replay");
        let gate = Config::from_spec(&spec)
            .unwrap()
            .unwrap()
            .open(&path)
            .unwrap();
        let mut headers = axum::http::HeaderMap::new();
        let uri = "/v1/read".parse().unwrap();
        assert!(gate.verify(&headers, "POST", &uri, body).is_err());
        headers.insert("dpop", proof.parse().unwrap());
        assert!(gate.verify(&headers, "POST", &uri, b"changed").is_err());
        assert!(gate.verify(&headers, "GET", &uri, body).is_err());
        assert!(
            gate.verify(&headers, "POST", &"/v1/write".parse().unwrap(), body)
                .is_err()
        );
        assert!(
            gate.verify(&headers, "POST", &"/v1/read?q=1".parse().unwrap(), body)
                .is_err()
        );
        headers.append("dpop", proof.parse().unwrap());
        assert!(gate.verify(&headers, "POST", &uri, body).is_err());
        headers.remove("dpop");
        headers.insert("dpop", proof.parse().unwrap());
        gate.verify(&headers, "POST", &uri, body).unwrap();
        assert!(gate.verify(&headers, "POST", &uri, body).is_err());
        drop(gate);
        let gate = Config::from_spec(&spec)
            .unwrap()
            .unwrap()
            .open(&path)
            .unwrap();
        assert!(gate.verify(&headers, "POST", &uri, body).is_err());
        let mut private = config.clone();
        private["key"]["d"] = "private".into();
        spec.metadata
            .labels
            .insert("nucleus.guest-proof".into(), private.to_string());
        assert!(Config::from_spec(&spec).is_err());
        let mut expired = config;
        expired["expires"] = 0.into();
        spec.metadata
            .labels
            .insert("nucleus.guest-proof".into(), expired.to_string());
        assert!(Config::from_spec(&spec).is_err());
    }
}
