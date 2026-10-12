//! Client-selected public proof key within an authenticated pod launch. This
//! grants no node API authority; it only attenuates that pod's tool listener.
use crate::{ApiError, PodSpec, signed_proxy::ProxyProofConfig};
use nucleus_identity::did::JsonWebKey;
use serde::Deserialize;
use std::path::Path;

pub(crate) const LABEL: &str = "nucleus.tool-proof";
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
struct Config {
    key: PublicKey,
    expires: u64,
}

pub(crate) fn admit(spec: &PodSpec, required: bool) -> Result<(), ApiError> {
    parse(spec, required).map(|_| ())
}

fn parse(spec: &PodSpec, required: bool) -> Result<Option<(JsonWebKey, u64)>, ApiError> {
    let refuse =
        || ApiError::InvalidSpec("bounded public tool proof configuration required".into());
    let Some(raw) = spec.metadata.labels.get(LABEL) else {
        return if required { Err(refuse()) } else { Ok(None) };
    };
    if raw.len() > 2048 {
        return Err(refuse());
    }
    let config: Config = serde_json::from_str(raw).map_err(|_| refuse())?;
    let now = crate::now_unix().max(0) as u64;
    if config.key.kty != "EC"
        || config.key.crv != "P-256"
        || config.expires <= now
        || config.expires.saturating_sub(now) > spec.spec.timeout_seconds.min(3600)
    {
        return Err(refuse());
    }
    let key = JsonWebKey::ec_p256(&config.key.x, &config.key.y);
    nucleus_request_proof::thumbprint(&key).map_err(|_| refuse())?;
    Ok(Some((key, config.expires)))
}

pub(crate) fn for_listener(
    spec: &PodSpec,
    required: bool,
    pod_dir: &Path,
    guest: Option<crate::guest_proof_provision::Signer>,
) -> Result<Option<ProxyProofConfig>, ApiError> {
    Ok(
        parse(spec, required)?.map(|(key, expires)| ProxyProofConfig {
            guest,
            key,
            expires,
            replay_path: pod_dir.join("tool-request-proofs.olog"),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_proofs_cannot_be_omitted_expired_or_private() {
        let mut spec: PodSpec = serde_json::from_value(serde_json::json!({
            "apiVersion":"nucleus/v1", "kind":"Pod", "metadata":{},
            "spec":{"timeout_seconds":300}
        }))
        .unwrap();
        assert!(admit(&spec, true).is_err());
        assert!(admit(&spec, false).is_ok());
        let now = crate::now_unix() as u64;
        use base64::Engine;
        let csr = nucleus_identity::CsrOptions::new("spiffe://test/ns/client/sa/tools")
            .generate()
            .unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
        let sample =
            nucleus_identity::dpop::DpopProofBuilder::new("POST", "http://127.0.0.1:1234/v1/read")
                .build(&pem.contents)
                .unwrap();
        let header: nucleus_identity::dpop::DpopHeader = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(sample.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        let valid = serde_json::json!({"key":{"kty":"EC","crv":"P-256", "x":header.jwk.x,"y":header.jwk.y},"expires":now+200});
        spec.metadata.labels.insert(LABEL.into(), valid.to_string());
        admit(&spec, true).unwrap();
        let proof = for_listener(&spec, true, Path::new("/fixture/pod"), None)
            .unwrap()
            .unwrap();
        assert_eq!(proof.expires, now + 200);
        assert_eq!(
            proof.replay_path,
            Path::new("/fixture/pod/tool-request-proofs.olog")
        );
        let config = serde_json::json!({"key":{"kty":"EC","crv":"P-256",
            "x":"fixture", "y":"fixture"},"expires":now+200});
        for value in [
            serde_json::json!({}),
            {
                let mut c = config.clone();
                c["expires"] = now.into();
                c
            },
            {
                let mut c = config.clone();
                c["expires"] = (now + 3601).into();
                c
            },
            {
                let mut c = config;
                c["key"]["d"] = "private".into();
                c
            },
        ] {
            spec.metadata.labels.insert(LABEL.into(), value.to_string());
            assert!(admit(&spec, true).is_err());
            assert!(admit(&spec, false).is_err());
        }
    }
}
