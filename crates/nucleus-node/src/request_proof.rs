//! Optional public-runtime protocol, mandatory in the orchestrator deployment.
//! Enabling it is atomic across HTTP API and federation; gRPC is then refused
//! at startup until its metadata adapter has the same proof boundary.
#[cfg(test)]
#[path = "request_proof_tls_tests.rs"]
mod tls_tests;
use axum::http::{HeaderMap, request::Parts};
use nucleus_request_proof::{Error, ProofGate};
use std::{path::Path, sync::Arc};

pub(crate) struct RequestProofs {
    pub api: ProofGate,
    pub exchange: ProofGate,
}
impl RequestProofs {
    pub fn open(
        args: &crate::federation_ingress::FederationArgs,
        dir: &Path,
        grpc: bool,
    ) -> Result<Option<Arc<Self>>, crate::ApiError> {
        match (
            &args.request_proof_api_origin,
            &args.request_proof_exchange_origin,
        ) {
            (None, None) => Ok(None),
            (Some(api), Some(exchange)) if !grpc => Ok(Some(Arc::new(Self {
                api: ProofGate::open(api, &dir.join("api-request-proof.olog"))
                    .map_err(|e| crate::ApiError::Driver(e.to_string()))?,
                exchange: ProofGate::open(exchange, &dir.join("exchange-request-proof.olog"))
                    .map_err(|e| crate::ApiError::Driver(e.to_string()))?,
            }))),
            _ => Err(crate::ApiError::Driver(
                "both request-proof origins are required, and gRPC must be disabled".into(),
            )),
        }
    }
    pub fn api(&self, parts: &Parts) -> Result<(), crate::ApiError> {
        let certificate = parts
            .extensions
            .get::<axum::extract::ConnectInfo<nucleus_identity::mtls::MtlsConnectInfo>>()
            .and_then(|c| c.0.client_cert.as_ref())
            .ok_or(crate::auth::AuthError::NoClientCertificate)?;
        let key = nucleus_request_proof::certificate_key(certificate.der()).map_err(map)?;
        let proof = one(&parts.headers, "dpop")
            .map_err(map)?
            .ok_or(crate::auth::AuthError::InvalidSignature)?;
        let token = one(&parts.headers, "x-nucleus-delegation-cert").map_err(map)?;
        let path = parts
            .extensions
            .get::<axum::extract::OriginalUri>()
            .map(|p| p.0.path())
            .unwrap_or(parts.uri.path());
        let verified = self
            .api
            .verify(proof, parts.method.as_str(), path, token, &key)
            .map_err(map)?;
        let _verified_key = verified.into_thumbprint();
        Ok(())
    }
}
pub(crate) fn one<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, Error> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(Error::Refused);
    }
    first
        .map(|v| v.to_str().map_err(|_| Error::Refused))
        .transpose()
}
fn map(error: Error) -> crate::ApiError {
    match error {
        Error::Refused => crate::auth::AuthError::InvalidSignature.into(),
        Error::Unavailable | Error::Configuration => {
            crate::ApiError::SupervisorUnavailable("request proof verifier unavailable".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, extract::State, middleware, response::IntoResponse, routing::get};
    use tower::ServiceExt;
    async fn check(
        State(state): State<Arc<RequestProofs>>,
        request: axum::extract::Request,
        next: middleware::Next,
    ) -> axum::response::Response {
        let (parts, body) = request.into_parts();
        match state.api(&parts) {
            Ok(()) => next.run(axum::http::Request::from_parts(parts, body)).await,
            Err(e) => e.into_response(),
        }
    }
    #[tokio::test]
    async fn request_proof_http_adapter_uses_verified_peer_certificate_not_embedded_key() {
        let dir = tempfile::tempdir().unwrap();
        let args = crate::federation_ingress::FederationArgs {
            request_proof_api_origin: Some("https://api.example.test".into()),
            request_proof_exchange_origin: Some("https://exchange.example.test".into()),
            ..crate::federation_ingress::FederationArgs::default()
        };
        assert!(RequestProofs::open(&args, dir.path(), true).is_err());
        let state = RequestProofs::open(&args, dir.path(), false)
            .unwrap()
            .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["client.example.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let peer = nucleus_identity::mtls::MtlsConnectInfo {
            peer_addr: "127.0.0.1:1234".parse().unwrap(),
            client_cert: Some(nucleus_identity::mtls::ClientCertInfo::from_der(
                cert.der().to_vec(),
            )),
        };
        let router = Router::new()
            .route("/v1/health", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(state, check));
        let wrong = rcgen::KeyPair::generate().unwrap();
        let proof = nucleus_identity::dpop::DpopProofBuilder::new(
            "GET",
            "https://api.example.test/v1/health",
        )
        .build(&key.serialize_der())
        .unwrap();
        let bad = nucleus_identity::dpop::DpopProofBuilder::new(
            "GET",
            "https://api.example.test/v1/health",
        )
        .build(&wrong.serialize_der())
        .unwrap();
        for (proof_header, expected) in [
            (None, 401),
            (Some(bad.as_str()), 401),
            (Some(proof.as_str()), 200),
            (Some(proof.as_str()), 401),
        ] {
            let mut request = axum::http::Request::builder().uri("/v1/health");
            if let Some(proof) = proof_header {
                request = request.header("dpop", proof);
            }
            let mut request = request.body(axum::body::Body::empty()).unwrap();
            request
                .extensions_mut()
                .insert(axum::extract::ConnectInfo(peer.clone()));
            assert_eq!(
                router
                    .clone()
                    .oneshot(request)
                    .await
                    .unwrap()
                    .status()
                    .as_u16(),
                expected
            );
        }
    }
}
