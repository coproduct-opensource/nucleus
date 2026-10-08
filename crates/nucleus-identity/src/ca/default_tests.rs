//! ADR 0016 D5: `CaClient`'s defaults never sign a weaker certificate than the
//! one asked for.

use super::*;
use crate::attestation::UnmeasuredTier;

/// A CA that never opted in to nucleus extensions: only the required methods,
/// so every extension-carrying call takes the trait's default.
struct PlainOnly(SelfSignedCa);

#[async_trait]
impl CaClient for PlainOnly {
    async fn sign_csr(
        &self,
        csr: &str,
        private_key: &str,
        identity: &Identity,
        ttl: Duration,
    ) -> Result<WorkloadCertificate> {
        self.0.sign_csr(csr, private_key, identity, ttl).await
    }

    async fn sign_csr_only(&self, csr: &str, identity: &Identity, ttl: Duration) -> Result<String> {
        self.0.sign_csr_only(csr, identity, ttl).await
    }

    fn trust_bundle(&self) -> &crate::certificate::TrustBundle {
        self.0.trust_bundle()
    }

    fn trust_domain(&self) -> &str {
        self.0.trust_domain()
    }
}

/// Asked for a certificate that states a launch, a CA that cannot embed it
/// refuses, naming what it cannot embed. Each default used to sign a weaker
/// certificate in its place: `sign_attested_csr` a plain one, and the fused and
/// bound variants an attested one without their fingerprint or binding.
/// Non-vacuous: the plain path still issues where a plain certificate is asked for.
#[tokio::test]
async fn no_default_signs_a_weaker_certificate_than_the_one_asked_for() {
    let ca = PlainOnly(SelfSignedCa::new("test.local").unwrap());
    let identity = Identity::for_pod("test.local", "pod-1");
    let cs = crate::CsrOptions::new(identity.to_spiffe_uri())
        .generate()
        .unwrap();
    let (csr, key, ttl) = (cs.csr(), cs.private_key(), Duration::from_secs(600));
    let att = LaunchAttestation::from_hashes([1; 32], [2; 32], [3; 32]);

    ca.sign_csr(csr, key, &identity, ttl)
        .await
        .expect("a plain certificate where a plain one is asked for");

    let refusals = [
        ca.sign_attested_csr(csr, key, &identity, ttl, &att).await,
        ca.sign_fused_csr(csr, key, &identity, ttl, &att, &[9; 32])
            .await,
        ca.sign_attested_and_bound_csr(csr, key, &identity, ttl, &att, &[9; 32])
            .await,
        ca.sign_unmeasured_csr(csr, key, &identity, ttl, UnmeasuredTier::Container)
            .await,
    ];
    for refused in refusals {
        let err = refused.expect_err("no weaker certificate in its place");
        assert!(
            err.to_string().contains("never issued in its place"),
            "{err}"
        );
    }
}
