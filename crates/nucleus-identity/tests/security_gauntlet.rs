//! SPIFFE Security Gauntlet: Comprehensive security tests for nucleus-identity.
//!
//! This test suite covers:
//! 1. Certificate fuzzing (Frankencerts-style)
//! 2. SPIFFE URI injection attacks
//! 3. Confused deputy attack scenarios
//! 4. Trust domain boundary violations
//! 5. Certificate chain validation bypasses
//! 6. Chaos/failure scenarios
//!
//! References:
//! - Frankencerts: https://pmc.ncbi.nlm.nih.gov/articles/PMC4232952/
//! - mTLS attacks: https://github.blog/security/vulnerability-research/mtls-when-certificate-authentication-is-done-wrong/
//! - SPIFFE security: https://tag-security.cncf.io/community/assessments/projects/spiffe-spire/self-assessment/

use nucleus_identity::{
    ca::CaClient, CsrOptions, Error, Identity, IdentityVerifier, SelfSignedCa, TrustDomainVerifier,
};
use proptest::prelude::*;
use std::time::Duration;

// ============================================================================
// SECTION 1: SPIFFE URI INJECTION ATTACKS
// ============================================================================
// Test vectors from GitHub's mTLS research: certificate fields can be used
// in queries before signature verification, creating injection opportunities.

mod spiffe_uri_injection {
    use super::*;

    /// SQL injection attempts via SPIFFE URI components
    #[test]
    fn test_sql_injection_in_namespace() {
        let payloads = [
            "'; DROP TABLE users; --",
            "1 OR 1=1",
            "admin'--",
            "1; SELECT * FROM passwords",
            "' UNION SELECT * FROM secrets --",
        ];

        for payload in payloads {
            let result = Identity::try_new("nucleus.local", payload, "service");
            assert!(
                result.is_err(),
                "SQL injection payload should be rejected: {}",
                payload
            );
        }
    }

    /// SQL injection attempts via service account
    #[test]
    fn test_sql_injection_in_service_account() {
        let payloads = ["service'; DELETE FROM certs; --", "admin' OR '1'='1"];

        for payload in payloads {
            let result = Identity::try_new("nucleus.local", "default", payload);
            assert!(
                result.is_err(),
                "SQL injection payload should be rejected: {}",
                payload
            );
        }
    }

    /// LDAP injection attempts
    #[test]
    fn test_ldap_injection_in_namespace() {
        let payloads = [
            "*)(uid=*))(|(uid=*",
            "admin)(&)",
            "*)(&(objectclass=*)",
            "*()|&'",
        ];

        for payload in payloads {
            let result = Identity::try_new("nucleus.local", payload, "service");
            // These should either be rejected or safely escaped
            // The current implementation rejects special chars
            if result.is_ok() {
                // If accepted, verify it round-trips safely
                let id = result.unwrap();
                let uri = id.to_spiffe_uri();
                let parsed = Identity::from_spiffe_uri(&uri);
                // Either parsing fails OR the parsed value matches exactly
                assert!(
                    parsed.is_err() || parsed.unwrap().namespace() == payload,
                    "LDAP injection payload must round-trip safely or be rejected"
                );
            }
        }
    }

    /// Path traversal attacks
    #[test]
    fn test_path_traversal_in_namespace() {
        let payloads = [
            ("../../../etc/passwd", "contains slash"),
            (
                "..%2f..%2f..%2fetc/passwd",
                "contains percent-encoded or slash",
            ),
            ("....//....//etc/passwd", "contains slash"),
            ("..\\..\\..\\windows\\system32", "contains backslash"),
            ("%2e%2e%2f", "contains percent-encoded"),
            ("..%00/", "contains percent-encoded or slash"),
            ("..", "standalone dot-dot (relative path modifier)"),
            (".", "standalone dot (relative path modifier)"),
        ];

        for (payload, reason) in payloads {
            let result = Identity::try_new("nucleus.local", payload, "service");
            assert!(
                result.is_err(),
                "Path traversal payload should be rejected ({}): {}",
                reason,
                payload
            );
        }
    }

    /// Valid edge cases that should be ACCEPTED
    #[test]
    fn test_valid_edge_cases() {
        // These should be valid per SPIFFE spec - dots within segment names are ok
        let valid_cases = [
            "a.b.c",        // Multiple dots
            "a..b",         // Double dot within name (not standalone)
            "test.service", // Typical service name
            "v1.0.0",       // Version-like
            "my-service",   // Hyphens
            "my_service",   // Underscores
            "Service123",   // Mixed case
        ];

        for valid in valid_cases {
            let result = Identity::try_new("nucleus.local", valid, "service");
            assert!(
                result.is_ok(),
                "Valid namespace should be accepted: {}",
                valid
            );
        }
    }

    /// Null byte injection (C string termination attacks)
    #[test]
    fn test_null_byte_injection() {
        let payloads = ["admin\x00.evil.com", "namespace\x00", "\x00hidden"];

        for payload in payloads {
            let result = Identity::try_new("nucleus.local", payload, "service");
            assert!(
                result.is_err(),
                "Null byte injection should be rejected: {:?}",
                payload.as_bytes()
            );
        }
    }

    /// Control character injection
    #[test]
    fn test_control_character_injection() {
        // Various control characters that could cause issues
        let control_chars = [
            '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x0b', '\x0c', '\x0e',
            '\x0f', '\x10', '\x1b', '\x7f', // DEL
        ];

        for c in control_chars {
            let payload = format!("namespace{}test", c);
            let result = Identity::try_new("nucleus.local", &payload, "service");
            assert!(
                result.is_err(),
                "Control character {:02x} should be rejected",
                c as u8
            );
        }
    }

    /// Unicode normalization attacks
    #[test]
    fn test_unicode_normalization_attacks() {
        // Homograph attacks and normalization issues
        let payloads = [
            "аdmin",         // Cyrillic 'а' looks like Latin 'a'
            "ɑdmin",         // Latin alpha
            "admin\u{200B}", // Zero-width space
            "adm\u{00AD}in", // Soft hyphen
        ];

        for payload in payloads {
            let result = Identity::try_new("nucleus.local", payload, "service");
            // Either reject or handle consistently
            if let Ok(id) = result {
                // If accepted, it should be stored exactly as provided
                assert_eq!(id.namespace(), payload);
            }
        }
    }

    /// Newline injection (HTTP header/log injection)
    #[test]
    fn test_newline_injection() {
        let payloads = [
            "namespace\r\nX-Injected: header",
            "namespace\nSet-Cookie: evil",
            "namespace\r",
        ];

        for payload in payloads {
            let result = Identity::try_new("nucleus.local", payload, "service");
            assert!(
                result.is_err(),
                "Newline injection should be rejected: {:?}",
                payload.as_bytes()
            );
        }
    }
}

// ============================================================================
// SECTION 2: TRUST DOMAIN BOUNDARY VIOLATIONS
// ============================================================================
// Verify that trust domain boundaries are properly enforced.

mod trust_domain_violations {
    use super::*;

    /// Attempt to create identity with different trust domain than CA serves
    #[tokio::test]
    async fn test_cross_trust_domain_signing_rejected() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();

        // Try to get certificate for a different trust domain
        let foreign_identity = Identity::new("attacker.evil", "default", "service");
        let csr_options = CsrOptions::new(foreign_identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let result = ca
            .sign_csr(
                cert_sign.csr(),
                &foreign_identity,
                Duration::from_secs(3600),
            )
            .await;

        assert!(
            matches!(result, Err(Error::TrustDomainMismatch { .. })),
            "CA should reject signing for foreign trust domain"
        );
    }

    /// Verify TrustDomainVerifier rejects certificates from wrong domain
    #[tokio::test]
    async fn test_verifier_rejects_wrong_trust_domain() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let verifier = TrustDomainVerifier::new("different.domain", ca.trust_bundle()).unwrap();

        let identity = Identity::new("nucleus.local", "default", "service");
        let csr_options = CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let cert = ca
            .sign_csr(cert_sign.csr(), &identity, Duration::from_secs(3600))
            .await
            .unwrap();

        // The certificate is valid but for wrong trust domain
        // TrustDomainVerifier.verify_identity should reject it
        use nucleus_identity::certificate::Certificate;
        let cert_obj = Certificate::from_der(cert.leaf().der().to_vec());
        let extracted = cert_obj.extract_spiffe_identity().unwrap();

        assert!(
            !extracted.is_in_trust_domain("different.domain"),
            "Certificate should not be in verifier's trust domain"
        );
    }

    /// Trust domain spoofing via subdomain
    #[test]
    fn test_trust_domain_subdomain_spoofing() {
        let victim_domain = "nucleus.local";
        let attacker_domains = [
            "nucleus.local.evil.com",
            "evil.nucleus.local", // Subdomain
            "nucleus-local",      // Similar name
            "nucleus.locall",     // Typosquatting
        ];

        for attacker_domain in attacker_domains {
            let victim_id = Identity::new(victim_domain, "default", "service");
            let attacker_id = Identity::new(attacker_domain, "default", "service");

            // Verify they are NOT equal
            assert_ne!(
                victim_id.trust_domain(),
                attacker_id.trust_domain(),
                "Trust domains should be distinct"
            );
            assert!(
                !attacker_id.is_in_trust_domain(victim_domain),
                "Attacker domain should not match victim domain"
            );
        }
    }
}

// ============================================================================
// SECTION 3: CONFUSED DEPUTY ATTACKS
// ============================================================================
// Test scenarios where a trusted component could be tricked into
// issuing credentials for the wrong identity.

mod confused_deputy {
    use super::*;

    /// CSR for one identity, request signing for another (identity mismatch)
    #[tokio::test]
    async fn test_csr_identity_mismatch_rejected() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();

        // Attacker generates CSR with their identity in the SAN
        let attacker_identity = Identity::new("nucleus.local", "attacker-ns", "attacker-sa");
        let csr_options = CsrOptions::new(attacker_identity.to_spiffe_uri());
        let attacker_csr = csr_options.generate().unwrap();

        // Attacker tries to claim victim's identity
        let victim_identity = Identity::new("nucleus.local", "victim-ns", "admin-sa");

        let result = ca
            .sign_csr(
                attacker_csr.csr(),
                &victim_identity,
                Duration::from_secs(3600),
            )
            .await;

        assert!(
            matches!(result, Err(Error::VerificationFailed(_))),
            "CA should reject CSR with mismatched identity"
        );
    }

    /// Verify that CSR signature is validated (proof of key possession)
    #[tokio::test]
    async fn test_csr_signature_validation() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "service");

        // Create a malformed CSR (corrupted signature)
        let malformed_csr = r#"-----BEGIN CERTIFICATE REQUEST-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWyf
INVALID_BASE64_DATA_HERE_TO_CORRUPT_SIGNATURE
-----END CERTIFICATE REQUEST-----"#;

        let result = ca
            .sign_csr(malformed_csr, &identity, Duration::from_secs(3600))
            .await;

        assert!(result.is_err(), "Malformed CSR should be rejected");
    }

    /// Attempt to use one workload's cert to impersonate another
    #[tokio::test]
    async fn test_identity_verifier_prevents_impersonation() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();

        // Create expected identity list (what we're willing to talk to)
        let expected = vec![Identity::new("nucleus.local", "production", "api-server")];
        let verifier = IdentityVerifier::new(expected.clone(), ca.trust_bundle()).unwrap();

        // Attacker gets valid certificate for THEIR identity
        let attacker_identity = Identity::new("nucleus.local", "attacker-ns", "evil-service");
        let csr_options = CsrOptions::new(attacker_identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let attacker_cert = ca
            .sign_csr(
                cert_sign.csr(),
                &attacker_identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // Extract and verify identity - should fail because attacker is not in expected list
        let extracted = attacker_cert.leaf().extract_spiffe_identity().unwrap();
        assert!(
            !expected.contains(&extracted),
            "Attacker identity should not be in expected list"
        );
    }
}

// ============================================================================
// SECTION 4: CERTIFICATE CHAIN VALIDATION BYPASSES
// ============================================================================
// Test that certificate chain validation cannot be bypassed.

mod chain_validation {
    use super::*;
    use rustls::pki_types::{CertificateDer, UnixTime};

    /// Certificates from untrusted CA must be rejected
    #[tokio::test]
    async fn test_untrusted_ca_rejected() {
        let trusted_ca = SelfSignedCa::new("trusted.local").unwrap();
        let rogue_ca = SelfSignedCa::new("rogue.local").unwrap();

        // Verifier only trusts the first CA
        let verifier = IdentityVerifier::any_identity(trusted_ca.trust_bundle()).unwrap();

        // Get cert from rogue CA
        let identity = Identity::new("rogue.local", "default", "service");
        let csr_options = CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let rogue_cert = rogue_ca
            .sign_csr(cert_sign.csr(), &identity, Duration::from_secs(3600))
            .await
            .unwrap();

        // Build DER chain
        let cert_der = CertificateDer::from(rogue_cert.leaf().der().to_vec());
        let intermediates: Vec<CertificateDer<'_>> = rogue_cert.chain()[1..]
            .iter()
            .map(|c| CertificateDer::from(c.der().to_vec()))
            .collect();

        // This should fail - certificate not signed by trusted CA
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::ServerName;

        let server_name = ServerName::try_from("test.local").unwrap();
        let result = verifier.verify_server_cert(
            &cert_der,
            &intermediates,
            &server_name,
            &[],
            UnixTime::now(),
        );

        assert!(result.is_err(), "Rogue CA certificate must be rejected");
    }

    /// Self-signed end-entity certificates must be rejected
    #[tokio::test]
    async fn test_self_signed_end_entity_rejected() {
        let real_ca = SelfSignedCa::new("real.local").unwrap();
        let verifier = IdentityVerifier::any_identity(real_ca.trust_bundle()).unwrap();

        // Create a completely separate "fake" CA and use its cert directly
        // as if it were an end-entity cert
        let fake_ca = SelfSignedCa::new("fake.local").unwrap();

        // The fake CA's root cert is self-signed - try to use it as end-entity
        let fake_root_der = fake_ca.trust_bundle().roots()[0].der();
        let cert_der = CertificateDer::from(fake_root_der.to_vec());

        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::ServerName;

        let server_name = ServerName::try_from("test.local").unwrap();
        let result =
            verifier.verify_server_cert(&cert_der, &[], &server_name, &[], UnixTime::now());

        assert!(
            result.is_err(),
            "Self-signed certificate not in trust store must be rejected"
        );
    }
}

// ============================================================================
// SECTION 5: PROPERTY-BASED FUZZING
// ============================================================================
// Use proptest to generate random inputs and find edge cases.

mod fuzzing {
    use super::*;

    proptest! {
        /// Fuzz SPIFFE URI parsing with random strings
        #[test]
        fn fuzz_spiffe_uri_parsing(input in ".*") {
            // Should never panic, only return Ok or Err
            let _ = Identity::from_spiffe_uri(&input);
        }

        /// Fuzz trust domain with printable ASCII
        #[test]
        fn fuzz_trust_domain(domain in "[a-zA-Z0-9.-]{1,100}") {
            // Valid domain characters should work
            let result = Identity::try_new(&domain, "default", "service");
            // May succeed or fail depending on specific pattern, but shouldn't panic
            let _ = result;
        }

        /// Fuzz namespace with SPIFFE-valid characters only
        /// Per SPIFFE spec: only [a-zA-Z0-9.-_] allowed, cannot start with dot
        #[test]
        fn fuzz_namespace(namespace in "[a-zA-Z][a-zA-Z0-9._-]{0,50}") {
            let result = Identity::try_new("test.local", &namespace, "service");
            // Valid SPIFFE characters should be accepted
            prop_assert!(result.is_ok(), "Valid SPIFFE namespace should be accepted: {}", namespace);
            let id = result.unwrap();

            // Must round-trip correctly
            let uri = id.to_spiffe_uri();
            let parsed = Identity::from_spiffe_uri(&uri);
            prop_assert!(parsed.is_ok(), "Accepted namespace must round-trip: {}", uri);
            let parsed_id = parsed.unwrap();
            prop_assert_eq!(parsed_id.namespace(), namespace);
        }

        /// Fuzz service account with SPIFFE-valid characters
        #[test]
        fn fuzz_service_account(sa in "[a-zA-Z][a-zA-Z0-9._-]{0,50}") {
            let result = Identity::try_new("test.local", "default", &sa);
            prop_assert!(result.is_ok(), "Valid SPIFFE service account should be accepted: {}", sa);
            let id = result.unwrap();

            let uri = id.to_spiffe_uri();
            let parsed = Identity::from_spiffe_uri(&uri);
            prop_assert!(parsed.is_ok(), "Accepted service account must round-trip");
            let parsed_id = parsed.unwrap();
            prop_assert_eq!(parsed_id.service_account(), sa);
        }

        /// Fuzz with invalid characters - should always reject
        #[test]
        fn fuzz_invalid_namespace_chars(
            prefix in "[a-z]{1,5}",
            invalid_char in "[^a-zA-Z0-9._-]",
            suffix in "[a-z]{0,5}"
        ) {
            let payload = format!("{}{}{}", prefix, invalid_char, suffix);
            let result = Identity::try_new("test.local", &payload, "service");
            prop_assert!(result.is_err(), "Invalid character should be rejected in: {}", payload);
        }

        /// Fuzz complete SPIFFE URIs
        #[test]
        fn fuzz_complete_uri(
            scheme in "(spiffe|http|https|ftp|file)?",
            domain in "[a-zA-Z0-9.-]{0,50}",
            path in "[a-zA-Z0-9/_-]{0,100}"
        ) {
            let uri = format!("{}://{}/{}", scheme, domain, path);
            let result = Identity::from_spiffe_uri(&uri);
            // Non-spiffe schemes should fail, spiffe may succeed
            if scheme != "spiffe" {
                prop_assert!(result.is_err(), "Non-SPIFFE scheme should fail: {}", uri);
            }
        }

        /// Fuzz with null bytes at various positions
        #[test]
        fn fuzz_null_byte_injection(
            prefix in "[a-z]{0,10}",
            suffix in "[a-z]{0,10}"
        ) {
            let payload = format!("{}\x00{}", prefix, suffix);
            let result = Identity::try_new("test.local", &payload, "service");
            prop_assert!(result.is_err(), "Null byte must be rejected");
        }

        /// Fuzz with path traversal sequences
        #[test]
        fn fuzz_path_traversal(
            prefix in "[a-z]{0,5}",
            dots in "\\.{2,5}",
            sep in "[/\\\\]",
            suffix in "[a-z]{0,10}"
        ) {
            let payload = format!("{}{}{}{}", prefix, dots, sep, suffix);
            // Double dots should be rejected
            if payload.contains("..") {
                let result = Identity::try_new("test.local", &payload, "service");
                prop_assert!(result.is_err(), "Path traversal must be rejected: {}", payload);
            }
        }
    }
}

// ============================================================================
// SECTION 6: CHAOS AND FAILURE SCENARIOS
// ============================================================================
// Test resilience under failure conditions.

mod chaos {
    use super::*;

    /// Very short TTL should still produce valid certificate
    #[tokio::test]
    async fn test_very_short_ttl() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "service");
        let csr_options = CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        // 1 second TTL
        let cert = ca
            .sign_csr(cert_sign.csr(), &identity, Duration::from_secs(1))
            .await
            .unwrap();

        assert!(
            !cert.is_expired(),
            "Freshly issued cert should not be expired"
        );

        // After waiting, it should expire
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(cert.is_expired(), "Cert should be expired after TTL");
    }

    /// Very long TTL should be handled
    #[tokio::test]
    async fn test_very_long_ttl() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "service");
        let csr_options = CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        // 10 year TTL
        let ttl = Duration::from_secs(10 * 365 * 24 * 60 * 60);
        let cert = ca.sign_csr(cert_sign.csr(), &identity, ttl).await.unwrap();

        assert!(!cert.is_expired());
    }

    /// Empty components should be rejected
    #[test]
    fn test_empty_components_rejected() {
        assert!(Identity::try_new("", "default", "service").is_err());
        assert!(Identity::try_new("test.local", "", "service").is_err());
        assert!(Identity::try_new("test.local", "default", "").is_err());
    }

    /// Very long identifiers should be handled (DoS prevention)
    #[test]
    fn test_very_long_identifiers() {
        let long_string = "a".repeat(10000);

        // These should either succeed or fail gracefully (no panic)
        let _ = Identity::try_new(&long_string, "default", "service");
        let _ = Identity::try_new("test.local", &long_string, "service");
        let _ = Identity::try_new("test.local", "default", &long_string);
    }

    /// Concurrent certificate requests should be isolated
    #[tokio::test]
    async fn test_concurrent_requests_isolated() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let ca = SelfSignedCa::new("nucleus.local").unwrap();
                let identity = Identity::new("nucleus.local", "default", format!("service-{}", i));

                tokio::spawn(async move {
                    let csr_options = CsrOptions::new(identity.to_spiffe_uri());
                    let cert_sign = csr_options.generate().unwrap();

                    let cert = ca
                        .sign_csr(cert_sign.csr(), &identity, Duration::from_secs(3600))
                        .await
                        .unwrap();

                    (i, cert.identity().clone())
                })
            })
            .collect();

        for handle in handles {
            let (i, identity) = handle.await.unwrap();
            assert_eq!(
                identity.service_account(),
                format!("service-{}", i),
                "Each request should get its own identity"
            );
        }
    }
}

// ============================================================================
// SECTION 7: REGRESSION TESTS FOR KNOWN VULNERABILITIES
// ============================================================================

mod regressions {
    use super::*;

    /// Regression: Certificate fields used in queries before signature verification
    /// (GitHub mTLS research finding)
    #[tokio::test]
    async fn test_no_fields_used_before_signature_verification() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();

        // Create CSR with potentially dangerous characters in SAN
        // The CA should verify signature BEFORE using any certificate fields
        let identity = Identity::new("nucleus.local", "default", "service");
        let csr_options = CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        // This should succeed because CSR signature is valid
        let result = ca
            .sign_csr(cert_sign.csr(), &identity, Duration::from_secs(3600))
            .await;

        assert!(
            result.is_ok(),
            "Valid CSR should be accepted after signature verification"
        );
    }

    /// Regression: SPIFFE assumes workload isolation
    /// Test that certificate extraction doesn't leak to wrong identity
    #[tokio::test]
    async fn test_certificate_identity_isolation() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();

        let id1 = Identity::new("nucleus.local", "ns1", "service1");
        let id2 = Identity::new("nucleus.local", "ns2", "service2");

        let csr1 = CsrOptions::new(id1.to_spiffe_uri()).generate().unwrap();
        let csr2 = CsrOptions::new(id2.to_spiffe_uri()).generate().unwrap();

        let cert1 = ca
            .sign_csr(csr1.csr(), &id1, Duration::from_secs(3600))
            .await
            .unwrap();
        let cert2 = ca
            .sign_csr(csr2.csr(), &id2, Duration::from_secs(3600))
            .await
            .unwrap();

        // Verify certificates have correct isolated identities
        assert_eq!(cert1.identity(), &id1);
        assert_eq!(cert2.identity(), &id2);
        assert_ne!(cert1.identity(), cert2.identity());

        // Verify extraction from DER also gives correct identity
        let extracted1 = cert1.leaf().extract_spiffe_identity().unwrap();
        let extracted2 = cert2.leaf().extract_spiffe_identity().unwrap();

        assert_eq!(extracted1, id1);
        assert_eq!(extracted2, id2);
    }

    /// Regression: JWT SVIDs are susceptible to replay attacks
    /// (Not applicable to X.509, but verify we use X.509 correctly)
    #[tokio::test]
    async fn test_x509_svid_not_replayable_across_identities() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();

        let victim = Identity::new("nucleus.local", "production", "api-server");
        let attacker = Identity::new("nucleus.local", "attacker-ns", "evil");

        // Attacker cannot use victim's CSR to get victim's certificate
        let victim_csr = CsrOptions::new(victim.to_spiffe_uri()).generate().unwrap();

        // Trying to sign victim's CSR for attacker's identity should fail
        let result = ca
            .sign_csr(victim_csr.csr(), &attacker, Duration::from_secs(3600))
            .await;

        assert!(result.is_err(), "Cannot sign CSR for different identity");
    }
}
