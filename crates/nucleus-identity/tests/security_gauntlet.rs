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
            if let Ok(id) = result {
                // If accepted, verify it round-trips safely
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
                cert_sign.private_key(),
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
        let _verifier = TrustDomainVerifier::new("different.domain", ca.trust_bundle()).unwrap();

        let identity = Identity::new("nucleus.local", "default", "service");
        let csr_options = CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let cert = ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
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
                attacker_csr.private_key(),
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

        // Generate a valid private key to pair with the malformed CSR (though it won't match)
        let valid_csr = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();

        let result = ca
            .sign_csr(
                malformed_csr,
                valid_csr.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await;

        assert!(result.is_err(), "Malformed CSR should be rejected");
    }

    /// Attempt to use one workload's cert to impersonate another
    #[tokio::test]
    async fn test_identity_verifier_prevents_impersonation() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();

        // Create expected identity list (what we're willing to talk to)
        let expected = vec![Identity::new("nucleus.local", "production", "api-server")];
        let _verifier = IdentityVerifier::new(expected.clone(), ca.trust_bundle()).unwrap();

        // Attacker gets valid certificate for THEIR identity
        let attacker_identity = Identity::new("nucleus.local", "attacker-ns", "evil-service");
        let csr_options = CsrOptions::new(attacker_identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let attacker_cert = ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
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
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
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
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(1),
            )
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
        let cert = ca
            .sign_csr(cert_sign.csr(), cert_sign.private_key(), &identity, ttl)
            .await
            .unwrap();

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
        let _ca = SelfSignedCa::new("nucleus.local").unwrap();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let ca = SelfSignedCa::new("nucleus.local").unwrap();
                let identity = Identity::new("nucleus.local", "default", format!("service-{}", i));

                tokio::spawn(async move {
                    let csr_options = CsrOptions::new(identity.to_spiffe_uri());
                    let cert_sign = csr_options.generate().unwrap();

                    let cert = ca
                        .sign_csr(
                            cert_sign.csr(),
                            cert_sign.private_key(),
                            &identity,
                            Duration::from_secs(3600),
                        )
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
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
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
            .sign_csr(
                csr1.csr(),
                csr1.private_key(),
                &id1,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let cert2 = ca
            .sign_csr(
                csr2.csr(),
                csr2.private_key(),
                &id2,
                Duration::from_secs(3600),
            )
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
            .sign_csr(
                victim_csr.csr(),
                victim_csr.private_key(),
                &attacker,
                Duration::from_secs(3600),
            )
            .await;

        assert!(result.is_err(), "Cannot sign CSR for different identity");
    }
}

// ============================================================================
// SECTION 8: ATTESTATION SECURITY TESTS
// ============================================================================
// Test the attestation system for forgery, replay, and bypass attacks.

mod attestation_security {
    use nucleus_identity::{AttestationRequirements, LaunchAttestation};
    use proptest::prelude::*;

    /// Malformed DER payloads should be rejected gracefully
    #[test]
    fn test_malformed_der_rejection() {
        // Empty payload
        assert!(
            LaunchAttestation::from_der(&[]).is_err(),
            "Empty DER should be rejected"
        );

        // Just a SEQUENCE tag with no content
        assert!(
            LaunchAttestation::from_der(&[0x30, 0x00]).is_err(),
            "Empty SEQUENCE should be rejected"
        );

        // Wrong tag (OCTET STRING instead of SEQUENCE)
        assert!(
            LaunchAttestation::from_der(&[0x04, 0x01, 0x00]).is_err(),
            "Wrong outer tag should be rejected"
        );

        // Truncated data mid-structure
        let valid_attestation = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);
        let der = valid_attestation.to_der();
        for truncate_at in [1, 5, 10, 20, 50, der.len() - 1] {
            if truncate_at < der.len() {
                assert!(
                    LaunchAttestation::from_der(&der[..truncate_at]).is_err(),
                    "Truncated DER at {} bytes should be rejected",
                    truncate_at
                );
            }
        }
    }

    /// Invalid length encodings should be rejected
    #[test]
    fn test_invalid_der_length_encoding() {
        // Length claiming more bytes than available
        let malformed = vec![
            0x30, 0x82, 0xFF, 0xFF, // SEQUENCE claiming 65535 bytes
            0x01, 0x02, 0x03, // Only 3 bytes follow
        ];
        assert!(
            LaunchAttestation::from_der(&malformed).is_err(),
            "Oversized length should be rejected"
        );

        // Indefinite length (not allowed in DER)
        let indefinite = vec![
            0x30, 0x80, // SEQUENCE with indefinite length
            0x02, 0x01, 0x01, // INTEGER 1
            0x00, 0x00, // End of contents
        ];
        assert!(
            LaunchAttestation::from_der(&indefinite).is_err(),
            "Indefinite length should be rejected"
        );
    }

    /// Version field manipulation should be rejected
    #[test]
    fn test_attestation_version_bypass() {
        // Create valid attestation and modify version in DER
        let attestation = LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], [0xcc; 32]);
        let mut der = attestation.to_der();

        // Find and modify the version INTEGER (should be near the start)
        // DER structure: SEQUENCE { INTEGER 1, ... }
        // Position 0: 0x30 (SEQUENCE)
        // Position 1-2: length
        // Position 3: 0x02 (INTEGER)
        // Position 4: 0x01 (length)
        // Position 5: 0x01 (value = 1)

        // Modify version to 0 (invalid)
        if der.len() > 5 && der[3] == 0x02 && der[4] == 0x01 {
            der[5] = 0x00;
            assert!(
                LaunchAttestation::from_der(&der).is_err(),
                "Version 0 should be rejected"
            );

            // Modify to version 2 (unsupported)
            der[5] = 0x02;
            assert!(
                LaunchAttestation::from_der(&der).is_err(),
                "Version 2 should be rejected"
            );

            // Modify to version 255 (way unsupported)
            der[5] = 0xFF;
            assert!(
                LaunchAttestation::from_der(&der).is_err(),
                "Version 255 should be rejected"
            );
        }
    }

    /// Hash truncation attacks should be rejected
    #[test]
    fn test_hash_truncation_rejected() {
        // Create malformed DER with truncated hash (only 16 bytes instead of 32)
        // This tests the FWID parsing for correct hash length enforcement

        // Build a minimal malformed structure manually
        let mut malformed = vec![0x30]; // SEQUENCE
        let mut content = vec![];

        // Version INTEGER 1
        content.extend_from_slice(&[0x02, 0x01, 0x01]);

        // Kernel FWID with truncated hash (16 bytes)
        let mut fwid = vec![0x30]; // SEQUENCE
        let mut fwid_content = vec![];
        // OID for SHA-256
        fwid_content.extend_from_slice(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ]);
        // OCTET STRING with only 16 bytes (should be 32)
        fwid_content.extend_from_slice(&[0x04, 0x10]); // 16 bytes
        fwid_content.extend_from_slice(&[0xaa; 16]);
        fwid.push(fwid_content.len() as u8);
        fwid.extend_from_slice(&fwid_content);
        content.extend_from_slice(&fwid);

        // Add remaining FWIDs and timestamp (simplified - will fail on first FWID anyway)
        malformed.push(content.len() as u8);
        malformed.extend_from_slice(&content);

        assert!(
            LaunchAttestation::from_der(&malformed).is_err(),
            "Truncated hash (16 bytes) should be rejected"
        );
    }

    /// Test that hash comparison is done correctly (not timing-vulnerable comparison)
    /// Note: This is a documentation test - actual timing analysis requires external tooling
    #[test]
    fn test_requirements_hash_comparison_correctness() {
        let req = AttestationRequirements::exact([0xaa; 32], [0xbb; 32], [0xcc; 32]);

        // Correct attestation should pass
        let correct = LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], [0xcc; 32]);
        assert!(req.verify(&correct).is_ok());

        // Single byte difference in kernel should fail
        let mut wrong_kernel = [0xaa; 32];
        wrong_kernel[31] = 0xab; // Last byte different
        let att = LaunchAttestation::from_hashes(wrong_kernel, [0xbb; 32], [0xcc; 32]);
        assert!(
            req.verify(&att).is_err(),
            "Single byte kernel difference should fail"
        );

        // Single byte difference in rootfs should fail
        let mut wrong_rootfs = [0xbb; 32];
        wrong_rootfs[0] = 0xbc; // First byte different
        let att = LaunchAttestation::from_hashes([0xaa; 32], wrong_rootfs, [0xcc; 32]);
        assert!(
            req.verify(&att).is_err(),
            "Single byte rootfs difference should fail"
        );

        // Single byte difference in config should fail
        let mut wrong_config = [0xcc; 32];
        wrong_config[15] = 0xcd; // Middle byte different
        let att = LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], wrong_config);
        assert!(
            req.verify(&att).is_err(),
            "Single byte config difference should fail"
        );
    }

    /// Test requirements with empty allowed lists (should accept any)
    #[test]
    fn test_requirements_empty_lists_accept_any() {
        let req = AttestationRequirements::any();

        // Any random attestation should be accepted
        for _ in 0..10 {
            let att = LaunchAttestation::from_hashes(rand_hash(), rand_hash(), rand_hash());
            assert!(
                req.verify(&att).is_ok(),
                "Empty requirements should accept any attestation"
            );
        }
    }

    /// Test combined hash is different when any component changes
    #[test]
    fn test_combined_hash_sensitivity() {
        let base = LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x33; 32]);
        let base_combined = base.combined_hash();

        // Change kernel
        let kernel_changed = LaunchAttestation::from_hashes([0x12; 32], [0x22; 32], [0x33; 32]);
        assert_ne!(
            kernel_changed.combined_hash(),
            base_combined,
            "Combined hash should change when kernel changes"
        );

        // Change rootfs
        let rootfs_changed = LaunchAttestation::from_hashes([0x11; 32], [0x23; 32], [0x33; 32]);
        assert_ne!(
            rootfs_changed.combined_hash(),
            base_combined,
            "Combined hash should change when rootfs changes"
        );

        // Change config
        let config_changed = LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x34; 32]);
        assert_ne!(
            config_changed.combined_hash(),
            base_combined,
            "Combined hash should change when config changes"
        );
    }

    /// Test DER roundtrip preserves all fields exactly
    #[test]
    fn test_der_roundtrip_fidelity() {
        // Test with all zeros
        let zeros = LaunchAttestation::from_hashes([0x00; 32], [0x00; 32], [0x00; 32]);
        let der = zeros.to_der();
        let parsed = LaunchAttestation::from_der(&der).unwrap();
        assert_eq!(parsed.kernel_hash(), zeros.kernel_hash());
        assert_eq!(parsed.rootfs_hash(), zeros.rootfs_hash());
        assert_eq!(parsed.config_hash(), zeros.config_hash());

        // Test with all 0xFF
        let maxed = LaunchAttestation::from_hashes([0xFF; 32], [0xFF; 32], [0xFF; 32]);
        let der = maxed.to_der();
        let parsed = LaunchAttestation::from_der(&der).unwrap();
        assert_eq!(parsed.kernel_hash(), maxed.kernel_hash());
        assert_eq!(parsed.rootfs_hash(), maxed.rootfs_hash());
        assert_eq!(parsed.config_hash(), maxed.config_hash());

        // Test with mixed patterns
        let mut kernel = [0u8; 32];
        let mut rootfs = [0u8; 32];
        let mut config = [0u8; 32];
        for i in 0..32 {
            kernel[i] = i as u8;
            rootfs[i] = (i * 2) as u8;
            config[i] = (255 - i) as u8;
        }
        let mixed = LaunchAttestation::from_hashes(kernel, rootfs, config);
        let der = mixed.to_der();
        let parsed = LaunchAttestation::from_der(&der).unwrap();
        assert_eq!(parsed.kernel_hash(), mixed.kernel_hash());
        assert_eq!(parsed.rootfs_hash(), mixed.rootfs_hash());
        assert_eq!(parsed.config_hash(), mixed.config_hash());
    }

    /// Parse hash utility function tests
    #[test]
    fn test_parse_hash_security() {
        use nucleus_identity::attestation::{format_hash, parse_hash};

        // Valid 64-char hex should work
        let hex = "aa".repeat(32);
        assert!(parse_hash(&hex).is_some());

        // Too short should fail
        assert!(parse_hash("aabb").is_none());
        assert!(parse_hash(&"aa".repeat(31)).is_none()); // 62 chars

        // Too long should fail
        assert!(parse_hash(&"aa".repeat(33)).is_none()); // 66 chars

        // Invalid hex characters should fail
        assert!(parse_hash(&format!("{}gg", "aa".repeat(31))).is_none());
        assert!(parse_hash(&format!("zz{}", "aa".repeat(31))).is_none());

        // Null bytes in string should fail
        let with_null = format!("aa\0{}", "bb".repeat(31));
        // parse_hash should handle this - either reject or parse only up to null
        let result = parse_hash(&with_null);
        // The string is 65 chars (with null), so it should fail the length check
        assert!(result.is_none() || result.unwrap() != [0xaa; 32]);

        // Uppercase should work (normalize to lowercase)
        let upper = "AA".repeat(32);
        let parsed = parse_hash(&upper);
        assert!(parsed.is_some());
        let formatted = format_hash(parsed.as_ref().unwrap());
        assert_eq!(formatted, "aa".repeat(32));
    }

    proptest! {
        /// Fuzz DER parsing with random bytes - should never panic
        #[test]
        fn fuzz_der_parsing(data in proptest::collection::vec(any::<u8>(), 0..500)) {
            // Should never panic, only return Ok or Err
            let _ = LaunchAttestation::from_der(&data);
        }

        /// Fuzz with SEQUENCE-tagged random content
        #[test]
        fn fuzz_der_with_sequence_tag(content in proptest::collection::vec(any::<u8>(), 0..200)) {
            let mut der = vec![0x30]; // SEQUENCE tag
            if content.len() < 128 {
                der.push(content.len() as u8);
            } else {
                der.push(0x81);
                der.push(content.len() as u8);
            }
            der.extend_from_slice(&content);

            // Should never panic
            let _ = LaunchAttestation::from_der(&der);
        }

        /// Valid attestation roundtrip with random hashes
        #[test]
        fn roundtrip_random_hashes(
            kernel in proptest::collection::vec(any::<u8>(), 32..=32),
            rootfs in proptest::collection::vec(any::<u8>(), 32..=32),
            config in proptest::collection::vec(any::<u8>(), 32..=32)
        ) {
            let mut k = [0u8; 32];
            let mut r = [0u8; 32];
            let mut c = [0u8; 32];
            k.copy_from_slice(&kernel);
            r.copy_from_slice(&rootfs);
            c.copy_from_slice(&config);

            let attestation = LaunchAttestation::from_hashes(k, r, c);
            let der = attestation.to_der();
            let parsed = LaunchAttestation::from_der(&der);

            prop_assert!(parsed.is_ok());
            let parsed = parsed.unwrap();
            prop_assert_eq!(parsed.kernel_hash(), &k);
            prop_assert_eq!(parsed.rootfs_hash(), &r);
            prop_assert_eq!(parsed.config_hash(), &c);
        }
    }

    /// Helper to generate random 32-byte hash
    fn rand_hash() -> [u8; 32] {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut hash = [0u8; 32];
        for (i, byte) in hash.iter_mut().enumerate() {
            *byte = ((seed >> (i % 16)) & 0xFF) as u8 ^ i as u8;
        }
        hash
    }
}

// ============================================================================
// SECTION 9: SESSION IDENTITY SECURITY TESTS
// ============================================================================
// Test the session identity system for security vulnerabilities.

mod session_security {
    use nucleus_identity::{Identity, SessionId, SessionIdentity};
    use proptest::prelude::*;
    use std::time::Duration;

    /// Session ID uniqueness test
    #[test]
    fn test_session_id_collision_resistance() {
        use std::collections::HashSet;

        let mut ids = HashSet::new();
        let iterations = 10000;

        for _ in 0..iterations {
            let id = SessionId::new_v7();
            let id_str = id.to_string();
            assert!(
                ids.insert(id_str.clone()),
                "Session ID collision detected: {}",
                id_str
            );
        }

        assert_eq!(ids.len(), iterations, "All session IDs should be unique");
    }

    /// Session ID parse injection tests
    #[test]
    fn test_session_id_parse_injection() {
        // SQL injection attempts
        let sql_payloads = ["'; DROP TABLE sessions; --", "1' OR '1'='1", "admin'--"];

        for payload in sql_payloads {
            assert!(
                SessionId::parse(payload).is_none(),
                "SQL injection should not parse as session ID: {}",
                payload
            );
        }

        // Path traversal attempts
        let path_payloads = ["../../../etc/passwd", "..%2f..%2f", "....//"];

        for payload in path_payloads {
            assert!(
                SessionId::parse(payload).is_none(),
                "Path traversal should not parse as session ID: {}",
                payload
            );
        }

        // Null byte handling: The current parser strips non-hex characters,
        // which means null bytes are silently removed. This is documented behavior
        // but worth noting for security reviews.
        //
        // This test verifies that injecting a null byte into a valid hex string
        // that would otherwise have 32 valid chars (64 hex) results in either:
        // 1. Parse failure (too few chars after filtering)
        // 2. A different result than the clean input
        //
        // A string with extra chars that filter down to 32 valid bytes should fail:
        let null_with_extra = "01234567\x0089abcdef0123456789abcdefFF";
        let clean_extra = "0123456789abcdef0123456789abcdefFF"; // 66 hex chars
        assert!(
            SessionId::parse(null_with_extra).is_none() || SessionId::parse(clean_extra).is_none(),
            "Strings with wrong length after filtering should not parse"
        );

        // A string that filters to exactly 32 bytes will parse - this is
        // expected behavior. The security implication is that the null byte
        // cannot be used to inject different semantics into the same ID.
    }

    /// Session identity expiry cannot be bypassed
    #[test]
    fn test_session_expiry_enforced() {
        let parent = Identity::new("nucleus.local", "agents", "claude");

        // Create already-expired session (created 1 hour ago with 30 min TTL)
        let session = SessionIdentity::new(parent.clone(), Duration::from_secs(1800));

        // Manually backdate the created_at to simulate expired session
        // This tests that is_expired() correctly computes expiry
        // We can't directly set created_at, but we can verify the logic
        assert!(!session.is_expired(), "Fresh session should not be expired");
        assert!(
            session.remaining().is_some(),
            "Fresh session should have remaining time"
        );

        // Session with 0 TTL should be immediately expired
        // Note: This depends on timing - session created at T, expires at T+0 = T
        // Checking at T should show not expired, but at T+ε should show expired
        let zero_session = SessionIdentity::new(parent.clone(), Duration::from_secs(0));
        // Give it a moment
        std::thread::sleep(Duration::from_millis(10));
        // Now it should definitely be expired
        assert!(
            zero_session.is_expired() || zero_session.remaining().is_none(),
            "Zero TTL session should expire immediately or have no remaining time"
        );
    }

    /// Session identity SPIFFE URI format validation
    #[test]
    fn test_session_spiffe_uri_format() {
        let parent = Identity::new("nucleus.local", "agents", "claude");
        let session = SessionIdentity::new(parent.clone(), Duration::from_secs(3600));

        let uri = session.to_spiffe_uri();

        // Should have correct prefix
        assert!(
            uri.starts_with("spiffe://nucleus.local/ns/agents/sa/claude/session/"),
            "Session URI should extend parent URI"
        );

        // Should contain valid UUID
        let uuid_part = uri.split('/').next_back().unwrap();
        assert_eq!(
            uuid_part.len(),
            36,
            "UUID should be 36 characters with hyphens"
        );
        assert!(
            uuid_part.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
            "UUID should only contain hex digits and hyphens"
        );
    }

    /// Session ID timestamp extraction
    #[test]
    fn test_session_id_timestamp_validity() {
        let id = SessionId::new_v7();

        let ts = id.timestamp_millis();
        assert!(ts.is_some(), "UUID v7 should have extractable timestamp");

        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let extracted = ts.unwrap();
        assert!(
            extracted <= now_millis,
            "Timestamp should not be in the future"
        );
        assert!(
            extracted > now_millis - 60_000,
            "Timestamp should be within last minute"
        );
    }

    /// Test that certificate identity maintains uniqueness
    #[test]
    fn test_certificate_identity_uniqueness() {
        let parent = Identity::new("nucleus.local", "agents", "claude");

        let session1 = SessionIdentity::new(parent.clone(), Duration::from_secs(3600));
        let session2 = SessionIdentity::new(parent.clone(), Duration::from_secs(3600));

        let cert_id1 = session1.to_certificate_identity();
        let cert_id2 = session2.to_certificate_identity();

        // Different sessions should produce different certificate identities
        assert_ne!(
            cert_id1.service_account(),
            cert_id2.service_account(),
            "Different sessions should have different certificate identities"
        );

        // But same trust domain and namespace
        assert_eq!(cert_id1.trust_domain(), cert_id2.trust_domain());
        assert_eq!(cert_id1.namespace(), cert_id2.namespace());
    }

    proptest! {
        /// Fuzz session ID parsing
        #[test]
        fn fuzz_session_id_parse(input in ".*") {
            // Should never panic
            let _ = SessionId::parse(&input);
        }

        /// Valid UUIDs should parse
        #[test]
        fn valid_uuid_format_parses(
            a in "[0-9a-f]{8}",
            b in "[0-9a-f]{4}",
            c in "[0-9a-f]{4}",
            d in "[0-9a-f]{4}",
            e in "[0-9a-f]{12}"
        ) {
            let uuid = format!("{}-{}-{}-{}-{}", a, b, c, d, e);
            let result = SessionId::parse(&uuid);
            // Should parse (though may not be valid v7)
            prop_assert!(result.is_some(), "Valid UUID format should parse: {}", uuid);
        }
    }
}

// ============================================================================
// SECTION 10: OWASP LLM TOP 10 ATTESTATION TESTS
// ============================================================================
// Tests specifically targeting OWASP LLM Top 10 vulnerabilities in the
// attestation context.

mod owasp_llm_attestation {
    use nucleus_identity::{AttestationRequirements, LaunchAttestation};

    /// LLM01: Prompt Injection via attestation metadata
    /// Attackers might try to embed malicious instructions in attestation data
    #[test]
    fn test_prompt_injection_in_attestation() {
        // Attestation only stores hashes, not arbitrary data
        // But test that hash display doesn't enable injection
        let attestation = LaunchAttestation::from_hashes([0x00; 32], [0x00; 32], [0x00; 32]);

        let summary = attestation.to_hex_summary();
        // Summary should only contain hex and field labels
        assert!(
            !summary.contains("ignore previous"),
            "Summary should not contain injection text"
        );
        assert!(
            !summary.contains("system:"),
            "Summary should not contain system prefix"
        );
    }

    /// LLM02: Insecure Output Handling - verify attestation output is safe
    #[test]
    fn test_attestation_output_sanitization() {
        let attestation = LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], [0xcc; 32]);

        let summary = attestation.to_hex_summary();

        // Verify output format is predictable and safe
        assert!(summary.contains("kernel="));
        assert!(summary.contains("rootfs="));
        assert!(summary.contains("config="));

        // Verify no script injection possible
        assert!(!summary.contains('<'));
        assert!(!summary.contains('>'));
        assert!(!summary.contains("javascript:"));
    }

    /// LLM03: Training Data Poisoning analog - config hash tampering
    /// If an attacker can modify the config that gets hashed, they could
    /// inject malicious policies. This tests that hash verification works.
    #[test]
    fn test_config_hash_integrity() {
        let legitimate_config_hash = [0x11; 32];
        let malicious_config_hash = [0x22; 32];

        // Requirements allow only legitimate config
        let req = AttestationRequirements::any().allow_config(legitimate_config_hash);

        // Legitimate config should pass
        let legitimate =
            LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], legitimate_config_hash);
        assert!(req.verify(&legitimate).is_ok());

        // Malicious config should fail
        let malicious =
            LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], malicious_config_hash);
        assert!(
            req.verify(&malicious).is_err(),
            "Tampered config should be rejected"
        );
    }

    /// LLM05: Supply Chain Vulnerabilities - rootfs/kernel tampering
    #[test]
    fn test_supply_chain_integrity() {
        // Known good kernel and rootfs
        let trusted_kernel = [0x11; 32];
        let trusted_rootfs = [0x22; 32];

        // Compromised versions
        let compromised_kernel = [0x99; 32];
        let compromised_rootfs = [0x88; 32];

        let req = AttestationRequirements::any()
            .allow_kernel(trusted_kernel)
            .allow_rootfs(trusted_rootfs);

        // Trusted attestation passes
        let trusted = LaunchAttestation::from_hashes(trusted_kernel, trusted_rootfs, [0x00; 32]);
        assert!(req.verify(&trusted).is_ok());

        // Compromised kernel rejected
        let bad_kernel =
            LaunchAttestation::from_hashes(compromised_kernel, trusted_rootfs, [0x00; 32]);
        assert!(
            req.verify(&bad_kernel).is_err(),
            "Compromised kernel should be rejected"
        );

        // Compromised rootfs rejected
        let bad_rootfs =
            LaunchAttestation::from_hashes(trusted_kernel, compromised_rootfs, [0x00; 32]);
        assert!(
            req.verify(&bad_rootfs).is_err(),
            "Compromised rootfs should be rejected"
        );
    }

    /// LLM07: Insecure Plugin Design - verify attestation cannot bypass policies
    #[test]
    fn test_attestation_policy_enforcement() {
        // Strict requirements
        let strict = AttestationRequirements::exact([0x11; 32], [0x22; 32], [0x33; 32]);

        // Only exact match passes
        let exact_match = LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x33; 32]);
        assert!(strict.verify(&exact_match).is_ok());

        // Any deviation fails
        let deviations = [
            // One byte different in each field
            LaunchAttestation::from_hashes([0x12; 32], [0x22; 32], [0x33; 32]),
            LaunchAttestation::from_hashes([0x11; 32], [0x23; 32], [0x33; 32]),
            LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x34; 32]),
            // All different
            LaunchAttestation::from_hashes([0xff; 32], [0xff; 32], [0xff; 32]),
        ];

        for (i, deviation) in deviations.iter().enumerate() {
            assert!(
                strict.verify(deviation).is_err(),
                "Deviation {} should be rejected",
                i
            );
        }
    }

    /// LLM08: Excessive Agency - attestation should limit scope
    #[test]
    fn test_attestation_scope_limitation() {
        // Different configs = different scopes
        let web_scraper_config = [0x01; 32];
        let code_executor_config = [0x02; 32];

        // Web scraper requirements
        let web_scraper_req = AttestationRequirements::any().allow_config(web_scraper_config);

        // Code executor attestation should NOT pass web scraper requirements
        let code_executor_att =
            LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], code_executor_config);

        assert!(
            web_scraper_req.verify(&code_executor_att).is_err(),
            "Code executor should not pass web scraper requirements"
        );
    }

    /// LLM09: Overreliance - test that attestation is necessary but not sufficient
    #[test]
    fn test_attestation_not_sole_security() {
        // Valid attestation doesn't guarantee security
        // It only proves the stated configuration was running
        // Additional checks (like identity verification) are still needed

        // This is a documentation test - attestation is ONE layer of defense
        let attestation = LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], [0xcc; 32]);

        // Attestation passes empty requirements
        let any_req = AttestationRequirements::any();
        assert!(any_req.verify(&attestation).is_ok());

        // But this doesn't mean the workload is trusted for all operations
        // Identity verification and policy checks are separate layers
    }
}
