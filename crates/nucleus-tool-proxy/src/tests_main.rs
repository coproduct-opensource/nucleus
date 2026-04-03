use super::*;

#[test]
fn test_rate_limiter_allows_burst() {
    let limiter = ApprovalRateLimiter::new(5, 1);
    // Should allow burst of 5
    for i in 0..5 {
        assert!(limiter.try_acquire(), "request {} should be allowed", i);
    }
    // 6th should be rejected
    assert!(!limiter.try_acquire(), "request 6 should be rate limited");
}

#[test]
fn test_rate_limiter_default_config() {
    let limiter = ApprovalRateLimiter::default();
    // Default is 20 burst, 10/sec refill
    for i in 0..20 {
        assert!(limiter.try_acquire(), "request {} should be allowed", i);
    }
    assert!(!limiter.try_acquire(), "request 21 should be rate limited");
}

#[test]
fn test_nonce_cache_rejects_replay() {
    let cache = ApprovalNonceCache::default();
    let now = 1000;
    let expiry = 2000;

    // First use should succeed
    assert!(cache.check_and_insert("nonce-1", expiry, now));
    // Replay should fail
    assert!(!cache.check_and_insert("nonce-1", expiry, now));
    // Different nonce should succeed
    assert!(cache.check_and_insert("nonce-2", expiry, now));
}

#[test]
fn test_nonce_cache_expires_old_entries() {
    let cache = ApprovalNonceCache::default();
    let now = 1000;
    let expiry = 1500;

    assert!(cache.check_and_insert("nonce-old", expiry, now));

    // Time passes, entry expires
    let later = 2000;
    // Old nonce was cleaned up, so this should succeed
    assert!(cache.check_and_insert("nonce-old", 3000, later));
}

#[test]
fn test_approval_registry_consume() {
    let registry = ApprovalRegistry::default();

    // Approve 2 uses
    registry.approve("read /etc/passwd", 2, None);

    // Should consume successfully twice
    assert!(registry.consume("read /etc/passwd"));
    assert!(registry.consume("read /etc/passwd"));
    // Third should fail
    assert!(!registry.consume("read /etc/passwd"));
}

#[test]
fn test_run_request_array_form() {
    let json = r#"{"args": ["ls", "-la", "/tmp"]}"#;
    let req: RunRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.args, vec!["ls", "-la", "/tmp"]);
    assert!(req.stdin.is_none());
    assert!(req.directory.is_none());
    assert!(req.timeout_seconds.is_none());
}

#[test]
fn test_run_request_with_all_fields() {
    let json =
        r#"{"args": ["cat"], "stdin": "hello", "directory": "subdir", "timeout_seconds": 30}"#;
    let req: RunRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.args, vec!["cat"]);
    assert_eq!(req.stdin, Some("hello".to_string()));
    assert_eq!(req.directory, Some("subdir".to_string()));
    assert_eq!(req.timeout_seconds, Some(30));
}

#[test]
fn test_glob_request_parsing() {
    let json = r#"{"pattern": "**/*.rs", "directory": "src", "max_results": 100}"#;
    let req: GlobRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.pattern, "**/*.rs");
    assert_eq!(req.directory, Some("src".to_string()));
    assert_eq!(req.max_results, Some(100));
}

#[test]
fn test_glob_request_minimal() {
    let json = r#"{"pattern": "*.txt"}"#;
    let req: GlobRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.pattern, "*.txt");
    assert!(req.directory.is_none());
    assert!(req.max_results.is_none());
}

#[test]
fn test_grep_request_parsing() {
    let json = r#"{"pattern": "fn main", "path": "src/main.rs", "context_lines": 2}"#;
    let req: GrepRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.pattern, "fn main");
    assert_eq!(req.path, Some("src/main.rs".to_string()));
    assert_eq!(req.context_lines, Some(2));
}

#[test]
fn test_grep_request_with_glob() {
    let json = r#"{"pattern": "TODO", "glob": "**/*.rs", "case_insensitive": true}"#;
    let req: GrepRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.pattern, "TODO");
    assert_eq!(req.file_glob, Some("**/*.rs".to_string()));
    assert_eq!(req.case_insensitive, Some(true));
}

#[test]
fn test_web_search_request_parsing() {
    let json = r#"{"query": "rust async await", "max_results": 5}"#;
    let req: WebSearchRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.query, "rust async await");
    assert_eq!(req.max_results, Some(5));
}

#[test]
fn test_glob_response_serialization() {
    let resp = GlobResponse {
        matches: vec!["src/main.rs".to_string(), "src/lib.rs".to_string()],
        truncated: None,
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("src/main.rs"));
    assert!(!json.contains("truncated"));
}

#[test]
fn test_grep_match_serialization() {
    let m = GrepMatch {
        file: "src/main.rs".to_string(),
        line: 42,
        content: "fn main() {".to_string(),
        context_before: Some(vec!["// entry point".to_string()]),
        context_after: None,
    };
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("src/main.rs"));
    assert!(json.contains("42"));
    assert!(json.contains("entry point"));
}

// ── Approval Bundle Tests ──────────────────────────────────────────

fn make_test_key() -> (Vec<u8>, nucleus_identity::did::JsonWebKey) {
    use ring::signature::KeyPair;
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap();
    let pub_bytes = key_pair.public_key().as_ref();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
    let jwk = nucleus_identity::did::JsonWebKey::ec_p256(&x, &y);
    (pkcs8.as_ref().to_vec(), jwk)
}

#[test]
fn test_approval_bundle_populates_registry() {
    let (pkcs8, _jwk) = make_test_key();
    let spec = "apiVersion: nucleus/v1\nkind: Pod\nspec:\n  work_dir: .";
    let manifest_hash = compute_manifest_hash(spec.as_bytes());

    let jws =
        nucleus_identity::approval_bundle::ApprovalBundleBuilder::new("spiffe://test/human/alice")
            .approve_operation("write_files")
            .approve_operation("run_bash")
            .manifest_hash(&manifest_hash)
            .ttl_seconds(3600)
            .build(&pkcs8)
            .unwrap();

    let registry = ApprovalRegistry::default();
    let result = verify_and_load_approval_bundle(&jws, spec, &registry);

    assert!(result.is_ok(), "verify_and_load failed: {:?}", result);
    assert!(
        registry.consume("write_files"),
        "write_files should be approved"
    );
    assert!(registry.consume("run_bash"), "run_bash should be approved");
    assert!(
        !registry.consume("web_fetch"),
        "web_fetch should NOT be approved"
    );
}

#[test]
fn test_approval_bundle_wrong_manifest() {
    let (pkcs8, _jwk) = make_test_key();
    let manifest_hash = compute_manifest_hash(b"different-manifest");

    let jws =
        nucleus_identity::approval_bundle::ApprovalBundleBuilder::new("spiffe://test/human/bob")
            .approve_operation("read_files")
            .manifest_hash(&manifest_hash)
            .ttl_seconds(3600)
            .build(&pkcs8)
            .unwrap();

    let registry = ApprovalRegistry::default();
    let result = verify_and_load_approval_bundle(&jws, "actual-manifest-content", &registry);
    assert!(result.is_err(), "should fail with manifest hash mismatch");
}

#[test]
fn test_approval_bundle_max_uses() {
    let (pkcs8, _jwk) = make_test_key();
    let spec = "spec: limited-use";
    let manifest_hash = compute_manifest_hash(spec.as_bytes());

    let jws =
        nucleus_identity::approval_bundle::ApprovalBundleBuilder::new("spiffe://test/human/carol")
            .approve_operation("write_files")
            .manifest_hash(&manifest_hash)
            .max_uses(2)
            .ttl_seconds(3600)
            .build(&pkcs8)
            .unwrap();

    let registry = ApprovalRegistry::default();
    verify_and_load_approval_bundle(&jws, spec, &registry).unwrap();

    // Should only allow 2 uses
    assert!(registry.consume("write_files"));
    assert!(registry.consume("write_files"));
    assert!(
        !registry.consume("write_files"),
        "third use should be denied"
    );
}

#[test]
fn test_approval_bundle_invalid_jws() {
    let registry = ApprovalRegistry::default();
    let result = verify_and_load_approval_bundle("not.a.valid.jws", "spec", &registry);
    assert!(result.is_err());
}

// ── Lockdown meet(current, read_only) Tests ───────────────────────

#[test]
fn test_lockdown_allows_read_only_operations() {
    // These operations map to PermissionLattice::read_only() capabilities
    // that are set to Always: read_files, glob_search, grep_search.
    assert!(
        is_allowed_during_lockdown("/v1/read"),
        "read should be allowed during lockdown"
    );
    assert!(
        is_allowed_during_lockdown("/v1/glob"),
        "glob should be allowed during lockdown"
    );
    assert!(
        is_allowed_during_lockdown("/v1/grep"),
        "grep should be allowed during lockdown"
    );
    assert!(
        is_allowed_during_lockdown("/v1/health"),
        "health should always be allowed"
    );
}

#[test]
fn test_lockdown_blocks_mutating_operations() {
    // Every mutating endpoint should be blocked during lockdown.
    let blocked_paths = [
        "/v1/write",
        "/v1/run",
        "/v1/web_fetch",
        "/v1/web_search",
        "/v1/approve",
        "/v1/escalate",
        "/v1/pod/create",
        "/v1/pod/cancel",
        "/v1/pod/list",
        "/v1/pod/status",
        "/v1/pod/logs",
    ];
    for path in &blocked_paths {
        assert!(
            !is_allowed_during_lockdown(path),
            "{} should be blocked during lockdown",
            path
        );
    }
}

#[test]
fn test_lockdown_blocks_unknown_paths() {
    // Unknown paths should be blocked by default (deny-by-default).
    assert!(
        !is_allowed_during_lockdown("/v1/unknown"),
        "unknown paths should be blocked during lockdown"
    );
    assert!(
        !is_allowed_during_lockdown("/v2/read"),
        "non-v1 read should be blocked during lockdown"
    );
    assert!(
        !is_allowed_during_lockdown(""),
        "empty path should be blocked during lockdown"
    );
}
