//! Integration tests that load and validate the example policy files.

use lattice_guard::constraint::spec::PolicySpec;
use std::fs;
use std::path::PathBuf;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join("policies")
}

fn load_policy(name: &str) -> PolicySpec {
    let path = examples_dir().join(name);
    let yaml = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    PolicySpec::from_yaml(&yaml).unwrap_or_else(|e| panic!("Failed to parse {}: {:?}", name, e))
}

#[test]
fn test_basic_codegen_loads() {
    let spec = load_policy("basic-codegen.yaml");
    assert_eq!(spec.name, "basic-codegen");
    assert!(spec.enforce_trifecta);
    assert_eq!(spec.constraints.len(), 3);

    // Should build successfully
    let policy = spec.build().expect("Failed to build basic-codegen");
    assert_eq!(policy.name(), "basic-codegen");
    assert!(policy.enforces_trifecta());
}

#[test]
fn test_secure_review_loads() {
    let spec = load_policy("secure-review.yaml");
    assert_eq!(spec.name, "secure-review");
    assert!(spec.enforce_trifecta);
    assert_eq!(spec.constraints.len(), 4);

    let policy = spec.build().expect("Failed to build secure-review");
    assert_eq!(policy.constraints().len(), 4);
}

#[test]
fn test_rate_limited_loads() {
    let spec = load_policy("rate-limited.yaml");
    assert_eq!(spec.name, "rate-limited");
    assert_eq!(spec.constraints.len(), 3);

    let policy = spec.build().expect("Failed to build rate-limited");
    assert_eq!(policy.constraints().len(), 3);
}

#[test]
fn test_research_mode_loads() {
    let spec = load_policy("research-mode.yaml");
    assert_eq!(spec.name, "research-mode");
    assert_eq!(spec.constraints.len(), 4);

    let policy = spec.build().expect("Failed to build research-mode");
    assert_eq!(policy.constraints().len(), 4);
}

#[test]
fn test_trifecta_demo_loads() {
    let spec = load_policy("trifecta-demo.yaml");
    assert_eq!(spec.name, "trifecta-demo");
    assert!(spec.enforce_trifecta);
    assert_eq!(spec.constraints.len(), 3);

    let policy = spec.build().expect("Failed to build trifecta-demo");
    assert_eq!(policy.constraints().len(), 3);
}

#[test]
fn test_isolation_aware_loads() {
    let spec = load_policy("isolation-aware.yaml");
    assert_eq!(spec.name, "isolation-aware");
    assert!(spec.enforce_trifecta);
    assert_eq!(spec.constraints.len(), 5);

    let policy = spec.build().expect("Failed to build isolation-aware");
    assert_eq!(policy.constraints().len(), 5);
}

#[test]
fn test_all_example_policies_valid() {
    let examples_path = examples_dir();

    // Ensure the directory exists
    assert!(
        examples_path.exists(),
        "Examples directory does not exist: {}",
        examples_path.display()
    );

    let mut count = 0;
    for entry in fs::read_dir(&examples_path).expect("Failed to read examples dir") {
        let entry = entry.expect("Failed to read entry");
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "yaml") {
            let yaml = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
            let spec = PolicySpec::from_yaml(&yaml)
                .unwrap_or_else(|e| panic!("Failed to parse {}: {:?}", path.display(), e));
            let _policy = spec
                .build()
                .unwrap_or_else(|e| panic!("Failed to build {}: {:?}", path.display(), e));

            count += 1;
        }
    }

    assert!(
        count >= 6,
        "Expected at least 6 example policies, found {}",
        count
    );
}
