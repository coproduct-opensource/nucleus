//! Does the cache actually invalidate?
//!
//! `nucleus-action-key`'s own tests prove the key moves when the read-set or
//! the gate's code moves. This crate's own tests prove the store refuses a
//! mislabelled blob. **Neither proves the composition**, and the composition
//! is the design's whole claim: that a change to what a gate reads, or to the
//! gate itself, produces a MISS rather than a stale hit.
//!
//! Two proven parts do not make a proven join. That gap is how
//! `FETCH_POD_SPEC` shipped with a protocol, a handler and tests and nothing
//! sending it, and how a receipt `build()` shipped with no test that one it
//! produced verified. So: one test that runs the real derivation over a real
//! git tree, files a real receipt, perturbs the tree, and asks the store.

use nucleus_action_key::derive;
use nucleus_receipt_store::ReceiptStore;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The merge-queue constants `ci-spec`'s model requires. Values are irrelevant
/// — a model that will not build is a "could not look", not a fixture.
const QUEUE_FIXTURE: &str = "\
ruleset_id = 1
check_response_timeout_minutes = 360
max_entries_to_build = 1
max_entries_to_merge = 1
min_entries_to_merge = 1
min_entries_to_merge_wait_minutes = 1
grouping_strategy = \"ALLGREEN\"
merge_method = \"SQUASH\"
strict = true
";

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn fixture() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "nucleus-receipt-store-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    git(&root, &["init", "-q"]);
    write(
        &root,
        "rust-toolchain.toml",
        "[toolchain]\nchannel = \"1.95\"\n",
    );
    write(&root, "src/lib.rs", "fn a() {}\n");
    write(&root, "docs/readme.md", "unrelated\n");
    write(
        &root,
        ".github/workflows/gate.yml",
        r#"name: Gate
on:
  pull_request:
    paths:
      - "src/**"
      - ".github/workflows/gate.yml"
  merge_group:
jobs:
  gate:
    name: The Gate
    runs-on: ubuntu-latest
    steps:
      - run: scripts/check-thing.sh
"#,
    );
    write(&root, "scripts/check-thing.sh", "#!/bin/sh\nexit 0\n");
    git(&root, &["add", "-A"]);
    root
}

fn key_of(root: &Path) -> nucleus_action_key::ActionKey {
    let wf = (
        ".github/workflows/gate.yml".to_string(),
        std::fs::read_to_string(root.join(".github/workflows/gate.yml")).unwrap(),
    );
    let model = ci_spec::loader::from_parts(
        std::slice::from_ref(&wf),
        "# PINNED = 1\nThe Gate\n",
        QUEUE_FIXTURE,
        "",
        "",
        vec!["scripts/check-thing.sh".to_string()],
    )
    .expect("model");
    derive::key_for(root, &model, "The Gate")
        .expect("could look")
        .expect("has a key")
}

fn receipt_for(k: &nucleus_action_key::ActionKey) -> nucleus_receipt::Receipt {
    let verdict = nucleus_ci_verdict::CiVerdict {
        action_key: k.to_hex(),
        context: "The Gate".into(),
        tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
        conclusion: nucleus_ci_verdict::Conclusion::Success,
        exit_status: 0,
        log_digest: "ab".repeat(32),
        pod_id: "pod-1".into(),
        certificate: None,
    };
    nucleus_receipt::Receipt::sign(
        nucleus_receipt::Session {
            session_id: "spiffe://nucleus/node/1".into(),
            issuer_kid: "kid-1".into(),
            issued_at_micros: 1_757_000_000_000_000,
            parent_chain: vec![],
        },
        vec![verdict.to_projection()],
        &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
    )
}

/// File a receipt at one tree, then change a file the gate reads. The new key
/// must MISS — a hit here is the failure the whole design exists to prevent: a
/// green check citing a run against code that no longer exists.
#[test]
fn changing_a_file_the_gate_reads_turns_a_hit_into_a_miss() {
    let root = fixture();
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::new(dir.path().to_path_buf());

    let before = key_of(&root);
    store.put(&before, &receipt_for(&before)).unwrap();
    assert!(
        store.get(&before).unwrap().is_some(),
        "the receipt just filed must be findable, or the rest of this test proves nothing"
    );

    write(&root, "src/lib.rs", "fn a() {}\nfn b() {}\n");
    git(&root, &["add", "-A"]);

    let after = key_of(&root);
    assert_ne!(before, after, "the read-set moved, so the key must move");
    assert!(
        store.get(&after).unwrap().is_none(),
        "a changed read-set must MISS — a hit here is a green check citing work \
         done on code that no longer exists"
    );
}

/// **The one that matters most.** Weaken the gate itself, change nothing it
/// reads, and ask again. A hit means a gate that was made weaker keeps
/// answering green out of its stronger self's history — the single failure
/// that makes a receipt store worse than no cache at all.
#[test]
fn a_weakened_gate_cannot_answer_from_its_stronger_selfs_history() {
    let root = fixture();
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::new(dir.path().to_path_buf());

    let strong = key_of(&root);
    store.put(&strong, &receipt_for(&strong)).unwrap();

    // The gate now checks nothing. Its inputs are untouched.
    write(&root, "scripts/check-thing.sh", "#!/bin/sh\n# do nothing\nexit 0\n");
    git(&root, &["add", "-A"]);

    let weakened = key_of(&root);
    assert_ne!(strong, weakened, "the gate's own code is part of the key");
    assert!(
        store.get(&weakened).unwrap().is_none(),
        "a weakened gate must MISS and re-run, never inherit the verdict its \
         stronger self earned"
    );
}

/// The other half of the bargain, and the reason this is worth building: a
/// file the gate does not read must NOT invalidate. Without this every new
/// tree is a cold cache, which is the state gatehouse's own `docs/hard-cut.md`
/// records for its receipts — and the whole saving evaporates.
#[test]
fn an_unrelated_file_leaves_the_hit_intact() {
    let root = fixture();
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::new(dir.path().to_path_buf());

    let before = key_of(&root);
    store.put(&before, &receipt_for(&before)).unwrap();

    write(&root, "docs/readme.md", "still unrelated, but different\n");
    write(&root, "docs/new-note.md", "a file that did not exist\n");
    git(&root, &["add", "-A"]);

    let after = key_of(&root);
    assert_eq!(
        before, after,
        "a file outside the read-set must not move the key"
    );
    assert!(
        store.get(&after).unwrap().is_some(),
        "the receipt must still be a hit across an unrelated change — this is \
         the cross-tree hit the design is for"
    );
}
