//! Hands `git describe` to the crate as `NUCLEUS_GIT_DESCRIBE`, when the build
//! has a checkout and a git to ask (#3208). It decides nothing: what the binary
//! reports is `nucleus_spec::release_version::decide`, which also reads the
//! release workflow's tag and prefers it.

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (out.status.success() && !text.is_empty()).then(|| text.to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=GITHUB_REF_TYPE");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    // Re-describe when this crate's sources change (they can make the tree
    // dirty) and when HEAD, the index or the tags move.
    for own in ["build.rs", "Cargo.toml", "src"] {
        println!("cargo:rerun-if-changed={own}");
    }
    let dirs = [
        git(&["rev-parse", "--git-dir"]),
        git(&["rev-parse", "--git-common-dir"]),
    ];
    for dir in dirs.iter().flatten() {
        for name in ["HEAD", "index", "packed-refs", "refs/tags"] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir).join(name);
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
    if let Some(describe) = git(&["describe", "--tags", "--match", "v[0-9]*", "--dirty"]) {
        println!("cargo:rustc-env=NUCLEUS_GIT_DESCRIBE={describe}");
    }
}
