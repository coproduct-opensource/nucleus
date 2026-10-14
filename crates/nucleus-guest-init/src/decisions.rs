//! Place the node's owner-decision material where the tool-proxy reads it.
//!
//! The material arrives in the `FETCH_POD_SPEC` reply (`nucleus_spec::decision_gate`). It is
//! written under `decision_gate::GUEST_DIR`, on the `/run` tmpfs that the workload's Landlock
//! ruleset hides, before the tool-proxy is exec'd, and the three variables naming it are what
//! the proxy is exec'd with. Nothing here verifies a bundle: the proxy is the one verifier. What
//! is checked is the shape ([`DecisionMaterial::check`]), so a bundle id can only ever be a
//! plain file name, and any refusal stops the boot rather than starting a proxy with a partial
//! set.

use std::path::Path;

use nucleus_spec::decision_gate::{DecisionMaterial, GUEST_BUNDLES, GUEST_TRUST_ROOTS};

/// `path` under `root`: the guest's absolute layout, re-rooted so a test can place it anywhere.
fn under(root: &Path, path: &str) -> std::path::PathBuf {
    root.join(path.trim_start_matches('/'))
}

/// Write `material` under `root` (`/` in the guest) and return the tool-proxy's variables.
///
/// # Errors
/// The material's shape is refused, or a file cannot be written. Names the cause, never a
/// bundle's bytes.
pub fn place(
    root: &Path,
    material: &DecisionMaterial,
) -> Result<[(&'static str, String); 3], String> {
    material
        .check()
        .map_err(|e| format!("decision material refused: {e}"))?;
    let bundles = under(root, GUEST_BUNDLES);
    std::fs::create_dir_all(&bundles)
        .map_err(|e| format!("cannot create {}: {e}", bundles.display()))?;
    let roots = under(root, GUEST_TRUST_ROOTS);
    std::fs::write(&roots, &material.trust_roots)
        .map_err(|e| format!("cannot write {}: {e}", roots.display()))?;
    for b in &material.bundles {
        let path = bundles.join(format!("{}.json", b.id));
        std::fs::write(&path, &b.json)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(material.guest_env())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_spec::decision_gate::{DecisionBundleFile, TRUST_ROOTS_ENV};

    /// A fresh directory per test; the crate takes no tempfile dependency.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nucleus-guest-init-decisions-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn material(id: &str) -> DecisionMaterial {
        DecisionMaterial {
            trust_roots: "[roots]".into(),
            tenant: "github~example~repo".into(),
            bundles: vec![DecisionBundleFile {
                id: id.into(),
                json: "{\"bundle\":1}".into(),
            }],
        }
    }

    #[test]
    fn material_lands_where_the_proxy_is_told_to_read_it() {
        let dir = scratch("lands");
        let id = "ab".repeat(32);
        let env = place(&dir, &material(&id)).unwrap();
        assert_eq!(env[0], (TRUST_ROOTS_ENV, GUEST_TRUST_ROOTS.to_string()));
        let roots = std::fs::read_to_string(under(&dir, GUEST_TRUST_ROOTS)).unwrap();
        assert_eq!(roots, "[roots]");
        let bundle = under(&dir, GUEST_BUNDLES).join(format!("{id}.json"));
        assert_eq!(std::fs::read_to_string(bundle).unwrap(), "{\"bundle\":1}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A bundle id from the host is a file name; one that could name another path is refused
    /// before anything is written.
    #[test]
    fn an_id_that_is_not_a_decision_id_writes_nothing() {
        let dir = scratch("refused");
        assert!(place(&dir, &material("../../etc/nucleus/pod")).is_err());
        assert!(!under(&dir, GUEST_TRUST_ROOTS).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
