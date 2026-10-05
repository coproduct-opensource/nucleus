//! Configure the selected Apple host only after readiness and requested verification.
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::{ArtifactSourceArg, SetupArgs};
use crate::microvm_host::{settings, verification};

pub(super) async fn execute(args: &SetupArgs, path: &Path, config_path: &str) -> Result<()> {
    ensure!(
        !args.force
            && !args.skip_vm
            && !args.rotate_secrets
            && !args.skip_artifacts
            && !args.install_deps
            && args.vm_name == "nucleus"
            && args.vm_cpus == 4
            && args.vm_memory_gib == 8
            && args.vm_disk_gib == 50
            && args.artifacts == ArtifactSourceArg::Auto,
        "Lima provisioning, artifact-download and secret-rotation options do not apply to Apple host setup"
    );
    let selected = std::path::absolute(path)?;
    // Parse both files before starting or replacing a host.
    settings::configuration(&selected)?;
    let update = ConfigUpdate::prepare(config_path, &selected)?;
    let host = settings::ready(&selected).await?;
    let checked = if args.skip_verify {
        None
    } else {
        Some(verification::verify(&host).await?)
    };
    update.commit()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "backend":"apple-container", "state":"configured",
            "host_config":selected, "node_url":host.node_url(),
            "identity_dir":host.identity_dir(), "workload_verification":checked,
            "verification_skipped":args.skip_verify,
        }))?
    );
    Ok(())
}

struct ConfigUpdate {
    path: PathBuf,
    original: Option<String>,
    content: String,
}

fn read(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

impl ConfigUpdate {
    fn prepare(config_path: &str, selected: &Path) -> Result<Self> {
        let path = std::path::absolute(shellexpand::tilde(config_path).as_ref())?;
        let original = read(&path)?;
        let mut document: toml_edit::DocumentMut = original.as_deref().unwrap_or("").parse()?;
        let node = document
            .as_table_mut()
            .entry("node")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()))
            .as_table_like_mut()
            .context("node configuration must be a TOML table")?;
        node.insert(
            "apple_host_config",
            toml_edit::value(
                selected
                    .to_str()
                    .context("Apple host configuration path is not UTF-8")?,
            ),
        );
        Ok(Self {
            path,
            original,
            content: document.to_string(),
        })
    }

    fn commit(self) -> Result<()> {
        ensure!(
            read(&self.path)? == self.original,
            "CLI configuration changed during setup; refusing to replace it"
        );
        let parent = self
            .path
            .parent()
            .context("CLI configuration has no parent directory")?;
        std::fs::create_dir_all(parent)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(self.content.as_bytes())?;
        file.as_file().sync_all()?;
        file.persist(&self.path)
            .with_context(|| format!("saving Apple host selection in {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_setup_accepts_verification_choice_but_not_lima_provisioning_flags() {
        use clap::Parser;
        #[derive(Parser)]
        struct Parse {
            #[command(flatten)]
            args: SetupArgs,
        }
        let parsed =
            Parse::try_parse_from(["setup", "--apple-host-config", "host.json", "--skip-verify"])
                .unwrap();
        assert!(parsed.args.skip_verify);
        for extra in [
            vec!["--force"],
            vec!["--skip-vm"],
            vec!["--rotate-secrets"],
            vec!["--skip-artifacts"],
            vec!["--install-deps"],
            vec!["--vm-name", "other"],
            vec!["--artifacts", "local"],
        ] {
            let mut input = vec!["setup", "--apple-host-config", "host.json"];
            input.extend(extra);
            assert!(Parse::try_parse_from(input).is_err());
        }
    }

    #[test]
    fn selection_preserves_existing_settings_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "# operator settings\n[budget]\nmax_cost_usd = 2.5\n[node]\n# remote choice\nurl = 'https://existing.example:8080'\n").unwrap();
        let selected = dir.path().join("host.json");
        ConfigUpdate::prepare(path.to_str().unwrap(), &selected)
            .unwrap()
            .commit()
            .unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("# operator settings") && saved.contains("# remote choice"));
        let config = crate::config::Config::load(path.to_str().unwrap()).unwrap();
        assert_eq!(config.node.apple_host_config, Some(selected));
        assert_eq!(config.node.url, "https://existing.example:8080");
        assert_eq!(config.budget.max_cost_usd, 2.5);
    }

    #[test]
    fn setup_does_not_replace_edits_made_while_verification_runs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let update =
            ConfigUpdate::prepare(path.to_str().unwrap(), &dir.path().join("host.json")).unwrap();
        std::fs::write(&path, "# concurrent edit\n").unwrap();
        assert!(update.commit().is_err());
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "# concurrent edit\n"
        );
    }
}
