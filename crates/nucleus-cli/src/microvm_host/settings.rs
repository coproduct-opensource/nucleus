//! Shared explicit host settings for `microvm-host up` and run configuration.
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use nucleus_spec::microvm_host::HostNames;
use serde::Deserialize;

use super::lifecycle::{Connection, HostConfig};

fn cpus() -> u32 {
    4
}
fn memory() -> u32 {
    4096
}
fn timeout() -> u64 {
    120
}

#[derive(clap::Args, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostSettings {
    /// Node and relay route; both require the same readiness checks
    #[arg(long, value_enum, default_value = "published-loopback")]
    #[serde(default = "Connection::published")]
    connection: Connection,
    /// Locally built host image containing matched node and guest artifacts
    #[arg(long)]
    image: String,
    /// Built L1 kernel Image, with its build config beside it
    #[arg(long)]
    kernel: PathBuf,
    /// Separate development host and volume
    #[arg(long)]
    #[serde(default)]
    development: bool,
    /// Host-side CA, identity and lifecycle state
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Host VM CPUs (creation only)
    #[arg(long, default_value_t = cpus(), value_parser = clap::value_parser!(u32).range(1..))]
    #[serde(default = "cpus")]
    cpus: u32,
    /// Host VM memory in MiB (creation only)
    #[arg(long, default_value_t = memory(), value_parser = clap::value_parser!(u32).range(512..))]
    #[serde(default = "memory")]
    memory_mib: u32,
    /// Node readiness deadline in seconds
    #[arg(long, default_value_t = timeout(), value_parser = clap::value_parser!(u64).range(1..))]
    #[serde(default = "timeout")]
    ready_timeout_secs: u64,
}

impl HostSettings {
    pub(crate) fn from_file(path: &std::path::Path) -> Result<Self> {
        serde_json::from_slice(
            &std::fs::read(path)
                .with_context(|| format!("reading Apple host configuration {}", path.display()))?,
        )
        .context("invalid Apple host configuration")
    }

    pub(crate) fn config(self) -> Result<HostConfig> {
        ensure!(
            !self.image.trim().is_empty(),
            "image reference must not be empty"
        );
        ensure!(
            self.cpus > 0 && self.memory_mib >= 512 && self.ready_timeout_secs > 0,
            "host requires positive CPUs/timeout and at least 512 MiB"
        );
        let state_dir = match self.state_dir {
            Some(path) => std::path::absolute(path)?,
            None => crate::config::nucleus_dir()?.join(if self.development {
                "microvm-host-dev"
            } else {
                "microvm-host"
            }),
        };
        Ok(HostConfig {
            names: if self.development {
                HostNames::DEV
            } else {
                HostNames::INSTALL
            },
            image: self.image,
            kernel: self
                .kernel
                .canonicalize()
                .context("resolving the L1 kernel path")?,
            state_dir,
            cpus: self.cpus,
            memory: format!("{}m", self.memory_mib),
            trust_domain: "nucleus.local".into(),
            ready_timeout: Duration::from_secs(self.ready_timeout_secs),
            connection: self.connection,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Parse {
        #[command(flatten)]
        settings: HostSettings,
    }

    #[test]
    fn json_and_up_arguments_use_the_same_configuration_without_creating_state() {
        let temp = tempfile::tempdir().unwrap();
        let kernel = temp.path().join("Image");
        std::fs::write(&kernel, b"kernel input").unwrap();
        let state = temp.path().join("not-created");
        let json = serde_json::json!({"image":"local-host", "kernel":kernel,
            "development":true,"state_dir":state});
        let from_json: HostSettings = serde_json::from_value(json).unwrap();
        let from_cli = Parse::try_parse_from([
            "up",
            "--image",
            "local-host",
            "--kernel",
            kernel.to_str().unwrap(),
            "--development",
            "--state-dir",
            state.to_str().unwrap(),
        ])
        .unwrap()
        .settings;
        let a = from_json.config().unwrap();
        let b = from_cli.config().unwrap();
        assert_eq!(a.names, b.names);
        assert_eq!(a.image, b.image);
        assert_eq!(a.kernel, b.kernel);
        assert_eq!(a.state_dir, b.state_dir);
        assert_eq!(a.cpus, b.cpus);
        assert_eq!(a.memory, b.memory);
        assert_eq!(a.trust_domain, b.trust_domain);
        assert_eq!(a.ready_timeout, b.ready_timeout);
        assert_eq!(a.connection, b.connection);
        assert!(!state.exists());
    }

    #[test]
    fn json_capacity_errors_are_refused_before_host_changes() {
        for (field, value) in [("cpus", 0), ("memory_mib", 128), ("ready_timeout_secs", 0)] {
            let mut json = serde_json::json!({"image":"local-host","kernel":"/missing"});
            json[field] = value.into();
            let settings: HostSettings = serde_json::from_value(json).unwrap();
            assert!(
                settings
                    .config()
                    .unwrap_err()
                    .to_string()
                    .contains("positive CPUs")
            );
        }
    }
}
