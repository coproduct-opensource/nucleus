//! Resolve the selected host afresh for every operator command.
use anyhow::{Context, Result};

use super::NodeArgs;
use crate::microvm_host::settings;

/// Defaults never replace an explicit CLI or environment connection selection.
pub(super) fn apply_default(args: &mut NodeArgs, config: &crate::config::Config) {
    if args.apple_host_config.is_none()
        && args.url.is_none()
        && args.secrets_file.is_none()
        && args.auth_secret.is_none()
        && args.tls_cert.is_none()
        && args.tls_key.is_none()
        && args.trust_bundle.is_none()
    {
        args.apple_host_config = config.node.apple_host_config.clone();
    }
    if args.url.is_none() {
        args.url = Some(config.node.url.clone());
    }
}

pub(super) async fn apply(args: &mut NodeArgs) -> Result<()> {
    let Some(path) = &args.apple_host_config else {
        return Ok(());
    };
    let host = settings::ready(path).await?;
    // Require the whole ready host identity before applying any defaults.
    // A missing file must never substitute a different installation's identity.
    let (cert, key, bundle) = super::provisioned_identity_paths_in(host.identity_dir())
        .context("ready Apple host identity is incomplete")?;
    args.url = Some(host.node_url());
    args.tls_cert = Some(cert);
    args.tls_key = Some(key);
    args.trust_bundle = Some(bundle);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Parse {
        #[command(flatten)]
        args: NodeArgs,
    }

    #[test]
    fn saved_host_is_selected_only_without_an_explicit_connection() {
        let mut config = crate::config::Config::default();
        config.node.apple_host_config = Some("saved-host.json".into());
        config.node.url = "https://configured.example:8080".into();
        let mut ordinary = Parse::try_parse_from(["node", "health"]).unwrap();
        apply_default(&mut ordinary.args, &config);
        assert_eq!(
            ordinary.args.apple_host_config,
            config.node.apple_host_config
        );
        for option in [
            "--url",
            "--tls-cert",
            "--tls-key",
            "--trust-bundle",
            "--secrets-file",
            "--auth-secret",
        ] {
            let mut selected =
                Parse::try_parse_from(["node", option, "explicit", "health"]).unwrap();
            apply_default(&mut selected.args, &config);
            assert!(
                selected.args.apple_host_config.is_none(),
                "default replaced {option}"
            );
        }
        let mut explicit =
            Parse::try_parse_from(["node", "--apple-host-config", "explicit.json", "health"])
                .unwrap();
        apply_default(&mut explicit.args, &config);
        assert_eq!(
            explicit.args.apple_host_config.unwrap(),
            std::path::Path::new("explicit.json")
        );
        config.node.apple_host_config = None;
        let mut ordinary = Parse::try_parse_from(["node", "health"]).unwrap();
        apply_default(&mut ordinary.args, &config);
        assert_eq!(ordinary.args.url(), config.node.url);
    }

    #[test]
    fn explicit_host_accepts_default_connection_but_not_another_selection() {
        let ordinary =
            Parse::try_parse_from(["node", "--apple-host-config", "host.json", "health"]).unwrap();
        assert_eq!(
            ordinary.args.apple_host_config.unwrap().to_str(),
            Some("host.json")
        );
        for option in [
            "--url",
            "--tls-cert",
            "--tls-key",
            "--trust-bundle",
            "--secrets-file",
            "--auth-secret",
        ] {
            assert!(
                Parse::try_parse_from([
                    "node",
                    "--apple-host-config",
                    "host.json",
                    option,
                    "other",
                    "health",
                ])
                .is_err(),
                "accepted conflicting {option}"
            );
        }
    }

    #[tokio::test]
    async fn no_selection_preserves_the_existing_connection() {
        let mut parsed =
            Parse::try_parse_from(["node", "--url", "https://selected.example:8080", "health"])
                .unwrap();
        apply(&mut parsed.args).await.unwrap();
        assert_eq!(
            parsed.args.url.as_deref(),
            Some("https://selected.example:8080")
        );
        assert!(parsed.args.tls_cert.is_none());
    }
}
