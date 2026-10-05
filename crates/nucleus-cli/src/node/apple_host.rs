//! Resolve the selected host afresh for every operator command.
use anyhow::{Context, Result};

use super::NodeArgs;
use crate::microvm_host::settings;

pub(super) async fn apply(args: &mut NodeArgs) -> Result<()> {
    let Some(path) = &args.apple_host_config else {
        return Ok(());
    };
    let host = settings::ready(path).await?;
    // Require the whole ready host identity before applying any defaults.
    // A missing file must never substitute a different installation's identity.
    let (cert, key, bundle) = super::provisioned_identity_paths_in(host.identity_dir())
        .context("ready Apple host identity is incomplete")?;
    args.url = host.node_url();
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
        assert_eq!(parsed.args.url, "https://selected.example:8080");
        assert!(parsed.args.tls_cert.is_none());
    }
}
