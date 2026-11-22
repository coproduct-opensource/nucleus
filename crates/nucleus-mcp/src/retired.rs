//! Flags this bridge no longer has, and the refusal of their variables.
//!
//! Once a flag is deleted, clap refuses it on the command line by name
//! (`unexpected argument '--sandbox-token'`). Its variable is another matter:
//! clap never looks at an environment variable it was not told about, so a
//! caller still setting one would be ignored silently and believe the bridge
//! was carrying it. Each is refused at startup by name instead (ADR 0007 B-2,
//! fail closed; A-1, "not read" is not "read and fine").

use anyhow::Result;

/// Environment variables of flags this bridge no longer has, each with why.
const RETIRED_ENV: &[(&str, &str)] = &[
    (
        "NUCLEUS_MCP_SANDBOX_TOKEN",
        "--sandbox-token was retired with the tool-proxy's tier-3 orchestrator token (#2446 \
         step 3c); this bridge never sent it, and nothing mints one",
    ),
    (
        "NUCLEUS_MCP_APPROVAL_SECRET",
        "--approval-secret was retired: a bridge holding an approval key lets the agent \
         behind it approve its own operations, and the tool-proxy's shared-key approval \
         tier it signed for is deleted (2026-11-21). Approvals are an approver's Ed25519 \
         signature, made outside the agent's reach",
    ),
];

/// Refuses the first retired variable that `is_set` reports, naming it.
///
/// # Errors
///
/// When any variable in [`RETIRED_ENV`] is set, empty or not.
pub(crate) fn refuse_retired_env(is_set: impl Fn(&str) -> bool) -> Result<()> {
    for (var, why) in RETIRED_ENV {
        if is_set(var) {
            anyhow::bail!("{var} is set, but {why}. Unset {var}.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::refuse_retired_env;
    use crate::Args;
    use clap::Parser;

    /// #2446 step 3c: `--sandbox-token` is gone, so clap refuses the flag by
    /// name. Red before: the flag parsed into a field nothing read.
    #[test]
    fn the_sandbox_token_flag_is_refused_by_name() {
        let err = Args::try_parse_from([
            "nucleus-mcp",
            "--proxy-url",
            "unix:///run/nucleus-door/workload.sock",
            "--sandbox-token",
            "test-token-123",
        ])
        .expect_err("--sandbox-token is retired");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        assert!(err.to_string().contains("--sandbox-token"), "{err}");
    }

    /// The flag's variable, which clap no longer looks at, is refused by name
    /// when set at all (an empty value included), and nothing else is.
    #[test]
    fn the_sandbox_token_variable_is_refused_by_name() {
        let err = refuse_retired_env(|var| var == "NUCLEUS_MCP_SANDBOX_TOKEN")
            .expect_err("a retired variable is refused")
            .to_string();
        assert!(err.contains("NUCLEUS_MCP_SANDBOX_TOKEN"), "{err}");
        assert!(err.contains("#2446"), "{err}");
        refuse_retired_env(|var| var == "NUCLEUS_MCP_PROXY_URL").expect("a live variable");
    }

    /// 2026-11-21: `--approval-secret` is gone, so clap refuses the flag by
    /// name. Red before: the flag parsed, and only the transport refused it.
    #[test]
    fn the_approval_secret_flag_is_refused_by_name() {
        let err = Args::try_parse_from([
            "nucleus-mcp",
            "--proxy-url",
            "unix:///run/nucleus-door/workload.sock",
            "--approval-secret",
            "test-token-123",
        ])
        .expect_err("--approval-secret is retired");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        assert!(err.to_string().contains("--approval-secret"), "{err}");
    }

    /// Its variable, which clap no longer looks at, is refused by name when
    /// set at all, and the refusal never carries the value.
    #[test]
    fn the_approval_secret_variable_is_refused_by_name() {
        let err = refuse_retired_env(|var| var == "NUCLEUS_MCP_APPROVAL_SECRET")
            .expect_err("a retired variable is refused")
            .to_string();
        for needle in [
            "NUCLEUS_MCP_APPROVAL_SECRET",
            "--approval-secret",
            "retired",
        ] {
            assert!(err.contains(needle), "missing {needle:?} in {err}");
        }
    }
}
