//! Node configuration that #2446 step 3 deleted, refused by name.
//!
//! The node used to hold two shared secrets for its pods' tool-proxies:
//! `--proxy-auth-secret` (`NUCLEUS_NODE_PROXY_AUTH_SECRET`), which HMAC'd every
//! forwarded request and minted each container pod's tier-3 sandbox token, and
//! `--proxy-approval-secret` (`NUCLEUS_NODE_PROXY_APPROVAL_SECRET`), which signed
//! approvals for pods provisioned with it. Both were required. The container
//! driver could also be told to provision them into its pods with
//! `--container-proxy-transport tcp-hmac`.
//!
//! None of that has a reader any more: every pod is reached over a transport
//! that authenticates the node (vsock, the peer-verified socket), approvals are
//! Ed25519 against the node's public key, and the proxy's proof is its identity
//! files. A node that is still handed one of these is configured for a node
//! that no longer exists, so it stops at startup and names what to remove,
//! rather than starting with a secret it ignores (ADR 0007 B). `nucleus setup`
//! takes the two variables back out of an existing `node.env`
//! (`provision::RETIRED_NODE_ENV_KEYS`).

use crate::ApiError;

/// What the node was started with, for the inputs that are retired.
pub(crate) struct Retired<'a> {
    pub(crate) proxy_auth_secret: Option<&'a str>,
    pub(crate) proxy_approval_secret: Option<&'a str>,
    pub(crate) container_proxy_transport: Option<&'a str>,
}

/// The one transport there is. Accepted as a value so an existing
/// `--container-proxy-transport unix` keeps meaning what it always meant.
const SOCKET_TRANSPORT: &str = "unix";
/// The transport #2446 step 3 deleted.
const RETIRED_TRANSPORT: &str = "tcp-hmac";

/// Refuse every retired input that is set, naming each.
///
/// An empty secret is not refused: it is not a secret, and the env file of a
/// launcher that blanks the variable configures nothing.
pub(crate) fn refuse(retired: &Retired<'_>) -> Result<(), ApiError> {
    let Retired {
        proxy_auth_secret,
        proxy_approval_secret,
        container_proxy_transport,
    } = retired;
    let mut named = Vec::new();
    for (value, flag, env) in [
        (
            proxy_auth_secret,
            "--proxy-auth-secret",
            "NUCLEUS_NODE_PROXY_AUTH_SECRET",
        ),
        (
            proxy_approval_secret,
            "--proxy-approval-secret",
            "NUCLEUS_NODE_PROXY_APPROVAL_SECRET",
        ),
    ] {
        if value.is_some_and(|v| !v.trim().is_empty()) {
            named.push(format!(
                "{flag} ({env}) is retired: every pod is reached over a transport that \
                 authenticates the node, and approvals are signed with the node's Ed25519 key"
            ));
        }
    }
    match container_proxy_transport.map(str::trim) {
        None => {}
        Some(SOCKET_TRANSPORT) => {}
        Some(RETIRED_TRANSPORT) => named.push(format!(
            "--container-proxy-transport {RETIRED_TRANSPORT} (NUCLEUS_CONTAINER_PROXY_TRANSPORT) \
             is retired: the shared-secret tier it spoke is deleted. Container pods are \
             reached over the peer-verified socket (`{SOCKET_TRANSPORT}`), the only transport"
        )),
        Some(other) => named.push(format!(
            "--container-proxy-transport {other:?} is not a transport: the only one is \
             `{SOCKET_TRANSPORT}`"
        )),
    }
    if named.is_empty() {
        return Ok(());
    }
    Err(ApiError::Driver(format!(
        "refusing to start: {} (#2446 step 3). Remove it; `nucleus setup` takes the retired \
         variables out of an installed node.env",
        named.join("; ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Retired<'static> = Retired {
        proxy_auth_secret: None,
        proxy_approval_secret: None,
        container_proxy_transport: None,
    };

    /// Each input a node used to require, or could be told, is refused by
    /// name. Red before #2446 step 3: the two secrets were required (a node
    /// without them refused to start) and `tcp-hmac` was a transport.
    #[test]
    fn each_retired_input_is_refused_by_name() {
        let cases = [
            (
                Retired {
                    proxy_auth_secret: Some("ab"),
                    ..NONE
                },
                ["--proxy-auth-secret", "NUCLEUS_NODE_PROXY_AUTH_SECRET"],
            ),
            (
                Retired {
                    proxy_approval_secret: Some("ab"),
                    ..NONE
                },
                [
                    "--proxy-approval-secret",
                    "NUCLEUS_NODE_PROXY_APPROVAL_SECRET",
                ],
            ),
            (
                Retired {
                    container_proxy_transport: Some("tcp-hmac"),
                    ..NONE
                },
                [
                    "--container-proxy-transport tcp-hmac",
                    "NUCLEUS_CONTAINER_PROXY_TRANSPORT",
                ],
            ),
        ];
        for (retired, needles) in cases {
            let why = refuse(&retired).expect_err("retired").to_string();
            for needle in needles.iter().chain(&["#2446", "nucleus setup"]) {
                assert!(why.contains(needle), "missing {needle:?} in {why}");
            }
        }
    }

    /// Nothing set, the one transport named, and a blanked secret all start.
    #[test]
    fn what_was_not_retired_starts() {
        assert!(refuse(&NONE).is_ok());
        assert!(
            refuse(&Retired {
                container_proxy_transport: Some("unix"),
                ..NONE
            })
            .is_ok()
        );
        assert!(
            refuse(&Retired {
                proxy_auth_secret: Some(""),
                proxy_approval_secret: Some("  "),
                ..NONE
            })
            .is_ok()
        );
    }

    /// A transport that never existed is refused too, not read as the default.
    #[test]
    fn an_unknown_transport_is_refused() {
        let why = refuse(&Retired {
            container_proxy_transport: Some("tcp"),
            ..NONE
        })
        .expect_err("not a transport")
        .to_string();
        assert!(why.contains("\"tcp\""), "{why}");
    }

    /// Through clap, so the flags and their variables are the ones parsed: a
    /// node handed the old secrets parses, and is then refused.
    #[test]
    fn the_retired_flags_still_parse_so_they_can_be_refused() {
        use clap::Parser as _;
        let args = crate::Args::try_parse_from([
            "nucleus-node",
            "--proxy-auth-secret",
            "a",
            "--proxy-approval-secret",
            "b",
            "--container-proxy-transport",
            "tcp-hmac",
        ])
        .expect("parses");
        let why = refuse(&Retired {
            proxy_auth_secret: args.proxy_auth_secret.as_deref(),
            proxy_approval_secret: args.proxy_approval_secret.as_deref(),
            container_proxy_transport: args.container_proxy_transport.as_deref(),
        })
        .expect_err("all three are retired")
        .to_string();
        for needle in ["--proxy-auth-secret", "--proxy-approval-secret", "tcp-hmac"] {
            assert!(why.contains(needle), "missing {needle:?} in {why}");
        }
    }
}
