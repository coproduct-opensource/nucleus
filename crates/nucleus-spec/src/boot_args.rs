//! What a `PodSpec` may add to the guest kernel command line (#3124).
//!
//! # The node owns the command line
//!
//! The guest kernel command line decides who PID 1 is (`init=`), the network the guest is given
//! (`nucleus.net=`), the approval verification key the in-guest proxy trusts
//! (`nucleus.approval_pubkeys=`), and, because the kernel hands any undotted parameter it does not
//! recognise to PID 1, part of the environment the tool-proxy inherits. Enforcement for a pod runs
//! inside that guest, so whoever writes the command line writes the rules that bound the pod.
//!
//! A spec author is not trusted to write any of that: they include federated tenants, CI identities,
//! and pods creating child pods. `image.boot_args` used to replace the node's default command line
//! wholesale, and the node decided whether to add its own keys with substring checks, so a spec
//! could pick its own `init=`, set `nucleus.net=` or `ipv6.disable=0`, or get its
//! `nucleus.approval_pubkeys=` in ahead of the node's (guest-init takes the first match).
//!
//! Now a spec may add only the tokens in [`SpecBootToken`]. Every other token is
//! **refused** with a [`BootArgRefused`], and is never stripped. Silently dropping part of what an
//! author asked for is how the earlier `pci=` floor worked, and an author whose `pci=on` disappears
//! does not learn that their spec means something other than what they wrote.
//!
//! # One decider
//!
//! [`SpecBootArgs::parse`] is the only function that decides whether a token is admissible. The node
//! calls it at admission to refuse a spec, and again when it builds the command line, through the
//! value admission minted. The parsed type has no public constructor except `parse`, so a command
//! line cannot be built from tokens nobody checked (ADR 0007 C-1, C-2, G-1, I-2). Tokens are parsed
//! into key and value and matched exactly, never by substring. A `contains("init=")` check also
//! matches `xinit=`, which is I-4.

use crate::ImageSpec;

/// The one key a spec may give an arbitrary (charset-restricted) value: an inert marker.
///
/// It exists for the `nucleus two-safety` positive control. That control has to plant a value into
/// a channel that certainly reaches `/proc/cmdline` on a real boot through the real node API, and
/// then show that the harness can see it.
///
/// It is inert by construction, not by convention:
/// - **The key is dotted.** The kernel treats a dotted parameter as a module parameter and drops it
///   instead of passing it to PID 1, so it never enters init's environment or argv.
/// - **The key is outside `nucleus.`.** guest-init reads only exact `nucleus.*` prefixes, so the
///   guest's behaviour cannot depend on it.
/// - **The value is restricted** to `[A-Za-z0-9_-]`, 1 to 64 characters. It cannot carry a space,
///   quote or `=`, so it cannot smuggle a second token.
///
/// Reading it grants nothing; it is not a secret and not an identity.
pub const CANARY_KEY: &str = "twosafety.canary";

/// The longest canary value admitted.
pub const CANARY_MAX_LEN: usize = 64;

/// The highest kernel `loglevel=` (KERN_DEBUG).
const MAX_LOGLEVEL: u8 = 7;

/// A token a spec may add to the guest command line. Exhaustive: a token that is not one of these
/// is refused, and adding a variant here is the only way to widen what a spec may say.
///
/// Why these and nothing else: no shipped example or doc uses `boot_args`. The in-tree uses are tests
/// passing the node's own defaults (now always emitted by the node) and the two-safety canary.
/// Verbosity is the one kernel knob that changes only how much the guest kernel prints, and the
/// node's own console reading never depends on kernel log lines below `KERN_ERR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecBootToken {
    /// `quiet`: kernel console verbosity down to warnings.
    Quiet,
    /// `loglevel=N`, `0..=7`.
    LogLevel(u8),
    /// `twosafety.canary=<value>`; see [`CANARY_KEY`].
    Canary(String),
}

impl std::fmt::Display for SpecBootToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quiet => f.write_str("quiet"),
            Self::LogLevel(n) => write!(f, "loglevel={n}"),
            Self::Canary(v) => write!(f, "{CANARY_KEY}={v}"),
        }
    }
}

/// Why a spec's `image.boot_args` token was refused. Every variant names the token.
///
/// The categories exist for the message, not the verdict: every one of them is a refusal. A token
/// that is in no named category is still refused, as [`BootArgRefused::NotAllowlisted`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BootArgRefused {
    /// A key the node sets itself (PID 1, console, PCI, IPv6, and every `nucleus.*` key).
    #[error(
        "image.boot_args token `{token}` is refused: `{key}` is set by the node, never by a pod \
         spec. The node owns the guest kernel command line, including PID 1, the console, the \
         network plan, and every nucleus.* key."
    )]
    NodeOwned { token: String, key: String },
    /// An undotted `KEY=VALUE` with an uppercase key. The kernel would place it in PID 1's
    /// environment, which the in-guest tool-proxy inherits.
    #[error(
        "image.boot_args token `{token}` is refused: it is shaped like an environment variable, \
         and the kernel passes such tokens into the environment of the guest's PID 1, which the \
         in-guest enforcement inherits. Pass configuration through the pod spec, not boot args."
    )]
    EnvironmentShaped { token: String },
    /// A kernel parameter that turns off a guest hardening measure.
    #[error(
        "image.boot_args token `{token}` is refused: it disables a guest kernel hardening measure"
    )]
    WeakensTheGuest { token: String },
    /// An allowlisted key with a value outside its domain.
    #[error("image.boot_args token `{token}` is refused: {why}")]
    BadValue { token: String, why: String },
    /// Any other token.
    #[error(
        "image.boot_args token `{token}` is refused: a pod spec may add only `quiet`, \
         `loglevel=0..7`, or `{CANARY_KEY}=<[A-Za-z0-9_-]{{1,64}}>` to the guest kernel command line"
    )]
    NotAllowlisted { token: String },
}

/// Keys only the node may set. Exact key match. `nucleus.` and `ipv6.` are prefixes and are checked
/// separately.
const NODE_OWNED_KEYS: &[&str] = &[
    "init",
    "rdinit",
    "root",
    "rootfstype",
    "rootflags",
    "ro",
    "rw",
    "console",
    "earlycon",
    "earlyprintk",
    "reboot",
    "panic",
    "pci",
    "ip",
    "nfsroot",
];

/// Kernel parameters that turn off a hardening measure, matched by exact key.
const WEAKENING_KEYS: &[&str] = &[
    "mitigations",
    "nokaslr",
    "nosmap",
    "nosmep",
    "nopti",
    "pti",
    "nospectre_v1",
    "nospectre_v2",
    "spectre_v2",
    "spectre_v2_user",
    "spec_store_bypass_disable",
    "l1tf",
    "mds",
    "tsx",
    "init_on_alloc",
    "init_on_free",
    "page_alloc.shuffle",
    "slab_nomerge",
    "randomize_kstack_offset",
    "lockdown",
    "module.sig_enforce",
    "security",
    "lsm",
    "selinux",
    "apparmor",
    "audit",
    "vsyscall",
    "debugfs",
    "seccomp",
    "nosmt",
    "kfence.sample_interval",
];

/// The tokens a spec added to the guest command line, every one of them checked.
///
/// The only constructor is [`SpecBootArgs::parse`] (and [`SpecBootArgs::of`], which calls it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecBootArgs {
    tokens: Vec<SpecBootToken>,
}

impl SpecBootArgs {
    /// Parse a whitespace-separated command line. The first inadmissible token refuses the whole
    /// line; nothing is dropped.
    ///
    /// # Errors
    ///
    /// [`BootArgRefused`] naming the first token that is not a [`SpecBootToken`].
    pub fn parse(line: &str) -> Result<Self, BootArgRefused> {
        line.split_whitespace()
            .map(parse_token)
            .collect::<Result<Vec<_>, _>>()
            .map(|tokens| Self { tokens })
    }

    /// The image's `boot_args`, parsed. No `boot_args` is no tokens.
    ///
    /// # Errors
    ///
    /// As [`SpecBootArgs::parse`].
    pub fn of(image: &ImageSpec) -> Result<Self, BootArgRefused> {
        image
            .boot_args
            .as_deref()
            .map_or_else(|| Ok(Self { tokens: Vec::new() }), Self::parse)
    }

    /// The admitted tokens, in the order the spec gave them.
    #[must_use]
    pub fn tokens(&self) -> &[SpecBootToken] {
        &self.tokens
    }
}

fn parse_token(token: &str) -> Result<SpecBootToken, BootArgRefused> {
    let (key, value) = match token.split_once('=') {
        Some((k, v)) => (k, Some(v)),
        None => (token, None),
    };
    let bad = |why: &str| BootArgRefused::BadValue {
        token: token.to_string(),
        why: why.to_string(),
    };
    match (key, value) {
        ("quiet", None) => Ok(SpecBootToken::Quiet),
        ("quiet", Some(_)) => Err(bad("`quiet` takes no value")),
        ("loglevel", Some(v)) => match v.parse::<u8>() {
            Ok(n) if n <= MAX_LOGLEVEL && v == n.to_string() => Ok(SpecBootToken::LogLevel(n)),
            _ => Err(bad("`loglevel` must be a single digit 0 to 7")),
        },
        ("loglevel", None) => Err(bad("`loglevel` needs a value 0 to 7")),
        (CANARY_KEY, Some(v)) => {
            let charset_ok = v
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
            if !v.is_empty() && v.len() <= CANARY_MAX_LEN && charset_ok {
                Ok(SpecBootToken::Canary(v.to_string()))
            } else {
                Err(bad(
                    "the canary value must be 1 to 64 characters of [A-Za-z0-9_-]",
                ))
            }
        }
        (CANARY_KEY, None) => Err(bad("the canary needs a value")),
        // Everything below is a refusal. The match above is the whole allowlist, and the arms
        // that follow only pick which message the refusal carries (B-3: the fallthrough denies).
        _ => Err(refusal(token, key, value)),
    }
}

fn refusal(token: &str, key: &str, value: Option<&str>) -> BootArgRefused {
    let token = token.to_string();
    if NODE_OWNED_KEYS.contains(&key) || key.starts_with("nucleus.") || key.starts_with("ipv6.") {
        BootArgRefused::NodeOwned {
            token,
            key: key.to_string(),
        }
    } else if WEAKENING_KEYS.contains(&key) {
        BootArgRefused::WeakensTheGuest { token }
    } else if value.is_some() && !key.contains('.') && key.chars().any(|c| c.is_ascii_uppercase()) {
        BootArgRefused::EnvironmentShaped { token }
    } else {
        BootArgRefused::NotAllowlisted { token }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(line: &str) -> BootArgRefused {
        SpecBootArgs::parse(line).expect_err(line)
    }

    #[test]
    fn the_allowlist_is_admitted_and_renders_back_verbatim() {
        let line = "quiet loglevel=0 loglevel=7 twosafety.canary=twosafety-control-aaaaaaaa";
        let parsed = SpecBootArgs::parse(line).expect("allowlisted");
        let rendered: Vec<String> = parsed.tokens().iter().map(ToString::to_string).collect();
        assert_eq!(rendered.join(" "), line);
    }

    #[test]
    fn nothing_is_no_tokens() {
        assert!(SpecBootArgs::parse("").expect("empty").tokens().is_empty());
        assert!(
            SpecBootArgs::parse("  \t ")
                .expect("blank")
                .tokens()
                .is_empty()
        );
    }

    #[test]
    fn pid_one_is_the_nodes() {
        for t in ["init=/bin/sh", "rdinit=/x", "init=/init"] {
            assert!(
                matches!(refused(t), BootArgRefused::NodeOwned { .. }),
                "{t}"
            );
        }
        // The old substring check's false friend: `xinit=` is not `init=`, and is still refused,
        // for the right reason.
        assert!(matches!(
            refused("xinit=/bin/sh"),
            BootArgRefused::NotAllowlisted { .. }
        ));
    }

    #[test]
    fn every_nucleus_and_ipv6_key_is_the_nodes() {
        for t in [
            "nucleus.net=10.0.0.2/30,gw=10.0.0.1",
            "nucleus.approval_pubkeys=00",
            "nucleus.workload_api_port=1",
            "nucleus.anything",
            "ipv6.disable=0",
            "ipv6.disable=1",
            "pci=off",
            "pci=on",
            "console=ttyS1",
        ] {
            assert!(
                matches!(refused(t), BootArgRefused::NodeOwned { .. }),
                "{t}"
            );
        }
    }

    #[test]
    fn an_environment_shaped_token_is_refused() {
        for t in ["NUCLEUS_TOOL_PROXY_POLICY=permissive", "PATH=/tmp", "Foo=1"] {
            assert!(
                matches!(refused(t), BootArgRefused::EnvironmentShaped { .. }),
                "{t}"
            );
        }
    }

    #[test]
    fn hardening_cannot_be_turned_off() {
        for t in ["mitigations=off", "nokaslr", "init_on_free=0", "nopti"] {
            assert!(
                matches!(refused(t), BootArgRefused::WeakensTheGuest { .. }),
                "{t}"
            );
        }
    }

    #[test]
    fn an_allowlisted_key_with_a_bad_value_is_refused() {
        for t in [
            "loglevel=8",
            "loglevel=07",
            "loglevel=+1",
            "loglevel",
            "quiet=1",
            "twosafety.canary=",
            "twosafety.canary=a=b",
            "twosafety.canary=a.b",
            "twosafety.canary=\"a",
        ] {
            assert!(matches!(refused(t), BootArgRefused::BadValue { .. }), "{t}");
        }
        let long = format!("twosafety.canary={}", "a".repeat(CANARY_MAX_LEN + 1));
        assert!(matches!(refused(&long), BootArgRefused::BadValue { .. }));
    }

    /// One bad token refuses the line: nothing is stripped and the rest kept.
    #[test]
    fn one_bad_token_refuses_the_whole_line() {
        let e = refused("quiet init=/bin/sh loglevel=3");
        assert_eq!(
            e,
            BootArgRefused::NodeOwned {
                token: "init=/bin/sh".into(),
                key: "init".into()
            }
        );
        assert!(e.to_string().contains("init=/bin/sh"));
    }

    /// The canary has to be inert in the guest: dotted (so the kernel never hands it to PID 1) and
    /// outside `nucleus.` (so guest-init never reads it).
    #[test]
    fn the_canary_key_is_inert() {
        assert!(CANARY_KEY.contains('.'));
        assert!(!CANARY_KEY.starts_with("nucleus."));
    }
}
