//! `CredentialedEgressSpec::admitted_by`, `CredentialedEgressSpec::clamp` and
//! the header-name rules in `workload_egress` decide exactly what they decided
//! before they were rewritten over `nucleus_cred_protocol::extracted`.
//!
//! `old` is the implementation before the rewrite, verbatim and test-only: the
//! reference the rewrite is held to, not a second decider (ADR 0007 G-1).

use proptest::prelude::*;

use super::*;
use crate::workload_egress::{
    guest_may_propose_header, header_value_admissible, names_a_credential,
};

/// The implementation before the rewrite.
mod old {
    use super::*;

    pub fn admitted_by(entry: &CredentialedEgressSpec, ceiling: &[CredentialedEgressSpec]) -> bool {
        ceiling.iter().any(|granted| granted == entry)
    }

    pub fn clamp(
        requested: Vec<CredentialedEgressSpec>,
        ceiling: &[CredentialedEgressSpec],
    ) -> (Vec<CredentialedEgressSpec>, Vec<CredentialedEgressSpec>) {
        requested
            .into_iter()
            .partition(|up| admitted_by(up, ceiling))
    }

    const CREDENTIAL_NAMES: &[&str] = &[
        "key",
        "sig",
        "code",
        "auth",
        "authorization",
        "jwt",
        "bearer",
        "assertion",
        "clientassertion",
        "pwd",
    ];

    const CREDENTIAL_FRAGMENTS: &[&str] = &[
        "token",
        "secret",
        "passw",
        "credential",
        "apikey",
        "signature",
        "session",
        "cookie",
    ];

    pub fn names_a_credential(name: &str) -> bool {
        let folded: String = name
            .chars()
            .filter(|c| *c != '-' && *c != '_')
            .map(|c| c.to_ascii_lowercase())
            .collect();
        CREDENTIAL_NAMES.contains(&folded.as_str())
            || CREDENTIAL_FRAGMENTS.iter().any(|f| folded.contains(f))
    }

    const NEVER_PROPOSED: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "host",
        "content-type",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "expect",
        "forwarded",
        "via",
    ];

    const NEVER_PROPOSED_PREFIXES: &[&str] = &["proxy-", "x-forwarded-", "x-nucleus-", "sec-"];

    pub fn guest_may_propose_header(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !NEVER_PROPOSED.contains(&name)
            && !NEVER_PROPOSED_PREFIXES.iter().any(|p| name.starts_with(p))
            && !names_a_credential(name)
    }

    pub fn header_value_admissible(value: &str) -> bool {
        value.len() <= 1024 && value.bytes().all(|b| (0x20..0x7f).contains(&b))
    }

    /// Every name the two lists hold, for the generator.
    pub fn listed() -> Vec<&'static str> {
        CREDENTIAL_NAMES
            .iter()
            .chain(CREDENTIAL_FRAGMENTS)
            .chain(NEVER_PROPOSED)
            .chain(NEVER_PROPOSED_PREFIXES)
            .copied()
            .collect()
    }
}

/// Entries from small domains, so equal and nearly-equal entries are common.
fn entry() -> impl Strategy<Value = CredentialedEgressSpec> {
    let forge = || {
        nucleus_cred_protocol::EffectTable::from_parts(
            Some(nucleus_cred_protocol::UpstreamKind::Forge),
            Vec::new(),
        )
        .expect("an empty forge table is valid")
    };
    (
        prop::sample::select(vec!["forge", "model"]),
        prop::sample::select(vec!["https://a.invalid", "https://b.invalid"]),
        prop::sample::select(vec!["", "NODE_VAR"]),
        prop::sample::select(vec!["authorization", "x-api-key"]),
        prop::sample::select(vec!["", "Bearer "]),
        any::<bool>(),
    )
        .prop_map(move |(name, upstream, env, header, prefix, forge_kind)| {
            CredentialedEgressSpec {
                name: name.into(),
                upstream: upstream.into(),
                credential_env: env.into(),
                header: header.into(),
                value_prefix: prefix.into(),
                effects: if forge_kind {
                    forge()
                } else {
                    nucleus_cred_protocol::EffectTable::unclassified()
                },
            }
        })
}

fn entries() -> impl Strategy<Value = Vec<CredentialedEgressSpec>> {
    prop::collection::vec(entry(), 0..6)
}

/// Header names: the listed names, with separators, case and affixes varied,
/// and arbitrary short text.
fn name() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => prop::sample::select(old::listed()).prop_map(String::from),
        4 => (
            prop::sample::select(old::listed()),
            prop::sample::select(vec!["", "x-", "my-", "_", "-"]),
            prop::sample::select(vec!["", "-id", "s", "_v2", "-"]),
            any::<bool>(),
        )
            .prop_map(|(word, before, after, upper)| {
                let n = format!("{before}{word}{after}");
                if upper { n.to_ascii_uppercase() } else { n }
            }),
        2 => "[a-zA-Z0-9_ -]{0,8}",
        1 => "[a-z-]{60,68}",
        1 => ".{0,6}",
    ]
}

fn value() -> impl Strategy<Value = String> {
    prop_oneof!["[ -~]{0,12}", ".{0,6}", "[ -~]{1020,1030}"]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// `admitted_by` answers as before.
    #[test]
    fn admitted_by_decides_as_before(entry in entry(), ceiling in entries()) {
        prop_assert_eq!(entry.admitted_by(&ceiling), old::admitted_by(&entry, &ceiling));
    }

    /// `clamp` keeps and drops exactly what it did, in the same order.
    #[test]
    fn clamp_decides_as_before(requested in entries(), ceiling in entries()) {
        prop_assert_eq!(
            CredentialedEgressSpec::clamp(requested.clone(), &ceiling),
            old::clamp(requested, &ceiling)
        );
    }

    /// The header-name rules answer as before.
    #[test]
    fn header_rules_decide_as_before(name in name(), value in value()) {
        prop_assert_eq!(names_a_credential(&name), old::names_a_credential(&name), "{}", name);
        prop_assert_eq!(
            guest_may_propose_header(&name),
            old::guest_may_propose_header(&name),
            "{}",
            name
        );
        prop_assert_eq!(header_value_admissible(&value), old::header_value_admissible(&value));
    }
}
