//! `forwarded_headers` sends exactly the headers it sent before it was
//! rewritten over `nucleus_cred_protocol::extracted::headers`.
//!
//! `old_forwarded_headers` is the implementation before the rewrite, with
//! `RegistryEntry::forwards_header` as it was, over the entry's fields as
//! [`RegistryEntry::header_entry`] reports them: test-only, the reference the
//! rewrite is held to, not a second decider (ADR 0007 G-1). The entries are
//! built unvalidated (`with_request_headers`, `with_header_policy`), so the
//! per-call rule is compared on registries the loader would refuse too.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;

use super::*;

/// `forwarded_headers` and `forwards_header` before the rewrite.
fn old_forwarded_headers(req: &StreamRequest, entry: &RegistryEntry) -> BTreeMap<String, String> {
    let view = entry.header_entry();
    let text = |b: &Vec<u8>| String::from_utf8(b.clone()).expect("built from a String");
    let request_headers: BTreeSet<String> = view.listed.iter().map(text).collect();
    let header = text(&view.credential_header);
    let secret: BTreeSet<String> = view.withheld.iter().map(text).collect();
    let fixed: BTreeMap<String, String> =
        view.fixed.iter().map(|(n, v)| (text(n), text(v))).collect();
    let forwards_header = |name: &str| {
        request_headers.contains(name)
            && nucleus_spec::workload_egress::guest_may_propose_header(name)
            && !name.eq_ignore_ascii_case(&header)
            && !secret.contains(name)
            && !fixed.contains_key(name)
    };
    let mut forwarded: BTreeMap<String, String> = req
        .headers
        .iter()
        .filter(|(name, value)| {
            forwards_header(name) && nucleus_spec::workload_egress::header_value_admissible(value)
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    forwarded.extend(
        fixed
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    forwarded
}

/// Names a registry or a guest might use, allowed and not, in both cases.
const NAMES: &[&str] = &[
    "accept",
    "Accept",
    "x-api-version",
    "X-Api-Version",
    "x-account-binding",
    "authorization",
    "Authorization",
    "x-forge-key",
    "user-agent",
    "git-protocol",
    "host",
    "x-forwarded-for",
    "x-session-id",
    "",
    "é",
];

const VALUES: &[&str] = &["application/json", "2026-01-01", "", "a\u{7f}b", "é", "v 1"];

fn names() -> impl Strategy<Value = Vec<&'static str>> {
    prop::collection::vec(prop::sample::select(NAMES), 0..6)
}

fn pairs() -> impl Strategy<Value = Vec<(&'static str, &'static str)>> {
    prop::collection::vec(
        (prop::sample::select(NAMES), prop::sample::select(VALUES)),
        0..6,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// The headers a call sends are the ones it sent before.
    #[test]
    fn forwarded_headers_decide_as_before(
        listed in names(),
        credential in prop::sample::select(vec!["authorization", "X-Forge-Key", "x-api-version"]),
        fixed in pairs(),
        secret in names(),
        proposed in pairs(),
    ) {
        let entry = RegistryEntry::env(nucleus_spec::CredentialedEgressSpec {
            name: "model-api".into(),
            upstream: "https://upstream.invalid".into(),
            credential_env: "LLM_API_TOKEN".into(),
            header: credential.into(),
            value_prefix: String::new(),
            effects: nucleus_spec::EffectTable::unclassified(),
        })
        .with_request_headers(&listed)
        .with_header_policy(&fixed, &secret);
        let mut req = open("model-api", "n");
        req.headers = proposed
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect();
        prop_assert_eq!(forwarded_headers(&req, &entry), old_forwarded_headers(&req, &entry));
    }
}
