//! `header_policy` accepts, refuses and words exactly what it did before it
//! was rewritten over `nucleus_cred_protocol::extracted::headers`.
//!
//! `old_header_policy` is the implementation before the rewrite, verbatim and
//! test-only: the reference the rewrite is held to, not a second decider
//! (ADR 0007 G-1).

use proptest::prelude::*;

use super::*;

/// `header_policy` before the rewrite.
fn old_header_policy(
    name: &str,
    credential_header: &str,
    fixed: BTreeMap<String, String>,
    secret: Vec<String>,
) -> Result<HeaderPolicy, String> {
    let mut secret_names = BTreeSet::new();
    for header in secret {
        let lower = header.to_ascii_lowercase();
        if lower.is_empty()
            || lower.len() > 64
            || !lower
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!(
                "upstream {name:?}: secret_headers lists {header:?}, which is not a header name"
            ));
        }
        secret_names.insert(lower);
    }
    let mut fixed_headers = BTreeMap::new();
    for (header, value) in fixed {
        let lower = header.to_ascii_lowercase();
        if lower.eq_ignore_ascii_case(credential_header)
            || secret_names.contains(&lower)
            || !nucleus_spec::workload_egress::guest_may_propose_header(&lower)
        {
            return Err(format!(
                "upstream {name:?}: fixed_headers may not set {header:?}: a fixed header is \
                 not secret, so it may not be a credential, secret, framing or forwarding header"
            ));
        }
        if value.is_empty() || !nucleus_spec::workload_egress::header_value_admissible(&value) {
            return Err(format!(
                "upstream {name:?}: fixed_headers sets {header:?} to a value that is not a \
                 non-empty visible-ASCII header value"
            ));
        }
        if fixed_headers.insert(lower, value).is_some() {
            return Err(format!(
                "upstream {name:?}: fixed_headers sets {header:?} twice, in different cases"
            ));
        }
    }
    if fixed_headers.len() > nucleus_spec::workload_egress::MAX_PROPOSED_HEADERS {
        return Err(format!(
            "upstream {name:?}: fixed_headers sets {} headers, above the {} a call may carry",
            fixed_headers.len(),
            nucleus_spec::workload_egress::MAX_PROPOSED_HEADERS
        ));
    }
    Ok(HeaderPolicy {
        fixed: fixed_headers,
        secret: secret_names,
    })
}

/// Names an operator might write, allowed and not, in both cases.
const NAMES: &[&str] = &[
    "x-api-version",
    "X-Api-Version",
    "x-account-binding",
    "X-ACCOUNT-BINDING",
    "authorization",
    "Authorization",
    "user-agent",
    "accept",
    "host",
    "x-forwarded-for",
    "x-session-id",
    "x_bad",
    "",
    "é",
    "a234567890123456789012345678901234567890123456789012345678901234",
    "a2345678901234567890123456789012345678901234567890123456789012345",
];

const VALUES: &[&str] = &["2026-01-01", "", "a\u{7f}b", "é", "v 1", "x"];

/// Header names `h0` .. `h19`, for policies near the fixed-header bound.
fn many() -> impl Strategy<Value = Vec<(String, String)>> {
    (0usize..20).prop_map(|n| (0..n).map(|i| (format!("h{i}"), "v".to_string())).collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// Every policy is accepted, or refused with the same message, as before.
    #[test]
    fn header_policy_decides_as_before(
        credential in prop::sample::select(vec!["authorization", "X-Forge-Key", "x-api-version"]),
        fixed in prop_oneof![
            3 => prop::collection::vec(
                (prop::sample::select(NAMES), prop::sample::select(VALUES))
                    .prop_map(|(n, v)| (n.to_string(), v.to_string())),
                0..6,
            ),
            1 => many(),
        ],
        secret in prop::collection::vec(prop::sample::select(NAMES).prop_map(String::from), 0..4),
    ) {
        let fixed: BTreeMap<String, String> = fixed.into_iter().collect();
        prop_assert_eq!(
            header_policy("u", credential, fixed.clone(), secret.clone()),
            old_header_policy("u", credential, fixed, secret)
        );
    }
}
