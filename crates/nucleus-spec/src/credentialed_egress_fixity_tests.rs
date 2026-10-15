//! `CredentialedEgressSpec` fixity tests (moved out of `lib.rs` for the line ceiling).

use super::*;

fn spec() -> CredentialedEgressSpec {
    CredentialedEgressSpec {
        name: "model-api".into(),
        upstream: "https://upstream.invalid/v1".into(),
        credential_env: "NUCLEUS_TEST_EGRESS_CRED".into(),
        header: "authorization".into(),
        value_prefix: "Bearer ".into(),
        effects: crate::EffectTable::unclassified(),
    }
}

/// The subset check the node and the tool-proxy both call. An identical
/// entry is admitted; changing ANY one field, including ones a hand-written
/// comparison would be likely to forget, is not.
#[test]
fn admission_is_whole_struct_equality() {
    let granted = [spec()];
    assert!(
        spec().admitted_by(&granted),
        "the control: an equal entry is admitted"
    );
    let perturbations: [fn(&mut CredentialedEgressSpec); 5] = [
        |s| s.name = "other".into(),
        |s| s.upstream = "https://attacker.invalid".into(),
        |s| s.credential_env = "SOME_OTHER_NODE_VAR".into(),
        |s| s.header = "x-api-key".into(),
        |s| s.value_prefix = String::new(),
    ];
    for perturb in perturbations {
        let mut changed = spec();
        perturb(&mut changed);
        assert!(
            !changed.admitted_by(&granted),
            "{changed:?} differs and was admitted"
        );
    }
    assert!(!spec().admitted_by(&[]), "an empty ceiling grants nothing");

    let (kept, dropped) = CredentialedEgressSpec::clamp(
        vec![spec(), {
            let mut s = spec();
            s.credential_env = "SOME_OTHER_NODE_VAR".into();
            s
        }],
        &granted,
    );
    assert_eq!((kept.len(), dropped.len()), (1, 1));
    assert_eq!(kept[0], spec());
}

/// A selection of a federated upstream omits `credential_env`, and the
/// omission is the empty string — which is what the registry's projection
/// of a federated entry carries, so the two compare equal. And an empty
/// variable is not a wildcard: it does not match an entry that names one.
#[test]
fn an_omitted_credential_env_is_empty_and_not_a_wildcard() {
    let selected: CredentialedEgressSpec = serde_json::from_value(serde_json::json!({
        "name": "model-api",
        "upstream": "https://upstream.invalid/v1",
        "header": "authorization",
        "value_prefix": "Bearer ",
    }))
    .expect("credential_env may be omitted");
    assert_eq!(selected.credential_env, "");
    let federated = CredentialedEgressSpec {
        credential_env: String::new(),
        ..spec()
    };
    assert!(selected.admitted_by(std::slice::from_ref(&federated)));
    assert!(
        !selected.admitted_by(&[spec()]),
        "an empty variable matched an entry that names one"
    );
}

/// **The control, first.** Everything below asserts a refusal, and an
/// implementation that refused every path would satisfy all of them while
/// being completely broken. This says the ordinary case still works.
#[test]
fn an_ordinary_path_resolves_under_the_configured_base() {
    assert_eq!(
        spec().url_for("/messages").as_deref(),
        Some("https://upstream.invalid/v1/messages")
    );
    assert_eq!(
        spec().url_for("messages").as_deref(),
        Some("https://upstream.invalid/v1/messages")
    );
}

/// **A caller cannot redirect where the credential is sent.** This is the
/// property; the guest picks the path and must not thereby pick the host.
#[test]
fn a_path_cannot_redirect_the_upstream() {
    for hostile in [
        "https://attacker.invalid/steal",
        "http://attacker.invalid/steal",
        "../../../other",
        "messages/../../escape",
    ] {
        assert!(
            spec().url_for(hostile).is_none(),
            "{hostile:?} must not resolve to an upstream URL"
        );
    }
}

/// Percent-encoded traversal, which a plain `..` scan does not see.
///
/// The path reaches the upstream verbatim, so an upstream that decodes
/// before it normalises treats `%2e%2e/` exactly as `../`. Same host, so
/// this is not a redirect — it is reaching a path above the base the
/// operator fixed, which the base exists to prevent.
#[test]
fn percent_encoded_traversal_is_refused_in_any_case() {
    for hostile in [
        "%2e%2e/admin",
        "%2E%2E/admin",
        "messages/%2e%2e/%2e%2e/admin",
        "%2e%2E/admin",
    ] {
        assert!(
            spec().url_for(hostile).is_none(),
            "{hostile:?} decodes to traversal at an upstream that decodes first"
        );
    }
}

/// **The join is what makes protocol-relative paths harmless**, and the
/// docs say so — so this pins it rather than leaving the claim unchecked.
///
/// `url_for` deliberately does NOT test for a leading `//`, because
/// trimming leading `/` from the path already puts it under the base. If
/// the concatenation ever changes so a leading `//` survives, the doc
/// comment silently becomes false; this test fails at that moment instead.
#[test]
fn a_protocol_relative_path_stays_under_the_base() {
    let url = spec()
        .url_for("//attacker.invalid/steal")
        .expect("not refused — it is neutralised by the join, not rejected");
    assert_eq!(url, "https://upstream.invalid/v1/attacker.invalid/steal");
    assert!(
        url.starts_with("https://upstream.invalid/v1/"),
        "a protocol-relative path escaped the base: {url}"
    );
}

/// A base with a trailing slash must not produce a doubled separator, and
/// more importantly must not produce `https://host//x` — which some proxies
/// and origin servers do not treat as `https://host/x`.
#[test]
fn a_trailing_slash_on_the_base_does_not_double_the_separator() {
    let mut s = spec();
    s.upstream = "https://upstream.invalid/v1/".into();
    assert_eq!(
        s.url_for("messages").as_deref(),
        Some("https://upstream.invalid/v1/messages")
    );
}
