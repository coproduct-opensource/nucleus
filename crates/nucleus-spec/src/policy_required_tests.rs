//! #3400 (ADR 0007 B-2): a pod spec names its policy. Leaving the field out
//! used to parse and resolve to the `default` profile, so absence picked a
//! policy on the caller's behalf. Now it is refused, and the error names it.

use super::*;

/// #3400 (ADR 0007 B-2): a spec with no `policy` is refused, and the
/// error names the field. It used to parse and resolve to the `default`
/// profile, so leaving the field out picked a policy for the caller.
#[test]
fn a_spec_without_a_policy_is_refused_and_names_the_field() {
    let yaml = "apiVersion: nucleus/v1\nkind: Pod\nspec:\n  work_dir: .\n";
    let err =
        nucleus_yaml::from_str::<PodSpec>(yaml).expect_err("a spec with no policy must not parse");
    let msg = err.to_string();
    assert!(
        msg.contains("policy"),
        "the refusal must name the missing field, got: {msg}"
    );
    // The JSON door refuses it the same way.
    let json = r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"work_dir":"."}}"#;
    let err = serde_json::from_str::<PodSpec>(json).expect_err("JSON too");
    assert!(err.to_string().contains("policy"), "got: {err}");
}

/// Non-vacuity for the refusal above: the same spec with the policy named
/// explicitly parses, so the refusal is about the missing field and
/// nothing else.
#[test]
fn the_same_spec_naming_its_policy_parses() {
    let yaml = "apiVersion: nucleus/v1\nkind: Pod\nspec:\n  work_dir: .\n  policy:\n    type: profile\n    name: default\n";
    let spec: PodSpec = nucleus_yaml::from_str(yaml).expect("an explicit policy parses");
    assert!(matches!(
        &spec.spec.policy,
        PolicySpec::Profile { name } if name == "default"
    ));
}
