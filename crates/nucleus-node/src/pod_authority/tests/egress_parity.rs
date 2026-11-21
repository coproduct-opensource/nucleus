//! `PodAuthority::admit_upstreams` admits and refuses exactly what it did
//! before it was rewritten over `nucleus_cred_protocol::extracted::admission`.
//!
//! `old_admit_upstreams` is the implementation before the rewrite, verbatim
//! but for the clamp, which is the old `CredentialedEgressSpec::clamp`
//! inlined: test-only, the reference the rewrite is held to, not a second
//! decider (ADR 0007 G-1).

use proptest::prelude::*;

use super::*;
use std::sync::Arc;

use crate::upstreams::UpstreamRegistry;

fn old_clamp(
    requested: Vec<CredentialedEgressSpec>,
    ceiling: &[CredentialedEgressSpec],
) -> (Vec<CredentialedEgressSpec>, Vec<CredentialedEgressSpec>) {
    requested
        .into_iter()
        .partition(|up| ceiling.iter().any(|granted| granted == up))
}

/// `admit_upstreams` before the rewrite, without its log line.
fn old_admit_upstreams(
    loaded: &registry::Loaded,
    requested: &[CredentialedEgressSpec],
    parent: Option<&[CredentialedEgressSpec]>,
) -> Result<Vec<CredentialedEgressSpec>, ApiError> {
    let registry = loaded
        .upstreams
        .as_deref()
        .map_or(&[][..], UpstreamRegistry::entries);
    let (mut kept, mut dropped) = old_clamp(requested.to_vec(), registry);
    if let Some(parent) = parent {
        let (narrowed, beyond_parent) = old_clamp(kept, parent);
        kept = narrowed;
        dropped.extend(beyond_parent);
    }
    match dropped.first() {
        None => Ok(kept),
        Some(up) => Err(ApiError::Authority(format!(
            "credentialed upstream `{}` is not granted",
            up.name
        ))),
    }
}

/// Four upstreams an operator might register.
const UPSTREAMS: [&str; 4] = [
    "[[upstream]]\nname = \"a\"\nbase_url = \"https://a.invalid\"\nheader = \"authorization\"\ncredential.env.var = \"A_TOKEN\"\n",
    "[[upstream]]\nname = \"b\"\nbase_url = \"https://b.invalid\"\nheader = \"x-api-key\"\ncredential.env.var = \"B_TOKEN\"\n",
    "[[upstream]]\nname = \"c\"\nbase_url = \"https://c.invalid\"\nheader = \"authorization\"\nvalue_prefix = \"Bearer \"\ncredential.env.var = \"C_TOKEN\"\n",
    "[[upstream]]\nname = \"d\"\nbase_url = \"https://d.invalid\"\nheader = \"authorization\"\ncredential.env.var = \"D_TOKEN\"\n",
];

/// Every upstream's projection, and each retargeted at another URL.
fn pool() -> Vec<CredentialedEgressSpec> {
    let all = UpstreamRegistry::from_toml_str(&UPSTREAMS.concat()).expect("the fixture loads");
    let mut pool = all.entries().to_vec();
    for entry in all.entries() {
        let mut retargeted = entry.clone();
        retargeted.upstream = "https://elsewhere.invalid".into();
        pool.push(retargeted);
    }
    pool
}

fn some_of(pool: &[CredentialedEgressSpec]) -> impl Strategy<Value = Vec<CredentialedEgressSpec>> {
    prop::collection::vec(prop::sample::select(pool.to_vec()), 0..5)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Admission keeps, refuses and names exactly as before.
    #[test]
    fn admit_upstreams_decides_as_before(
        registered in prop::option::of(prop::sample::subsequence(UPSTREAMS.to_vec(), 0..=4)),
        requested in some_of(&pool()),
        parent in prop::option::of(some_of(&pool())),
    ) {
        let loaded = registry::Loaded {
            upstreams: registered.map(|files| {
                Arc::new(UpstreamRegistry::from_toml_str(&files.concat()).expect("loads"))
            }),
            bindings: Arc::new(crate::federation_ingress::CallerBindings::default()),
        };
        let new = PodAuthority::admit_upstreams(
            &loaded,
            &requested,
            parent.as_deref(),
            Uuid::new_v4(),
        );
        let old = old_admit_upstreams(&loaded, &requested, parent.as_deref());
        prop_assert_eq!(
            new.map_err(|e| e.to_string()),
            old.map_err(|e| e.to_string())
        );
    }
}
