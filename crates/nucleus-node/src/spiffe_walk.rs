//! The SPIFFE taxonomy walk: every parser and every matcher of a SPIFFE ID the
//! node reaches, driven over one bounded, exhaustively generated corpus and held
//! to one oracle ([`model`]). `docs/spiffe-taxonomy.md` states the grammar and
//! the properties; this is where they are checked.
//!
//! # The corpus
//!
//! A path is 1..=[`DEPTH`] segments drawn from [`STRUCTURAL`] (the taxonomy's
//! own words: `ns`, `sa`, `pods`, `github`, a uuid, a `sha256:` digest, …) with
//! AT MOST ONE drawn from [`ADVERSARIAL`] (empty, `.`, `..`, `%2F`, `%2E`, `;`,
//! `?`, `#`, `@`, `:`, NUL, a Cyrillic and a fullwidth confusable, the other
//! casings, the other uuid spellings, and boundary probes like `defaultx`). Every
//! such path is walked under the node's trust domain; every trust domain in
//! [`TRUST_DOMAINS`] (case, port, userinfo, `td.example.evil`, `td.examplex`,
//! confusables, 255/256 bytes) is walked under a set of principal paths; and
//! every principal is re-spelled by every [`decorations`] (trailing and doubled
//! `/`, query, fragment, scheme casing, `wimse://`, whitespace, NUL) and walked
//! at exactly 2048 and 2049 bytes. "Exhaustive up to the bound" means every
//! combination, not a sample.
//!
//! # The properties
//!
//! 1. **Canonical form.** Each parser accepts exactly what its oracle accepts,
//!    and what it accepts it returns unchanged: nothing is normalised into
//!    another ID. A rejected spelling has no authority at all.
//! 2. **Segment boundary.** The node's grants are decided by the oracle's
//!    segment-exact reading (`model::authority`); every prefix site agrees with
//!    it on the whole corpus, including the boundary probes.
//! 3. **Monotonicity.** Below a principal, a descendant never holds more: not a
//!    longer path, not a lineage `/call/…` child, not a delegated child pod's
//!    certificate. It reaches no sibling and no ancestor.
//! 4. **Trust-domain isolation.** An ID in another trust domain holds nothing
//!    here; a federated tenant holds its own pods and nothing else.
//! 5. **Agreement.** The parsers agree pairwise — accept/reject and the parsed
//!    fields — on every input both are defined over.
//!
//! A relying party's prefix condition outside the node (say
//! `startsWith("spiffe://" + td + "/")`) is for whoever deploys it to walk. An
//! external walk that generates this corpus and pins [`CORPUS_FINGERPRINT`] is
//! walking the same inputs under the same reading of the grammar.

mod model;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use model::{Id, Reach};
use sha2::{Digest, Sha256};

use crate::auth::{AuthContext, AuthorizationPolicy};

/// The digest `corpus_fingerprint` computes. An external walk over this corpus pins the same
/// value to show it walks the same inputs under the same reading of the grammar; change the
/// corpus and the value together.
const CORPUS_FINGERPRINT: &str = "ab27ce141509eac21268a1ca4c00b20476937192af8e41c89dcdec3ce5452701";

/// Path depth bound.
const DEPTH: usize = 4;

const NODE_TD: &str = "td.example";
const TENANT_TD: &str = "tenant.example";
const OPERATOR: &str = "spiffe://td.example/ns/system/sa/cli";

const U1: &str = "6f1c3d2a-9b8e-4c7d-a1f0-2e3d4c5b6a79";
const U2: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const U3: &str = "11111111-2222-4333-8444-555555555555";
const U4: &str = "99999999-8888-4777-8666-555555555555";

fn sha_seg() -> String {
    format!("sha256:{}", "ab".repeat(32))
}

/// The taxonomy's own words.
fn structural() -> Vec<String> {
    [
        "ns", "sa", "a", "ab", "default", "pods", "system", "cli", "github", "call", U1,
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([sha_seg()])
    .collect()
}

/// Everything a spelling trick might use, at most one per path.
fn adversarial() -> Vec<String> {
    let mut v: Vec<String> = [
        "", ".", "..", "%2F", "%2E", "%2e%2e", "a%2Fb", "a;b", "a?b", "a#b", "a@b", "a:b", "a\0",
        "a b", " a", "\u{0430}", "\u{FF41}", "A", "CALL", "Call", "sax", "defaultx", "githubx",
        "podsx", "clix",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    v.push(U1.to_uppercase());
    v.push(U1.replace('-', ""));
    v.push(format!("{{{U1}}}"));
    v.push(format!("{U1}x"));
    v.push(format!("SHA256:{}", "ab".repeat(32)));
    v.push(format!("sha256:{}", "ab".repeat(31)));
    v.push(format!("sha256:{}", "AB".repeat(32)));
    v
}

const TRUST_DOMAINS: &[&str] = &[
    NODE_TD,
    TENANT_TD,
    "td.example.evil",
    "td.examplex",
    "td.exampl",
    "xtd.example",
    "TD.example",
    "Td.Example",
    "td.example:443",
    "u@td.example",
    "td_example",
    "td.example.",
    "td..example",
    "",
    "t\u{0501}.example",
    "td.ex\u{FF41}mple",
    "td.example\0",
    "td%2Eexample",
    "tenant.example.evil",
    "tenant.exampl",
];

/// Paths, as segment lists, of depth 1..=DEPTH with at most one adversarial
/// segment. Partition `part` of `parts`, by position in the generation order.
fn paths(part: usize, parts: usize) -> Vec<Vec<String>> {
    let s = structural();
    let x = adversarial();
    let mut out = Vec::new();
    // (path, adversarial used?)
    let mut frontier: Vec<(Vec<String>, bool)> = vec![(Vec::new(), false)];
    for _ in 0..DEPTH {
        let mut next = Vec::new();
        for (p, used) in &frontier {
            for t in s
                .iter()
                .map(|t| (t, false))
                .chain(x.iter().map(|t| (t, true)))
            {
                if t.1 && *used {
                    continue;
                }
                let mut q = p.clone();
                q.push(t.0.clone());
                next.push((q, *used || t.1));
            }
        }
        out.extend(next.iter().map(|(p, _)| p.clone()));
        frontier = next;
    }
    out.into_iter()
        .enumerate()
        .filter(|(i, _)| i % parts == part)
        .map(|(_, p)| p)
        .collect()
}

fn uri(td: &str, segs: &[String]) -> String {
    format!("spiffe://{td}/{}", segs.join("/"))
}

/// Principal paths every trust domain is walked under.
fn principal_paths() -> Vec<Vec<String>> {
    [
        vec!["ns", "a", "sa", "b"],
        vec!["ns", "default", "sa", "x"],
        vec!["ns", "pods", "sa", U1],
        vec!["ns", "github", "sa", "a"],
        vec!["ns", "system", "sa", "cli"],
    ]
    .into_iter()
    .map(|p| p.into_iter().map(String::from).collect())
    .collect()
}

/// Re-spellings of a canonical ID. None of them is canonical.
fn decorations(id: &str) -> Vec<String> {
    let rest = id.strip_prefix("spiffe://").expect("canonical");
    let mut v = vec![
        format!("{id}/"),
        format!("{id}//"),
        format!("{id}?x"),
        format!("{id}#x"),
        format!("{id};x"),
        format!("{id}\0"),
        format!("{id} "),
        format!(" {id}"),
        format!("{id}\n"),
        format!("SPIFFE://{rest}"),
        format!("Spiffe://{rest}"),
        format!("spiffe:/{rest}"),
        format!("spiffe:///{rest}"),
        format!("spiffe:{rest}"),
        format!("wimse://{rest}"),
        format!("https://{rest}"),
        rest.to_string(),
        format!("spiffe://{}", rest.replacen('/', "//", 1)),
        format!("spiffe://{}", rest.replacen('/', ":443/", 1)),
        format!("spiffe://user@{rest}"),
        format!("spiffe://{}", rest.replacen('/', "/./", 1)),
        format!("spiffe://{}", rest.replacen('/', "/x/../", 1)),
        format!("spiffe://{}", rest.replacen('/', "%2F", 1)),
    ];
    // Doubled slash at every boundary.
    for (i, _) in rest.match_indices('/') {
        v.push(format!("spiffe://{}/{}", &rest[..i], &rest[i..]));
    }
    v
}

/// The length bounds, exactly: an ID of 2048 bytes and one of 2049, and a trust
/// domain of 255 bytes and one of 256.
fn length_edges() -> Vec<String> {
    let mut v = Vec::new();
    for td in ["a".repeat(model::MAX_TD), "a".repeat(model::MAX_TD + 1)] {
        v.push(format!("spiffe://{td}/ns/a/sa/b"));
    }
    for total in [model::MAX_ID, model::MAX_ID + 1] {
        let head = format!("spiffe://{NODE_TD}/ns/a/sa/");
        v.push(format!("{head}{}", "b".repeat(total - head.len())));
    }
    v
}

// ── The implementations, each reduced to (td, segments) or None ─────────────

fn lineage(s: &str) -> Option<Id> {
    let id = nucleus_lineage::CallSpiffeId::parse(s.to_string()).ok()?;
    // Property 1: accepted means returned unchanged.
    assert_eq!(id.as_str(), s, "lineage normalised {s:?}");
    model::fields(id.as_str())
}

fn identity(s: &str) -> Option<Id> {
    let id = nucleus_identity::Identity::from_spiffe_uri(s).ok()?;
    assert_eq!(id.to_spiffe_uri(), s, "nucleus-identity normalised {s:?}");
    let mut segs = vec![
        "ns".to_string(),
        id.namespace().to_string(),
        "sa".to_string(),
    ];
    segs.extend(id.service_account().split('/').map(String::from));
    Some(Id {
        td: id.trust_domain().to_string(),
        segs,
    })
}

fn portcullis(s: &str) -> Option<Id> {
    let id = portcullis::identity::ParsedSpiffeId::parse(s)?;
    assert_eq!(id.to_string(), s, "portcullis normalised {s:?}");
    Some(Id {
        td: id.trust_domain,
        segs: id.path,
    })
}

fn oidc_core(s: &str) -> Option<Id> {
    let id = nucleus_oidc_core::spiffe_federation::SpiffeId::parse(s).ok()?;
    assert_eq!(
        format!("spiffe://{}{}", id.trust_domain, id.path),
        s,
        "oidc-core normalised {s:?}"
    );
    Some(Id {
        td: id.trust_domain,
        segs: id.path[1..].split('/').map(String::from).collect(),
    })
}

type Parser = (&'static str, fn(&str) -> Option<Id>, fn(&str) -> Option<Id>);

/// Each parser beside the oracle that defines its domain.
const PARSERS: [Parser; 4] = [
    ("nucleus-lineage", lineage, model::lineage),
    ("nucleus-identity", identity, model::principal),
    ("portcullis", portcullis, model::core),
    ("nucleus-oidc-core", oidc_core, model::core),
];

// ── The pod universe the scopes are measured over ───────────────────────────

struct Pod {
    id: uuid::Uuid,
    parent: Option<uuid::Uuid>,
    ci: Option<&'static str>,
    tenant: Option<&'static str>,
}

impl crate::pod_api::Lineage for Pod {
    fn lineage_id(&self) -> uuid::Uuid {
        self.id
    }
    fn lineage_parent(&self) -> Option<uuid::Uuid> {
        self.parent
    }
    fn lineage_ci_principal(&self) -> Option<&str> {
        self.ci
    }
    fn lineage_tenant(&self) -> Option<&str> {
        self.tenant
    }
}

const CI_A: &str = "spiffe://td.example/ns/github/sa/a";
const CI_AB: &str = "spiffe://td.example/ns/github/sa/a/ab";
const CI_SIB: &str = "spiffe://td.example/ns/github/sa/ab";

/// U1 with child U3 and grandchild U4; a sibling root U2; pods made by a CI
/// identity, its descendant and its sibling; and a tenant's pod.
fn universe() -> Vec<Pod> {
    let u = |s: &str| s.parse::<uuid::Uuid>().unwrap();
    let pod = |id, parent, ci, tenant| Pod {
        id,
        parent,
        ci,
        tenant,
    };
    vec![
        pod(u(U1), None, None, Some(NODE_TD)),
        pod(u(U3), Some(u(U1)), None, Some(NODE_TD)),
        pod(u(U4), Some(u(U3)), None, Some(NODE_TD)),
        pod(u(U2), None, None, Some(NODE_TD)),
        pod(uuid::Uuid::from_u128(5), None, Some(CI_A), Some(NODE_TD)),
        pod(uuid::Uuid::from_u128(6), None, Some(CI_AB), Some(NODE_TD)),
        pod(uuid::Uuid::from_u128(7), None, Some(CI_SIB), Some(NODE_TD)),
        pod(uuid::Uuid::from_u128(8), None, None, Some(TENANT_TD)),
    ]
}

fn reach_model(r: &Reach, pods: &[Pod]) -> BTreeSet<usize> {
    (0..pods.len())
        .filter(|&i| match r {
            Reach::Nothing => false,
            Reach::NodeWide => true,
            Reach::Ci(id) => pods[i].ci == Some(id.as_str()),
            Reach::Pod(p) => pods[i].id == *p || pods[i].parent == Some(*p),
            Reach::Tenant(td) => pods[i].tenant == Some(td.as_str()),
        })
        .collect()
}

fn policy() -> AuthorizationPolicy {
    AuthorizationPolicy::new(NODE_TD)
        .with_operator_identity(OPERATOR)
        .with_federated_trust_domains([TENANT_TD, NODE_TD])
}

/// What the node actually grants `s`: the op mask and the pods its scope reaches.
fn node_authority(p: &AuthorizationPolicy, s: &str, pods: &[Pod]) -> (u16, BTreeSet<usize>) {
    let ctx = AuthContext::from_spiffe(s.to_string());
    let mask = model::OPS
        .iter()
        .enumerate()
        .filter(|(_, op)| p.authorize(&ctx, **op).is_ok())
        .fold(0u16, |m, (i, _)| m | (1 << i));
    let reach = match p.caller_scope(None, s) {
        Err(_) => BTreeSet::new(),
        Ok(scope) => (0..pods.len())
            .filter(|&i| crate::pod_api::in_scope(&pods[i], &scope))
            .collect(),
    };
    (mask, reach)
}

/// The tallies one partition reports.
#[derive(Default)]
struct Tally {
    inputs: usize,
    accepted: BTreeMap<&'static str, usize>,
    pair_agreed: BTreeMap<(&'static str, &'static str), usize>,
    authority_checks: usize,
    /// Pairs where one parser accepts and the other refuses because their
    /// oracles' domains differ (a lineage `sha256:` segment, a non-`ns/sa` path).
    profile_differences: usize,
}

/// Every property that is a function of one input.
fn check(s: &str, p: &AuthorizationPolicy, pods: &[Pod], t: &mut Tally) {
    t.inputs += 1;
    let mut got: Vec<(&'static str, Option<Id>)> = Vec::new();
    for (name, imp, oracle) in PARSERS {
        let (want, have) = (oracle(s), imp(s));
        assert_eq!(
            have, want,
            "{name} disagrees with the oracle on {s:?}: got {have:?}, want {want:?}"
        );
        if have.is_some() {
            *t.accepted.entry(name).or_default() += 1;
        }
        got.push((name, have));
    }
    // Property 5, pairwise: where two parsers both accept, they read the same
    // fields; where the core grammar refuses, every one of them refuses.
    for i in 0..got.len() {
        for j in i + 1..got.len() {
            let ((a, x), (b, y)) = (&got[i], &got[j]);
            match (x, y) {
                (Some(x), Some(y)) => assert_eq!(x, y, "{a} and {b} read {s:?} differently"),
                (None, None) => {}
                _ => {
                    // Allowed only where the two oracles' domains differ.
                    let (oa, ob) = ((PARSERS[i].2)(s), (PARSERS[j].2)(s));
                    assert_ne!(
                        oa.is_some(),
                        ob.is_some(),
                        "{a} and {b} disagree on {s:?} with no profile to explain it"
                    );
                    t.profile_differences += 1;
                }
            }
            *t.pair_agreed.entry((a, b)).or_default() += 1;
        }
    }
    // The single-field readers, on what the principal grammar accepts.
    let principal = model::principal(s);
    assert_eq!(
        crate::auth::is_canonical_spiffe_id(s),
        principal.is_some(),
        "{s:?}"
    );
    if let Some(id) = &principal {
        assert_eq!(
            crate::federation_ingress::trust_domain_of(s),
            Some(id.td.as_str()),
            "{s:?}"
        );
        assert_eq!(
            AuthContext::from_spiffe(s.to_string()).actor.as_deref(),
            id.segs.last().map(String::as_str),
            "{s:?}"
        );
    }
    // Properties 1, 2 and 4: the node grants exactly what the rules say —
    // nothing at all to a non-canonical spelling or a foreign trust domain.
    let (want_mask, want_reach) = model::authority(s, NODE_TD, &[TENANT_TD]);
    let (mask, reach) = node_authority(p, s, pods);
    assert_eq!(mask, want_mask, "ops granted to {s:?}");
    assert_eq!(
        reach,
        reach_model(&want_reach, pods),
        "pods reached by {s:?}"
    );
    let pod = p.pod_id_from_spiffe(s);
    assert_eq!(
        pod.map(Reach::Pod),
        matches!(want_reach, Reach::Pod(_)).then(|| want_reach.clone()),
        "pod named by {s:?}"
    );
    t.authority_checks += 1;
}

fn report(name: &str, t: &Tally, started: Instant) {
    eprintln!(
        "spiffe walk [{name}]: {} inputs, {} authority checks, accepted {:?}, {} pairwise \
         comparisons ({} explained by a narrower profile), {:.2?}",
        t.inputs,
        t.authority_checks,
        t.accepted,
        t.pair_agreed.values().sum::<usize>(),
        t.profile_differences,
        started.elapsed()
    );
}

const PARTS: usize = 8;

fn walk_paths(part: usize) {
    let started = Instant::now();
    let (p, pods) = (policy(), universe());
    let mut t = Tally::default();
    for segs in paths(part, PARTS) {
        check(&uri(NODE_TD, &segs), &p, &pods, &mut t);
    }
    report(&format!("paths {part}/{PARTS}"), &t, started);
    // Non-vacuity: every partition reaches both verdicts.
    let core = t.accepted.get("portcullis").copied().unwrap_or(0);
    let principals = t.accepted.get("nucleus-identity").copied().unwrap_or(0);
    assert!(
        principals > 0 && core > principals && t.inputs > core,
        "partition {part} did not reach every verdict"
    );
}

#[test]
fn paths_0() {
    walk_paths(0)
}
#[test]
fn paths_1() {
    walk_paths(1)
}
#[test]
fn paths_2() {
    walk_paths(2)
}
#[test]
fn paths_3() {
    walk_paths(3)
}
#[test]
fn paths_4() {
    walk_paths(4)
}
#[test]
fn paths_5() {
    walk_paths(5)
}
#[test]
fn paths_6() {
    walk_paths(6)
}
#[test]
fn paths_7() {
    walk_paths(7)
}

/// Trust domains, decorations and length edges, over the principal paths.
#[test]
fn trust_domains_spellings_and_lengths() {
    let started = Instant::now();
    let (p, pods) = (policy(), universe());
    let mut t = Tally::default();
    let mut inputs = Vec::new();
    for td in TRUST_DOMAINS {
        for segs in principal_paths() {
            inputs.push(uri(td, &segs));
        }
    }
    for segs in principal_paths() {
        for td in [NODE_TD, TENANT_TD] {
            let id = uri(td, &segs);
            let respelled = decorations(&id);
            for r in &respelled {
                assert!(model::core(r).is_none(), "decoration {r:?} is canonical");
            }
            inputs.extend(respelled);
        }
    }
    inputs.extend(length_edges());
    for s in &inputs {
        check(s, &p, &pods, &mut t);
    }
    report("trust domains + spellings + lengths", &t, started);

    // The documented alias, and the only one: `wimse://` is the same ID.
    for segs in principal_paths() {
        let id = uri(NODE_TD, &segs);
        let w = id.replacen("spiffe://", "wimse://", 1);
        assert_eq!(
            nucleus_lineage::CallSpiffeId::from_wimse_uri(&w)
                .unwrap()
                .as_str(),
            id
        );
    }
    // The length edges land on both sides of each bound.
    let edges = length_edges();
    assert!(model::core(&edges[0]).is_some() && model::core(&edges[1]).is_none());
    assert!(model::core(&edges[2]).is_some() && model::core(&edges[3]).is_none());
    assert_eq!(edges[2].len(), 2048);
}

/// Property 3 for paths: below a principal, a longer path holds no more, and
/// reaches nothing its ancestor or a sibling owns.
#[test]
fn a_descendant_never_holds_more() {
    let started = Instant::now();
    let (p, pods) = (policy(), universe());
    let words: Vec<String> = structural()
        .into_iter()
        .chain(["sax", "defaultx", "A"].map(String::from))
        .collect();
    let mut pairs = 0usize;
    // Every principal of depth 4 over the structural words, under both domains.
    let mut parents = Vec::new();
    for td in [NODE_TD, TENANT_TD] {
        for a in &words {
            for b in &words {
                let segs = vec!["ns".to_string(), a.clone(), "sa".to_string(), b.clone()];
                let id = uri(td, &segs);
                if model::principal(&id).is_some() {
                    parents.push(id);
                }
            }
        }
    }
    parents.extend([OPERATOR.to_string(), CI_A.to_string()]);
    for a in &parents {
        let (amask, areach) = node_authority(&p, a, &pods);
        // One hop below the bounded principal; a longer descent is a chain of hops.
        {
            for parent in [a] {
                for w in &words {
                    let b = format!("{parent}/{w}");
                    if model::principal(&b).is_none() {
                        continue;
                    }
                    let (bmask, breach) = node_authority(&p, &b, &pods);
                    pairs += 1;
                    assert_eq!(bmask & !amask, 0, "{b} holds an op {a} does not");
                    // A CI identity's scope is the pods IT created; any other
                    // descendant's scope is inside its ancestor's.
                    let own: BTreeSet<usize> = (0..pods.len())
                        .filter(|&i| pods[i].ci == Some(b.as_str()))
                        .collect();
                    let beyond: BTreeSet<usize> = breach.difference(&areach).copied().collect();
                    assert!(
                        beyond.is_subset(&own),
                        "{b} reaches {beyond:?}, which neither {a} nor it owns"
                    );
                }
            }
        }
    }
    // The CI arm, by name: a descendant reaches neither its ancestor's pods
    // nor its sibling's.
    let reach = |s: &str| node_authority(&p, s, &pods).1;
    assert_eq!(reach(CI_A), BTreeSet::from([4]));
    assert_eq!(reach(CI_AB), BTreeSet::from([5]));
    assert_eq!(reach(CI_SIB), BTreeSet::from([6]));
    // And a pod reaches itself and its direct child, never its grandchild,
    // its sibling or its parent.
    assert_eq!(
        reach(&format!("spiffe://{NODE_TD}/ns/pods/sa/{U1}")),
        BTreeSet::from([0, 1])
    );
    assert_eq!(
        reach(&format!("spiffe://{NODE_TD}/ns/pods/sa/{U3}")),
        BTreeSet::from([1, 2])
    );
    eprintln!(
        "spiffe walk [descendants]: {} principals, {pairs} ancestor/descendant pairs, {:.2?}",
        parents.len(),
        started.elapsed()
    );
    assert!(pairs > 3000);
}

/// Property 3 for lineage: a `/call/…` child is below its parent at a segment
/// boundary, names it as its parent, holds nothing the parent does not, and
/// is never an ancestor of its sibling.
#[test]
fn a_call_is_below_its_caller_and_holds_no_more() {
    let (p, pods) = (policy(), universe());
    let mut checked = 0usize;
    for segs in principal_paths() {
        let root = nucleus_lineage::CallSpiffeId::parse(uri(NODE_TD, &segs)).unwrap();
        let mut level = vec![root];
        for _ in 0..DEPTH {
            let mut next = Vec::new();
            for parent in &level {
                let kids = [
                    parent.derive_tool("bash", None).unwrap(),
                    parent.derive_tool("read", Some(b"x")).unwrap(),
                    parent.derive_llm("model", "prompt", b"y").unwrap(),
                ];
                for (i, kid) in kids.iter().enumerate() {
                    let (k, a) = (kid.as_str(), parent.as_str());
                    assert!(k.starts_with(&format!("{a}/call/")), "{k} under {a}");
                    assert_eq!(kid.parent().as_ref(), Some(parent), "{k}");
                    assert_eq!(model::lineage(k).map(|id| id.uri()), Some(k.to_string()));
                    let (km, kr) = node_authority(&p, k, &pods);
                    let (am, ar) = node_authority(&p, a, &pods);
                    assert_eq!(km & !am, 0, "{k} holds an op {a} does not");
                    assert!(kr.is_subset(&ar), "{k} reaches beyond {a}");
                    for sib in &kids[i + 1..] {
                        let s = sib.as_str();
                        assert!(
                            !s.starts_with(&format!("{k}/")) && !k.starts_with(&format!("{s}/"))
                        );
                    }
                    checked += 1;
                }
                // Depth is bounded by DEPTH; widen only the first child.
                next.push(kids[0].clone());
            }
            level = next;
        }
    }
    eprintln!("spiffe walk [lineage]: {checked} derived calls");
}

/// Property 3 for delegation: every chain of up to DEPTH child pods, over a
/// set of lattices, never widens — each certificate's effective authority is
/// at most its parent's, the root (and so the tenant) never changes, and the
/// leaf is the pod the certificate was minted for.
#[test]
fn a_delegated_child_never_widens() {
    use portcullis::PermissionLattice;
    use portcullis::certificate::{
        DEFAULT_MAX_CHAIN_DEPTH, LatticeCertificate, SinkScope, verify_certificate,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};

    let started = Instant::now();
    let key = || {
        let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap()
    };
    let budget = PermissionLattice::permissive().budget;
    let presets: Vec<PermissionLattice> = [
        PermissionLattice::permissive(),
        PermissionLattice::codegen(),
        PermissionLattice::read_only(),
    ]
    .into_iter()
    .map(|mut l| {
        l.budget = budget.clone();
        l
    })
    .collect();
    let root_key = key();
    let not_after = chrono::Utc::now() + chrono::Duration::hours(1);
    let (mut minted, mut refused, mut clamped) = (0usize, 0usize, 0usize);

    // Depth-first over every sequence of presets.
    struct Frame {
        cert: LatticeCertificate,
        holder: Ed25519KeyPair,
        depth: usize,
    }
    let mut stack = Vec::new();
    for root_perms in &presets {
        let holder = key();
        let cert = LatticeCertificate::mint_with_holder_key(
            root_perms.clone(),
            OPERATOR.to_string(),
            not_after,
            None,
            &root_key,
            &holder,
        );
        stack.push(Frame {
            cert,
            holder,
            depth: 0,
        });
    }
    while let Some(f) = stack.pop() {
        if f.depth == DEPTH {
            continue;
        }
        for (i, requested) in presets.iter().enumerate() {
            let child_key = key();
            let child = uuid::Uuid::from_u128((f.depth * 16 + i) as u128 + 1);
            let child_id = format!("spiffe://{NODE_TD}/ns/pods/sa/{child}");
            let Ok(cert) = f.cert.mint_child_with_scope_using_key(
                requested,
                child_id.clone(),
                not_after,
                "walk",
                SinkScope::unrestricted(),
                &f.holder,
                &child_key,
            ) else {
                refused += 1;
                continue;
            };
            minted += 1;
            let parent = f.cert.effective_permissions();
            let eff = cert.effective_permissions();
            assert!(
                eff.leq(parent),
                "a child widened its parent at depth {}",
                f.depth + 1
            );
            if !requested.leq(parent) {
                clamped += 1;
            }
            assert_eq!(cert.root_identity(), OPERATOR);
            assert_eq!(cert.leaf_identity(), child_id);
            assert!(model::principal(cert.leaf_identity()).is_some());
            let verified = verify_certificate(
                &cert,
                root_key.public_key().as_ref(),
                chrono::Utc::now(),
                DEFAULT_MAX_CHAIN_DEPTH,
            )
            .expect("a minted chain verifies");
            assert_eq!(verified.leaf_identity(), child_id);
            stack.push(Frame {
                cert,
                holder: child_key,
                depth: f.depth + 1,
            });
        }
    }
    eprintln!(
        "spiffe walk [delegation]: {minted} certificates minted, {refused} refused, {clamped} \
         asked for more than their parent and were narrowed, {:.2?}",
        started.elapsed()
    );
    // Non-vacuity: the walk asked for more than a parent held, and got less.
    assert!(minted > 300 && clamped > 100);
}

/// The federated principal: every `sub` over a small alphabet maps to a
/// canonical principal in the binding's trust domain and namespace, and no two
/// map to one.
#[test]
fn a_federated_sub_maps_into_its_tenant_injectively() {
    let alphabet = [
        "a", "A", "-", ".", "_", "/", "%", ":", "\u{e9}", "\0", " ", "..",
    ];
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut frontier = vec![String::new()];
    for _ in 0..3 {
        let mut next = Vec::new();
        for p in &frontier {
            for c in alphabet {
                let sub = format!("{p}{c}");
                if seen.values().any(|s| *s == sub) {
                    continue; // `.` + `.` is the token `..`: one sub, built twice
                }
                let principal = crate::federation_ingress::principal_of(TENANT_TD, "runtime", &sub)
                    .expect("short subs always map");
                let id = model::principal(&principal).expect("canonical");
                assert_eq!(id.td, TENANT_TD);
                assert_eq!(&id.segs[..3], ["ns", "runtime", "sa"]);
                assert_eq!(id.segs.len(), 4, "{sub:?} split into segments");
                if let Some(other) = seen.insert(principal.clone(), sub.clone()) {
                    panic!("{other:?} and {sub:?} are one principal, {principal}");
                }
                next.push(sub);
            }
        }
        frontier = next;
    }
    eprintln!(
        "spiffe walk [federation]: {} subs, all distinct",
        seen.len()
    );
}

/// The corpus fingerprint: a digest over every path input and the oracle's
/// verdict on it. An external walk that generates the same corpus prints the
/// same value.
#[test]
fn corpus_fingerprint() {
    // Order-independent: the sorted set of (path, core verdict).
    let mut all: Vec<(String, bool)> = paths(0, 1)
        .into_iter()
        .map(|segs| {
            let s = uri(NODE_TD, &segs);
            let ok = model::core(&s).is_some();
            (s, ok)
        })
        .collect();
    all.sort();
    let mut h = Sha256::new();
    for (s, ok) in &all {
        h.update(s.as_bytes());
        h.update([*ok as u8, 0xff]);
    }
    let accepted = all.iter().filter(|(_, ok)| *ok).count();
    let got = hex::encode(h.finalize());
    eprintln!(
        "spiffe walk [corpus]: {} paths ({accepted} canonical), fingerprint {got}",
        all.len()
    );
    assert_eq!(
        got, CORPUS_FINGERPRINT,
        "the corpus or its verdicts changed"
    );
}
