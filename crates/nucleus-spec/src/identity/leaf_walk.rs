//! A4 of the command walk (`docs/design/command-walk.md`): identity is
//! invariant under OUT and sensitive to IN, stated at the LEAF.
//!
//! `program_digest`'s exhaustive destructure makes every top-level field declare
//! a side at compile time. It cannot see inside a field it keeps whole:
//! `workload`, `network`, `resources`, `credentialed_egress`, the policy lattice.
//! A leaf in one of those that serde drops — a `skip`, a `skip_serializing_if`
//! that fires on a real value, a projection that forgets a sub-field — leaves the
//! digest unchanged when that leaf changes, and nothing fails. The validity
//! window inside an inline lattice was exactly that kind of leaf, in the other
//! direction (#2900): IN by field, OUT by meaning.
//!
//! So this walks every leaf of a real, fully populated spec, changes exactly
//! one, and asserts the digest moves if and only if the leaf is IN.
//!
//! # What is derived and what is written down
//!
//! The leaves are DERIVED: the serialized spec itself is walked, so a new field
//! enters the walk the moment it serializes. What is written down is only the
//! short OUT list below, the same classification `program_digest` argues field
//! by field. That is a second statement of the rule, deliberately — A4 exists to
//! catch the implementation disagreeing with it (ADR 0007 G names this as a
//! parity test and its cost: a disagreement becomes a test failure, not an
//! impossibility).

use std::collections::BTreeSet;

use serde_json::Value;

use super::program_digest;
use crate::PodSpec;

/// Leaves outside the program identity, as JSON-pointer prefixes. Everything
/// else is IN. Each line restates the argument made in `program_digest`.
const OUT: &[&str] = &[
    // An annotation, and a per-run authority binding.
    "/metadata/name",
    "/metadata/task_grant_id",
    // Host transport, placement, audit routing, and what the pod is GIVEN.
    "/spec/vsock",
    "/spec/cgroup",
    "/spec/audit_sink",
    "/spec/credentials",
    // Image locations: the digests are the identity.
    "/spec/image/kernel_path",
    "/spec/image/rootfs_path",
    "/spec/image/scratch_path",
    "/spec/image/data_path",
    // An inline lattice's label and provenance, and its validity window —
    // `program_checksum` leaves out when a policy may run, never what it permits.
    "/spec/policy/lattice/id",
    "/spec/policy/lattice/description",
    "/spec/policy/lattice/derived_from",
    "/spec/policy/lattice/created_at",
    "/spec/policy/lattice/created_by",
    "/spec/policy/lattice/time",
];

/// Leaves the walk cannot change into another VALID spec, so they are not
/// evidence either way. Named, not tolerated: a leaf that newly lands here is a
/// failure until someone decides it belongs.
const UNPERTURBABLE: &[&str] = &[
    // Single-variant enums: there is no other valid value.
    "/apiVersion",
    "/kind",
    "/spec/resources/huge_pages",
    // Internally tagged enums: switching the tag alone always leaves the other
    // variant's fields wrong. The fields of the variant in use are walked.
    "/spec/policy/type",
    // Forced on by deserialization: an inline spec cannot turn the uninhabitable
    // constraint off, so there is no second value to try. Worth knowing in itself.
    "/spec/policy/lattice/uninhabitable_constraint",
];

/// Maps whose KEYS are data, so renaming a key is a perturbation.
const MAPS: &[&str] = &[
    "/metadata/labels",
    "/spec/workload/env",
    "/spec/workload/artifacts",
    "/spec/credentials/env",
];

const D: [&str; 4] = [
    "sha-256:1111111111111111111111111111111111111111111111111111111111111111",
    "sha-256:2222222222222222222222222222222222222222222222222222222222222222",
    "sha-256:3333333333333333333333333333333333333333333333333333333333333333",
    "sha-256:4444444444444444444444444444444444444444444444444444444444444444",
];

/// Every optional field set, so every leaf exists to be changed.
fn maximal(policy: &str) -> PodSpec {
    let json = format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod",
          "metadata":{{"name":"walk","namespace":"ns","labels":{{"team":"a","tier":"b"}},
                      "task_grant_id":"grant-1"}},
          "spec":{{
            "work_dir":"/work","timeout_seconds":60,
            "policy":{policy},
            "budget_model":{{"base_cost_usd":0.5,"cost_per_second_usd":0.25}},
            "resources":{{"cpu_cores":2,"memory_mib":512,"huge_pages":"2M"}},
            "network":{{"allow":["10.0.0.0/8:443"],"deny":["10.1.0.0/16"],
                       "dns_allow":["example.com"],"url_allow":["https://example.com/a"],
                       "mime_allow":["text/plain"],"max_response_bytes":4096}},
            "image":{{"kernel_path":"/k","rootfs_path":"/r","boot_args":"console=ttyS0",
                     "read_only":true,"scratch_path":"/s","data_path":"/d",
                     "kernel_digest":"{d0}","rootfs_digest":"{d1}",
                     "scratch_digest":"{d2}","data_digest":"{d3}"}},
            "credentialed_egress":[{{"name":"model-api","upstream":"https://upstream.invalid/v1",
                                    "credential_env":"LLM_API_TOKEN","header":"authorization",
                                    "value_prefix":"Bearer "}}],
            "workload":{{"command":"/bin/run","args":["--fast","x"],"env":{{"MODE":"a"}},
                        "artifacts":{{"out":"target/out"}},"uid":1000}},
            "vsock":{{"guest_cid":3,"port":5005}},
            "seccomp":{{"mode":"custom","filter_path":"/f"}},
            "cgroup":{{"path":"/sys/fs/cgroup/p","settings":[{{"file":"cpu.max","value":"1"}}]}},
            "audit_sink":{{"s3_bucket":"b","s3_prefix":"p","s3_region":"r","s3_endpoint":"e"}},
            "credentials":{{"env":{{"LLM_API_TOKEN":"test-token-123"}}}}
          }}}}"#,
        d0 = D[0],
        d1 = D[1],
        d2 = D[2],
        d3 = D[3],
    );
    serde_json::from_str(&json).expect("the maximal spec parses")
}

fn is_out(pointer: &str) -> bool {
    OUT.iter()
        .any(|p| pointer == *p || pointer.starts_with(&format!("{p}/")))
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Every string leaf in the document: the pool a string leaf may be swapped to,
/// so an enum-valued leaf finds another valid variant without a list of them.
fn string_pool(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            out.insert(s.clone());
        }
        Value::Array(a) => a.iter().for_each(|x| string_pool(x, out)),
        Value::Object(o) => {
            // Keys too: operation names are keys under `capabilities` and values
            // under `obligations`, so an empty approvals list finds a real one.
            out.extend(o.keys().cloned());
            o.values().for_each(|x| string_pool(x, out));
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// A leaf and the candidate replacements for it, tried in order.
struct Leaf {
    pointer: String,
    candidates: Vec<Candidate>,
}

#[derive(Clone)]
enum Candidate {
    Value(Value),
    /// Rename a map key: pointer is the map, `from` the key.
    RenameKey {
        from: String,
        to: String,
    },
}

fn leaves(v: &Value, pointer: &str, pool: &BTreeSet<String>, out: &mut Vec<Leaf>) {
    match v {
        Value::Null => out.push(Leaf {
            pointer: pointer.to_string(),
            candidates: Vec::new(),
        }),
        Value::Bool(b) => out.push(Leaf {
            pointer: pointer.to_string(),
            candidates: vec![Candidate::Value(Value::Bool(!b))],
        }),
        Value::Number(n) => {
            let mut c = Vec::new();
            if let Some(u) = n.as_u64() {
                c.push(Candidate::Value(Value::from(u + 1)));
                if u > 0 {
                    c.push(Candidate::Value(Value::from(u - 1)));
                }
            }
            if let Some(f) = n.as_f64() {
                c.push(Candidate::Value(Value::from(f * 2.0 + 1.0)));
            }
            out.push(Leaf {
                pointer: pointer.to_string(),
                candidates: c,
            });
        }
        Value::String(s) => {
            let mut c = Vec::new();
            // Change the last character within its class first, so a string with
            // a format — a digest, a UUID, a number in a string — stays valid.
            let mut chars: Vec<char> = s.chars().collect();
            if let Some(last) = chars.last_mut() {
                *last = match *last {
                    '0'..='8' | 'a'..='e' | 'A'..='E' => char::from(*last as u8 + 1),
                    '9' => '0',
                    'f' => 'a',
                    'F' => 'A',
                    other => other,
                };
                let flipped: String = chars.into_iter().collect();
                if &flipped != s {
                    c.push(Candidate::Value(Value::from(flipped)));
                }
            }
            c.push(Candidate::Value(Value::from(format!("{s}x"))));
            c.extend(
                pool.iter()
                    .filter(|p| *p != s)
                    .map(|p| Candidate::Value(Value::from(p.clone()))),
            );
            out.push(Leaf {
                pointer: pointer.to_string(),
                candidates: c,
            });
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                leaves(x, &format!("{pointer}/{i}"), pool, out);
            }
            // An empty list is a leaf: one element from the pool is a different list.
            if a.is_empty() {
                out.push(Leaf {
                    pointer: pointer.to_string(),
                    candidates: pool
                        .iter()
                        .map(|p| Candidate::Value(Value::Array(vec![Value::from(p.clone())])))
                        .collect(),
                });
            }
            // The length is a leaf too. One fewer element is a different list even
            // when the type is a set, where one more copy would be deduplicated.
            if let Some(last) = a.last() {
                let shorter = a[..a.len() - 1].to_vec();
                let mut longer = a.clone();
                longer.push(last.clone());
                out.push(Leaf {
                    pointer: pointer.to_string(),
                    candidates: vec![
                        Candidate::Value(Value::Array(shorter)),
                        Candidate::Value(Value::Array(longer)),
                    ],
                });
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                leaves(x, &format!("{pointer}/{}", escape(k)), pool, out);
            }
            // An empty list of structured elements (`allowed_rules`) cannot be
            // filled from a pool of strings. A sibling list in the same object
            // (`blocked_rules`) holds elements of the shape it takes.
            for (k, x) in o {
                if x.as_array().is_some_and(Vec::is_empty) {
                    let siblings: Vec<Candidate> = o
                        .iter()
                        .filter(|(k2, _)| *k2 != k)
                        .filter_map(|(_, v2)| v2.as_array()?.first().cloned())
                        // Also a TWEAKED copy: an allowed rule identical to a
                        // blocked one is normalized away, which is policy, not a
                        // reason to give up on the leaf.
                        .flat_map(|e| [tweak_first_string(&e), e])
                        .map(|e| Candidate::Value(Value::Array(vec![e])))
                        .collect();
                    if !siblings.is_empty() {
                        out.push(Leaf {
                            pointer: format!("{pointer}/{}", escape(k)),
                            candidates: siblings,
                        });
                    }
                }
            }
            if MAPS.contains(&pointer)
                && let Some(k) = o.keys().next()
            {
                out.push(Leaf {
                    pointer: pointer.to_string(),
                    candidates: vec![Candidate::RenameKey {
                        from: k.clone(),
                        to: format!("{k}_renamed"),
                    }],
                });
            }
        }
    }
}

/// `v` with its first string leaf (depth-first) suffixed, so it keeps its shape
/// and is no longer equal to the element it was copied from.
fn tweak_first_string(v: &Value) -> Value {
    fn go(v: &mut Value) -> bool {
        match v {
            Value::String(s) => {
                s.push('x');
                true
            }
            Value::Array(a) => a.iter_mut().any(go),
            Value::Object(o) => o.values_mut().any(go),
            Value::Null | Value::Bool(_) | Value::Number(_) => false,
        }
    }
    let mut out = v.clone();
    go(&mut out);
    out
}

enum Outcome {
    /// Changed, and the digest moved (`true`) or did not.
    Perturbed { moved: bool },
    /// No candidate produced a valid spec that differs from the base.
    Unperturbable,
}

fn try_leaf(base: &Value, base_digest: &str, leaf: &Leaf) -> Outcome {
    let mut candidates: Vec<Candidate> = leaf.candidates.clone();
    // Variants learned from the deserializer's own refusal, appended once: the
    // valid values of an enum leaf come from the type, not from a list kept here.
    let mut learned_from_error = false;
    let mut next = 0;
    while let Some(cand) = candidates.get(next).cloned() {
        next += 1;
        let mut doc = base.clone();
        let Some(slot) = doc.pointer_mut(&leaf.pointer) else {
            continue;
        };
        match &cand {
            Candidate::Value(v) => *slot = v.clone(),
            Candidate::RenameKey { from, to } => {
                let Some(map) = slot.as_object_mut() else {
                    continue;
                };
                let Some(val) = map.remove(from) else {
                    continue;
                };
                map.insert(to.clone(), val);
            }
        }
        let spec = match serde_json::from_value::<PodSpec>(doc) {
            Ok(spec) => spec,
            Err(e) => {
                let msg = e.to_string();
                if !learned_from_error && msg.contains("unknown variant") {
                    learned_from_error = true;
                    let current = base.pointer(&leaf.pointer);
                    candidates.extend(
                        msg.split('`')
                            .skip(3)
                            .step_by(2)
                            .map(|v| Value::from(v.to_string()))
                            .filter(|v| Some(v) != current)
                            .map(Candidate::Value),
                    );
                }
                continue;
            }
        };
        // A change the parser normalizes away is no change at all.
        let reserialized = serde_json::to_value(&spec).expect("a parsed spec serializes");
        if &reserialized == base {
            continue;
        }
        let Ok(digest) = program_digest(&spec) else {
            continue;
        };
        return Outcome::Perturbed {
            moved: digest != base_digest,
        };
    }
    Outcome::Unperturbable
}

/// The result of walking one base spec.
#[derive(Default)]
struct Report {
    perturbed: BTreeSet<String>,
    unperturbable: BTreeSet<String>,
    nulls: BTreeSet<String>,
    /// IN leaves the digest ignored — the dangerous direction.
    in_but_ignored: Vec<String>,
    /// OUT leaves that moved the digest.
    out_but_counted: Vec<String>,
}

fn walk(spec: &PodSpec) -> Report {
    let base = serde_json::to_value(spec).expect("serializes");
    let base_digest = program_digest(spec).expect("the maximal spec is pinned");
    let mut pool = BTreeSet::new();
    string_pool(&base, &mut pool);
    let mut all = Vec::new();
    leaves(&base, "", &pool, &mut all);

    let mut r = Report::default();
    for leaf in &all {
        if leaf.candidates.is_empty() {
            r.nulls.insert(leaf.pointer.clone());
            continue;
        }
        match try_leaf(&base, &base_digest, leaf) {
            Outcome::Unperturbable => {
                r.unperturbable.insert(leaf.pointer.clone());
            }
            Outcome::Perturbed { moved } => {
                r.perturbed.insert(leaf.pointer.clone());
                match (is_out(&leaf.pointer), moved) {
                    (false, false) => r.in_but_ignored.push(leaf.pointer.clone()),
                    (true, true) => r.out_but_counted.push(leaf.pointer.clone()),
                    (false, true) | (true, false) => {}
                }
            }
        }
    }
    // One pointer can carry several candidate sets (an empty list: from the
    // string pool, and from a sibling list). Perturbed by any is perturbed.
    let perturbed = r.perturbed.clone();
    r.unperturbable.retain(|p| !perturbed.contains(p));
    r
}

fn assert_clean(label: &str, r: &Report, required_prefixes: &[&str]) {
    // Non-vacuity first: every field the spec has must have been perturbed
    // somewhere beneath it, or the walk proved nothing about it.
    let untouched: Vec<&&str> = required_prefixes
        .iter()
        .filter(|p| {
            !r.perturbed
                .iter()
                .any(|q| q == **p || q.starts_with(&format!("{p}/")))
        })
        .collect();
    assert!(
        untouched.is_empty(),
        "{label}: no leaf perturbed under {untouched:?}"
    );
    assert!(
        r.nulls.is_empty(),
        "{label}: unpopulated leaves {:?}",
        r.nulls
    );
    // And the other direction: an allowlisted leaf the walk DID change is a stale
    // entry, which would otherwise excuse a real regression later.
    let stale: Vec<&&str> = UNPERTURBABLE
        .iter()
        .filter(|p| r.perturbed.contains(**p))
        .collect();
    assert!(
        stale.is_empty(),
        "{label}: allowlisted as unperturbable but perturbed: {stale:?}"
    );
    let unexpected: Vec<&String> = r
        .unperturbable
        .iter()
        .filter(|p| !UNPERTURBABLE.contains(&p.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "{label}: leaves the walk could not change: {unexpected:?}"
    );
    assert!(
        r.in_but_ignored.is_empty() && r.out_but_counted.is_empty(),
        "{label}: IN leaves the digest ignores: {:?}; OUT leaves it counts: {:?}",
        r.in_but_ignored,
        r.out_but_counted
    );
}

/// Every field of the spec, named so a new one stops this compiling until the
/// walk's base spec populates it.
fn every_field() -> Vec<&'static str> {
    let PodSpec {
        api_version: _,
        kind: _,
        metadata:
            crate::Metadata {
                name: _,
                namespace: _,
                labels: _,
                task_grant_id: _,
            },
        spec:
            crate::PodSpecInner {
                work_dir: _,
                timeout_seconds: _,
                policy: _,
                budget_model: _,
                resources: _,
                network: _,
                image: _,
                credentialed_egress: _,
                workload: _,
                vsock: _,
                seccomp: _,
                cgroup: _,
                audit_sink: _,
                credentials: _,
            },
    } = maximal(r#"{"type":"profile","name":"codegen"}"#);
    vec![
        "/metadata/name",
        "/metadata/namespace",
        "/metadata/labels",
        "/metadata/task_grant_id",
        "/spec/work_dir",
        "/spec/timeout_seconds",
        "/spec/policy",
        "/spec/budget_model",
        "/spec/resources",
        "/spec/network",
        "/spec/image",
        "/spec/credentialed_egress",
        "/spec/workload",
        "/spec/vsock",
        "/spec/seccomp",
        "/spec/cgroup",
        "/spec/audit_sink",
        "/spec/credentials",
    ]
}

#[test]
fn every_leaf_of_a_profile_spec_is_classified_by_the_digest() {
    let spec = maximal(r#"{"type":"profile","name":"codegen"}"#);
    let r = walk(&spec);
    assert_clean("profile policy", &r, &every_field());
}

#[test]
fn every_leaf_of_an_inline_lattice_is_classified_by_the_digest() {
    let profile = maximal(r#"{"type":"profile","name":"codegen"}"#);
    let mut lattice = profile.spec.resolve_policy().expect("codegen resolves");
    // Absent by default, and skipped when absent: set it so its leaves exist.
    lattice.minimum_isolation = Some(portcullis::IsolationLattice::default());
    lattice.derived_from = Some(lattice.id);
    lattice.paths.work_dir = Some("/work".into());
    let policy = serde_json::to_string(&crate::PolicySpec::Inline {
        lattice: Box::new(lattice),
    })
    .expect("serializes");
    let spec = maximal(&policy);
    let r = walk(&spec);
    let mut required = every_field();
    required.extend([
        "/spec/policy/lattice/capabilities",
        "/spec/policy/lattice/obligations",
        "/spec/policy/lattice/paths",
        "/spec/policy/lattice/budget",
        "/spec/policy/lattice/commands",
        "/spec/policy/lattice/time",
        "/spec/policy/lattice/minimum_isolation",
    ]);
    assert_clean("inline lattice", &r, &required);
}
