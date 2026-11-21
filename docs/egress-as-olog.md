# Olog: credentialed egress (`Pa.Egress.1`), public summary

An [olog](https://arxiv.org/abs/1102.1889): objects are types read as English nouns, arrows are
functions read as "is", and the laws are diagrams that must commute.

**This is the public summary of a schema that lives in a private repository.** The full `Pa.Egress.1`
schema, with its commuting diagrams, is kept with the other ologs outside this repository. What is
here is enough to read the laws, find their falsifiers, and recompute the metric below from this
tree alone. Nothing on this page depends on the private schema to be checked.

The broker performs a pod's credentialed network calls on the host: the guest proposes a request,
and the node decides whether it is allowed, what policy operation it is, which headers go out, and
then attaches a credential the guest never sees. The laws below are the properties those decisions
must have.

---

## Objects

| object | reading | where |
|---|---|---|
| credentialed request | a call a pod asks the host to make with a credential: method, path, query, proposed headers | `crates/nucleus-node/src/broker_stream.rs` (`StreamRequest`) |
| upstream registry entry | the operator's declaration of one upstream: base URL, credential source, header policy, effect table | `crates/nucleus-node/src/upstreams.rs` (`RegistryEntry`) |
| registry projection | the part of a registry entry a pod may name and hold | `crates/nucleus-spec/src/lib.rs` (`CredentialedEgressSpec`) |
| effect table | an upstream's kind and the effects the operator declared for it | `crates/nucleus-cred-protocol/src/egress/effects.rs` (`EffectTable`) |
| declared effect | one `(method, path pattern) -> operation` row of an effect table | same file (`DeclaredEffect`) |
| egress operation | the policy operation a call is: `web_fetch`, `git_push`, `create_pr` | `crates/nucleus-cred-protocol/src/egress.rs` (`EgressOperation`) |
| refusal | a write to a forge that no declared effect classifies | same file (`Unclassified`) |
| grant push_refs | the refs a push under a grant may update | not on main (see L2) |
| pod egress entry | an upstream a pod spec requests | `CredentialedEgressSpec`, in a `PodSpec` |
| fixed header set | headers the operator fixes for an upstream, name and value | `crates/nucleus-node/src/upstreams.rs` (`fixed_headers`) |
| guest header proposal | headers the guest asks to send | `StreamRequest::headers` |

## Arrows

| arrow | reading | decided by |
|---|---|---|
| classify : request -> operation + refusal | a request is one operation, or is refused | `operation_for`, via `EffectTable::declared` |
| build : (kind, effects) -> effect table + error | a list of effects is a table only if no two can disagree | `EffectTable::from_parts` |
| project : registry entry -> registry projection | an entry's pod-visible part | the node's registry |
| admit : pod entry -> registry projection | a requested entry is granted by being equal to one | `CredentialedEgressSpec::admitted_by`, `CredentialedEgressSpec::clamp`, `PodAuthority::admit_upstreams` |
| validate : (fixed, secret) -> header policy + error | the operator's header set is one a guest could not abuse | `header_policy` |
| forward : (proposal, fixed) -> headers | the headers that go out | `forwarded_headers` |
| push-scope : push -> ref updates ⊆ push_refs | a push names only refs its grant allows | not on main |

## Laws

Every law's status today is the same: **stated; enforced by Rust tests; not proved.** The one
exception is L2, whose code is not on main. The falsifiers are tests that exist in this tree;
`cargo xtask egress-proofs` checks that each named test is still a `fn` in its file.

| law | statement | falsifiers | status |
|---|---|---|---|
| L1 | Every credentialed request maps to exactly one declared effect (one `EgressOperation`) or is refused; a push is `GitPush` whatever the operator's table says. | `a_forge_write_is_what_the_operator_declared_or_refused`, `a_push_is_classified_by_what_it_does`, `an_effect_table_is_valid_or_refused` (`crates/nucleus-cred-protocol/src/egress.rs`) | stated; enforced by Rust tests; not proved |
| L2 | A push's ref updates all lie within the grant's `push_refs`. | none on main | code not on main |
| L3 | A pod egress entry is admitted only if it equals (the whole struct) an entry of the registry projection, and, for a pod caller, an entry of the parent's admitted set. | `admission_is_whole_struct_equality` (`crates/nucleus-spec/src/credentialed_egress_fixity_tests.rs`), `a_pod_caller_is_refused_an_upstream_its_parent_lacks`, `root_and_external_callers_are_refused_what_the_registry_lacks` (`crates/nucleus-node/src/pod_authority/tests/mod.rs`) | stated; enforced by Rust tests; not proved |
| L4 | Host `fixed_headers` cannot be overridden by the guest: for every fixed name the forwarded value is the operator's. A fixed header may not be a credential, secret, framing or forwarding header. | `fixed_and_secret_headers_are_never_the_guests` (`crates/nucleus-node/src/upstreams.rs`), `a_fixed_header_reaches_the_upstream_and_a_guest_cannot_choose_it` (`crates/nucleus-node/src/broker_stream/tests/headers.rs`), `a_buffered_call_carries_the_fixed_headers_and_binds_them` (`crates/nucleus-node/src/broker_perform.rs`) | stated; enforced by Rust tests; not proved |
| L5 | An unclassified write (a body-carrying method) to a forge upstream is refused (`Unclassified`), never decided as a fetch. | `a_forge_write_is_what_the_operator_declared_or_refused` | stated; enforced by Rust tests; not proved |

**A gap in L1's falsifiers, 2026-10-31.** No test fixture's effect table *declares* the push service
(`git-receive-pack`) as some other operation. The tests show a push is `GitPush` under a table that
says nothing about it. They do not show it under a table that tries to call it a fetch. If the push
check in `operation_for` were moved after the table lookup, every L1 test would still pass. The
clause "whatever the operator's table says" is stated in the code's comments and is not yet
falsified.

## The decisions, and the metric

Eight functions make these decisions on main. They are pinned in `ci/egress-decisions.toml`:

| decision | file | laws |
|---|---|---|
| `operation_for` | `crates/nucleus-cred-protocol/src/egress.rs` | L1, L5 |
| `EffectTable::declared` | `crates/nucleus-cred-protocol/src/egress/effects.rs` | L1 |
| `EffectTable::from_parts` | `crates/nucleus-cred-protocol/src/egress/effects.rs` | L1 |
| `CredentialedEgressSpec::admitted_by` | `crates/nucleus-spec/src/lib.rs` | L3 |
| `CredentialedEgressSpec::clamp` | `crates/nucleus-spec/src/lib.rs` | L3 |
| `PodAuthority::admit_upstreams` | `crates/nucleus-node/src/pod_authority.rs` | L3 |
| `header_policy` | `crates/nucleus-node/src/upstreams.rs` | L4 |
| `forwarded_headers` | `crates/nucleus-node/src/broker_stream.rs` | L4 |

`cargo xtask egress-proofs` prints `{"decisions": N, "proved": M, "pct": P}`, with
`P = floor(100 * M / N)`. On this tree it prints `{"decisions":8,"proved":0,"pct":0}`.

A decision counts as proved only when, for **every** law it cites, an obligation names all of these
and each one holds:

1. a tracked Lean proof file that declares the named `theorem` once, and declares no `axiom`;
2. the theorem's signature, whitespace-normalised, equal to the `statement` pinned in the TOML;
3. a pinned statement that mentions the extracted definition (`lean_def`);
4. that definition, `def <lean_def>`, in a tracked Aeneas `generated/**/Funs.lean`;
5. a proof body (up to the next top-level declaration, comments removed) with no `sorry`, `admit`
   or `native_decide`, and a theorem that is not vacuous by the exemplar scoreboard's own
   `vacuous_lean` regex (`:= by trivial`, `: True :=`);
6. a tracked Rust parity test file that declares the named test and mentions the production fn.

An obligation that is present but fails any of these makes the command exit non-zero, naming the
obligation. It is never counted quietly as "unproved". A decision whose function no longer exists
is an error, not an omission. Each law must be cited by some decision, or carry the status
"code not on main". `--check` holds the count to `ci/egress-proofs.json` in both directions, so a
rise and a fall are each an edit in the change that causes it. The exemplar scoreboard also carries
the count, as `egress_proved` (may not fall) and `egress_decisions_GUARD` (may not fall). Without
the guard, the share could be raised by deleting a decision that was never proved.

**What the metric does not check.** It is static: it does not run `lake build` or `#print axioms`,
which stay the job of the Aeneas workflows that build these proofs. "States the law" is checked as
exact equality with a signature that review pinned. Whether that signature says what the law's
prose says is decided by human review. The end of a proof body is found by a textual rule, not by
Lean's parser.

## Why this exists: three defects, 2026-10-31

Each of these was a decision that two parts of the system made differently. A Lean theorem about
the extracted function is the one statement both sides would have had to agree with.

1. **A push was classified by its URL path, while opening a pull request needed a matching declared
   effect.** Two different rules decided "which operation is this call?". That is why L1 is stated
   as one map from a request to one declared effect or a refusal, with the push rule applied before
   the table.
2. **A pod egress entry must equal the registry projection field for field.** An entry that
   differs from the projection in any one field is refused. A requester that builds its entry
   anywhere other than from that projection is refused for a difference it cannot see. That is
   L3: admission is whole-struct equality, never a match on a hand-picked set of fields.
3. **REST calls carried no `User-Agent` until host `fixed_headers` existed** (#3213). The header
   had no operator-owned source. That is L4: the operator fixes such a header, and the guest can
   neither drop it nor choose its value.
