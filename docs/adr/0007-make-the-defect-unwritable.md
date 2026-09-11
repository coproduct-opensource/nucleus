# ADR 0007 — Make the defect unwritable: thirty-nine Rust mandates from the defect record

- Status: **accepted** (2026-09-11) for the mandates; **partially wired** — four entries in `clippy.toml` (C-1, C-5, H-1 ×2) plus `cargo xtask clippy-config`, the rest carry a named enforcement target and a measured baseline.
- Tracks: a full review of `coproduct-opensource/nucleus` (2,248 commits) and `coproduct-private/gatehouse` (232 commits + 62 `FINDINGS.md` rows), 2026-09-11
- Applies to: all Rust under `crates/` and `tools/`. New code from this ADR forward; existing code as each file is touched.

## Context

A review scored every fix, refactor and security commit in both repositories against
three architectures: writ matured as a plan language, a rewrite of the decision core in
writ, and a proof-oriented Rust fork. 252 defect records were read from real diffs —
103 in effectful code, 149 pure.

The architecture question is settled elsewhere. **This ADR is about the residue**, and
the residue is the largest single actionable result of the review:

> **58 of 252 records — 23% — were defects whose refusal needs no language extension,
> no verifier, no rewrite, and no fork. The type discipline already existed in stable
> Rust and was not applied.**

That number is not a consolation prize. It is larger than what the *plan language*
reaches on its own, it costs nothing to adopt, and it is available today rather than
after a research programme. Five of the strongest cases in the whole study —
named struct fields, exhaustive enums, `#[derive(Deserialize)]` plus a `for` loop,
move semantics, sealed constructors — needed nothing that was not already shipping.

The load-bearing example is `f7f9719b`. `DischargedBundle` was already `!Clone`,
`!Copy` and `#[must_use]` — every affine signal Rust offers was present — and a
one-shot authorization could still be replayed, because three signatures took it by
`&`. **No language feature was missing. The refactor was the fix, and a written rule
would have been cheaper.** That is the thesis of this ADR: where the mechanism exists
and the defect recurs anyway, what is missing is a mandate, not a type system.

This mirrors ADR 0006's finding one level down. 0006 found mechanisms built,
machine-proved, and *not wired to the enforcement path*. This ADR finds mechanisms
built into the language itself, and not reached for.

### What the review measured about this tree

Numbers below are from 2026-09-11 and are quoted rather than estimated, because the
first pass of this analysis overstated three of them by counting imports and macro
text instead of call sites:

| quantity | measured | note |
|---|---|---|
| `Command::new` sites | **133** | not 262; 64 of those were `std::process::exit` |
| `libc::` / `nix::` sites | **53** | not 91 |
| real `unsafe` blocks | **35**, in 10 files | not 71 |
| `std::env::set_var` in production | **0** | 14 sites, all `#[cfg(test)]` or comments |
| `transmute`, `Vec::leak` | **0** | the two entries this ADR wires today |

## Decision

Thirty-nine mandates in nine families. Each carries an id, a headline stated so a
static analyser could in principle decide it, the defect that motivated it with its
commit, and the tier that enforces it. Ids are stable and are cited from `clippy.toml`
and from lint sources.

Rule ids are **not** a priority order. Families are grouped by the shape of the error,
which is how the corpus clustered.

---

### Family A — Sum types that lost a case

The largest family. Two or more outcomes with different consequences share one
constructor, and the collapse is invisible because the caller cannot see what was
merged. Every member was fixed by adding an arm.

**A-1 — A `bool` may not carry a decision whose domain has three or more outcomes.**
Narrowing happens at the *signature*, where it is invisible to every caller
downstream. gatehouse `0109d29` narrowed a three-valued decision to a boolean at a function
boundary. `dc97daaa` used a `Bool` where the domain had three inhabitants, and the
else-branch of one field became the success path for a different finding entirely.
This is `CLAUDE.md`'s own `Merged | Ejected | InFlight` argument restated as a rule.
*Enforcement: review.*

**A-2 — "I could not look" is never "I looked and it was fine."**
A check that can be unable to observe its subject must not be able to return success.
`417ea1b0` — *a verifier may not succeed where it cannot check*. `b0b2d07e` hung a
"pod booted" claim off a constructor that also meant "nothing was verified". The
positive constructor should carry the evidence — `Confirmed(SeccompMode)` — so a
platform that cannot observe the mode cannot construct it.
*Enforcement: dylint (proposed `evidence_free_success`).*

**A-3 — A search returns `Result<Vec<T>, E>`. "Found nothing" and "could not search" are different constructors.**
The `grep` trap from `CLAUDE.md` in Rust clothing. `9fe86607`: two Lean sorry-bans
could pass having scanned nothing, because a clean result and a failed scan were both
encoded as no output. Compare `ci-spec` `GI002`.
*Enforcement: review.*

**A-4 — No blanket `map_err` onto a single variant.**
`15e3530f` — *an errno is not an authorization decision*. Fourteen sites in
`sandbox.rs` mapped every filesystem error to `PathDenied`, so "`audit` is a
directory" was reported as a policy denial with a 403, sending readers to inspect a
policy that had no part in it.
*Enforcement: review; a dylint on `map_err` closures that ignore the matched value is
tractable and proposed.*

**A-5 — Absence is a third value, never a pass.**
The shape that made GitHub count a *skipped* required check as passed, and that
gatehouse `F-28` records as "absence is a third value conflated with pass". Any
question of the form "did every declared thing report?" is a set difference over the
declared set, never a conjunction over what happened to arrive.
*Enforcement: dylint, on gate code under `crates/xtask` and `crates/ci-spec`.*

**A-6 — A sum type keeps its payload.**
`60c22053`: a sum type lost its payload, forcing a stringly-typed side channel that
every consumer re-parsed independently — so the parses could disagree, with no place
they could be made to agree.
*Enforcement: review.*

**A-7 — Mutually exclusive alternatives are an enum, not an untyped map.**
`079bc6c6`: a sum stored as a map let mutually exclusive alternatives co-occur and
required fields be absent — and the malformed value then passed through signing,
which is where a schema stops being a convenience.
*Enforcement: review.*

**A-8 — Split a rejection type when its halves carry different consequences.**
gatehouse `112bea6`: one `Reject` conflated "this claim is internally false" with "this claim
answers a different question", and the punitive action hung off the *union* — so a
routine plan edit or toolchain bump became a trust-destroying event that quarantined
an honest signer.
*Enforcement: review.*

---

### Family B — Defaults that grant

Every member fails **open**. An absent operand silently supplies the permissive value.

**B-1 — No `#[derive(Default)]` on a security-relevant type.**
`af52442c`: an omitted declaration silently supplied the dangerous value, because the
type had a total order with a distinguished element and the derive picked it. The
derive does not know which end of the lattice is safe. Write `Default` by hand at the
restrictive end, or do not implement it.
*Enforcement: dylint (proposed `derived_default_on_authority`), scoped to types
reachable from `PodSpec`, `Cap`, `Authority` and the lattice types.*

**B-2 — `Option<T>` may not mean "unrestricted" when `None`.**
`7348f024`: an optional configuration where absent silently meant unrestricted — "no
ceiling was set" and "no ceiling applies" became the same constructor. Make the field
total so the unconfigured state has no value. `#2440` did exactly this: *narrowing is
unconditional*.
*Enforcement: dylint, same scope as B-1.*

**B-3 — A `_ =>` arm in a policy match denies. Prefer no fallthrough at all.**
`661606a9`: a total function from an open domain (strings) to a closed one
(operations), whose fallthrough arm was chosen permissive. Close the domain — parse
to an enum at the boundary — and the arm disappears.
*Enforcement: clippy `wildcard_enum_match_arm`, once the baseline is walked down;
see §Enforcement for why it is not on today.*

**B-4 — No `unwrap_or` / `unwrap_or_default` on an operand that decides a gate or a permission.**
The Rust spelling of `[ "$V" -lt N ]` with an empty `$V`, which `ci-spec` `GI006`
exists to find. `79604ae4` replaced four vacuous ratchets whose numeric verdict rested
on an operand nothing established; `61c0b1dd` had an absent field defaulted to a
sentinel that made the predicate vacuous.
*Enforcement: dylint, scoped to gate and policy crates. **Not** a workspace clippy
deny — measured baseline 2026-09-11 is 218 `unwrap_or_default` and 584 `unwrap_or`
call sites tree-wide, the overwhelming majority benign.*

**B-5 — A declaration with no consumer is a defect.**
Two independent instances. `4401ab61`: the operator writes a constraint, the parser
accepts it, and nothing is obliged to read it — enforcement silently differs from what
was declared. `3242ebf0`: a field that must be either honoured or refused was simply
never read. This is gatehouse `F-16`'s shape inverted — there, a predicate with no
operand; here, an operand with no predicate.
Rust cannot force relevance the way a linear type can. What it can do is E-1.
*Enforcement: dylint, via E-1.*

---

### Family C — Evidence and witnesses

A value is trusted for a property it carries no evidence of. This is the family where
the codebase already had the right pattern in one place and the wrong one three
hundred lines away.

**C-1 — A type that names evidence has a private constructor.**
A witness type whose fields are public is not a witness — anyone can fabricate it.
`60c22053` measured exactly this: `GuardedAction` seals its constructor correctly and
`Authorized`, three hundred lines away in the same crate, does not.
*Enforcement: **clippy.toml, wired today** (`std::mem::transmute`), plus review for
the constructor itself. See §Enforcement for what the wired half does and does not
cover.*

**C-2 — Evidence is minted by the thing that checks, never by the caller.**
`023b7c7f`: a predicate over two values the caller supplied, called a proof —
authority derived from function arguments rather than from authenticated evidence.
`61c0b1dd` is the same shape one level up: a comparison between two values written by
the *same untrusted producer*, called verification.
*Enforcement: review.*

**C-3 — A capability is indexed by what it authorizes.**
A token proving *a* check ran is not a token proving *this* check ran. `e080c4d7`: a
read authority could pay for a sandbox write. `f8b06284`: a read bundle could
authorize a write, because the token's subject rode as an inert data field instead of
a type index, so any token substituted for any other. `portcullis-effects` already had
`CapToken<OpRead>` — the language was never the blocker.
*Enforcement: review.*

**C-4 — A one-shot right is taken by value. A `&` on a consuming parameter is the bug.**
The single most instructive record in the corpus, and the origin of this ADR.
`f7f9719b`: `DischargedBundle` was `!Clone`, `!Copy`, `#[must_use]`, and replayable,
because three methods took it by reference. Affine intent expressed with a non-affine
calling convention.
*Enforcement: dylint (proposed `authority_by_reference`) over the types in
`portcullis-effects` that carry `#[must_use]` and lack `Clone`.*

**C-5 — Capability and authority types are `!Clone`, `!Copy`, `#[must_use]`.**
Necessary and — per C-4 — not sufficient. Stated separately so the derive list is
checkable mechanically while the calling convention is checked by C-4.
*Enforcement: **clippy.toml, wired today** for the `leak` escape hatch; dylint for the
derive list.*

**C-6 — Two witnesses that must both hold need an operator that conjoins them.**
`60c22053`: two independent witnesses required together, with no combinator producing
the conjunction — so holding both was a convention at each call site rather than a
value anyone could pass.
*Enforcement: review.*

---

### Family D — Order as a type

"X must happen before Y", held by nothing but the order of statements in a function.

**D-1 — An ordering invariant is a value, not source-line adjacency.**
`5b6d0a8d` — *boot typestate: exec only from `Sealed`* — is the model, and it shipped
in stock Rust: `PhantomData` state parameters plus a private-constructor `SealedProof`
only `Boot<Sealed>::exec` can mint. `ef54df79` is the same defect unfixed: the identity
bridge started *after* the health check that depended on it.
*Enforcement: review.*

**D-2 — A safety-critical construction sequence is not replicated per call site.**
`a346ab27` routed three sync spawns through one `spawn_checked`; `f1aac68e` unified
one argv predicate across two spawn paths. The half-built object gets its own type and
the terminal method exists only on the finished one — `Command<Unhardened>` →
`Command<Hardened>`, with `spawn` on `Hardened` alone. This reaches all 133
`Command::new` sites.
*Enforcement: dylint (proposed `unhardened_spawn`), extending the existing
`nucleus-mediation-lint`.*

**D-3 — A `compile_fail` doctest is not a substitute for a type.**
Where the type already refuses the program, the refusal needs no test. `5b6d0a8d`
shipped with three `compile_fail` doctests standing in for the guarantee; a doctest can
be deleted, skipped, or fail for the wrong reason, and none of those is visible at the
call site.
*Enforcement: review.*

---

### Family E — Records and exhaustiveness

A record grows a field and the places that should have been forced to consider it were
not. `60c22053` names the remedy: **mechanism, not vigilance.**

**E-1 — No `..` in a record pattern on a delegation or policy path.**
`60c22053`: an invariant that must hold over *all* fields of a record was enforced by
naming *some* of them, so a thirteenth field would be granted to children by default.
Exhaustive destructuring makes that `E0027` — the build breaks until someone decides
what the new field means.
*Enforcement: dylint (proposed `rest_pattern_on_policy_path`).*

**E-2 — A policy enum is matched exhaustively. A new variant must break the build.**
`a17fa16f`: the isolation backend was read from an environment variable rather than
derived from the driver that enforces it. Making the posture an exhaustive function of
`DriverKind` means a new driver is a compile error before it is a mis-declared posture.
*Enforcement: clippy `wildcard_enum_match_arm`, scoped; see §Enforcement.*

**E-3 — Three or more components means named fields, never a positional tuple.**
The defect writ documents against itself. `prelude/ci.writ:83-86`: *"inserting a field
mid-tuple renumbers every accessor after it and silently reinterprets every existing
literal's remaining fields as the wrong types."* gatehouse `F-34` is that hazard firing
anyway against a second positional reader in Rust.
*Enforcement: review; clippy has no scoped equivalent.*

---

### Family F — Derive, never restate

A structural fact about a datatype — its fields, its width, its count, its encoding —
written out a second time by hand, with nothing holding the two equal.

**F-1 — Serialization is derived, never hand-written.**
gatehouse `b2ded50`: a hand-written format drifted from its datatype, and the
differential meant to catch the drift was blind to anything that never reached the
artifact. `#[derive(Serialize, Deserialize)]` makes a dropped section unwritable.
*Enforcement: review.*

**F-2 — Config is one `Deserialize` struct and a loop over the parsed collection.**
`3ba99eb9`, in its own words: *"a `for` loop over a parsed `Vec` cannot enforce only
its head, and one `Deserialize` struct cannot diverge from itself."* It replaced a
hand-rolled parser reading only the first entry of a declared list. gatehouse `F-20` is
the same file read by two independent awk programs with *different field sets* — dead
fields in one, load-bearing in the other.
*Enforcement: covered by the `CLAUDE.md` "gates are Rust, not shell" mandate; review
for new Rust parsers.*

**F-3 — A count, width or arity is never restated as a literal beside the thing it counts.**
gatehouse `F-13`: a migration count restated beside the array it counts became a merge
artifact with *no textual conflict* — two branches each appended a migration, git
merged clean, the count went to 14 and three assertions still pinned 13. `F-43` is the
same shape where the restated thing is a type's arity.
*Enforcement: review. Note this rule does **not** apply to the deliberate population
pins (`PINNED`, `CLAUSES`, `NOT_YET`, `UNCOVERED_CEILING`), which are two-directional
ratchets whose entire purpose is to require a human decision — see §Consequences.*

**F-4 — One algorithm, generic. Never N monomorphic copies.**
gatehouse `fafe910`: one algorithm forced into N copies by a non-parametric
eliminator. In writ that is a kernel limitation — `listRec` is closed-element-type, so
`allNat`, `allBytes`, `allGate`, `allEdge` and `allLink` all exist separately. In Rust
the copies simply never exist, which is worth stating precisely because it is free here
and expensive there.
*Enforcement: review.*

---

### Family G — One decider per fact

Thirty records — the second-largest class in the study. One fact written down twice,
with no term, type or gate holding the copies equal.

**G-1 — If a fact is written twice, delete one. A parity test is not a fix.**
`3f850437` states the principle against itself: a parity test *leaves two copies* and
converts the next drift into a test failure rather than an impossibility.
*Enforcement: review.*

**G-2 — Where a second copy is unavoidable, the gate lives at the declaration.**
gatehouse `ccc5c46`: a declared value well-formed locally and unusable by the external system it
was handed to, with the validator one layer away from the declaration. gatehouse `F-21`
is the two-sided version — an import digest and a build ref that must move together,
where testing the wrong side produced the wrong diagnosis and a closed PR.
*Enforcement: review; `ci/merge-group-scope-parity.sh` is the existing model.*

**G-3 — A collection carrying a uniqueness law is a keyed map, not a `Vec`.**
`1702fb12` — *"one re-run per workflow per PR" as a type, not a rule to remember*.
`Vec<RunId>` became `BTreeMap<(Pr, Workflow), Run>` and duplicates collapse on
insertion. The commit states its own dependent-type reading and then notes that a map
*is* the proof-carrying representation.
*Enforcement: review.*

---

### Family H — Ambient authority

An effect performed by any code that can name a constructor, with the policy bounding
it living as a value somewhere else that nothing forces the call site to consult.

**H-1 — No `std::env::set_var` or `std::env::remove_var`.**
`7caaa1a8`: a value intended for one scope written into ambient global state, so every
later reader in the process tree inherits authority nobody granted them.
`nucleus-guest-init` already did this migration — `src/main.rs:88` records that 28
values *used to be* `set_var`.
*Enforcement: **clippy.toml, wired.** Measured 2026-09-11: 0 production call sites.
Every remaining site is inside `#[cfg(test)]` and carries an
`#[expect(clippy::disallowed_methods, reason = "ADR 0007 H-1: test-only process-global
mutation")]`. The count is **25**, not the 27 estimated here from `grep` — two of the
matches were comments, and nine of the 25 were invisible to the root config until the
`nucleus-tool-proxy` shadow was closed. `#[expect]` rather than `#[allow]` on purpose:
when a site stops mutating the environment the expectation becomes unfulfilled and the
attribute must be deleted, so the suppression cannot outlive its reason (B-5).*

**H-2 — A client that performs an effect is constructible only from a witness.**
`57920b28` — *a pod cannot build a client for a host its own policy forbids* —
introduced an `Admitted` witness with no public constructor, mintable only by
`EgressPolicy::admit(host)`. `8ef8d45d` then made the witness the only door with the
`unpoliced_http_client` dylint. **That pairing is the template for every new effect
surface**, and it is the one place in the corpus where a lint beside the language was
the right answer rather than a workaround.
*Enforcement: dylint — `nucleus-egress-lint` exists; extend per effect surface.*

**H-3 — A single-writer resource is owned, not named by path.**
`af52442c`: a resource with exactly one writer's worth of meaning was aliased by every
pod that named its path — and a comment named a guard that did not exist. A comment
asserting an invariant nothing enforces is worse than no comment, because it stops the
next reader looking.
*Enforcement: review.*

---

### Family I — Gates that can fail

The rules that keep a check from being green for the wrong reason. These are the Rust
restatement of the shell traps enumerated in `CLAUDE.md`, plus the two that survive the
move to Rust.

**I-1 — Every gate is driven red on the real defect before it ships.**
A-19 is a row of gatehouse's assurance ledger and `UNCOVERED_CEILING = 0` lives in
gatehouse's `crates/xtask/src/gates.rs:21`; this repository's own `CLAUDE.md` already
cites both in the "gates are Rust, not shell" mandate. nucleus has no local equivalent
constant — its gate probes live in `crates/xtask/src/{allowlist_gates,law_mechanisms}.rs`
without a population ceiling, which is itself worth fixing and is out of scope here.
`f7f9719b` carries a gate whose green was indistinguishable from vacuity; gatehouse
`F-12` records the subtler failure — a probe whose subject is red either way is never
recorded as probed, and the accounting then reports a coverage gap when the fault is a
broken subject.
**This rule applies to every lint proposed in this ADR, including the two already
wired.**
*Enforcement: review today; a nucleus-side probe ceiling is the proposed follow-up.*

**I-2 — Parse to a type. A string compared to a string is not a check.**
gatehouse `e8f7582`: a value crossed a trust boundary as text, and relating it to the
number the predicate decides on needed a decoder the language did not have — so the
check was silently delegated. `str::parse` returns `Result`; there is no empty
inhabitant of `usize`. Use both.
*Enforcement: review.*

**I-3 — The error path and the allow path may not share an exit status.**
`8ec7bf72`: absence of a decision encoded identically to a permissive decision.
`74ba4c8b` is the same at a finer grain — a lock acquisition whose failure is
indistinguishable from its success at the call site, an errno-shaped result read as a
boolean.
*Enforcement: review.*

**I-4 — An ordering question is not answered by substring matching.**
`b797ec00`: an ordering question answered by substring matching, and a non-convex
admissible set approximated by a single floor. Implement `Ord`, or enumerate the set.
An approximation whose error is one-sided in the permissive direction is a permission
bug, not a precision one.
*Enforcement: review.*

---

## Enforcement

Three tiers, in descending order of preference. The tier is named on every rule above
so that "review" is on the record as a gap rather than mistaken for coverage.

| tier | mechanism | where |
|---|---|---|
| **clippy** | a workspace lint, or a `clippy.toml` entry | `clippy.toml` (new in this ADR), `[workspace.lints]` in `Cargo.toml` |
| **dylint** | a pass with UI tests | `tools/nucleus-*-lint/` — six exist today |
| **review** | no mechanical check is possible yet | stated, not hidden |

### A-19 applies to every lint in this ADR

A lint ships only once it has been driven **red on the commit its rule cites** and
green with the defect restored. A lint that has only ever passed proves nothing — the
discipline gatehouse pins as `UNCOVERED_CEILING = 0`, and which this repository's
`CLAUDE.md` already adopts by reference.

**Probe record for the two entries wired here**, run 2026-09-11 on Rust 1.96.1:

```
# RED — inject the violation
$ printf 'fn adr0007_probe(x: u32) -> i32 { unsafe { std::mem::transmute(x) } }\n' \
    >> crates/nucleus-net-probe/src/main.rs
$ cargo clippy -p nucleus-net-probe --all-targets
warning: use of a disallowed method `std::mem::transmute`
  = note: `#[warn(clippy::disallowed_methods)]` on by default

# GREEN — restore
$ git checkout crates/nucleus-net-probe/src/main.rs
$ cargo clippy -p nucleus-net-probe --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.32s
```

This also establishes, empirically, that a `clippy.toml` at the workspace root resolves
for workspace members — which the Clippy documentation does not state and which
`CARGO_MANIFEST_DIR` being the *member* directory gives reason to doubt.

**It resolves only for members that do not have their own.** Clippy reads **one**
configuration file — `CLIPPY_CONF_DIR`, else `CARGO_MANIFEST_DIR` — and the nearest
`clippy.toml` wins outright. There is no merge. A member with its own config receives
**none** of the root's entries.

`crates/nucleus-tool-proxy/clippy.toml` has existed since #1216 to hold
`disallowed-types`, and by existing it dropped the root's `disallowed-methods`. So both
entries wired above were **not enforced in the crate that holds the HTTP and MCP effect
boundary** — measured by injecting a violation there and watching the crate compile,
report the function as unused, and say nothing about `transmute`:

```
$ printf 'fn probe() { unsafe { std::env::set_var("P","1") }; }\n' \
    >> crates/nucleus-tool-proxy/src/egress.rs
$ cargo clippy -p nucleus-tool-proxy --all-targets --all-features
warning: function `probe` is never used     <- the crate IS being checked
                                            <- and disallowed_methods does NOT fire
```

This is I-1 firing against this ADR. Both entries measured **zero** occurrences
tree-wide, so a green run and a run that never asked were the same observation — the
vacuity A-2 names, in the gate that exists to prevent it. The probe above is a
*positive control*: it is the thing the §Enforcement probe should have done in the
crate it mattered most in.

The remedy is G-2 — where a second copy is unavoidable, the gate lives at the
declaration. `cargo xtask clippy-config` compares every crate-level `clippy.toml`
against the root's and REDs on any dropped entry, naming the entry to add. Adding a
root entry without restating it in a shadowing config is now a build failure rather
than a silent hole.

### Why only two entries are wired today

CI runs `cargo clippy --all-targets --all-features -- -D warnings`. A single existing
violation — in test code as much as in production — reds the merge queue. So an entry
is added only when the tree is already clean of it. Measured 2026-09-11:

| candidate | occurrences | wired |
|---|---|---|
| `std::mem::transmute` | **0** | yes |
| `std::vec::Vec::leak` | **0** | yes |
| `std::env::set_var` | 13, all `#[cfg(test)]` | yes — 13 `#[expect]` |
| `std::env::remove_var` | 12, all `#[cfg(test)]` | yes — 12 `#[expect]` |
| `unwrap_or_default` | 218 | no — dylint, scoped |
| `unwrap_or` | 584 | no — dylint, scoped |
| `#[derive(Default)]` | 177 | no — dylint, scoped |

H-1 was the next step and has landed, with the `#[expect]` at each of the 25 test sites
and both paths in `clippy.toml`. It did not stay mechanical: the shadowing defect above
was found while driving it red, which is what A-19 is for.

### What the wired half does not cover

`c05ee2af` measured module privacy being re-opened on four types at once. Three things
defeat a sealed constructor: `unsafe` field access, `transmute`, and a derived
`Deserialize`. **Only `transmute` is expressible as a `clippy.toml` entry.** The other
two need the proposed C-1 dylint, which must check the derive list as well as the
constructor. Wiring one third of a rule and calling C-1 enforced would be exactly the
error ADR 0006 is about, so it is written here instead.

## Consequences

**This ADR does not claim a majority.** 58 of 252 records is 23%. The remaining 194
needed something these mandates cannot give: a plan-level predicate, a total language,
an effect system, or nothing at all. Any claim that a style guide would have prevented
most of this project's defects is false, and the counts are recorded here so the claim
cannot be made by omission.

**They reach no effectful defect directly.** 103 of 252 records are in code that
spawns, syscalls, awaits or reads a clock. C-4 and D-2 *fence* that surface; they do
not enter it.

**No rule here addresses memory safety or undefined behaviour.** 35 real `unsafe`
blocks across 10 files, none of which appear in this corpus.

**F-3 does not apply to the ratchets.** `.kani-minimum-proofs`, `.line-ratchet.toml`,
`ci/required-checks.txt`'s `PINNED`, and gatehouse's `CLAUSES` / `NOT_YET` /
`UNCOVERED_CEILING` are restated counts by design: they are two-directional pins whose
purpose is to force a human decision when the population moves. F-3 is about a count
restated where nothing requires the restatement to be revisited. The distinction is the
*direction of the obligation*, and conflating them would delete the repository's main
anti-drift mechanism.

**Nothing detects a mandate that was never written down.** The same gap gatehouse's
`CLAUDE.md` names for the findings mandate applies here. This list catches what it
enumerates; its own population is unpinned, deliberately, until the dylint targets
above exist and a count means something.
