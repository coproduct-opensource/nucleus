# The economic layer boundary

**Economics never widens authority.**

Every economics epic in this repository (#2498–#2503) states the same governing
constraint. This page is its home, and `cargo xtask econ-boundary` is the gate
that decides the part of it a program can decide (#2514).

## The invariant

The deny-by-default capability boundary — `Kernel::decide`, `LatticeCertificate`,
`run_gate` — decides **whether** an agent may act. The economic layer —
`nucleus-econ-kernels`, `nucleus-permission-market`, `nucleus-creditworthiness`,
`nucleus-externality`, and everything built on them — decides only:

- **price** — what an already-authorised request costs;
- **collateral** — what standing or bond participation requires;
- **allocation** — which of several already-authorised requests gets a scarce slot;
- **payout, rebate, slash** — where money moves afterwards.

The single point where the two layers touch is
`cert_bridge::intersect_grant_with_certificate`, and it is a **meet**: it can
narrow what a request may do, never widen it. Bond and reputation may gate
*market participation*; they may never gate `PodSpec` or admission (#2438,
#2474). Nucleus is non-custodial: it verifies external locks and emits signed
evidence, and never holds funds.

## Why it needs a gate

The defect is the easiest one in the repository to write. A reputation score in
the admission path. A bid ceiling consulted by `levels_for`. A price that makes
`certificate_denies_endpoint` say yes. Each is a few lines, each compiles, each
reads as reasonable in review — and each turns the enforcement boundary into
something a number can move. The proofs about that boundary
(`chain_attenuates_monotone`, the IFC noninterference family) are proofs about
code that does not consult prices. The moment it does, they are about
something else.

## What the gate decides

`cargo xtask econ-boundary` runs in `Manifest Guards` and asks three questions:

1. **Do the authority crates reach an economic crate?** `nucleus-ifc-kernel`,
   `portcullis-core` and `ck-policy`, transitively, per `cargo metadata`. A
   dependency edge is the only way an import can exist, so this is the
   structural half.
2. **Do the decision functions in `run_gate.rs` name an economic type?** The
   crate as a whole legitimately depends on the market — it renders a 402 from
   a `PermissionGrant` — so the rule is per function. Each named decision
   function's body is parsed with `syn`, and a path rooted at an economic
   crate, or a `use` of one, fails. The names are pinned; a decision function
   that is renamed is reported rather than silently unguarded.
3. **Does `pod_authority.rs` name an economic type anywhere?** It is the host's
   admission path and holds the root key. No.

And it anchors the sentence above to code: `cert_bridge.rs` must still define
`intersect_grant_with_certificate`. If the meet moves, six epics are pointing
at nothing, and the gate says so.

Per A-19 the gate was driven red on a planted `nucleus_permission_market` path
inside `levels_for` before its green was trusted.

## What the gate does not decide

That the meet is a meet. A function of that name that *joined* would pass this
gate. The Kani harness `effective ≤ verified.effective()` (#2513) is the check
on that. This gate decides reachability; that one decides semantics; neither
substitutes for the other.

It also does not reach the private platform, which consumes these crates by
pinned revision. The constraint is stated for nucleus and enforced here; a
downstream that widens authority with a price has left the guarantee, and
ADR 0009 is where that line is drawn.
