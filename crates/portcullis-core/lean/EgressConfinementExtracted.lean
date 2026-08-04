/-
  Egress confinement — proven OVER the Aeneas-EXTRACTED matcher.

  Chain, identical to the mediation theorem's:

      crates/nucleus-ifc-kernel/src/extracted/egress.rs           (real Rust)
        --charon (scoped, --start-from)-->  nucleus_ifc_kernel.llbc
        --aeneas -backend lean -split-files-->
          generated-egress/PortcullisCoreEgress/{Types,Funs}.lean
        --(this file)-->  confinement theorems over THOSE generated defs.

  Aeneas reported 0 opaque functions for this slice, so nothing on the critical
  path is an unspecified axiom.

  # Why this property, and why here

  Complete mediation on the effect layer bounds what an agent may ASK for. It
  does not bound what a shell does once running: one (RunBash, BashExec)
  authority buys arbitrary syscalls in the guest, and `bash -c 'curl … | sh'`
  never passes through NetEffect::fetch. For shell effects the enforcement
  boundary is the network policy. So this is the leg that has to hold for
  "a jailbreak cannot exceed its authority" to mean anything — the defence
  cannot be preventing the jailbreak.

  # What is proven

  * `in_cidr_never_fails`, `rule_matches_never_fails`, `rule_admits_never_fails`
      — totality. The generated defs live in Aeneas's `Result` monad; without
      these, every theorem below would be vacuous on a `fail` branch.
  * `rule_admits_implies_allow`      — a DENY rule NEVER admits, however well it
      matches. Collapsing match and admit would turn every deny entry into an
      allow entry.
  * `rule_admits_implies_matches`    — admission requires an actual match, so no
      packet is admitted by a rule that does not cover it.
  * `verdict_default_is_drop`        — the empty ruleset drops. This is the
      `-P OUTPUT DROP` baseline `apply_default_deny` sets.
  * `unmatched_is_dropped`           — THE CONFINEMENT THEOREM. If no rule in the
      list admits a destination, the verdict is Drop. Contrapositive: passage
      implies some rule explicitly granted it.
  * `deny_before_allow_wins`         — a Deny rule earlier in the list beats any
      later Allow, which is what `net.rs`'s append order buys under
      first-match-wins.
  * `zero_prefix_admits_everything`  — `0.0.0.0/0` admits every destination.
      Stated as a theorem rather than a footnote because `parse_rules` accepts
      whatever CIDR a PodSpec supplies, so `allow: ["0.0.0.0/0"]` is a nominal
      network policy that permits unrestricted egress. The proof says the
      matcher is behaving correctly; the hazard is that nothing REJECTS such a
      policy.

  # The honest boundary

  `verdict` below is written in Lean, NOT extracted. Every function in
  `extracted/` is scalar-only by design, because Aeneas emits derived
  comparisons and most collection operations as opaque axioms. So the fold over
  a rule list is stated here and the per-rule matcher is extracted — the same
  split the verified-iptables work (Diekmann et al.) uses: rule-list semantics
  in the prover, matchers underneath.

  Obligations that therefore sit OUTSIDE this file:

  1. That `verdict`'s order is the order `nucleus_node::net` actually appends
     rules in. DISCHARGED, by construction plus tests rather than by proof:
     `net::egress_chain` now returns the chain as an ordered VALUE and
     `apply_host_policy` applies exactly that list in exactly that order, in one
     pass. Before that refactor the ordering lived in two filtered loops of
     subprocess calls and there was nothing for this fold to correspond TO.
     `deny_precedes_allow_in_the_chain` and `a_specific_deny_beats_a_broader_allow`
     pin it; reversing the two `extend`s fails exactly those two tests.
     `tests_main.rs` also mirrors `verdict` below against the same extracted
     matcher, so only the fold is restated, never the matching.
  2. That iptables implements these semantics, and that the rules are applied at
     all. NOT discharged. Diekmann et al. needed a whole paper for the first
     half, and even they approximate unknown match expressions.
  3. That the chain is inside this model at all. `net::model_chain` returns
     `None` for an IPv6 rule rather than converting lossily, so "not covered" is
     never silently reported as "covered and fine". The baseline rules
     `apply_default_deny` installs (loopback, and conntrack ESTABLISHED/RELATED)
     are likewise outside `Rule` — it has no interface or ctstate field — so
     this fold models the POLICY segment for a NEW connection to an external
     destination, which is the case exfiltration needs.

  This also says nothing about DNS-tunnelled egress: a destination on the
  allowlist can still carry exfiltrated data, and queries to an allowed resolver
  are a documented channel. Confinement is about WHERE packets may go, not what
  they carry.
-/

import PortcullisCoreEgress.Types
import PortcullisCoreEgress.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

namespace EgressConfinement

open nucleus_ifc_kernel

abbrev Rule := extracted.egress.Rule
abbrev Dest := extracted.egress.Dest

/-! ## Totality

The generated defs return `Result Bool`. Each theorem below is stated against a
concrete `ok` value, so it would be vacuously true if the function could `fail`.
These three rule that out. -/

/-- The mask table returns in every arm — including the unreachable `_`. -/
theorem netmask_never_fails (p : Std.U8) :
    ∃ m : Std.U32, extracted.egress.netmask p = ok m := by
  unfold extracted.egress.netmask
  split <;> exact ⟨_, rfl⟩

theorem in_cidr_never_fails (net : Std.U32) (p : Std.U8) (addr : Std.U32) :
    ∃ b : Bool, extracted.egress.in_cidr net p addr = ok b := by
  unfold extracted.egress.in_cidr
  obtain ⟨m, hm⟩ := netmask_never_fails p
  rw [hm]
  simp only [bind_tc_ok, lift]
  exact ⟨_, rfl⟩

theorem rule_matches_never_fails (r : Rule) (d : Dest) :
    ∃ b : Bool, extracted.egress.rule_matches r d = ok b := by
  unfold extracted.egress.rule_matches
  obtain ⟨c, hc⟩ := in_cidr_never_fails r.net r.«prefix» d.addr
  rw [hc]
  cases c with
  | false => exact ⟨false, rfl⟩
  | true =>
      cases hp : r.port_specific with
      | false => exact ⟨true, rfl⟩
      | true  => exact ⟨_, rfl⟩

theorem rule_admits_never_fails (r : Rule) (d : Dest) :
    ∃ b : Bool, extracted.egress.rule_admits r d = ok b := by
  unfold extracted.egress.rule_admits
  obtain ⟨m, hm⟩ := rule_matches_never_fails r d
  rw [hm]
  cases m with
  | false => exact ⟨false, rfl⟩
  | true  => exact ⟨_, rfl⟩

/-! ## The matcher discriminates correctly -/

/-- A DENY rule never admits, however well it matches.

    This is the property that keeps a deny entry from behaving as an allow
    entry. It is separate from `rule_matches` precisely so that "matches" cannot
    be misread as "passes". -/
theorem rule_admits_implies_allow (r : Rule) (d : Dest) :
    extracted.egress.rule_admits r d = ok true → r.allow = true := by
  unfold extracted.egress.rule_admits
  obtain ⟨m, hm⟩ := rule_matches_never_fails r d
  rw [hm]
  cases m with
  | false => intro h; simp at h
  | true  => intro h; simpa using h

/-- Admission requires the rule to actually cover the destination. -/
theorem rule_admits_implies_matches (r : Rule) (d : Dest) :
    extracted.egress.rule_admits r d = ok true →
    extracted.egress.rule_matches r d = ok true := by
  intro h
  unfold extracted.egress.rule_admits at h
  obtain ⟨m, hm⟩ := rule_matches_never_fails r d
  rw [hm] at h
  cases m with
  | false => simp at h
  | true  => exact hm

/-- `0.0.0.0/0` matches every address.

    The matcher is correct; the hazard is upstream. `parse_rules` in
    `nucleus_node::net` accepts whatever CIDR a PodSpec supplies, so a policy of
    `allow: ["0.0.0.0/0"]` is a nominal network policy under which this theorem
    says every destination is admitted. Nothing rejects such a policy today. -/
theorem zero_prefix_matches_everything (net addr : Std.U32) :
    extracted.egress.in_cidr net 0#u8 addr = ok true := by
  unfold extracted.egress.in_cidr
  have h0 : extracted.egress.netmask 0#u8 = ok 0#u32 := rfl
  rw [h0]
  simp only [bind_tc_ok, lift]
  simp

/-! ## Rule-list semantics

First match wins, and an unmatched packet falls through to the chain policy,
which `apply_default_deny` sets to DROP. Written here rather than extracted —
see the header for why, and for the correspondence obligation that creates. -/

/-- What the filter does with a packet. -/
inductive Verdict where
  | accept : Verdict
  | drop   : Verdict
  deriving DecidableEq, Repr

/-- First-match-wins evaluation against a chain whose policy is DROP. -/
def verdict : List Rule → Dest → Verdict
  | [], _ => Verdict.drop
  | r :: rest, d =>
      match extracted.egress.rule_matches r d with
      | ok true  => if r.allow then Verdict.accept else Verdict.drop
      | _        => verdict rest d

/-- The baseline: no rules means everything is dropped. -/
@[simp] theorem verdict_default_is_drop (d : Dest) :
    verdict [] d = Verdict.drop := rfl

/-- **The confinement theorem.**

    If no rule in the chain admits `d`, the packet is dropped.

    Contrapositive — the form that matters operationally: if a packet gets out,
    some rule in the chain explicitly granted it passage. There is no path to
    `accept` that is not named by a rule. -/
theorem unmatched_is_dropped (rules : List Rule) (d : Dest)
    (h : ∀ r ∈ rules, extracted.egress.rule_admits r d ≠ ok true) :
    verdict rules d = Verdict.drop := by
  induction rules with
  | nil => rfl
  | cons r rest ih =>
      unfold verdict
      have hr : extracted.egress.rule_admits r d ≠ ok true := h r (by simp)
      obtain ⟨m, hm⟩ := rule_matches_never_fails r d
      rw [hm]
      cases m with
      | false => simpa using ih (fun x hx => h x (by simp [hx]))
      | true =>
          simp only []
          have : r.allow = false := by
            by_contra hne
            have hallow : r.allow = true := by
              cases hv : r.allow with
              | false => exact absurd hv hne
              | true  => rfl
            apply hr
            unfold extracted.egress.rule_admits
            rw [hm]
            simp [hallow]
          simp [this]

/-- A Deny rule earlier in the chain beats any later Allow.

    This is what `net.rs` buys by appending every Deny before every Allow into a
    first-match-wins chain. Without the ordering, an `allow: 10.0.0.0/8` would
    silently re-open a `deny: 10.0.0.7/32`. -/
theorem deny_before_allow_wins (deny : Rule) (rest : List Rule) (d : Dest)
    (hmatch : extracted.egress.rule_matches deny d = ok true)
    (hdeny : deny.allow = false) :
    verdict (deny :: rest) d = Verdict.drop := by
  unfold verdict
  rw [hmatch]
  simp [hdeny]

/-- Passage is always attributable: an `accept` verdict names a rule that
    admitted the destination. The audit-facing reading of confinement. -/
theorem accept_implies_a_granting_rule (rules : List Rule) (d : Dest)
    (h : verdict rules d = Verdict.accept) :
    ∃ r ∈ rules, extracted.egress.rule_admits r d = ok true := by
  by_contra hcon
  have hall : ∀ r ∈ rules, extracted.egress.rule_admits r d ≠ ok true := by
    intro r hr hEq
    exact hcon ⟨r, hr, hEq⟩
  rw [unmatched_is_dropped rules d hall] at h
  exact absurd h (by simp)

/-! ## Axiom audit

Every theorem must rest on Lean's three standard axioms and nothing else. In
particular `native_decide` (which would add `Lean.ofReduceBool`) is not used —
it was tried for `zero_prefix_matches_everything` and replaced with a real
proof, because a kernel-external evaluation on the critical path is exactly the
kind of assumption this file exists to avoid. -/

#print axioms unmatched_is_dropped
#print axioms accept_implies_a_granting_rule
#print axioms deny_before_allow_wins
#print axioms rule_admits_implies_allow
#print axioms rule_admits_implies_matches
#print axioms zero_prefix_matches_everything
#print axioms in_cidr_never_fails
#print axioms netmask_never_fails

end EgressConfinement
