/-
  Nucleus / Auctions / Sealed  (commit→reveal binding for sealed-bid auctions)

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: pure logic over the named
  injectivity hypothesis. Closes gap **G2b** — sealed-bid commit-reveal was
  tested but the binding property was an unstated assumption.

  Mirrors `nucleus-econ-kernels::sealed`: a bidder publishes a commitment
  `c = SHA-256(domain ‖ auctionId ‖ agentId ‖ value ‖ profileDigest ‖ nonce)` in
  the commit phase, then reveals the opening `(value, profileDigest, nonce, …)` in
  the reveal phase; the verifier recomputes the hash and checks it matches.

  This file proves the **binding** half (a commitment cannot be opened to two
  different bids) that `CredibleClearing.lean` *assumed* when it used commitment
  set-membership to close the OMIT attack.

  # Honest scope boundary (read this)

  `commit` is modelled as an ABSTRACT INJECTIVE function (the named hypothesis
  `Scheme.binding`), exactly as in `CredibleClearing.lean`. That injectivity IS the
  collision-resistance of SHA-256 over the domain-separated opening — a STANDARD
  cryptographic ASSUMPTION we name, not a theorem we re-derive (re-proving SHA-256
  collision-resistance is out of scope and not the claim). HIDING (the commitment
  leaks nothing about the bid) is a probabilistic property of the random `nonce`
  and is NOT stated here — only binding.
-/

namespace Nucleus.Auctions.Sealed

/-- A bid opening: the fields bound into the commitment hash (mirrors
    `nucleus-econ-kernels::sealed::BidOpening`). `nonce` is the 32-byte hiding
    randomness; digests/ids are modelled as `Nat`. -/
structure Opening where
  value : Nat
  profileDigest : Nat
  auctionId : Nat
  agentId : Nat
  nonce : Nat
  deriving DecidableEq, Repr

/-- A 256-bit commitment digest, modelled as `Nat`. -/
structure Commitment where
  digest : Nat
  deriving DecidableEq, Repr

/-- A commitment scheme. `binding` is the NAMED cryptographic hypothesis: `commit`
    is injective — i.e. SHA-256 is collision-resistant over the domain-separated
    opening. Assumed (standard), not re-derived. -/
structure Scheme where
  commit : Opening → Commitment
  binding : ∀ {o1 o2 : Opening}, commit o1 = commit o2 → o1 = o2

/-- A reveal verifies iff recomputing the commitment from the opening matches the
    published commitment (mirrors the Rust `verify`/`open` recompute check). -/
def verifyOpening (s : Scheme) (c : Commitment) (o : Opening) : Prop :=
  s.commit o = c

/-- **G2b — binding (PROVED under the named injectivity hypothesis).** No
    commitment opens to two different bids: any two openings that both verify
    against the same commitment are equal. -/
theorem opening_unique (s : Scheme) (c : Commitment) {o1 o2 : Opening}
    (h1 : verifyOpening s c o1) (h2 : verifyOpening s c o2) : o1 = o2 := by
  unfold verifyOpening at h1 h2
  exact s.binding (h1.trans h2.symm)

/-- The revealed **value** is therefore unique — a bidder cannot open a commitment
    to a different price than it committed to. -/
theorem value_unique (s : Scheme) (c : Commitment) {o1 o2 : Opening}
    (h1 : verifyOpening s c o1) (h2 : verifyOpening s c o2) : o1.value = o2.value := by
  rw [opening_unique s c h1 h2]

/-- The revealed **externality profile** is likewise unique — the Pigouvian inputs
    can't be swapped post-commit. -/
theorem profile_unique (s : Scheme) (c : Commitment) {o1 o2 : Opening}
    (h1 : verifyOpening s c o1) (h2 : verifyOpening s c o2) :
    o1.profileDigest = o2.profileDigest := by
  rw [opening_unique s c h1 h2]

/-- Contrapositive: changing ANY committed field (the bid value, profile, nonce, …)
    necessarily changes the commitment — so a post-hoc tamper is detectable by the
    recompute-and-compare reveal check. -/
theorem tamper_changes_commitment (s : Scheme) {o1 o2 : Opening} (h : o1 ≠ o2) :
    s.commit o1 ≠ s.commit o2 := by
  intro hc
  exact h (s.binding hc)

end Nucleus.Auctions.Sealed
