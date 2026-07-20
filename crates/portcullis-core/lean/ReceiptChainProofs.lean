/-!
# Receipt Chain Append-Only Proofs  (PROVED — 0 proof-holes, 0 extra axioms)

Models the receipt hash-chain (`portcullis/src/receipt_sign.rs::receipt_hash`):
  `link_i = H(content_i, sig_i)` and `prev_hash_{i+1} = link_i`.
Proves TAMPER-EVIDENCE: modifying a receipt's content/sig, deleting a receipt, or
reordering receipts breaks the chain the verifier re-walks. Collision / second-
preimage resistance of `H` is a HYPOTHESIS (joint injectivity), not an axiom, so
these theorems say: *under a collision-resistant hash, tampering is detectable.*
Mathlib-free; same discipline as `DeclassifyProofs`.
-/

namespace ReceiptChain

/-- A receipt: abstract signed content + signature payload, and the recorded
    previous chain link. -/
structure Receipt where
  content  : Nat
  sig      : Nat
  prevHash : Nat

/-- The chain link of a receipt under hash `H`: `H(content, sig)`. -/
def link (H : Nat → Nat → Nat) (r : Receipt) : Nat := H r.content r.sig

/-- `r2` correctly follows `r1` iff its recorded `prevHash` equals `r1`'s link. -/
def linked (H : Nat → Nat → Nat) (r1 r2 : Receipt) : Prop :=
  r2.prevHash = link H r1

/-- A chain is intact iff every consecutive pair is `linked`. -/
def chainIntact (H : Nat → Nat → Nat) : List Receipt → Prop
  | []            => True
  | [_]           => True
  | r1 :: r2 :: t => linked H r1 r2 ∧ chainIntact H (r2 :: t)

/-- **Modification is detectable.** Under a collision-resistant `H`, changing a
    receipt's content to a different value breaks its successor's link. -/
theorem content_tamper_breaks_link
    (H : Nat → Nat → Nat)
    (hInj : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (r1 r2 : Receipt) (h : linked H r1 r2)
    (c' : Nat) (hc : c' ≠ r1.content) :
    ¬ linked H { r1 with content := c' } r2 := by
  intro h'
  simp only [linked, link] at h h'
  exact hc (hInj _ _ _ _ (h'.symm.trans h)).1

/-- **Signature tamper is detectable** (same mechanism, on `sig`). -/
theorem sig_tamper_breaks_link
    (H : Nat → Nat → Nat)
    (hInj : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (r1 r2 : Receipt) (h : linked H r1 r2)
    (s' : Nat) (hs : s' ≠ r1.sig) :
    ¬ linked H { r1 with sig := s' } r2 := by
  intro h'
  simp only [linked, link] at h h'
  exact hs (hInj _ _ _ _ (h'.symm.trans h)).2

/-- **Deletion is detectable.** Removing the middle receipt of an intact 3-chain
    yields a non-intact chain: the successor's `prevHash` points at the deleted
    receipt's link, not the new predecessor's. (Reordering breaks the chain by the
    same link-mismatch.) -/
theorem deletion_breaks_chain
    (H : Nat → Nat → Nat)
    (hInj : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (r1 r2 r3 : Receipt)
    (h : chainIntact H [r1, r2, r3])
    (hne : r1.content ≠ r2.content) :
    ¬ chainIntact H [r1, r3] := by
  intro hdel
  simp only [chainIntact, linked, link, and_true] at h hdel
  -- h.2 : r3.prevHash = H r2.content r2.sig ; hdel : r3.prevHash = H r1.content r1.sig
  exact hne (hInj _ _ _ _ (h.2.symm.trans hdel)).1.symm

/-- **Reordering is detectable.** Swapping two receipts (here the middle pair of
    an intact 3-chain) breaks the re-walk: the moved successor's recorded
    `prevHash` still commits to its *original* predecessor's link, which the hash's
    injectivity separates from the new predecessor's. -/
theorem reorder_breaks_chain
    (H : Nat → Nat → Nat)
    (hInj : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (r1 r2 r3 : Receipt)
    (h : chainIntact H [r1, r2, r3])
    (hne : r1.content ≠ r2.content) :
    ¬ chainIntact H [r1, r3, r2] := by
  intro hre
  simp only [chainIntact, linked, link, and_true] at h hre
  -- h.2 : r3.prevHash = H r2.content r2.sig ; hre.1 : r3.prevHash = H r1.content r1.sig
  exact hne (hInj _ _ _ _ (h.2.symm.trans hre.1)).1.symm

/-- **Backpointer tamper is detectable.** Distinct from content/sig tampering
    (which break the *successor's* link), altering a receipt's own recorded
    `prevHash` breaks *its* link to its predecessor. This closes the third and
    last tamper surface on a link: content, signature, and backpointer. -/
theorem prevhash_tamper_breaks_link
    (H : Nat → Nat → Nat)
    (r1 r2 : Receipt) (h : linked H r1 r2)
    (p' : Nat) (hp : p' ≠ r2.prevHash) :
    ¬ linked H r1 { r2 with prevHash := p' } := by
  intro h'
  simp only [linked, link] at h h'
  exact hp (h'.trans h.symm)

/-- **Predecessor commitment.** A receipt's `prevHash` commits to *exactly one*
    predecessor: any two receipts that validly precede the same receipt have the
    same `(content, sig)` under a collision-resistant `H`. This is what makes the
    chain a chain — no receipt can be silently reparented. -/
theorem link_determines_predecessor
    (H : Nat → Nat → Nat)
    (hInj : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (p p' r : Receipt)
    (h1 : linked H p r) (h2 : linked H p' r) :
    p.content = p'.content ∧ p.sig = p'.sig := by
  simp only [linked, link] at h1 h2
  exact hInj _ _ _ _ (h1.symm.trans h2)

/-- **Structural extraction (N-ary).** From an intact chain of any length, the
    head pair is `linked`. Lets tamper-evidence lift from the 3-chain lemmas to
    chains of arbitrary length by induction on the list. -/
theorem head_link_of_intact
    (H : Nat → Nat → Nat) (r1 r2 : Receipt) (t : List Receipt)
    (h : chainIntact H (r1 :: r2 :: t)) : linked H r1 r2 := by
  simp only [chainIntact] at h
  exact h.1

/-- **Append-only growth is well-formed.** Appending a fresh receipt whose
    `prevHash` is the current tail's link preserves intactness — the honest
    "grow the log" direction, complementing the tamper lemmas above. -/
theorem extend_intact
    (H : Nat → Nat → Nat) (r1 r2 : Receipt) (h : linked H r1 r2)
    (c s : Nat) :
    chainIntact H [r1, r2, { content := c, sig := s, prevHash := link H r2 }] := by
  simp only [chainIntact, linked, link, and_true] at h ⊢
  exact h

/-- **Non-vacuity.** A correctly-built chain verifies, so tamper-evidence is not
    vacuously satisfied. -/
theorem intact_chain_verifies
    (H : Nat → Nat → Nat) (r1 : Receipt) (c s : Nat) :
    chainIntact H [r1, { content := c, sig := s, prevHash := link H r1 }] := by
  simp [chainIntact, linked, link]

#print axioms content_tamper_breaks_link
#print axioms sig_tamper_breaks_link
#print axioms deletion_breaks_chain
#print axioms prevhash_tamper_breaks_link
#print axioms reorder_breaks_chain
#print axioms link_determines_predecessor
#print axioms head_link_of_intact
#print axioms extend_intact
#print axioms intact_chain_verifies

end ReceiptChain
