/-! # Universal Detection Impossibility

The `evasion_impossibility` theorem in `ComparisonTheorem.lean` is specific
to attention-coherence detectors over the `TaggedPoset ThreeSecret` type.
This file lifts that result to an **abstract** impossibility: any detector
that respects an observational equivalence in which a malicious system and
a non-malicious system are equivalent must have false negatives.

## Formal shape

A detector is a Boolean function on some system space. The argument is:

1. *Observability*: the detector reads only observable features, i.e. it
   respects some equivalence relation `~` on the system space.
2. *Soundness*: when the detector flags, the system is in some malicious
   class `M`.
3. *Non-trivial evasion*: there exists an indistinguishable pair `(m, t)`
   with `M m`, `¬ M t`, and `m ~ t`.

Under these three, the detector must output `false` on the malicious
`m` — a false negative.

This is a Rice-style semantic-impossibility result for **any** efficient
detector whose decisions factor through observables.

## Prior art

* Arxiv 2602.05656 — *Limits of Behavioral Alignment: Formal Verifiability
  and Normative Indistinguishability*. Introduces the *Indistinguishability
  Set* — the equivalence class of latent hypotheses agreeing on all
  observations. Same ontology as this file's `eq`.
* Arxiv 2507.03031 — *Mathematical Impossibility of Safe Universal
  Approximators*. Shows reliable catastrophe detection requires universal
  approximation capability, hence is itself catastrophically unreliable.
  Consistent with — and strictly implied by — the theorem below once one
  identifies the right equivalence.
* Rice 1953 — the original template. A non-trivial semantic property of
  Turing machines is undecidable. Our result is a decidable-space analog
  under the observability axiom.

## Relation to `evasion_impossibility`

The existing `EvasionImpossibility.evasion_impossibility` is the
specialization to `S := TaggedPoset ThreeSecret`, `M := isMalicious`, and
the equivalence "have the same `hasExclusive` value". The abstract version
below is strictly stronger: it shows the impossibility does not depend on
any attention-specific structure — only on the axioms.
-/

namespace PortcullisCore.UniversalDetection

/-- A detector on a system space is any Boolean-valued function on it. -/
abbrev Detector (S : Type) : Type := S → Bool

/-- **Observability**: the detector respects an equivalence relation on
    the system space. Concretely, the detector's answer depends only on
    the equivalence class. -/
def Observable {S : Type} (eq : S → S → Prop) (D : Detector S) : Prop :=
  ∀ s t, eq s t → D s = D t

/-- **Soundness**: when the detector flags, the system is in the
    target malicious class `M`. -/
def Sound {S : Type} (M : S → Prop) (D : Detector S) : Prop :=
  ∀ s, D s = true → M s

/-- **Non-trivial evasion**: there is a pair of systems `m, t`
    indistinguishable under `~` with `m` malicious and `t` benign. This
    is the information-theoretic gap that forces detection failure. -/
def NonTrivialEvasion {S : Type} (M : S → Prop) (eq : S → S → Prop) : Prop :=
  ∃ m t : S, M m ∧ ¬ M t ∧ eq m t

/-- **Universal Detection Impossibility**.

    If a detector is observable w.r.t. an equivalence `~`, is sound for
    a malicious class `M`, and there exists a non-trivial evasion pair
    under `~`, then the detector has a false negative.

    Proof: on the evasion pair `(m, t)`, observability gives `D m = D t`.
    If `D m = true`, soundness gives `M t`, contradicting `¬ M t`. So
    `D m = false`, witnessing a false negative on the malicious `m`. -/
theorem universal_detection_impossibility {S : Type}
    {M : S → Prop} {eq : S → S → Prop} (D : Detector S)
    (h_obs : Observable eq D) (h_sound : Sound M D)
    (h_evade : NonTrivialEvasion M eq) :
    ∃ s : S, M s ∧ D s = false := by
  obtain ⟨m, t, hM, hNotM, heq⟩ := h_evade
  refine ⟨m, hM, ?_⟩
  cases hDm : D m with
  | false => rfl
  | true =>
    have hDt : D t = true := (h_obs m t heq) ▸ hDm
    exact absurd (h_sound t hDt) hNotM

/-- **Contrapositive phrasing**: if a detector is observable and has no
    false negatives, then no non-trivial evasion pair exists. Equivalently,
    the observability equivalence must *separate* malicious from benign. -/
theorem detector_separates_malicious_of_complete {S : Type}
    {M : S → Prop} {eq : S → S → Prop} (D : Detector S)
    (h_obs : Observable eq D) (h_sound : Sound M D)
    (h_no_fn : ∀ s, M s → D s = true) :
    ¬ NonTrivialEvasion M eq := by
  intro h_evade
  obtain ⟨m, hM, hDm⟩ :=
    universal_detection_impossibility D h_obs h_sound h_evade
  exact Bool.false_ne_true (hDm ▸ h_no_fn m hM)

end PortcullisCore.UniversalDetection
