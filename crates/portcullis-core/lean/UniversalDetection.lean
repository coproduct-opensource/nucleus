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

/-! ## Reverse direction: perfect detector when no evasion exists

The impossibility theorem by itself tells us *when* detection fails but
doesn't address the case where the equivalence is fine enough. The
following converse shows that when no non-trivial evasion is witnessed
by the equivalence, a **perfect** detector exists (sound AND complete).
This turns the impossibility into a clean dichotomy. -/

/-- **Perfect detector existence**: if the observability equivalence is
    symmetric and admits no non-trivial evasion, then the decidable
    membership function of `M` is a perfect (sound + complete) detector
    respecting the equivalence.

    Informally: when `~` separates malicious from benign, the `decide M`
    detector works. Combined with `universal_detection_impossibility`,
    this proves that equivalence coarseness is the *sole* obstruction to
    perfect detection in the observable setting. -/
theorem perfect_detector_of_no_evasion {S : Type}
    (M : S → Prop) [DecidablePred M] (eq : S → S → Prop)
    (h_sym : ∀ s t, eq s t → eq t s)
    (h : ¬ NonTrivialEvasion M eq) :
    ∃ D : Detector S, Observable eq D ∧ Sound M D ∧ (∀ s, M s → D s = true) := by
  refine ⟨fun s => decide (M s), ?_, ?_, ?_⟩
  · -- Observability: decide respects eq because eq preserves M-membership
    -- in both directions (using symmetry + no evasion).
    intro s t h_eq
    by_cases hMs : M s
    · by_cases hMt : M t
      · simp [hMs, hMt]
      · exact absurd ⟨s, t, hMs, hMt, h_eq⟩ h
    · by_cases hMt : M t
      · exact absurd ⟨t, s, hMt, hMs, h_sym s t h_eq⟩ h
      · simp [hMs, hMt]
  · -- Soundness of decide
    intro s h_dec
    exact of_decide_eq_true h_dec
  · -- Completeness of decide
    intro s hM
    exact decide_eq_true hM

/-- **Detection Dichotomy**: for any decidable malicious class and any
    symmetric observability equivalence, exactly one of the following
    holds.

    * The equivalence admits a non-trivial evasion pair, and *every*
      observable sound detector has a false negative.
    * The equivalence admits no evasion, and a perfect (sound + complete)
      detector exists — concretely, the decidable membership function.

    This is the precise sense in which "observability equivalence
    coarseness is the obstruction to detection." There is no middle ground:
    the equivalence is either fine enough to detect perfectly or coarse
    enough to force impossibility. -/
theorem detection_dichotomy {S : Type}
    (M : S → Prop) [DecidablePred M] (eq : S → S → Prop)
    (h_sym : ∀ s t, eq s t → eq t s) :
    (NonTrivialEvasion M eq ∧
      ∀ D : Detector S, Observable eq D → Sound M D →
        ∃ s, M s ∧ D s = false)
    ∨
    (¬ NonTrivialEvasion M eq ∧
      ∃ D : Detector S, Observable eq D ∧ Sound M D ∧ (∀ s, M s → D s = true)) := by
  by_cases h : NonTrivialEvasion M eq
  · refine Or.inl ⟨h, ?_⟩
    intro D h_obs h_sound
    exact universal_detection_impossibility D h_obs h_sound h
  · exact Or.inr ⟨h, perfect_detector_of_no_evasion M eq h_sym h⟩

end PortcullisCore.UniversalDetection
