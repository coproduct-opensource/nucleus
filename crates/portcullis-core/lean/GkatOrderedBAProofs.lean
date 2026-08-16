import GkatOrderedProofs

/-!
# Ordered GKAT with the Boolean-test embedding

`GkatOrderedProofs.Leq` supplies the inequational and least-fixpoint layer, but its base
equational syntax intentionally contains only U/S/W. SGKAT's atom annotations additionally
need the standard embedding of the Boolean test algebra:

* Boolean implication becomes order between embedded tests;
* sequential test composition is Boolean conjunction; and
* false is the least program.

`LeqBA` adds exactly those rules and proves them sound for guarded-string inclusion. This is
the ordered target required to compile SGKAT's annotation-restriction rules. It remains a
conservative extension of the earlier `Leq` (`ofLeq`).
-/

namespace GkatOrderedBA

open GkatSyntax GkatGS GkatOrdered

variable {A T : Type}

/-- Ordered GKAT plus the standard Boolean-test embedding. -/
inductive LeqBA : Exp A T → Exp A T → Prop where
  | refl (e : Exp A T) : LeqBA e e
  | trans {e f g : Exp A T} : LeqBA e f → LeqBA f g → LeqBA e g
  | equiv {e f : Exp A T} : Equiv e f → LeqBA e f
  | seq_mono {e e' f f' : Exp A T} :
      LeqBA e e' → LeqBA f f' → LeqBA (.seq e f) (.seq e' f')
  | ite_mono {b : BExp T} {e e' f f' : Exp A T} :
      LeqBA e e' → LeqBA f f' → LeqBA (.ite b e f) (.ite b e' f')
  | wh_mono {b : BExp T} {e e' : Exp A T} : LeqBA e e' → LeqBA (.wh b e) (.wh b e')
  | star_ind {b : BExp T} {e f g : Exp A T} :
      LeqBA (.ite b (.seq e g) f) g → LeqBA (.seq (.wh b e) f) g
  | test_le {b c : BExp T} :
      (∀ (X : Type) (V : T → X → Bool) (x : X),
        bval V b x = true → bval V c x = true) →
      LeqBA (.test b : Exp A T) (.test c)
  | test_seq (b c : BExp T) :
      LeqBA (.seq (.test b) (.test c) : Exp A T) (.test (.and b c))
  | test_seq_rev (b c : BExp T) :
      LeqBA (.test (.and b c) : Exp A T) (.seq (.test b) (.test c))
  | test_ite (B b : BExp T) (e f : Exp A T) :
      LeqBA (.seq (.test B) (.ite b e f))
        (.ite b (.seq (.test (.and B b)) e)
          (.seq (.test (.and B (.not b))) f))
  | test_ite_rev (B b : BExp T) (e f : Exp A T) :
      LeqBA (.ite b (.seq (.test (.and B b)) e)
          (.seq (.test (.and B (.not b))) f))
        (.seq (.test B) (.ite b e f))
  | zero_le (e : Exp A T) : LeqBA (.test .zero) e

/-- The original ordered theory embeds into the Boolean-aware one. -/
theorem ofLeq {e f : Exp A T} (h : Leq e f) : LeqBA e f := by
  induction h with
  | refl e => exact LeqBA.refl e
  | trans _ _ ih₁ ih₂ => exact LeqBA.trans ih₁ ih₂
  | equiv h => exact LeqBA.equiv h
  | seq_mono _ _ ih₁ ih₂ => exact LeqBA.seq_mono ih₁ ih₂
  | ite_mono _ _ ih₁ ih₂ => exact LeqBA.ite_mono ih₁ ih₂
  | wh_mono _ ih => exact LeqBA.wh_mono ih
  | star_ind _ ih => exact LeqBA.star_ind ih

variable {Atom : Type} (V : T → Atom → Bool)

/-- Soundness of the Boolean-aware ordered theory for language inclusion. -/
theorem le_sound {e f : Exp A T} (h : LeqBA e f) : ∀ gs, den V e gs → den V f gs := by
  induction h with
  | refl e => exact fun _ h => h
  | trans _ _ ih₁ ih₂ => exact fun gs h => ih₂ gs (ih₁ gs h)
  | equiv h => exact fun gs => (GkatGS.sound V h gs).mp
  | seq_mono _ _ ih₁ ih₂ =>
      exact fun gs ⟨l₁, l₂, hs, he, hf⟩ => ⟨l₁, l₂, hs, ih₁ _ he, ih₂ _ hf⟩
  | ite_mono _ _ ih₁ ih₂ =>
      intro gs h
      rcases h with ⟨hb, he⟩ | ⟨hb, hf⟩
      · exact Or.inl ⟨hb, ih₁ _ he⟩
      · exact Or.inr ⟨hb, ih₂ _ hf⟩
  | @wh_mono b e e' _ ih => exact GkatOrdered.InLoop_mono V (fun gs => ih gs)
  | @star_ind b e f g _ ih =>
      rintro ⟨a, w⟩ ⟨l₁, l₂, hs, hloop, hf⟩
      simp only at hs; subst hs
      exact GkatOrdered.star_ind_den V ih (a, l₁) hloop l₂ hf
  | @test_le b c hbc =>
      rintro ⟨a, w⟩ ⟨hb, hw⟩
      exact ⟨hbc Atom V a hb, hw⟩
  | test_seq b c =>
      rintro ⟨a, w⟩ ⟨l₁, l₂, hs, ⟨hb, hl₁⟩, ⟨hc, hl₂⟩⟩
      have h₁ : l₁ = [] := hl₁
      subst l₁
      have h₂ : l₂ = [] := hl₂
      subst l₂
      simp only [List.nil_append] at hs
      subst w
      have hb' : bval V b a = true := by simpa using hb
      have hc' : bval V c a = true := by simpa [lastAtom] using hc
      exact ⟨by simp [bval, hb', hc'], rfl⟩
  | test_seq_rev b c =>
      rintro ⟨a, w⟩ ⟨hbc, hw⟩
      have h₀ : w = [] := hw
      subst w
      simp only [bval, Bool.and_eq_true] at hbc
      obtain ⟨hb, hc⟩ := hbc
      exact ⟨[], [], rfl, ⟨hb, rfl⟩, ⟨hc, rfl⟩⟩
  | test_ite B b e f =>
      rintro ⟨a, w⟩ h
      simp only [den_seq, den_test, den_ite] at h ⊢
      rcases h with ⟨l₁, l₂, hs, ⟨hB, hl₁⟩, hite⟩
      subst l₁
      simp only [List.nil_append, lastAtom] at hs hite
      subst l₂
      rcases hite with ⟨hb, he⟩ | ⟨hb, hf⟩
      · exact Or.inl ⟨hb, [], w, rfl, ⟨by simp [bval, hB, hb], rfl⟩, he⟩
      · exact Or.inr ⟨hb, [], w, rfl, ⟨by simp [bval, hB, hb], rfl⟩, hf⟩
  | test_ite_rev B b e f =>
      rintro ⟨a, w⟩ h
      simp only [den_ite, den_seq, den_test] at h ⊢
      rcases h with ⟨hb, l₁, l₂, hs, ⟨hBb, hl₁⟩, he⟩ |
          ⟨hb, l₁, l₂, hs, ⟨hBnb, hl₁⟩, hf⟩
      · subst l₁
        simp only [List.nil_append, lastAtom] at hs he hBb
        subst l₂
        have hpair : bval V B a = true ∧ bval V b a = true := by
          simpa [bval] using hBb
        have hB : bval V B a = true := hpair.1
        exact ⟨[], w, rfl, ⟨hB, rfl⟩, Or.inl ⟨hb, he⟩⟩
      · subst l₁
        simp only [List.nil_append, lastAtom] at hs hf hBnb
        subst l₂
        have hpair : bval V B a = true ∧ bval V b a = false := by
          simpa [bval] using hBnb
        have hB : bval V B a = true := hpair.1
        exact ⟨[], w, rfl, ⟨hB, rfl⟩, Or.inr ⟨hb, hf⟩⟩
  | zero_le e =>
      rintro ⟨a, w⟩ h
      simp [den, bval] at h

#print axioms ofLeq
#print axioms le_sound

end GkatOrderedBA
