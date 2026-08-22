/-! # Choice-free list pigeonhole (no imports — pure core)

    Kept import-free: the Gkat import chain carries an ambient classical
    instance that pollutes decidable case splits performed downstream. -/

namespace GkatListPigeon

def removeOne {γ : Type} [DecidableEq γ] (a : γ) : List γ → List γ
  | [] => []
  | x :: xs => if x = a then xs else x :: removeOne a xs
theorem removeOne_length {γ : Type} [DecidableEq γ] (a : γ) :
    ∀ l : List γ, a ∈ l → (removeOne a l).length + 1 = l.length := by
  intro l; induction l with
  | nil => intro ha; exact nomatch ha
  | cons x xs ih =>
      intro ha
      show (if x = a then xs else x :: removeOne a xs).length + 1 = xs.length + 1
      by_cases hxa : x = a
      · rw [if_pos hxa]
      · rw [if_neg hxa]
        have hax : a ∈ xs := by
          rcases List.mem_cons.mp ha with heq | hm
          · exact absurd heq.symm hxa
          · exact hm
        show (removeOne a xs).length + 1 + 1 = xs.length + 1
        rw [ih hax]
theorem removeOne_mem {γ : Type} [DecidableEq γ] (a y : γ) (hne : y ≠ a) :
    ∀ l : List γ, y ∈ l → y ∈ removeOne a l := by
  intro l; induction l with
  | nil => intro hy; exact nomatch hy
  | cons x xs ih =>
      intro hy
      show y ∈ if x = a then xs else x :: removeOne a xs
      by_cases hxa : x = a
      · rw [if_pos hxa]
        rcases List.mem_cons.mp hy with heq | hm
        · exact absurd (heq.trans hxa) hne
        · exact hm
      · rw [if_neg hxa]
        rcases List.mem_cons.mp hy with heq | hm
        · exact heq ▸ List.mem_cons_self ..
        · exact List.mem_cons_of_mem _ (ih hm)
theorem long_in_pool_has_dup {γ : Type} [DecidableEq γ] :
    ∀ (l pool : List γ), (∀ x ∈ l, x ∈ pool) → pool.length < l.length →
      ∃ (a : γ) (pre mid post : List γ), l = pre ++ a :: mid ++ a :: post := by
  intro l
  induction l with
  | nil => intro pool _ hlen; exact absurd hlen (by simp)
  | cons x xs ih =>
      intro pool hin hlen
      rcases Decidable.em (x ∈ xs) with hx | hx
      · obtain ⟨mid, post, hsplit⟩ := List.append_of_mem hx
        exact ⟨x, [], mid, post, by rw [hsplit]; rfl⟩
      · have hxp : x ∈ pool := hin x (List.mem_cons_self ..)
        have hsub : ∀ y ∈ xs, y ∈ removeOne x pool := by
          intro y hy
          have hyp : y ∈ pool := hin y (List.mem_cons_of_mem _ hy)
          have hne : y ≠ x := fun hcontra => hx (hcontra ▸ hy)
          exact removeOne_mem x y hne pool hyp
        have hlen' : (removeOne x pool).length < xs.length := by
          have h1 := removeOne_length x pool hxp
          have h2 : pool.length < xs.length + 1 := hlen
          omega
        obtain ⟨a, pre, mid, post, hsplit⟩ := ih (removeOne x pool) hsub hlen'
        exact ⟨a, x :: pre, mid, post, by rw [hsplit]; rfl⟩
#print axioms long_in_pool_has_dup

end GkatListPigeon
