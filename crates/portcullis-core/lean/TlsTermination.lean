/-
  ADR 0015 E3 (TLS termination), and its use by ADR 0017 links: the meaning,
  before any code.

  ADR 0015 §4 decides "terminate, with a per-pod CA that only the host holds":
    * at admission the node mints a CA per pod, valid no longer than the pod's
      timeout, whose name constraints are exactly the names the pod may reach
      (its registry hosts, and — for ADR 0017 — its link names);
    * the CA's key goes only to that pod's proxy; the guest gets the
      certificate, never the key;
    * the proxy mints a leaf per name on first use, ALPN http/1.1 only;
    * a request is decided only when the TLS name (SNI) and the `Host` header
      agree (domain fronting is refused);
    * a client that does not trust the pod's CA (a pinned client, or a CA from
      another pod) fails the handshake: refused and recorded, never tunnelled.

  Holding a key is authority, so who holds each CA key is part of the state, and
  the theorems say no step moves it. Mathlib-free, like `LinkTable.lean`.

  Note (2026-11-19, E3 node side): links are made after admission, so the node
  mints the CA with the link namespace as one DNS subtree (`link.nucleus.invalid`)
  and leaves "which link" to the link table. `permitted` here is exact names
  (`permitted.contains`), which is also what the proxy grants, so a link name is
  never permitted as modelled. Subtree semantics for that namespace is open
  (ADR 0017 §10).
-/

namespace TlsTermination

abbrev PodId := Nat
/-- A DNS name (or a link name), abstracted to its identity. -/
abbrev Name := Nat
abbrev Time := Nat

/-- Who holds a private key. Only `proxy p` should ever hold pod `p`'s CA key. -/
inductive Holder where
  | proxy (p : PodId)
  | node
  | guest (p : PodId)
  deriving DecidableEq, Repr

structure CA where
  pod : PodId
  permitted : List Name
  notAfter : Time
  keyHolder : Holder
  deriving Repr

structure Leaf where
  pod : PodId
  name : Name
  notAfter : Time
  deriving DecidableEq, Repr

/-- How a terminated exchange ended. There is no third, opaque outcome. -/
inductive Outcome where
  /-- Reached the per-request decision (ADR 0015 §2). -/
  | decided (pod : PodId) (name : Name)
  | refusedClientRejected (pod : PodId) (sni : Name)
  | refusedNameNotPermitted (pod : PodId) (sni : Name)
  | refusedFronting (pod : PodId) (sni host : Name)
  | refusedExpired (pod : PodId)
  deriving DecidableEq, Repr

structure State where
  now : Time
  cas : List CA
  leaves : List Leaf
  /-- Each guest trusts exactly the CA certificate of its own pod. -/
  journal : List Outcome

def caOf : List CA → PodId → Option CA
  | [], _ => none
  | c :: rest, p => if c.pod = p then some c else caOf rest p

inductive Op where
  /-- Admission: mint pod `p`'s CA for `permitted`, until `deadline`. -/
  | mint (p : PodId) (permitted : List Name) (deadline : Time)
  /-- A client in pod `p` opens TLS for `sni`, sends `Host: host`;
      `clientTrustsPod` says whether its trust store holds pod `p`'s CA
      (false for a pinned client). -/
  | handshake (p : PodId) (sni host : Name) (clientTrustsPod : Bool)
  | tick
  /-- The pod went away: its CA and leaves are discarded. -/
  | retire (p : PodId)

def step (s : State) : Op → State
  | .mint p permitted deadline =>
    match caOf s.cas p with
    | some _ => s
    | none =>
      { s with cas := ⟨p, permitted, deadline, .proxy p⟩ :: s.cas }
  | .handshake p sni host trusts =>
    match caOf s.cas p with
    | none => { s with journal := .refusedExpired p :: s.journal }
    | some ca =>
      if s.now > ca.notAfter then { s with journal := .refusedExpired p :: s.journal }
      else if !ca.permitted.contains sni then
        { s with journal := .refusedNameNotPermitted p sni :: s.journal }
      else if !trusts then
        { s with journal := .refusedClientRejected p sni :: s.journal }
      else if sni != host then
        { s with journal := .refusedFronting p sni host :: s.journal }
      else
        let leaf : Leaf := ⟨p, sni, ca.notAfter⟩
        { s with leaves := if s.leaves.contains leaf then s.leaves else leaf :: s.leaves,
                 journal := .decided p sni :: s.journal }
  | .tick => { s with now := s.now + 1 }
  | .retire p =>
    { s with cas := s.cas.filter (·.pod != p), leaves := s.leaves.filter (·.pod != p) }

/-! ## The invariant every step keeps -/

/-- Every CA key is held by its own pod's proxy; every leaf is for a name its
    pod's CA permits, and expires no later than that CA. -/
def Inv (s : State) : Prop :=
  (∀ c ∈ s.cas, c.keyHolder = .proxy c.pod) ∧
  (∀ l ∈ s.leaves, ∃ c, caOf s.cas l.pod = some c ∧ l.name ∈ c.permitted ∧ l.notAfter ≤ c.notAfter)

theorem caOf_mem {cs : List CA} {p : PodId} {c : CA} (h : caOf cs p = some c) :
    c ∈ cs ∧ c.pod = p := by
  induction cs with
  | nil => simp [caOf] at h
  | cons d rest ih =>
    simp only [caOf] at h
    split at h
    · rename_i hd; cases h; exact ⟨List.mem_cons_self .., hd⟩
    · have ⟨hm, hp⟩ := ih h; exact ⟨List.mem_cons_of_mem _ hm, hp⟩

theorem caOf_filter (cs : List CA) (p q : PodId) :
    caOf (cs.filter (·.pod != p)) q = if q = p then none else caOf cs q := by
  induction cs with
  | nil => simp [caOf]
  | cons d rest ih =>
    by_cases hdp : d.pod = p
    · have : (d :: rest).filter (·.pod != p) = rest.filter (·.pod != p) := by
        simp [List.filter, hdp]
      rw [this, ih]
      by_cases hqp : q = p
      · simp [hqp]
      · have : d.pod ≠ q := fun e => hqp (e ▸ hdp)
        simp [hqp, caOf, this]
    · have hb : (d.pod != p) = true := by simp [hdp]
      have : (d :: rest).filter (·.pod != p) = d :: rest.filter (·.pod != p) := by
        simp only [List.filter, hb]
      rw [this]
      simp only [caOf]
      rw [ih]
      by_cases hdq : d.pod = q
      · have : q ≠ p := fun e => hdp (hdq.trans e)
        simp [hdq, this]
      · simp [hdq]

theorem caOf_cons_fresh {cs : List CA} {p q : PodId} {c : CA}
    (hfresh : caOf cs p = none) (hc : c.pod = p) :
    caOf (c :: cs) q = if q = p then some c else caOf cs q := by
  simp only [caOf]
  by_cases hq : q = p
  · subst hq; simp [hc]
  · have : c.pod ≠ q := fun e => hq (e.symm.trans hc)
    simp [this, hq]

theorem step_inv {s : State} (op : Op) (h : Inv s) : Inv (step s op) := by
  obtain ⟨hk, hl⟩ := h
  cases op with
  | mint p permitted deadline =>
    simp only [step]
    split
    · exact ⟨hk, hl⟩
    · rename_i hnone
      refine ⟨?_, ?_⟩
      · intro c hc
        rcases List.mem_cons.mp hc with rfl | hm
        · rfl
        · exact hk c hm
      · intro l hlm
        obtain ⟨c, hcs, hn, ht⟩ := hl l hlm
        refine ⟨c, ?_, hn, ht⟩
        have hlp : l.pod ≠ p := by
          intro e; rw [e] at hcs; rw [hnone] at hcs; cases hcs
        rw [caOf_cons_fresh hnone rfl]
        simp [hlp, hcs]
  | handshake p sni host trusts =>
    simp only [step]
    split
    · exact ⟨hk, hl⟩
    · rename_i ca hca
      split
      · exact ⟨hk, hl⟩
      · rename_i hlive
        split
        · exact ⟨hk, hl⟩
        · rename_i hperm
          split
          · exact ⟨hk, hl⟩
          · split
            · exact ⟨hk, hl⟩
            · refine ⟨hk, ?_⟩
              intro l hlm
              split at hlm
              · exact hl l hlm
              · rcases List.mem_cons.mp hlm with rfl | hm
                · refine ⟨ca, ?_, ?_, Nat.le_refl _⟩
                  · exact hca
                  · simpa using hperm
                · exact hl l hm
  | tick => exact ⟨hk, hl⟩
  | retire p =>
    simp only [step]
    refine ⟨fun c hc => hk c (List.mem_filter.mp hc).1, ?_⟩
    intro l hlm
    have ⟨hm, hlp⟩ := List.mem_filter.mp hlm
    obtain ⟨c, hcs, hn, ht⟩ := hl l hm
    refine ⟨c, ?_, hn, ht⟩
    have : l.pod ≠ p := by simpa using hlp
    rw [caOf_filter]; simp [this, hcs]

/-! ## The theorems ADR 0015 §4 and ADR 0017 cite -/

/-- No step moves a CA key out of its pod's proxy: not to the node, not to any
    guest, not to another pod's proxy. -/
theorem ca_key_stays_in_proxy {s : State} (h : Inv s) (op : Op) :
    ∀ c ∈ (step s op).cas, c.keyHolder = .proxy c.pod :=
  (step_inv op h).1

/-- Every leaf the proxy holds is for a name its pod's CA permits, and expires
    no later than the CA (so no later than the pod's deadline). -/
theorem leaf_within_constraints {s : State} (h : Inv s) (op : Op) :
    ∀ l ∈ (step s op).leaves, ∃ c, caOf (step s op).cas l.pod = some c ∧
      l.name ∈ c.permitted ∧ l.notAfter ≤ c.notAfter :=
  (step_inv op h).2

/-- A handshake reaches the per-request decision only if: the pod has a live CA,
    the name is permitted, the client trusts this pod's CA, and SNI = Host. -/
theorem decided_only_if (s : State) (p : PodId) (sni host : Name) (trusts : Bool)
    (hd : (step s (.handshake p sni host trusts)).journal.head? = some (.decided p sni)) :
    ∃ ca, caOf s.cas p = some ca ∧ s.now ≤ ca.notAfter ∧ sni ∈ ca.permitted ∧
      trusts = true ∧ sni = host := by
  simp only [step] at hd
  split at hd
  · simp at hd
  · rename_i ca hca
    split at hd
    · simp at hd
    · rename_i hlive
      split at hd
      · simp at hd
      · rename_i hperm
        split at hd
        · simp at hd
        · rename_i htr
          split at hd
          · simp at hd
          · rename_i hsh
            refine ⟨ca, hca, Nat.le_of_not_gt hlive, by simpa using hperm, by simpa using htr,
              by simpa using hsh⟩

/-- Nothing is opaque: every handshake is journalled as decided or refused, and
    a client that does not trust the pod's CA (pinned, or holding another pod's
    CA) is refused — never tunnelled. -/
theorem untrusting_client_refused (s : State) (p : PodId) (sni host : Name) :
    ∀ n, (step s (.handshake p sni host false)).journal.head? ≠ some (.decided p n) := by
  intro n hdec
  simp only [step] at hdec
  split at hdec
  · simp at hdec
  · split at hdec
    · simp at hdec
    · split at hdec
      · simp at hdec
      · split at hdec
        · simp at hdec
        · rename_i h; exact absurd rfl h

/-- Domain fronting is refused: an SNI that differs from the Host header never
    reaches the decision. -/
theorem fronting_refused (s : State) (p : PodId) (sni host : Name) (trusts : Bool)
    (hne : sni ≠ host) (n : Name) :
    (step s (.handshake p sni host trusts)).journal.head? ≠ some (.decided p n) := by
  intro hd
  simp only [step] at hd
  split at hd
  · simp at hd
  · split at hd
    · simp at hd
    · split at hd
      · simp at hd
      · split at hd
        · simp at hd
        · split at hd
          · simp at hd
          · rename_i hsh; simp at hsh; exact hne hsh

/-- After its CA's deadline, a pod's handshakes are refused. -/
theorem expired_refused (s : State) (p : PodId) (sni host : Name) (trusts : Bool) (ca : CA)
    (hca : caOf s.cas p = some ca) (hlate : s.now > ca.notAfter) :
    (step s (.handshake p sni host trusts)).journal.head? = some (.refusedExpired p) := by
  simp [step, hca, hlate]

/-! ## Worked cases, decided by the kernel -/

/-- Pod 1 may reach names 10 (a registry host) and 20 (a link name). -/
def admitted : State :=
  step ⟨0, [], [], []⟩ (.mint 1 [10, 20] 100)

example : (step admitted (.handshake 1 20 20 true)).journal.head? = some (.decided 1 20) := by
  decide
/-- A name outside the CA's constraints. -/
example : (step admitted (.handshake 1 30 30 true)).journal.head? =
    some (.refusedNameNotPermitted 1 30) := by decide
/-- A pinned client, or one holding another pod's CA. -/
example : (step admitted (.handshake 1 20 20 false)).journal.head? =
    some (.refusedClientRejected 1 20) := by decide
/-- Domain fronting: SNI 10, Host 20. -/
example : (step admitted (.handshake 1 10 20 true)).journal.head? =
    some (.refusedFronting 1 10 20) := by decide
/-- Pod 2 has no CA here: nothing is terminated for it. -/
example : (step admitted (.handshake 2 20 20 true)).journal.head? =
    some (.refusedExpired 2) := by decide

end TlsTermination
