/-
  VM-to-VM links (ADR 0017, proposed): the meaning of the link table, before any
  code.

  A link is a host-held, directed allow-list entry `(src, dst, port)`: the
  workload in pod `src` may open connections to `port` on pod `dst`. The host
  relay (vsock, ADR 0017 §Mechanism) admits a connection only along a link in the
  table, so the table IS the cross-pod channel policy. This file fixes what the
  table means, so the relay, the API and the receipts are built to it rather than
  iterated into it.

  Decisions this models (owner, 2026-11-19):
    * links ride a host relay over vsock, not IP (no netns or iptables change);
    * `unlink` severs every live connection on the link before its receipt;
    * an API cancel of a pod a link names is refused;
    * an exit the node did not request (crash, timeout, reaper) drops the pod's
      links and their connections, with one receipt per dropped link.

  Tenancy is ADR 0001's: a tenant is a SPIFFE trust domain. A link joins two pods
  of one trust domain whose caller manages both; a cross-tenant link would need an
  explicit delegation and is out of scope here.

  The cross-pod claim (C2, `PodCrossView.lean`) is restated relative to the link
  graph: `noninterference_unlinked` is its local-respect condition with the links
  as the policy. It does not discharge C2; it says what C2 must become once links
  exist.

  Mathlib-free (pure `List`/`Nat`/`Bool`), like `PodCrossView.lean`.
-/

namespace LinkTable

abbrev PodId := Nat
/-- A SPIFFE trust domain (ADR 0001), abstracted to its identity. -/
abbrev Tenant := Nat
abbrev Port := Nat

structure Link where
  src : PodId
  dst : PodId
  port : Port
  deriving DecidableEq, Repr

/-- A live connection, relayed by the host along one link. -/
structure Conn where
  id : Nat
  link : Link
  deriving DecidableEq, Repr

/-- Who is calling the node API (`auth.rs` `CallerScope`, reduced to the cases
    that decide a link: node-wide, a federated tenant, or one pod). -/
inductive Scope where
  | nodeWide
  | tenant (t : Tenant)
  | pod (p : PodId)

structure Node where
  /-- Live pods and their trust domain. -/
  pods : List (PodId × Tenant)
  links : List Link
  conns : List Conn
  /-- What each pod holds of its own (abstract). -/
  secret : PodId → Nat
  /-- What each pod has received over relayed connections. -/
  inbox : PodId → List Nat
  /-- The host's decision on one request over a link (ADR 0014: the host
      decides; ADR 0015: every request is a decision). Abstract here: the
      theorems hold for ANY decision function. -/
  decide : Link → Nat → Bool

def tenantOf : List (PodId × Tenant) → PodId → Option Tenant
  | [], _ => none
  | (q, t) :: rest, p => if q = p then some t else tenantOf rest p

def Node.live (n : Node) (p : PodId) : Bool := (tenantOf n.pods p).isSome

def manages (s : Scope) (n : Node) (p : PodId) : Bool :=
  match s with
  | .nodeWide => n.live p
  | .tenant t => tenantOf n.pods p == some t
  | .pod q => n.live p && p == q

def names (p : PodId) (l : Link) : Bool := l.src == p || l.dst == p

/-! ## Receipts -/

inductive Effect where
  | link (l : Link)
  /-- An unlink, naming the connections it severed. -/
  | unlink (l : Link) (severed : List Nat)
  | connect (c : Conn)
  /-- One request over a connection, with the host's decision. -/
  | request (c : Conn) (v : Nat)
  | cancel (p : PodId)
  /-- A link dropped because a pod exited on its own. -/
  | drop (l : Link)
  deriving Repr

/-- A node-signed receipt (signature abstracted): the effect and whether the
    node did it. -/
structure Receipt where
  effect : Effect
  ok : Bool

/-! ## Transitions -/

inductive Op where
  | link (caller : Scope) (l : Link)
  | unlink (caller : Scope) (l : Link)
  /-- A guest dials the relay along `l`; the host admits or refuses. -/
  | connect (id : Nat) (l : Link)
  /-- A workload sends request `v` over connection `c`; the host decides it
      before the relay delivers a byte (owner decision 2026-11-19: links are
      per-request, so eval cells keep ADR 0015's promise). -/
  | request (c : Conn) (v : Nat)
  | cancel (caller : Scope) (p : PodId)
  /-- Environment: the pod exited without being asked to. -/
  | exit (p : PodId)

/-- The admission rule for a new link. -/
def admitLink (s : Scope) (n : Node) (l : Link) : Bool :=
  manages s n l.src && manages s n l.dst && l.src != l.dst &&
  tenantOf n.pods l.src == tenantOf n.pods l.dst && !n.links.contains l

def removePod (ps : List (PodId × Tenant)) (p : PodId) : List (PodId × Tenant) :=
  ps.filter (fun e => e.1 != p)

def step (n : Node) : Op → Node × List Receipt
  | .link s l =>
    if admitLink s n l then ({ n with links := l :: n.links }, [⟨.link l, true⟩])
    else (n, [⟨.link l, false⟩])
  | .unlink s l =>
    if n.links.contains l && manages s n l.src then
      ({ n with links := n.links.filter (· != l), conns := n.conns.filter (·.link != l) },
       [⟨.unlink l ((n.conns.filter (·.link == l)).map (·.id)), true⟩])
    else (n, [⟨.unlink l [], false⟩])
  | .connect i l =>
    if n.links.contains l then
      ({ n with conns := ⟨i, l⟩ :: n.conns }, [⟨.connect ⟨i, l⟩, true⟩])
    else (n, [⟨.connect ⟨i, l⟩, false⟩])
  | .request c v =>
    if n.conns.contains c && n.decide c.link v then
      ({ n with inbox := fun q => if q = c.link.dst then n.inbox q ++ [v] else n.inbox q },
       [⟨.request c v, true⟩])
    else (n, [⟨.request c v, false⟩])
  | .cancel s p =>
    if manages s n p && !n.links.any (names p) then
      ({ n with pods := removePod n.pods p }, [⟨.cancel p, true⟩])
    else (n, [⟨.cancel p, false⟩])
  | .exit p =>
    ({ n with pods := removePod n.pods p,
              links := n.links.filter (fun l => !names p l),
              conns := n.conns.filter (fun c => !names p c.link) },
     (n.links.filter (names p)).map (fun l => ⟨.drop l, true⟩))

/-! ## The invariant every step keeps -/

/-- Connections ride links; links join live pods of one trust domain. -/
def Inv (n : Node) : Prop :=
  (∀ c ∈ n.conns, c.link ∈ n.links) ∧
  (∀ l ∈ n.links, n.live l.src = true ∧ n.live l.dst = true ∧
    tenantOf n.pods l.src = tenantOf n.pods l.dst)

theorem tenantOf_removePod (ps : List (PodId × Tenant)) (p q : PodId) :
    tenantOf (removePod ps p) q = if q = p then none else tenantOf ps q := by
  induction ps with
  | nil => simp [removePod, tenantOf]
  | cons e rest ih =>
    obtain ⟨r, t⟩ := e
    by_cases hrp : r = p
    · subst hrp
      have : removePod ((r, t) :: rest) r = removePod rest r := by
        simp [removePod, List.filter]
      rw [this, ih]
      by_cases hqr : q = r
      · simp [hqr]
      · have : r ≠ q := fun h => hqr h.symm
        simp [hqr, tenantOf, this]
    · have hb : (r != p) = true := by simp [hrp]
      have : removePod ((r, t) :: rest) p = (r, t) :: removePod rest p := by
        simp only [removePod, List.filter, hb]
      rw [this]
      simp only [tenantOf]
      rw [ih]
      by_cases hrq : r = q
      · subst hrq; simp [hrp]
      · simp [hrq]

theorem step_inv {n : Node} (op : Op) (h : Inv n) : Inv (step n op).1 := by
  obtain ⟨hc, hl⟩ := h
  cases op with
  | link s l =>
    simp only [step]
    split
    · rename_i ha
      simp only [admitLink, Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq,
        Bool.not_eq_true'] at ha
      obtain ⟨⟨⟨⟨hs, hd⟩, _⟩, ht⟩, _⟩ := ha
      have live_of : ∀ q, manages s n q = true → n.live q = true := by
        intro q hq
        cases s with
        | nodeWide => exact hq
        | tenant t =>
          simp only [manages, beq_iff_eq] at hq
          simp [Node.live, hq]
        | pod r =>
          simp only [manages, Bool.and_eq_true] at hq
          exact hq.1
      refine ⟨fun c hcm => List.mem_cons_of_mem _ (hc c hcm), ?_⟩
      intro l' hl'
      rcases List.mem_cons.mp hl' with rfl | hm
      · exact ⟨live_of _ hs, live_of _ hd, ht⟩
      · exact hl l' hm
    · exact ⟨hc, hl⟩
  | unlink s l =>
    simp only [step]
    split
    · refine ⟨?_, ?_⟩
      · intro c hcm
        simp only [List.mem_filter, bne_iff_ne, ne_eq] at hcm ⊢
        exact ⟨hc c hcm.1, by simpa using hcm.2⟩
      · intro l' hl'
        exact hl l' (List.mem_filter.mp hl').1
    · exact ⟨hc, hl⟩
  | connect i l =>
    simp only [step]
    split
    · rename_i hin
      refine ⟨?_, hl⟩
      intro c hcm
      rcases List.mem_cons.mp hcm with rfl | hm
      · exact List.contains_iff_mem.mp hin
      · exact hc c hm
    · exact ⟨hc, hl⟩
  | request c v =>
    simp only [step]
    split <;> exact ⟨hc, hl⟩
  | cancel s p =>
    simp only [step]
    split
    · rename_i hok
      simp only [Bool.and_eq_true, Bool.not_eq_true', List.any_eq_false] at hok
      refine ⟨hc, ?_⟩
      intro l' hl'
      have ⟨h1, h2, h3⟩ := hl l' hl'
      have hfree := hok.2 l' hl'
      simp only [names, Bool.or_eq_true, beq_iff_eq, not_or] at hfree
      simp only [Node.live, tenantOf_removePod, hfree.1, hfree.2, ite_false]
      exact ⟨h1, h2, h3⟩
    · exact ⟨hc, hl⟩
  | exit p =>
    simp only [step]
    refine ⟨?_, ?_⟩
    · intro c hcm
      simp only [List.mem_filter] at hcm ⊢
      exact ⟨hc c hcm.1, hcm.2⟩
    · intro l' hl'
      simp only [List.mem_filter, Bool.not_eq_true', names, Bool.or_eq_false_iff,
        beq_eq_false_iff_ne, ne_eq] at hl'
      have ⟨h1, h2, h3⟩ := hl l' hl'.1
      simp only [Node.live, tenantOf_removePod, hl'.2.1, hl'.2.2, ite_false]
      exact ⟨h1, h2, h3⟩

/-! ## The theorems the ADR cites -/

/-- A connection exists only while its link is in the table — in every state
    reachable by steps from one that satisfies `Inv`. -/
theorem connect_only_along_links {n : Node} (h : Inv n) (op : Op) :
    ∀ c ∈ (step n op).1.conns, c.link ∈ (step n op).1.links :=
  (step_inv op h).1

/-- After an unlink, no live connection is carried by that link. -/
theorem unlink_severs (n : Node) (s : Scope) (l : Link) :
    ∀ c ∈ (step n (.unlink s l)).1.conns,
      (step n (.unlink s l)).2.all (·.ok) = true → c.link ≠ l := by
  intro c hc hok
  simp only [step] at hc hok
  split at hc
  · simp only [List.mem_filter, bne_iff_ne, ne_eq] at hc
    simpa using hc.2
  · split at hok
    · contradiction
    · simp at hok

/-- A link is made only when the caller manages both pods and both share a
    trust domain. -/
theorem no_cross_tenant_link (n : Node) (s : Scope) (l : Link)
    (hok : (step n (.link s l)).2.all (·.ok) = true) :
    manages s n l.src = true ∧ manages s n l.dst = true ∧
      tenantOf n.pods l.src = tenantOf n.pods l.dst := by
  simp only [step] at hok
  split at hok
  · rename_i ha
    simp only [admitLink, Bool.and_eq_true, beq_iff_eq] at ha
    exact ⟨ha.1.1.1.1, ha.1.1.1.2, ha.1.2⟩
  · simp at hok

/-- An API cancel of a pod some link names is refused and changes nothing. -/
theorem cancel_refuses_linked (n : Node) (s : Scope) (p : PodId)
    (hlinked : n.links.any (names p) = true) :
    (step n (.cancel s p)).2.all (·.ok) = false ∧ (step n (.cancel s p)).1 = n := by
  simp only [step, hlinked, Bool.not_true, Bool.and_false]
  simp

/-- After a pod exits on its own, no link names it and no connection rides a link
    that did. -/
theorem exit_drops_links (n : Node) (p : PodId) :
    (∀ l ∈ (step n (.exit p)).1.links, names p l = false) ∧
    (∀ c ∈ (step n (.exit p)).1.conns, names p c.link = false) := by
  simp only [step]
  constructor
  · intro l hl; simpa using (List.mem_filter.mp hl).2
  · intro c hc; simpa using (List.mem_filter.mp hc).2

/-! ## Receipts determine the table -/

/-- Replay what the receipts say happened to the link table. -/
def replay (ls : List Link) : List Receipt → List Link
  | [] => ls
  | r :: rs =>
    let ls' :=
      if r.ok then
        match r.effect with
        | .link l => l :: ls
        | .unlink l _ => ls.filter (· != l)
        | .drop l => ls.filter (· != l)
        | _ => ls
      else ls
    replay ls' rs

/-- Dropping each of `ds` in turn removes exactly the members of `ds`. -/
theorem replay_drops (ls ds : List Link) :
    replay ls (ds.map (fun l => (⟨.drop l, true⟩ : Receipt))) =
      ls.filter (fun x => !ds.contains x) := by
  induction ds generalizing ls with
  | nil =>
    simp only [List.map, replay]
    exact (List.filter_eq_self.mpr (by simp)).symm
  | cons d rest ih =>
    simp only [List.map, replay, ite_true]
    rw [ih, List.filter_filter]
    apply List.filter_congr
    intro x _
    simp only [List.contains_cons, Bool.not_or]
    by_cases hx : x = d
    · simp [hx]
    · rw [Bool.and_comm]; rfl

/-- Replaying one step's receipts onto the table before gives the table after. -/
theorem receipts_replay_links (n : Node) (op : Op) :
    replay n.links (step n op).2 = (step n op).1.links := by
  cases op with
  | link s l => simp only [step]; split <;> simp [replay]
  | unlink s l => simp only [step]; split <;> simp [replay]
  | connect i l => simp only [step]; split <;> simp [replay]
  | request c v => simp only [step]; split <;> simp [replay]
  | cancel s p => simp only [step]; split <;> simp [replay]
  | exit p =>
    simp only [step]
    rw [replay_drops]
    apply List.filter_congr
    intro x hx
    by_cases hn : names p x = true
    · simp [hn, hx]
    · have hn' : names p x = false := by simpa using hn
      simp [hn']

/-! ## Cross-pod noninterference, relative to the link graph -/

/-- What pod `q` can observe: its own holding and what it has received. -/
def view (q : PodId) (n : Node) : Nat × List Nat := (n.secret q, n.inbox q)

/-- Output consistency: what `q` observes is determined by its view. -/
theorem output_consistency (q : PodId) (n₁ n₂ : Node) (h : view q n₁ = view q n₂) :
    n₁.inbox q = n₂.inbox q := by
  simp only [view, Prod.mk.injEq] at h; exact h.2

/-- Every byte a pod receives over a link is a request the host decided: if a
    request step changes what `q` holds, the connection was live, `q` is its
    destination, and the host's decision admitted that request. -/
theorem request_is_a_decision (n : Node) (c : Conn) (v : Nat) (q : PodId)
    (hchg : (step n (.request c v)).1.inbox q ≠ n.inbox q) :
    c ∈ n.conns ∧ n.decide c.link v = true ∧ q = c.link.dst := by
  simp only [step] at hchg
  split at hchg
  · rename_i hok
    simp only [Bool.and_eq_true, List.contains_iff_mem] at hok
    by_cases hq : q = c.link.dst
    · exact ⟨hok.1, hok.2, hq⟩
    · simp [hq] at hchg
  · exact absurd rfl hchg

/-- Local respect, with the link table as the policy: if no link runs from `p`
    to `q`, no request `p` sends changes what `q` observes, whatever the host
    decides. -/
theorem noninterference_unlinked {n : Node} (h : Inv n) (p q : PodId) (c : Conn) (v : Nat)
    (hsrc : c.link.src = p) (hno : ∀ l ∈ n.links, ¬ (l.src = p ∧ l.dst = q)) :
    view q (step n (.request c v)).1 = view q n := by
  simp only [view, step]
  split
  · rename_i hok
    simp only [Bool.and_eq_true, List.contains_iff_mem] at hok
    have hq : q ≠ c.link.dst := fun hq => hno c.link (h.1 c hok.1) ⟨hsrc, hq.symm⟩
    simp [hq]
  · rfl

/-! ## Worked cases, decided by the kernel -/

def demo : Node :=
  { pods := [(1, 7), (2, 7), (3, 8)], links := [], conns := [],
    secret := fun _ => 0, inbox := fun _ => [],
    -- an example decision: requests under 1000 are admitted
    decide := fun _ v => decide (v < 1000) }

/-- Tenant 7 links its pods 1 → 2. -/
example : (step demo (.link (.tenant 7) ⟨1, 2, 80⟩)).2.all (·.ok) = true := by decide
/-- Pod 3 is in trust domain 8: even a node-wide caller cannot link across. -/
example : (step demo (.link .nodeWide ⟨1, 3, 80⟩)).2.all (·.ok) = false := by decide
/-- Tenant 7 cannot name tenant 8's pod. -/
example : (step demo (.link (.tenant 7) ⟨1, 3, 80⟩)).2.all (·.ok) = false := by decide

def linked : Node := (step (step demo (.link (.tenant 7) ⟨1, 2, 80⟩)).1 (.connect 5 ⟨1, 2, 80⟩)).1

/-- A connection rides the link; unlinking severs it and names it in the receipt. -/
example : linked.conns.length = 1 := by decide
example : (step linked (.unlink (.tenant 7) ⟨1, 2, 80⟩)).1.conns.length = 0 := by decide
/-- Cancelling a linked pod is refused; its exit drops the link instead. -/
example : (step linked (.cancel (.tenant 7) 2)).2.all (·.ok) = false := by decide
example : (step linked (.exit 2)).1.links.length = 0 := by decide
/-- A request over the link is delivered only when the host admits it. -/
example : ((step linked (.request ⟨5, ⟨1, 2, 80⟩⟩ 42)).1.inbox 2) = [42] := by decide
example : ((step linked (.request ⟨5, ⟨1, 2, 80⟩⟩ 5000)).1.inbox 2) = [] := by decide
/-- No connection, no delivery, whatever the decision. -/
example : ((step demo (.request ⟨5, ⟨1, 2, 80⟩⟩ 42)).1.inbox 2) = [] := by decide

end LinkTable
