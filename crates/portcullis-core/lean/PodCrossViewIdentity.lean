/-
  C2 (cross-pod noninterference), the identity surface: what SVID a pod is served
  depends on nothing another pod does.

  `PodCrossView.lean` mechanized `pods`, the first shared-mutable field. This file
  brings back the identity registry. `docs/cross-pod-view.md` excluded it because
  its code was defective: #2197 served an arbitrary registered entry, #2198 never
  drained it, and #2204 handed any connector an arbitrary cert+key. Those are now
  fixed, and the model follows the code as it ships on main:

  * A pod's identity is a pure, injective function of its id:
    `IdentityManager::pod_identity` gives `spiffe://<td>/ns/pods/sa/<pod_id>`,
    never anything derived from `spec.metadata`. (`podIdentity` below.)
  * A pod's workload-API bridge is bound to that pod's id when it is constructed,
    and the guest does not name itself. `handle_fetch_svid` serves
    `fetch_certificate(pod_identity(pod_id))` from the certificate cache, so the
    cache is the shared, pod-written state. (`served` below.)
  * `vm_registry` is written at register and at teardown, and no serving path
    reads it. Only `rebuild_registry_from_disk` and tests read it. It is in the
    model so that this is a theorem rather than an assumption:
    `local_respect_register`.

  The method is the one `PodCrossView` uses, after Nickel (OSDI 2018). Two
  unwinding conditions apply, and a deliberately coarsened relation is shown to
  break the upper one: `servedAny`, the #2197 shape, breaks local-respect.

  Mathlib-free (core `List`/`Nat` only).
-/
import PodCrossView

namespace PodCrossViewIdentity

open PodCrossView (PodId)

/-- A SPIFFE identity, by its two varying path segments. The trust domain is a
    node constant, one of the structural fields, so it is folded away. `ns = 0`
    is `pods`. Any other value stands for a non-pod namespace, such as
    `system/sa/node`. -/
structure Ident where
  ns : Nat
  sa : PodId
deriving DecidableEq, Repr

/-- `IdentityManager::pod_identity`: `ns/pods/sa/<pod_id>`. It is a pure function
    of the pod id. -/
def podIdentity (p : PodId) : Ident := { ns := 0, sa := p }

/-- Distinct pods have distinct identities. This is what makes "keyed by
    identity" mean "keyed by pod". If two pods could share a name, which is the
    pre-`pod_identity` spec-derived shape, the cache would be a cross-pod
    channel. -/
theorem podIdentity_injective (a b : PodId) (h : podIdentity a = podIdentity b) : a = b := by
  simp only [podIdentity, Ident.mk.injEq] at h
  exact h.2

/-- Certificate content, left abstract on purpose so that the theorem holds for
    every certificate. -/
abbrev Cert := Nat

/-- The identity-relevant shared state:
    * the certificate cache (`SecretManager`, newest entry first);
    * `vm_registry`, connection id to identity. -/
structure HostState where
  cache : List (Ident × Cert)
  registry : List (Nat × Ident)

/-- The most recent cached certificate for `k`. -/
def lookup (k : Ident) : List (Ident × Cert) → Option Cert
  | [] => none
  | (k', c) :: t => if k' = k then some c else lookup k t

/-- What pod `p` is served by `FETCH_SVID` on its own bridge. -/
def served (p : PodId) (σ : HostState) : Option Cert := lookup (podIdentity p) σ.cache

/-! ## Transitions a pod's lifecycle drives -/

/-- `fetch_certificate` mints and caches a certificate for pod `q`. The new entry
    shadows any older one. -/
def mint (q : PodId) (c : Cert) (σ : HostState) : HostState :=
  { σ with cache := (podIdentity q, c) :: σ.cache }

/-- `release_pod` / `forget_certificate` drops every cached entry for pod `q`. -/
def release (q : PodId) (σ : HostState) : HostState :=
  { σ with cache := σ.cache.filter (fun e => e.1 != podIdentity q) }

/-- `register_pod`: record a connection for pod `q`. -/
def register (conn : Nat) (q : PodId) (σ : HostState) : HostState :=
  { σ with registry := (conn, podIdentity q) :: σ.registry }

/-- `unregister_pod`: drop a connection. -/
def unregister (conn : Nat) (σ : HostState) : HostState :=
  { σ with registry := σ.registry.filter (fun e => e.1 != conn) }

/-! ## Lemmas -/

/-- Filtering out key `k'` leaves the lookup of any other key unchanged. -/
theorem lookup_filter_ne (k k' : Ident) (hne : k' ≠ k) (l : List (Ident × Cert)) :
    lookup k (l.filter (fun e => e.1 != k')) = lookup k l := by
  induction l with
  | nil => rfl
  | cons e t ih =>
    obtain ⟨k0, c0⟩ := e
    by_cases h0 : k0 = k'
    · subst h0
      have hk : ¬ k0 = k := hne
      simp [lookup, hk, ih]
    · have hb : (k0 != k') = true := bne_iff_ne.mpr h0
      simp only [List.filter_cons, hb, if_true, lookup]
      rw [ih]

/-! ## The two unwinding conditions -/

/-- **Output consistency (lower bound).** What `A` is served is determined by the
    cache's answer for `A`'s own identity. -/
theorem output_consistency (A : PodId) (σ₁ σ₂ : HostState)
    (h : lookup (podIdentity A) σ₁.cache = lookup (podIdentity A) σ₂.cache) :
    served A σ₁ = served A σ₂ := h

/-- **Local respect: another pod's mint.** It leaves what `A` is served
    unchanged. -/
theorem local_respect_mint (A q : PodId) (c : Cert) (σ : HostState) (hq : q ≠ A) :
    served A (mint q c σ) = served A σ := by
  have hne : ¬ podIdentity q = podIdentity A :=
    fun h => hq (podIdentity_injective q A h)
  simp [served, mint, lookup, hne]

/-- **Local respect: another pod's release.** -/
theorem local_respect_release (A q : PodId) (σ : HostState) (hq : q ≠ A) :
    served A (release q σ) = served A σ := by
  have hne : podIdentity q ≠ podIdentity A :=
    fun h => hq (podIdentity_injective q A h)
  exact lookup_filter_ne (podIdentity A) (podIdentity q) hne σ.cache

/-- **Local respect: any registry write, by any pod, A included.** No serving
    path reads `vm_registry`, so writing it changes no pod's served SVID. -/
theorem local_respect_register (A : PodId) (conn : Nat) (q : PodId) (σ : HostState) :
    served A (register conn q σ) = served A σ := rfl

theorem local_respect_unregister (A : PodId) (conn : Nat) (σ : HostState) :
    served A (unregister conn σ) = served A σ := rfl

/-! ## Cross-pod noninterference (the two-run payoff) -/

/-- **Cross-pod noninterference for identity.** Take two host states that agree
    on `A`'s cache entry. They serve `A` the same SVID, however their registries
    and every other pod's certificates differ. -/
theorem cross_pod_noninterference (A : PodId) (σ₁ σ₂ : HostState)
    (h : lookup (podIdentity A) σ₁.cache = lookup (podIdentity A) σ₂.cache) :
    served A σ₁ = served A σ₂ :=
  output_consistency A σ₁ σ₂ h

/-! ## Non-vacuity: separating witnesses, closed by `decide` -/

def σ0 : HostState := { cache := [(podIdentity 1, 100)], registry := [] }

/-- **Secret-blind.** Pod 2's certificate differs between the two runs, and pod 1
    is served the same SVID. -/
example :
    served 1 (mint 2 7 σ0) = served 1 (mint 2 999 σ0) := by decide

/-- **Non-triviality.** A pod's own mint DOES change what it is served, so
    `served` is not a constant. -/
example : served 1 (mint 1 555 σ0) ≠ served 1 σ0 := by decide

/-- **Release has teeth for its own pod.** -/
example : served 1 (release 1 σ0) ≠ served 1 σ0 := by decide

/-! ## The coarse-relation-fails guardrail

`servedAny` is the #2197 shape: the bridge serves whatever entry is newest,
whoever it belongs to. Under it, another pod's mint DOES change what pod 1 is
served, so `local_respect_mint` would be false. The per-pod key is what the
theorem stands on. -/

def servedAny (_p : PodId) (σ : HostState) : Option Cert :=
  match σ.cache with
  | [] => none
  | (_, c) :: _ => some c

example : servedAny 1 (mint 2 7 σ0) ≠ servedAny 1 σ0 := by decide

end PodCrossViewIdentity
