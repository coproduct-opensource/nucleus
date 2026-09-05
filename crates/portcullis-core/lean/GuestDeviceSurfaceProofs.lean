/-!
# Guest device surface and `pci=off` closure  (PROVED — 0 proof-holes, 0 extra axioms)

Tokenised model of two guest-side invariants of `nucleus-node/src/firecracker_config.rs`
(#2603, part of the #2558 isolation-surface programme):

1. **`enforce_pci_off`** (`firecracker_config.rs`, the `pci=off` floor): strip every
   `pci=` token from the kernel command line and append `pci=off`. Modelled over a
   token type rather than `String` — Aeneas string support is weak, and the property
   is about tokens, not characters. The Rust proptest
   `enforce_pci_off_agrees_with_the_token_model` pins the shipped string function to
   `Cmdline.enforce` below.
2. **The device surface**: Firecracker is told to attach exactly six device classes
   (`firecracker_device_surface_is_exactly_pinned`). Modelled as a finite `Device`
   enum and a `Config` whose optional attachments are the ones `from_spec` may omit
   (`network-interfaces` when there is no net plan, `vsock` when the spec has none).

Mathlib-free; same discipline as `SessionCeilingProofs`.
-/

namespace GuestDeviceSurface

/-! ## Part 1 — the tokenised command line -/

/-- The value of a `pci=` token. Anything other than the literal `off` is `on`
    from the posture's point of view: only `off` is the hardened value. -/
inductive PciVal where
  | off
  | on
  deriving DecidableEq, Repr

/-- One whitespace-separated command-line token: either a `pci=` assignment or
    anything else (`console=ttyS0`, `init=/init`, `quiet`, …), kept opaque. -/
inductive Tok where
  | pci (v : PciVal)
  | other (s : String)
  deriving DecidableEq, Repr

namespace Tok

/-- `tok.starts_with("pci=")` in the Rust. -/
def isPci : Tok → Bool
  | pci _   => true
  | other _ => false

@[simp] theorem isPci_pci (v : PciVal) : isPci (pci v) = true := rfl
@[simp] theorem isPci_other (s : String) : isPci (other s) = false := rfl

end Tok

/-- A command line is its token list. -/
abbrev Cmdline := List Tok

namespace Cmdline

/-- `enforce_pci_off`: drop every `pci=` token, then append `pci=off`. -/
def enforce (args : Cmdline) : Cmdline :=
  args.filter (fun t => !t.isPci) ++ [Tok.pci PciVal.off]

/-- `from_spec`'s later appends (`nucleus.*=` settings, `ipv6.disable=1`, the
    net plan) never mention `pci=`: this is what "safe to append after the floor"
    means. -/
def PciFree (args : Cmdline) : Prop := ∀ t ∈ args, t.isPci = false

/-- The filter half of `enforce` yields a `pci`-free prefix. -/
theorem filter_pciFree (args : Cmdline) :
    PciFree (args.filter (fun t => !t.isPci)) := by
  intro t ht
  have := List.mem_filter.mp ht
  cases t with
  | pci v => simp at this
  | other s => rfl

/-- A `pci`-free list is unchanged by the filter. -/
theorem filter_of_pciFree (args : Cmdline) (h : PciFree args) :
    args.filter (fun t => !t.isPci) = args := by
  induction args with
  | nil => rfl
  | cons t ts ih =>
    have ht : t.isPci = false := h t (List.mem_cons_self ..)
    have hts : PciFree ts := fun u hu => h u (List.mem_cons_of_mem _ hu)
    simp [ht, ih hts]

/-- **(A) Idempotence** — `enforce ∘ enforce = enforce`. Running the floor twice
    hands the kernel the same line: one `pci=off`, at the end. -/
theorem enforce_idem (args : Cmdline) : enforce (enforce args) = enforce args := by
  unfold enforce
  rw [List.filter_append, filter_of_pciFree _ (filter_pciFree args)]
  simp

/-- **(B) `pci=off` is present** after the floor, whatever the spec supplied. -/
theorem pciOff_mem_enforce (args : Cmdline) : Tok.pci PciVal.off ∈ enforce args := by
  unfold enforce
  exact List.mem_append_right _ (List.mem_singleton.mpr rfl)

/-- **(C) `pci=on` is absent** after the floor: a spec-supplied `pci=on` (or any
    non-`off` value) is stripped, not honoured. -/
theorem pciOn_not_mem_enforce (args : Cmdline) : Tok.pci PciVal.on ∉ enforce args := by
  unfold enforce
  intro h
  rcases List.mem_append.mp h with h | h
  · have := (List.mem_filter.mp h).2
    simp at this
  · simp at h

/-- **(D) Exactly one `pci=` token survives**, and it is `pci=off`: every `pci`
    token of the output is `pci=off`, and there is exactly one of them
    (`count = 1`), so the kernel is never handed two values. -/
theorem filter_isPci_of_pciFree (l : Cmdline) (h : PciFree l) : l.filter Tok.isPci = [] := by
  induction l with
  | nil => rfl
  | cons t ts ih =>
    have ht : t.isPci = false := h t (List.mem_cons_self ..)
    have hts : PciFree ts := fun u hu => h u (List.mem_cons_of_mem _ hu)
    simp [ht, ih hts]

theorem enforce_pci_tokens (args : Cmdline) :
    (enforce args).filter Tok.isPci = [Tok.pci PciVal.off] := by
  unfold enforce
  rw [List.filter_append, filter_isPci_of_pciFree _ (filter_pciFree args)]
  simp

theorem enforce_count_pciOff (args : Cmdline) :
    (enforce args).count (Tok.pci PciVal.off) = 1 := by
  unfold enforce
  rw [List.count_append, List.count_singleton_self]
  have h : (args.filter (fun t => !t.isPci)).count (Tok.pci PciVal.off) = 0 := by
    rw [List.count_eq_zero]
    intro hmem
    have := (List.mem_filter.mp hmem).2
    simp at this
  omega

/-- **(E) The floor survives `from_spec`'s later appends.** Everything appended
    after `enforce_pci_off` (`nucleus.approval_pubkeys=…`,
    `nucleus.workload_api_port=…`, the audit-sink settings) is `pci`-free, so
    (B) and (C) hold of the line the kernel finally sees. -/
theorem pciOff_mem_enforce_append (args extra : Cmdline) :
    Tok.pci PciVal.off ∈ enforce args ++ extra :=
  List.mem_append_left _ (pciOff_mem_enforce args)

theorem pciOn_not_mem_enforce_append (args extra : Cmdline) (h : PciFree extra) :
    Tok.pci PciVal.on ∉ enforce args ++ extra := by
  intro hmem
  rcases List.mem_append.mp hmem with hmem | hmem
  · exact pciOn_not_mem_enforce args hmem
  · have := h _ hmem
    simp at this

/-- Appending `pci`-free tokens after the floor and re-running the floor changes
    nothing but token order: the same multiset of non-`pci` tokens and one
    `pci=off`. Stated as: re-enforcing an already-enforced-then-appended line is
    the enforced line with the extras spliced before the trailing `pci=off`. -/
theorem enforce_append_pciFree (args extra : Cmdline) (h : PciFree extra) :
    enforce (enforce args ++ extra) =
      args.filter (fun t => !t.isPci) ++ extra ++ [Tok.pci PciVal.off] := by
  unfold enforce
  rw [List.filter_append, List.filter_append, filter_of_pciFree _ (filter_pciFree args),
      filter_of_pciFree _ h]
  simp

end Cmdline

/-! ## Part 2 — the device surface -/

/-- The six device classes Firecracker may be told to attach: the JSON object
    keys of the serialised `FirecrackerConfig`. Finite by construction — adding a
    variant here is the only way to widen the surface. -/
inductive Device where
  | bootSource
  | drives
  | machineConfig
  | networkInterfaces
  | vsock
  | logger
  deriving DecidableEq, Repr

/-- The pinned surface: what `firecracker_device_surface_is_exactly_pinned`
    asserts of a maximal pod. -/
def pinned : List Device :=
  [Device.bootSource, Device.drives, Device.machineConfig,
   Device.networkInterfaces, Device.vsock, Device.logger]

/-- Every `Device` is in the pinned list — the enum IS the surface. -/
theorem mem_pinned (d : Device) : d ∈ pinned := by
  cases d <;> simp [pinned]

/-- What `from_spec` may vary: the two attachments it serialises conditionally
    (`network-interfaces` is `skip_serializing_if = "Vec::is_empty"`, `vsock` is
    `skip_serializing_if = "Option::is_none"`). `boot-source`, `drives`,
    `machine-config` are unconditional fields; `logger` is always `Some` in
    `from_spec`. -/
structure Config where
  hasNet   : Bool
  hasVsock : Bool
  deriving DecidableEq, Repr

/-- The device classes the serialised config names, in JSON-key order. -/
def Config.devices (c : Config) : List Device :=
  [Device.bootSource, Device.drives] ++
  [Device.machineConfig] ++
  (if c.hasNet then [Device.networkInterfaces] else []) ++
  (if c.hasVsock then [Device.vsock] else []) ++
  [Device.logger]

/-- The maximal pod of the Rust test: every optional device present. -/
def Config.maximal : Config := ⟨true, true⟩

/-- **(F) `devices(from_spec maximal) = pinned`** — the Rust assertion, as a
    theorem over the model. -/
theorem devices_maximal : Config.maximal.devices = pinned := by
  decide

/-- **(G) Closure**: no configuration names a device outside the pinned six —
    `from_spec` can only ever *omit* an optional class, never add one. -/
theorem devices_subset_pinned (c : Config) : ∀ d ∈ c.devices, d ∈ pinned :=
  fun d _ => mem_pinned d

/-- **(H) The mandatory core is always present**: boot source, drives, machine
    config and the logger are named by every configuration. -/
theorem mandatory_mem_devices (c : Config) :
    Device.bootSource ∈ c.devices ∧ Device.drives ∈ c.devices ∧
    Device.machineConfig ∈ c.devices ∧ Device.logger ∈ c.devices := by
  cases c with
  | mk n v => cases n <;> cases v <;> decide

/-- **(I) Firecracker pods always have vsock**: `spawn_firecracker_pod` requires
    `spec.vsock`, so on the live path `hasVsock = true` and the vsock device is
    named — the identity channel is never silently absent. -/
theorem vsock_mem_devices (c : Config) (h : c.hasVsock = true) :
    Device.vsock ∈ c.devices := by
  cases c with
  | mk n v => subst h; cases n <;> decide

/-- Nothing but the two optional classes can distinguish two configurations. -/
theorem devices_inj (c₁ c₂ : Config) (h : c₁.devices = c₂.devices) : c₁ = c₂ := by
  cases c₁ with
  | mk n₁ v₁ => cases c₂ with
    | mk n₂ v₂ => cases n₁ <;> cases v₁ <;> cases n₂ <;> cases v₂ <;> first | rfl | (exfalso; simp [Config.devices] at h)

end GuestDeviceSurface
