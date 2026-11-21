/-!
# S0008: the guest cannot choose a fixed header, in any spelling

`Pa.Egress.1` law L4: "host fixed_headers cannot be overridden by the guest:
for every fixed name the forwarded value is the operator's. A fixed header may
not be a credential, secret, framing or forwarding header." The broker code is
`header_policy` (`crates/nucleus-node/src/upstreams.rs`), which validates an
upstream's `fixed_headers` and `secret_headers` when the node starts, and
`forwarded_headers` (`crates/nucleus-node/src/broker_stream.rs`), which builds
a call's headers from the guest's proposals and the fixed set, through
`RegistryEntry::forwards_header`.

The claim, for every header policy `header_policy` accepts:

1. every fixed name is one a guest could have proposed (so not a credential,
   framing or forwarding header, whatever that rule forbids), is not the
   credential header in any case, and is not a secret name;
2. every fixed header goes out with the operator's value; and
3. no header goes out whose name equals a fixed name *ignoring ASCII case*
   with any value but the operator's. HTTP header names are case-insensitive,
   so a guest's `User-Agent` beside the operator's `user-agent` would be the
   same header with the guest's value. The Rust compares the guest's names
   with the fixed names exactly; this clause holds because a name a guest may
   propose is lower-case and every fixed name is stored lower-cased.

## A hand model, not an extraction

This claim is about the model below, not about the Rust. `nucleus-node` uses
`BTreeMap`, `BTreeSet`, `String` and closures over iterators, which Aeneas
does not translate. So a proof of this row proves the model; that the model is
the code is checked by reading the two side by side, and by the Rust tests
`fixed_and_secret_headers_are_never_the_guests`,
`a_fixed_header_reaches_the_upstream_and_a_guest_cannot_choose_it` and
`a_buffered_call_carries_the_fixed_headers_and_binds_them`.

What the model keeps, and what it abstracts:

* A name or value is its bytes, as a list of `Nat`; lower-casing is
  `u8::to_ascii_lowercase`, and `eq_ignore_ascii_case` is equality after it.
* `guest_may_propose_header` is its byte-shape test (non-empty, at most 64
  bytes, each a lower-case letter, a digit or `-`) and an arbitrary further
  test `extra`, standing for the never-proposed names and prefixes and
  `names_a_credential`. The claim holds for every `extra`.
* A map is an association list; inserting replaces the key's old entry, as a
  `BTreeMap` insert does. The guest's proposals are any list of pairs, which
  includes every `BTreeMap` the guest can send.
* Error messages are not modelled; whether a policy is refused is.

`claim` is a `def … : Prop`, not a theorem, so nothing depends on it and the
axiom audit is unaffected. It is row `S0008` of `open-statements.toml` at the
repository root; see `Statements/README.md`. Once the row is `posted`, nothing
in this module or in the claim's closure may change.
-/

namespace Statements.S0008

/-- A header name or value, as bytes. -/
abbrev Bytes := List Nat

/-- `u8::to_ascii_lowercase`. -/
def lowerByte (b : Nat) : Nat :=
  if 65 ≤ b ∧ b ≤ 90 then b + 32 else b

/-- `str::to_ascii_lowercase`, byte by byte. -/
def lower (s : Bytes) : Bytes :=
  s.map lowerByte

/-- A header token as both checks spell it: non-empty, at most 64 bytes, each
a lower-case ASCII letter, an ASCII digit or `-`. -/
def nameShape (name : Bytes) : Bool :=
  !name.isEmpty && decide (name.length ≤ 64) &&
    name.all fun b => (decide (97 ≤ b) && decide (b ≤ 122)) ||
      (decide (48 ≤ b) && decide (b ≤ 57)) || b == 45

/-- `workload_egress::guest_may_propose_header`: the byte shape, and `extra`,
the never-proposed lists and the credential-name test. -/
def guestMayPropose (extra : Bytes → Bool) (name : Bytes) : Bool :=
  nameShape name && extra name

/-- `workload_egress::header_value_admissible`. -/
def valueAdmissible (value : Bytes) : Bool :=
  decide (value.length ≤ 1024) && value.all fun b => decide (32 ≤ b) && decide (b < 127)

/-- `workload_egress::MAX_PROPOSED_HEADERS`. -/
def maxProposedHeaders : Nat := 16

/-- `HeaderPolicy`: the fixed headers by lower-case name, and the secret names. -/
structure Policy where
  fixed : List (Bytes × Bytes)
  secret : List Bytes

/-- `header_policy`'s first loop: each secret name, lower-cased, must be a
header token. -/
def secretNames : List Bytes → List Bytes → Except Unit (List Bytes)
  | names, [] => .ok names
  | names, header :: rest =>
    if !nameShape (lower header) then .error ()
    else secretNames (if lower header ∈ names then names else names ++ [lower header]) rest

/-- `header_policy`'s second loop: each fixed header, lower-cased, must be
proposable, not the credential header, not secret, carry an admissible value,
and not repeat a name in another case. -/
def fixedHeaders (extra : Bytes → Bool) (credential : Bytes) (secret : List Bytes) :
    List (Bytes × Bytes) → List (Bytes × Bytes) → Except Unit (List (Bytes × Bytes))
  | fixed, [] => .ok fixed
  | fixed, (header, value) :: rest =>
    if lower (lower header) = lower credential ∨ lower header ∈ secret ∨
        guestMayPropose extra (lower header) = false then .error ()
    else if value.isEmpty || !valueAdmissible value then .error ()
    else if (fixed.lookup (lower header)).isSome then .error ()
    else fixedHeaders extra credential secret (fixed ++ [(lower header, value)]) rest

/-- `header_policy`. -/
def headerPolicy (extra : Bytes → Bool) (credential : Bytes)
    (fixed : List (Bytes × Bytes)) (secret : List Bytes) : Except Unit Policy :=
  match secretNames [] secret with
  | .error e => .error e
  | .ok names =>
    match fixedHeaders extra credential names [] fixed with
    | .error e => .error e
    | .ok headers =>
      if headers.length > maxProposedHeaders then .error ()
      else .ok { fixed := headers, secret := names }

/-- `RegistryEntry::forwards_header`: the operator listed the name, a guest
may propose it, and it is neither the credential header, a secret nor fixed. -/
def forwardsHeader (extra : Bytes → Bool) (credential : Bytes)
    (requestHeaders : List Bytes) (policy : Policy) (name : Bytes) : Bool :=
  requestHeaders.contains name && guestMayPropose extra name &&
    !(lower name == lower credential) && !policy.secret.contains name &&
    (policy.fixed.lookup name).isNone

/-- A `BTreeMap` insert: the key's old entry, if any, is replaced. -/
def insert (map : List (Bytes × Bytes)) (entry : Bytes × Bytes) : List (Bytes × Bytes) :=
  entry :: map.filter fun old => old.1 != entry.1

/-- `forwarded_headers`: the guest's forwarded proposals with admissible
values, then the fixed headers over them. -/
def forwarded (extra : Bytes → Bool) (credential : Bytes) (requestHeaders : List Bytes)
    (policy : Policy) (guest : List (Bytes × Bytes)) : List (Bytes × Bytes) :=
  let proposed := guest.filter fun header =>
    forwardsHeader extra credential requestHeaders policy header.1 && valueAdmissible header.2
  policy.fixed.foldl insert (proposed.foldl insert [])

/-- L4, for every policy `header_policy` accepts and every guest proposal. -/
def claim : Prop :=
  ∀ (extra : Bytes → Bool) (credential : Bytes) (fixedIn : List (Bytes × Bytes))
    (secretIn : List Bytes) (policy : Policy),
    headerPolicy extra credential fixedIn secretIn = .ok policy →
      (∀ name value, (name, value) ∈ policy.fixed →
          guestMayPropose extra name = true ∧ lower name ≠ lower credential ∧
            name ∉ policy.secret) ∧
      ∀ (requestHeaders : List Bytes) (guest : List (Bytes × Bytes)),
        (∀ name value, (name, value) ∈ policy.fixed →
            (name, value) ∈ forwarded extra credential requestHeaders policy guest) ∧
        (∀ sent value, (sent, value) ∈ forwarded extra credential requestHeaders policy guest →
            ∀ name fixedValue, (name, fixedValue) ∈ policy.fixed →
              lower sent = lower name → value = fixedValue)

/-! ## The hypotheses are satisfiable

Closed instances, checked by `decide` on every build. They add no declaration,
so the statement's export is unchanged by them. Names: `ua` is `[117, 97]`,
`UA` is `[85, 65]`, `x` is `[120]`, `auth` is `[97, 117, 116, 104]`. -/

/-- The operator fixes `UA: x`; it is stored as `ua`. A guest proposing `ua`
and `UA` with its own value sends neither: `ua` is fixed, and `UA` is not a
name a guest may propose. -/
example :
    (match headerPolicy (fun _ => true) [97, 117, 116, 104] [([85, 65], [120])] [] with
      | .ok policy =>
        policy.fixed == [([117, 97], [120])] &&
          forwarded (fun _ => true) [97, 117, 116, 104] [[117, 97], [85, 65]] policy
              [([117, 97], [121]), ([85, 65], [121])] == [([117, 97], [120])]
      | .error _ => false) = true := by decide

/-- A fixed header may not be the credential header, in any case. -/
example :
    (match headerPolicy (fun _ => true) [97, 117, 116, 104] [([65, 85, 84, 72], [120])] [] with
      | .ok _ => false
      | .error _ => true) = true := by decide

end Statements.S0008
