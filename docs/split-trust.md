# Split-Trust: Run Your Own Quorum Across Failure Domains

> **One-line thesis.** With nucleus you can make it so that **no single
> machine, region, cloud account, or key store you operate can forge or
> roll back your own agent log** — and you can do this *alone*, with zero
> counterparties. The "mesh" buys you **failure-domain diversity**, not
> other organizations. Network effects are additive, never a prerequisite.

This guide consolidates the shipped nucleus trust stack into a single
deployment story for the **single-tenant operator**. Everything below uses
real commands and flags from merged crates; nothing here is aspirational
unless it is explicitly marked as a future seam.

---

## 1. The thesis: single-tenant value first

Most "trust networks" sell you on a future where *other* parties watch
*your* log. That is a real benefit — but it is a chicken-and-egg trap: the
network is worthless until enough strangers join, so the tool is worthless
on day one.

Nucleus inverts this. The trust stack is **useful to one operator with no
counterparties at all**, because the thing you are defending against is not
"a malicious peer org" — it is **your own infrastructure failing or being
compromised in a correlated way**:

- a region goes dark or its disks are silently rolled back to a snapshot,
- one cloud account's credentials leak,
- one key store (KMS/HSM) is breached or its operator is coerced,
- one machine is rooted and starts rewriting history.

If a single failure domain can rewrite or roll back your agent's execution
lineage, your provenance is only as trustworthy as your weakest box. The
fix is the same one used by HashiCorp Vault Seal HA (pick seals "unlikely
to become unavailable at the same time" — KMS keys in two cloud regions or
two providers), by Sigstore witnesses (multiple independent co-signers
defeat the log's "split-view" attack), and by MPC/threshold signing
(distribute signing authority so "security is distributed across multiple,
independent parties... in different geographic or administrative domains"):

> **Spread the trust across failure domains you control, and require a
> _quorum_ of them to agree before anything counts.**

This is the classic *"come for the tool, stay for the network"* shape, but
honest about the order: the tool stands on its own first
([cdixon, 2015](https://cdixon.org/2015/01/31/come-for-the-tool-stay-for-the-network/)).
A single nucleus node already gives you tamper-evident, signed lineage you
can verify offline. Adding your own k-of-n witnesses across regions makes
that lineage **un-rollback-able without a threshold compromise** — still
with zero external parties. Federating with *other organizations* later is
strictly additive value on top.

---

## 2. Deployment recipe

The pieces, and which shipped crate each one is:

| Capability | Crate / tool | What it buys the solo operator |
|---|---|---|
| k-of-n checkpoint co-signing | `nucleus-witness` (binary) | No single region/cloud/key can roll back your log |
| Quorum policy | `nucleus-lineage::policy` (Sigsum grammar) | Declarative `k-of-n` over *your* witnesses |
| Bundle replication | `nucleus-bundle-cas` via `nucleus bundle` | Bao-verified provenance copies across your machines |
| Federate your own domains | `nucleus-oidc-core::spiffe_federation` | `prod`/`staging`/`edge`/`ci` trust each other, no central CA |
| Auditable enrollment | `nucleus-trust-registry` (binary) | PR-rooted, transparency-logged record of which domains federate |
| Client-side verification | `nucleus-verifier-wasm` (`@coproduct/nucleus-verifier-wasm`) | Verify in-browser/Node, trusting no server |

### 2.1 Run k-of-n witnesses across diverse failure domains

A nucleus **witness** is a [C2SP `tlog-witness`](https://c2sp.org/tlog-witness)
server: it mints an Ed25519 **cosignature** over a transparency-log
checkpoint, but *only* if the checkpoint is signed by a trusted log key,
strictly extends the last checkpoint it co-signed (an RFC 6962 consistency
proof), and is not a rollback. The whole security value is in that status
matrix — a witness refuses to co-sign a forked or rolled-back log.

Run **one witness per failure domain**: different regions, different cloud
accounts, ideally different cloud providers, with each witness key in a
different key store. The invocation (from `crates/nucleus-witness/src/main.rs`):

```sh
# Witness A — e.g. AWS us-east-1, key from that account's KMS.
# Seed comes from the environment (a secret manager), NOT a flag, in prod.
export NUCLEUS_WITNESS_SEED_HEX="<32-byte ed25519 seed, hex>"

nucleus-witness \
  --bind 0.0.0.0:8443 \
  --witness-name "nucleus.witness/aws-use1" \
  --origin "myagent.log.example/prod|myagent-log|<log-pubkey-hex>"
```

Flags (all real, from the `Cli` struct):

- `--bind` — listen address. Default `0.0.0.0:8443`; bind to all
  interfaces for 6PN / k8s reachability.
- `--witness-seed-hex` / `NUCLEUS_WITNESS_SEED_HEX` — hex 32-byte Ed25519
  seed. **Load it from a secret manager / HSM / KMS, never a CLI flag** in
  production (the help text says so; a missing seed falls back to a
  loud-warning *dev* seed that must not ship).
- `--witness-name` — the C2SP `key_name` that appears in cosignature
  lines. Default `nucleus.witness/local`. Give each witness a distinct,
  region-tagged name.
- `--origin` — repeatable; format `origin|log_key_name|log_pubkey_hex`.
  This is the log (and its public key) the witness will co-sign for. With
  no `--origin`, every checkpoint returns `404` until origins are added.

On startup each witness logs its own `pubkey_hex` — record those, they go
straight into your quorum policy below.

> **State persistence caveat.** The shipped store (`store::InMemoryStore`)
> is in-memory behind the `OriginStore` trait and is **not persistent**: a
> restart resets each origin to "never seen", which would let a producer
> replay an old checkpoint as a first submission. Production MUST back the
> store with durable storage (litewitness uses sqlite); the trait boundary
> makes that a drop-in without touching the status matrix.

### 2.2 Write a Sigsum k-of-n quorum policy

A verifier enforces *how many* of your witnesses must agree. Nucleus
parses the [sigsum-go policy grammar](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md)
in `nucleus-lineage::policy`. Example **2-of-3 across three failure
domains** (paste the `pubkey_hex` each witness logged at startup):

```text
# A Sigsum-style policy: 2 of my 3 own witnesses must co-sign.
# `log` is recorded for grammar completeness (future submission routing),
# not used by the quorum evaluator.
log     <log-pubkey-hex>

witness aws-use1   <witness-A-pubkey-hex>   https://witness-a.example:8443
witness gcp-euw1   <witness-B-pubkey-hex>   https://witness-b.example:8443
witness fly-iad    <witness-C-pubkey-hex>   https://witness-c.example:8443

group   my-quorum  2  aws-use1 gcp-euw1 fly-iad
quorum  my-quorum
```

Grammar (exactly as implemented in `policy.rs`):

- `witness <name> <pubkey-hex> [url]` — a named witness, 32-byte Ed25519
  key (hex).
- `group <name> all|any|<k> <member>...` — `all` = every member,
  `any` = ≥ 1, `<k>` = ≥ *k* **distinct** members. Members may be witness
  names *or other group names* — **groups nest**, so you can express
  "(any 1 of the EU pair) AND (any 1 of the US pair)".
- `quorum <name>` — exactly one, naming the top-level group/witness that
  satisfies the whole policy.

Security properties the parser/evaluator enforce (these are the
load-bearing parts, with negative tests):

- A witness that co-signs twice **counts once** — `is_satisfied` works
  over the *set* of distinct witnesses whose cosignatures already verified.
- A decimal threshold larger than the member count is rejected **at parse
  time** (`ThresholdExceedsMembers`) — an unsatisfiable policy can never
  silently "fail open".
- The evaluator does **not** itself verify Ed25519 signatures — you must
  only feed it the names of witnesses whose cosignatures you already
  cryptographically checked (e.g. via `nucleus-lineage::cosign`). The trust
  boundary is explicit and one-directional.

### 2.3 Replicate provenance bundles across your machines

`nucleus-bundle-cas` addresses a serialized provenance `Bundle` by the
**BLAKE3 hash of its JSON bytes** and moves it over
[`iroh-blobs`](https://github.com/n0-computer/iroh) as a **bao-verified**
stream. For the solo operator this is content-addressed,
self-validating **disaster-recovery replication of your own bundles**
across your own regions/clouds: any replica's bytes self-validate against
the hash, so a corrupted or substituted copy is rejected on fetch.

Publish (serves the bytes until Ctrl-C) — from `nucleus bundle`
(`crates/nucleus-cli/src/bundle.rs`):

```sh
nucleus bundle publish ./my-session-bundle.json
# prints:
#   blake3-hash: <64 hex>
#   node-ticket: <iroh BlobTicket>
```

Fetch on another machine, then **verify provenance separately**:

```sh
nucleus bundle fetch \
  "<node-ticket>" \
  "<blake3-hash>" \
  --trust-anchor ./trust-anchor.jwks.json \
  --json
```

Positional + flag arguments (exactly as in `FetchArgs`):

- `<node_ticket>` — the iroh ticket printed by `publish`; carries the
  peer's address **out-of-band** (there is no DHT/discovery — see §3).
- `<blake3_hash>` — 64 hex chars; the bao stream is *rooted* at this hash,
  so a peer **cannot substitute other content**. (The fetcher also
  cross-checks the ticket's embedded hash against this and refuses on
  mismatch.)
- `--trust-anchor <path>` — **required** out-of-band JWKS. Byte-integrity
  is not provenance (see §3); this is the anchor `verify_bundle` runs
  against. The bundle's *embedded* JWKS is deliberately ignored.
- `--json`, `--show-payload` — output controls.

> `nucleus-bundle-cas` is a native (tokio + QUIC) transport — it is
> **server/CLI-side only and is NOT wired into the WASM/browser verifier**.

### 2.4 Federate your own trust domains (no central CA)

Run each environment — `prod`, `staging`, `edge`, `ci` — as its **own
SPIFFE trust domain with its own authority**, then let them accept each
other's workload identities with **no central CA**.
`nucleus-oidc-core::spiffe_federation` is the **inbound** side: it consumes
a foreign domain's trust bundle and validates inbound JWT-SVIDs minted by
that domain.

The binding *trust-domain → (bundle-endpoint URL, profile)* is **operator-
supplied and out-of-band** (a `[[federates_with]]` config row), because the
SPIFFE Federation spec states this binding "cannot be securely inferred":

```toml
# prod accepts CI's workloads. None of these fields is ever derived from a
# token or from each other.
[[federates_with]]
trust_domain        = "ci.example.org"
bundle_endpoint_url = "https://ci.example.org/spiffe-bundle"
profile             = "https_web"   # the only profile implemented
```

What this module does and does not do (honest scope, from the module
docs):

- **Inbound only** — it consumes foreign bundles and verifies foreign
  JWT-SVIDs; it does **not** mint or serve your own bundle.
- **`https_web` profile only** — bundles are fetched over ordinary Web-PKI
  TLS (RFC 6125 server-cert validation). There is no `https_spiffe`
  profile, no x509-svid path, and no SPIFFE Workload API client.
- **JWT-SVID only**, with an **algorithm allowlist** (RS256/384/512,
  ES256/384, PS256/384/512). EdDSA/Ed25519 and `none` are out of spec for
  JWT-SVID and rejected; `ES512`/P-521 is spec-eligible but rejected
  because the pinned `jsonwebtoken` backend lacks P-521 (a dependency gap,
  fail-closed, not a security choice).
- **Anti-rollback hardening beyond the spec** — the spec only *SHOULD*
  compare `spiffe_sequence`; nucleus makes it a **MUST**: a fetched bundle
  whose sequence is not strictly greater than the last accepted is
  rejected, and the current good key set is **kept** (fail-safe — never
  blanked on a fetch error or rollback). This closes a key-rollback attack,
  which is exactly the failure-domain-diversity property at the identity
  layer.

### 2.5 Record which domains federate, auditably

`nucleus-trust-registry` is a **PR-rooted, GitHub-OIDC-attested,
transparency-logged SPIFFE federation-enrollment registry**. It records
which trust domains you federate with, who attested each, and produces a
deterministic federation set that feeds the §2.4 validator
(`FederationStore`), plus an append-only, witness-cosigned transparency log
of every binding.

For the solo operator, the immediate real use is enrolling your **own**
domains (`prod`/`staging`/`edge`/`ci`). Repo layout:

```text
registry/
  .github/CODEOWNERS                 # path-scoped per-domain ownership
  domains/
    <trust-domain>/
      bundle.json     # SPIFFE bundle = JWK Set + spiffe_sequence
      metadata.toml   # trust_domain, owner_github_org, owner_id (numeric),
                      # bundle_endpoint_url, profile = "https_web"
```

Enrollment is a pull request; the verifier binary runs as a fail-closed
gate, compiles the set, and seals the log:

```sh
nucleus-trust-registry verify-pr   # fail-closed PR enrollment gate
nucleus-trust-registry compile     # deterministic federation set
nucleus-trust-registry log-append  # append binding + seal cosigned STH
```

(The OIDC token *request* is enroller-side workflow config in
`.github/workflows/trust-registry.yml`; the binary is the *verifier*.)

### 2.6 Verify with the in-browser WASM verifier (trust no server)

`nucleus-verifier-wasm` ships the **same Rust verifier compiled to WASM**,
so anyone — including you — can verify a bundle in the browser or Node
**without trusting any hosted service, network path, or operator**. A
hosted verifier service is convenience; this is the trust root.

```ts
import init, { verifyBundle } from "@coproduct/nucleus-verifier-wasm";

await init();                                   // once per page
const bundle = await fetch("/your-bundle.json").then(r => r.text());
const trustAnchor = JSON.stringify({
  trust_jwks: { keys: [/* your OUT-OF-BAND JWKS — never the bundle's */] },
  // Optional knobs (real fields):
  // trusted_witnesses_hex: ["<witness-A-hex>", "<witness-B-hex>", "..."],
  // cosignature_threshold: 2,        // enforce your k-of-n at verify time
  // require_payload_binding: true,
});
const report = verifyBundle(bundle, trustAnchor);   // throws on failure
```

Note the `trusted_witnesses_hex` + `cosignature_threshold` knobs: this is
where your **k-of-n quorum (§2.2) is enforced at the point of
verification** — the verifier rejects a bundle that lacks a threshold of
cosignatures from witnesses you trust.

There is a self-contained **in-browser tamper demo** (`demo.html`) that
verifies a *real* execution-lineage bundle entirely client-side, then lets
you corrupt it and watch the local verifier reject it. To prove there is
no server round-trip, you can toggle DevTools → Offline and it still works:

```sh
cargo run -p nucleus-envelope --example emit_demo_bundle   # real fixtures
wasm-pack build sdks/verifier-js --target web --release    # build WASM
python3 -m http.server -d sdks/verifier-js 8000            # serve
# -> http://localhost:8000/demo.html
```

---

## 3. Honest framing (read this before you pitch it)

These caveats are not fine print — they are the difference between a
credible system and an overclaim. Each is enforced or documented in the
shipped code.

- **Value = failure-domain diversity, NOT other organizations.** A quorum
  of *your own* witnesses across regions/clouds/key-stores already gives
  you the un-rollback property with zero counterparties. Federating with
  other orgs is additive, never required. Do not sell the network effect as
  a prerequisite.

- **`fetched != trusted` (transport integrity ⊥ provenance).** A perfect
  BLAKE3 hash match guarantees you got *exactly the bytes the publisher
  served* — it says **nothing** about *who* produced them or whether they
  are policy-valid. A hash-perfect fetch can still FAIL
  `nucleus_envelope::verify_bundle` (e.g. forged/unknown issuer). You must
  always run `verify_bundle` with an **out-of-band** trust anchor. This is
  why `nucleus bundle fetch` makes `--trust-anchor` mandatory.

- **A BLAKE3 transport hash is not a CID** and is **distinct from** the
  envelope's SHA-256 canonical hash. Don't conflate them or treat the
  transport id as IPLD/IPFS-interoperable.

- **The system is non-custodial — a registry + verifier, NOT a CA.** The
  trust registry *records, distributes, and verifies* trust-domain → JWK-Set
  bindings. It is **never** a certificate authority and **never** holds a
  private key: it does not mint keys, sign on behalf of enrolled domains,
  or hold any private material. Each domain runs its own SPIFFE authority;
  the registry only pins the public JWK Set that domain publishes.

- **OIDC proves GitHub-ORG control, not trust-domain ownership.** The
  registry's GitHub Actions OIDC proof-of-control proves the enrolling PR
  ran in a repo owned by the GitHub org whose **numeric** `owner_id` is
  pinned (the numeric pin defeats org-rename squatting). It does **not**
  prove you own the SPIFFE trust-domain *name*. A DNS-01-style
  trust-domain proof is a v2 item.

- **Auditable ≠ un-backdoorable, and the MVP registry trust base is thin.**
  The transparency log makes a misbehaving maintainer *detectable*, not
  *impossible*: a binding counts only if its leaf is in a witness-cosigned
  Signed Tree Head, so an out-of-band insertion that never entered the
  cosigned log is rejected and bundle tampering breaks the inclusion proof
  — but a maintainer colluding with the witness can still enroll a binding.
  The MVP registry trust base is a **single maintainer + single witness**;
  there is no threshold signing or key ceremony there yet (adding witnesses
  is a drop-in). This is *separate* from the §2.1–2.2 log witnesses, which
  you should already run k-of-n.

- **Integrity-axis verification scope (the theorem).** The merged Lean
  noninterference theorem is proven over the **Aeneas-extracted enforcement
  core** (extracted from the real Rust in
  `crates/portcullis-core/src/extracted/ifc_integrity.rs`) and its
  `#print axioms` audit is `[propext, Classical.choice, Quot.sound]` — no
  `sorryAx`, no opaque external axiom. But its scope is the **integrity
  axis** (Biba "no read-down / no write-up" for integrity), not
  confidentiality, and it bounds the *enforcement model*. The WASM verifier
  proves lineage is **tamper-evident** (hash chain + Merkle inclusion) and
  **authentic** (signed/cosigned by keys in *your* trust anchor). Neither
  proves the agent *behaved well*, that confidentiality held, or that any
  computation was correct — those are separate guarantees. Do not claim
  end-to-end correctness.

- **A metered tier exists only as a dormant seam — there is no payment
  today.** A valid cosignature (witness), a verified-byte fetch
  (bundle-cas), and a cross-domain validation (federation) are each natural
  units of *proven work*, documented as future metering points for a
  possible **parallel paid tier** (priced by nucleus's verified VCG/Pigou
  clearing, settled over x402/L402). **None of that billing logic exists:
  no payment, no accounting, no token, no counter is wired anywhere.** The
  seams are documented only so a future paid tier is additive, not a
  rewrite — and per the Tor lesson, any such tier would meter *only* proven
  work and run *alongside* (never tax) the volunteer commons. C2SP itself
  flags witness funding as an unsolved open problem; this is one possible
  answer, not a settled one.

---

## 4. Why this beats hand-edited SPIRE federation config or a single log

**vs. a single trusted log.** A lone transparency log is vulnerable to the
"split-view" attack — a compromised log can present different signed tree
heads to different clients and rewrite history without breaking its own
consistency proofs. The standard defense (Sigstore, the
[C2SP witness protocol](https://c2sp.org/tlog-witness)) is multiple
independent witnesses that co-sign tree heads. Nucleus lets you *be* those
witnesses across your own failure domains, and enforce a `k-of-n` quorum at
verify time. One compromised box can no longer rewrite your history; an
attacker needs a **threshold** compromise spanning regions/clouds/key-stores.

**vs. hand-edited SPIRE federation config.** Plain SPIRE federation is a
set of YAML `federates_with` entries, hand-maintained, with the trust-
domain → bundle-endpoint binding sitting in config files that nobody
co-signs and nothing logs. Nucleus keeps SPIRE's actual federation
mechanism (SPIFFE bundle endpoints, the `https_web` profile, JWT-SVID
validation — it reuses the spec, it doesn't reinvent it) but adds three
things a raw config file can't give you:

1. **An auditable, append-only enrollment record** — every binding is a PR
   with GitHub-OIDC proof-of-control (numeric-`owner_id` pinned against
   rename squatting) and lands in a **witness-cosigned transparency log**,
   so a silently-added or backdated federation entry is *detectable*.
2. **Spec-exceeding anti-rollback** — the inbound validator makes the
   `spiffe_sequence` monotonicity check a **MUST** and keeps the last-good
   key set on any rollback or fetch error, closing a key-rollback hole the
   spec leaves as a *SHOULD*.
3. **A deterministic, reproducible federation set** — `compile` produces
   the same set from the same registry, instead of relying on whatever a
   human last edited into a YAML file.

The net: SPIRE gives you the *plumbing*; nucleus gives you the **evidence**
that the plumbing wasn't quietly re-wired — and it does so non-custodially,
across failure domains you already control, before any second organization
is involved.

---

## Sources & references

- "Come for the tool, stay for the network" — [cdixon (2015)](https://cdixon.org/2015/01/31/come-for-the-tool-stay-for-the-network/)
- HashiCorp Vault Seal HA / auto-unseal across regions+providers — [Vault Seal concepts](https://developer.hashicorp.com/vault/docs/concepts/seal), [Transit auto-unseal best practices](https://developer.hashicorp.com/vault/docs/configuration/seal/transit-best-practices)
- Sigstore witnesses & the log split-view attack — [Sigstore security model](https://docs.sigstore.dev/about/security/), [witnessing Sigstore](https://su3.io/posts/witnessing-sigstore-from-ethereum)
- SPIRE / SPIFFE federation (bundle endpoints, single-server SPOF) — [SPIRE server config](https://spiffe.io/docs/latest/deploying/spire_server/), [scaling SPIRE](https://spiffe.io/docs/latest/planning/scaling_spire/)
- MPC / threshold signing "no single point of failure" framing — [CertiK: What is MPC](https://www.certik.com/resources/blog/what-is-multi-party-computation-mpc), [Fireblocks: MPC vs multi-sig](https://www.fireblocks.com/blog/mpc-vs-multi-sig)
- C2SP `tlog-witness` spec — [c2sp.org/tlog-witness](https://c2sp.org/tlog-witness)
- Sigsum policy grammar — [sigsum-go policy doc](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md)
