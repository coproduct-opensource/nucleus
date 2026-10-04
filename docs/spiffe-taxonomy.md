# The SPIFFE taxonomy

Every authority nucleus derives from a SPIFFE ID is read from its string, by a
prefix test, a split on `/`, an exact comparison. Each of those readings is
sound for exactly one spelling of an ID. This page states that spelling, what
each level of an ID means, and the five properties that keep authority
narrowing as an ID gets longer. `crates/nucleus-node/src/spiffe_walk.rs` checks
them, exhaustively, up to a bound.

## The grammar

```text
spiffe-id     = "spiffe://" trust-domain 1*( "/" segment )      ; ≤ 2048 bytes
trust-domain  = 1*255( %x61-7A / DIGIT / "." / "-" )             ; a-z 0-9 . -
segment       = 1*( ALPHA / DIGIT / "." / "-" / "_" )            ; never "." or ".."
```

This is the SPIFFE ID specification with two narrowings:

- **The trust domain is a DNS name.** SPIFFE allows `_`; nucleus refuses it,
  since every trust domain nucleus issues for is a DNS name. Uppercase is
  refused, never folded.
- **An ID names a workload.** A bare trust domain (`spiffe://td`) is not one.

Everything else is refused, and refused rather than normalised: a trailing or
doubled `/`, `.` and `..`, percent-encoding (`%2F`, `%2E`), a port, userinfo, a
query, a fragment, `;`, whitespace, NUL, any non-ASCII byte (so no confusable),
any other scheme or scheme casing. One ID has exactly one accepted spelling.

The one exception is `wimse://`, which `CallSpiffeId::from_wimse_uri` reads as
the `spiffe://` ID with the same bytes after the scheme. It is the same ID, so it
carries the same authority.

## The levels

| Level | Shape | What it means |
|---|---|---|
| Trust domain | `spiffe://<td>` | The tenant ([ADR 0001](adr/0001-trust-domain-tenancy.md)). The node's own trust domain, or a federated tenant's. Nothing in one trust domain holds anything in another. |
| Namespace | `/ns/<ns>` | The class of principal: `system` (the node, `sa/node`; the operator, `sa/cli`), `pods` (pods the node minted), `default` and `workstream-kg` (orchestrators), `github` (CI/CD), or a federated binding's label (in the tenant's trust domain). |
| Account | `/sa/<sa>` | The principal. A pod's is its uuid, in lowercase hyphenated form only. |
| Below the account | `/<segment>...` | Belongs to the account: a CI identity's `<owner>/<repo>/refs/<ref>`, a lineage call. Never a principal of its own with more reach. |
| Call | `/call/<uuid>/(tool/<t> \| llm/<p>/<dir> \| derived)[/sha256:<hex>]` | A lineage child (`nucleus-lineage`): the call made by the ID above it. `call` is reserved (any other casing is refused); the uuid is lowercase hyphenated; `sha256:<64 lowercase hex>` is the one segment that may hold `:`. |

A principal is an ID of the shape `ns/<ns>/sa/<sa>[/...]`; nothing shorter
holds authority.

## The properties

1. **Canonical form.** Each parser accepts exactly the grammar (or its stated
   narrowing of it), and returns what it accepted unchanged. A refused spelling
   holds nothing.
2. **Segment boundary.** A grant is a path prefix that ends where a segment
   ends. A grant for `…/ns/a/` never matches `…/ns/ab/…`; `spiffe://td` never
   matches `spiffe://td.evil` or `spiffe://tdx`. Every prefix site enforces it:
   the node's grants (`auth::id_under`), a JWT-SVID subject prefix (refused at
   configuration unless it ends in `/`), a federation rule (a wildcard only as
   `/*`). A relying party outside nucleus that admits on a prefix condition must
   write it the same way: the trust domain followed by `/`.
3. **Monotonicity.** Below a principal, a descendant never holds more than its
   ancestor: not a longer path, not a lineage call, not a delegated child pod,
   whose certificate's authority is the meet of its request and its parent's.
   A descendant reaches no sibling and no ancestor. A CI identity reaches the
   pods it created; a descendant CI identity reaches its own, never its
   ancestor's or its sibling's.
4. **Trust-domain isolation.** An ID in another trust domain holds nothing. A
   federated tenant holds pod management over the pods rooted in its own trust
   domain and nothing else; the node's own trust domain is never a tenant.
5. **Agreement.** Every parser of an ID agrees with every other, pairwise, on
   accept or reject and on the fields it reads, wherever both are defined.

## The parsers and matchers

| Site | Reads |
|---|---|
| `nucleus_identity::Identity::from_spiffe_uri` | Every peer certificate's URI SAN (`spiffe_uri_from_svid`), every CSR's. Principals only. |
| `nucleus_lineage::CallSpiffeId::parse` | Lineage IDs, OIDC subjects (`nucleus-oidc-provider`, the CI and runner identities). Also on deserialization. |
| `nucleus_oidc_core::spiffe_federation::SpiffeId::parse` | Federated JWT-SVID subjects; the control plane's subject check. |
| `portcullis::identity::ParsedSpiffeId::parse` | Policy tooling. |
| `nucleus-node` `auth` (`id_under`, `pod_id_from_spiffe`, `federated_tenant`) | Operator, orchestrator, CI, pod and tenant grants. |
| `nucleus-node` `federation_ingress::principal_of` | A federated `sub` → `spiffe://<tenant>/ns/<label>/sa/<encoded sub>`, injective. |
| `nucleus-control-plane-server` subject prefix | `has_prefix` (Lean-extracted) over a canonical subject. |
| `nucleus-oidc-provider` federation rules | Exact ID, or `<prefix>/*`. |

## The walk

The walk generates every path of up to four segments over the taxonomy's own
words with at most one adversarial segment (empty, `.`, `..`, `%2F`, `%2E`,
`;`, `?`, `#`, `@`, `:`, NUL, whitespace, a Cyrillic and a fullwidth
confusable, other casings, other uuid spellings, and boundary probes such as
`defaultx`); every adversarial trust domain (case, port, userinfo,
`td.example.evil`, `td.examplex`, confusables, 255 and 256 bytes) under a set of
principals; every re-spelling of those principals; and IDs of exactly 2048 and
2049 bytes. Each parser is held to the oracle (`spiffe_walk/model.rs`, written
from this page), the parsers to each other pairwise, and the node's grants to
the rules above. Descendants are walked one hop below every bounded principal,
through four generations of lineage calls, and through every chain of four
delegated child pods over a set of lattices. Seeded mutations (a prefix test
without its `/`, case folding, accepting `..` or `%2F`, a child keeping its
request instead of the meet) each turn it red: `scripts/spiffe-walk-mutants.sh`.
