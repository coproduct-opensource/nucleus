# Nucleus Provenance & EU AI Act Article 50

**Status:** Compliance posture. This is not a legal opinion.
**Last updated:** 2026-10-13. C2PA export was removed. The standard attestation exports now name the produced artifacts and carry a typed AI-generation marking.
**Audience:** buyer compliance teams, integration architects, channel partners.

---

## TL;DR

EU AI Act Article 50 §2 obliges providers of AI systems that generate
synthetic content to make sure the **outputs are marked in a machine-readable format**
and are detectable as artificially generated. The Article names
non-exclusive techniques: *watermarks, metadata identifications,
cryptographic methods for proving provenance and authenticity, logging
methods, fingerprints, or combinations of these.*

**Nucleus does not, by itself, mark generated content.** It produces the
signed, content-bound **provenance record** that a marking can carry, and it
exports that record in standard attestation formats. The step that embeds a
marking into the generated media belongs to the orchestrator or generating
provider. That step can be a C2PA manifest, a watermark, or a visible notice.

| Article 50 §1 technique | What nucleus provides |
|---|---|
| Cryptographic methods for proving provenance and authenticity | Per-edge Ed25519 lineage proofs, RFC 6962 Merkle inclusion proofs, witness cosignatures, and a payload binding, all in the bundle. A DSSE-signed in-toto / SLSA / Sigstore attestation whose subjects are the produced artifacts' SHA-256 digests. |
| Logging methods | An append-only signed lineage chain, signed tree heads, and content-addressed `CallSpiffeId`s. |
| Metadata identification | **Partial.** The attestation's `aiGeneration` record states the content is AI-generated and names the agent and the model providers. It travels **beside** the output and is found by the output's digest. It is not embedded in the output (see below). |
| Watermarks / fingerprints | Not provided. |

---

## What nucleus emits

### 1. The bundle

`GET /v1/jobs/{id}/bundle` on the control plane returns the bundle, and `nucleus envelope`
builds it from a lineage log. It holds the agent's payload and an envelope of signed lineage edges.
Every `ArtifactProduced` edge records the SHA-256 of the artifact's bytes in
its signed child id (`…/derived/sha256:<hex>`). `nucleus envelope-verify`,
`sdks/verifier-js` and `sdks/verifier-py` re-verify a bundle offline against
an out-of-band JWKS.

### 2. Standard attestations, bound to the outputs

There are two ways to get them:

- `nucleus envelope-export <bundle> --format in-toto|slsa|sigstore|sigstore-slsa --signing-key <pkcs8.pem> --trust-jwks <jwks>`. This verifies the bundle first and refuses to attest one that fails.
- `GET /v1/jobs/{id}/attestation?format=…` on the control plane. This is signed by the platform's own lineage key.

The output is an in-toto Statement v1 in a DSSE envelope, optionally wrapped in a Sigstore
Bundle v0.3:

- **`subject`** has one entry per produced artifact. The name is the artifact's SPIFFE id
  and the digest is the artifact bytes' SHA-256. The bundle payload is a
  further subject. A consumer holding an output file hashes it and finds the
  attestation that names it. A file that was changed matches no subject.
  An artifact whose digest the lineage did not record **refuses the export**.
  It is never silently left out.
- **`predicateType: https://nucleus.coproduct.io/agent-provenance/v2`**. Its body is
  `aiGeneration` plus the verbatim `envelope`. `aiGeneration` contains:
  - `origin: "ai-agent-under-nucleus-enforcement"`: a closed enum, so a reader that meets an unknown value fails to parse.
  - `agent`: the session-root SPIFFE id.
  - `modelProviders`: read from each model call's **signed** lineage id. An empty list means the signed lineage records no model call.
- **SLSA Provenance v1** names the same subjects. It is signed by the build platform when
  served by the control plane.

These outputs were checked with an independent verifier: `cosign verify-blob-attestation --key <pub.pem>`
verifies all four formats against the artifact file and rejects the file with
one byte changed (`no matching subject digest found`).

---

## Article 50 — line-by-line

> "Providers of AI systems, including general-purpose AI systems,
> generating synthetic audio, image, video or text content, shall
> ensure that the outputs of the AI system are marked in a
> machine-readable format and detectable as artificially generated or
> manipulated."

| Article 50 §2 phrase | What nucleus contributes | What it does not do |
|---|---|---|
| *"outputs … marked in a machine-readable format"* | A machine-readable, signed record keyed by each output's digest (`subject[].digest.sha256`), with `aiGeneration` stating AI origin | It does not put a mark **in** the output. A record beside the output is only as good as the channel that keeps the two together. |
| *"detectable as artificially generated"* | Anyone with the output bytes and the attestation can check the digest, the signature and `aiGeneration.origin` | It does not detect a copy that was re-encoded, cropped or transcoded, because the digest no longer matches. Surviving transformation is a watermark's job. |
| *"or manipulated"* | `ToolCall` / `ArtifactProduced` edges reproduce the steps, and each is signed and chained | — |

### Article 50 §6 — implementation quality

| Quality criterion | Nucleus posture |
|---|---|
| **Effective** | Tampering with an edge breaks a chained Ed25519 signature and the Merkle inclusion proof. Tampering with an output breaks its subject digest. Detection is deterministic. |
| **Interoperable** | The native JSON bundle with public verifiers (Rust, JS/wasm, Python). in-toto Statement v1 / DSSE, SLSA Provenance v1 and Sigstore Bundle v0.3 exports, verified with cosign. **No C2PA output** (see below). |
| **Robust** | Hand-rolled JWS avoids the `alg=none` family. Constant-time error oracles. Replay defences. A cosignature threshold against a single lying witness. |
| **Reliable** | Pure-Rust primitives (`ed25519-dalek`, `sha2`). A public audit charter commits to periodic skeptical reviews. |

---

## C2PA: what moved where

Nucleus previously shipped an optional C2PA export (`nucleus-envelope`
feature `c2pa`, `portcullis-core` feature `c2pa-manifest`, `nucleus-audit`
feature `c2pa-verify`). No shipping binary enabled it. Its manifest's data hash covered the
**bundle payload** as a free-standing `application/c2pa` sidecar. It never
bound to the generated media, so it did not mark an output in the
sense Article 50 means. It was removed on 2026-10-13.

| What the C2PA export offered | Where it is now |
|---|---|
| A signed provenance record | The DSSE-signed in-toto / SLSA / Sigstore attestations above, now bound to each output's digest (the C2PA export never was). |
| An explicit AI-transparency assertion | `aiGeneration` in the agent-provenance/v2 predicate. Its `origin` corresponds to C2PA's `digitalSourceType` value `trainedAlgorithmicMedia` (the IPTC digital-source-type term for content created by a trained model). |
| X.509 / COSE signing with a caller-supplied signer | **Orchestrator / provider.** Nucleus signs with Ed25519 (DSSE). A C2PA claim signer with a certificate on a C2PA trust list belongs to whoever publishes the media. |
| A format C2PA readers recognize, embedded in media | **Orchestrator / provider.** Embedding a manifest into a JPEG, PNG, MP4 or PDF is a property of the media pipeline that writes the file. |
| `nucleus-audit verify-c2pa` sidecar check | `nucleus-audit inspect-provenance` (with `verify-c2pa` as an alias). A `.c2pa` sidecar is now reported as `NOT VERIFIED: C2PA support was removed`. |

### Carrying the nucleus record into a C2PA manifest (generating side)

If your pipeline emits C2PA Content Credentials, the nucleus attestation can
ride inside them. Do this in **your** C2PA tooling, at the point where you write the
final asset:

1. **Before embedding**, hash the bytes the agent produced and find the
   nucleus attestation whose `subject[].digest.sha256` matches. Verify it with
   `cosign verify-blob-attestation --key <nucleus-pub.pem> --signature <att> --type https://nucleus.coproduct.io/agent-provenance/v2 <file>`
   (or `--bundle … --new-bundle-format` for the Sigstore form).
2. In the manifest's `c2pa.actions` assertion, record a `c2pa.created` action
   with `digitalSourceType` set to the IPTC
   `trainedAlgorithmicMedia` term, derived from `aiGeneration.origin`.
3. Add the DSSE envelope (or Sigstore bundle) **verbatim** as a custom
   assertion under a label in your own reverse-DNS namespace. Put the matched
   subject digest beside it, so a reader can tie the two together. Alternatively, attach it
   as an ingredient whose hash is the pre-embedding artifact digest.
4. Sign the manifest with your C2PA claim signer. The manifest's hard binding
   covers the **final** asset bytes. Embedding changes the file, so the
   nucleus subject digest refers to the bytes **before** embedding. That is
   why step 3 records it explicitly.

A C2PA reader then sees your signed claim. A reader who also wants the
agent-runtime evidence extracts the nucleus attestation and verifies it with
the nucleus public key, independently of the C2PA trust list.

---

## Where nucleus stops, and what to layer above

Article 50 and the Code of Practice describe a multi-layered approach.
Nucleus is one layer.

| Layer | Done by | What it proves |
|---|---|---|
| **Cryptographic provenance + logging** | Nucleus (`nucleus-envelope`, `nucleus-lineage`) | Who computed what, in what order, from what inputs, and which outputs (by digest). Anyone holding the bundle or attestation can check it. |
| **Embedded metadata marking (e.g. C2PA)** | Orchestrator / generating provider's media pipeline | That a specific media file carries a signed, embedded claim of AI origin |
| **Visible AI disclosure** | Orchestrator's frontend | A human-readable "made with AI" notice |
| **Invisible watermark** | Orchestrator's media pipeline | That the marking survives screenshot, transcoding and recompression |
| **Indirect detection / fingerprinting** | Third-party detector services | Outputs from providers that ignored Article 50 |

---

## Code of Practice alignment

The Commission's draft *Code of Practice on Transparency of AI-Generated
Content* calls for machine-readable provenance information. It cites
C2PA Content Credentials as one example and does not mandate them. Nucleus provides the
cryptographic provenance layer and the standard attestations. It does
**not** emit Content Credentials, and it makes no claim that its output alone
meets the Code. A provider that embeds credentials (see the steps above)
and also keeps the nucleus attestation has both the embedded marking and
independently verifiable runtime evidence behind it.

---

## What this document is not

This document is **not legal advice**. The EU AI Act applies to
"providers" and "deployers" under specific definitions. Whether it applies depends on
where in the value chain an organisation sits, whether the AI
system is "placed on the market" or "put into service" in the Union,
and a number of carve-outs (open-source, research, law-enforcement,
…). Whether Article 50 §2 applies to your use of nucleus, and what
you must add on top, is a question for your legal team in light of your facts.

What this document **is**: a map from the Article's technical obligations
to what nucleus emits, including where nucleus stops. If you find a gap,
please file an issue against `coproduct-opensource/nucleus`.

---

## References

- Article 50 text: *Regulation (EU) 2024/1689* Article 50 §2-§6 (effective 2026-08-02)
- Draft Code of Practice on Transparency of AI-Generated Content
- in-toto Attestation Framework, Statement v1; DSSE v1.0
- SLSA Provenance v1; Sigstore Bundle v0.3 (`sigstore/protobuf-specs`)
- IPTC Digital Source Type vocabulary (`trainedAlgorithmicMedia`)
- Penalties: Regulation (EU) 2024/1689 Article 99 §3
