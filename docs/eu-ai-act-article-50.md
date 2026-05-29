# Nucleus Provenance & EU AI Act Article 50

**Status:** Compliance posture — not a legal opinion.
**Last updated:** 2026-05-28.
**Audience:** buyer compliance teams, integration architects, channel partners.

---

## TL;DR

EU AI Act Article 50 obliges providers of AI systems that generate
synthetic content to mark outputs in a **machine-readable format** so
they are detectable as artificially generated. The Article lists six
non-exclusive techniques: *watermarks, metadata identifications,
cryptographic methods for proving provenance and authenticity, logging
methods, fingerprints, or combinations of these.*

Nucleus envelopes provide **two of the six** named techniques out of the
box:

| Article 50 §1 technique | Nucleus surface |
|---|---|
| Cryptographic methods for proving provenance and authenticity | Per-edge Ed25519 proofs + RFC 6962 Merkle tree inclusion proofs + C2SP witness federation |
| Logging methods | Append-only signed lineage chain + signed tree heads + content-addressed CallSpiffeIds |

A C2PA v2.3 manifest emitted via `Bundle::export_c2pa_manifest_*`
(feature `c2pa`) carries the same evidence in the standard format the
European Commission's draft *Code of Practice on Transparency* names
*by example* for satisfying Article 50.

Nucleus does **not** do pixel-level invisible watermarking. The draft
Code of Practice calls for a multi-layered approach combining
cryptographic provenance *and* pixel-level marks; nucleus is the
upstream cryptographic layer, and downstream watermarking is the
caller's responsibility (and a complementary product in the
content-provenance market).

---

## Deadline

**2026-08-02.** Article 50 transparency obligations take effect on this
date. Penalties for non-compliance reach **EUR 15M or 3% of worldwide
annual turnover**, whichever is higher (Article 99 §3, in conjunction
with Article 50 §4).

Action items by integration stage:

| Stage | What ships before 2026-08-02 |
|---|---|
| Already on nucleus | Default bundles satisfy Article 50 §2's "machine-readable + detectable" hook today — no migration required. |
| Adding nucleus this quarter | Wire the control plane's `/v1/jobs/{id}/bundle` into your AI-output pipeline; emit alongside the synthetic content; archive. |
| Need C2PA interop | Build with `--features c2pa`; call `Bundle::export_c2pa_manifest_*`; ship the resulting `.c2pa` manifest alongside the output. |

---

## Article 50 — line-by-line mapping

Article 50 §2 (the relevant clause for generative AI):

> "Providers of AI systems, including general-purpose AI systems,
> generating synthetic audio, image, video or text content, shall
> ensure that the outputs of the AI system are marked in a
> machine-readable format and detectable as artificially generated or
> manipulated."

The Commission's draft guidelines (2026-05-08, public consultation
through 2026-06-03) clarify that "machine-readable format" includes
embedded content credentials and cryptographic provenance records.

### Mapping table

| Article 50 §2 phrase | Bundle field that satisfies it |
|---|---|
| *"marked in a machine-readable format"* | `Bundle.envelope.session_root` (canonical SPIFFE URI marking the producing agent identity) + `Bundle.payload` (the synthetic content) bound together via `canonical_bundle_hash` |
| *"detectable as artificially generated"* | `Bundle.envelope.edges[0].kind == PodAdmit` (the session was launched by an AI agent runtime, not a human user) + `EdgeKind::LlmCall` entries proving an LLM was invoked |
| *"or manipulated"* | `EdgeKind::ToolCall`/`EdgeKind::ArtifactProduced` entries reproducing the exact manipulation steps |

### Article 50 §6 — implementation quality

> "Providers shall ensure their technical solutions are effective,
> interoperable, robust and reliable as far as this is technically
> feasible, taking into account the specificities and limitations of
> various types of content, the costs of implementation and the
> generally acknowledged state of the art..."

| Quality criterion | Nucleus posture |
|---|---|
| **Effective** | Tampering with any bundle field breaks a chained Ed25519 signature *and* the Merkle inclusion proof. Detection is deterministic, not probabilistic. |
| **Interoperable** | (1) Native JSON bundle format with public schema; (2) C2PA v2.3 sidecar manifest via `export_c2pa_manifest_*`; (3) in-toto Statement v1 export (see #63); (4) SLSA Provenance v1.1 (see #64); (5) Sigstore Bundle v0.3 (see #65). |
| **Robust** | Hand-rolled JWS avoids the `alg=none` family of CVEs (closed in audit HIGH-5). Constant-time error oracles defeat timing attacks. JtiCache + retention floor defeat replay. STH cosignatures + threshold defeat single-witness lies. |
| **Reliable** | All cryptographic primitives in pure Rust (`ed25519-dalek`, `sha2`); no OpenSSL when built with `rust_native_crypto`. Public audit charter (see #88) commits to quarterly skeptical reviews. |
| **State of the art** | C2PA v2.3 (Feb 2026), RFC 9162 Certificate Transparency v2 (Dec 2021), RFC 8693 Token Exchange (Jan 2020), C2SP Cosigner Spec (in-progress 2026). |

---

## Where nucleus stops, and what to layer above

Article 50 + the Code of Practice describe a **multi-layered** approach.
Nucleus is one layer.

| Layer | Done by | What it proves |
|---|---|---|
| **Cryptographic provenance + logging** | Nucleus (this crate + `nucleus-lineage`) | Who computed what, in what order, with what inputs — provable by anyone holding the bundle |
| **C2PA / IPTC metadata marking** | Nucleus C2PA export (`--features c2pa`) | The same evidence, in the format Adobe / OpenAI / Microsoft / Sony content tools recognize |
| **Visible AI disclosure** | Caller's frontend | Human-readable "made with AI" notice |
| **Invisible pixel/audio watermark** | Caller's media pipeline (SynthID, Steg.AI, ImaTag, ...) | Survives screenshot, transcoding, recompression |
| **Indirect detection / fingerprinting** | Third-party detector services | Catches outputs from providers that ignored Article 50 |

The first two are the layers nucleus owns. The bottom three are
adjacent markets — buyers commonly combine nucleus with a pixel-domain
watermark vendor.

---

## Code of Practice alignment

The European Commission's *Code of Practice on Transparency of
AI-Generated Content* (draft 2, 2026-03-05; final due May–June 2026)
explicitly references C2PA Content Credentials as an example
implementation of the "machine-readable provenance information"
obligation.

By exporting C2PA v2.3 manifests, nucleus-emitted bundles inherit the
Code's `example-of-compliance` status. Buyers who can demonstrate
Code-of-Practice alignment receive **regulatory safe-harbour**
presumption under Article 56 §1, materially reducing audit exposure.

The Code of Practice does **not** mandate C2PA specifically — operators
may use any technique satisfying §2. Nucleus's native JSON bundle
format is independently sufficient; the C2PA export is the interop
bridge for buyers whose downstream pipelines already consume C2PA.

---

## What this document is not

This document is **not legal advice**. The EU AI Act applies to
"providers" and "deployers" with specific definitions that depend on
where in the value chain a given organisation sits, whether the AI
system is "placed on the market" or "put into service" in the Union,
and a number of carve-outs (open-source, research, law-enforcement,
…). Determining whether Article 50 §2 applies to your specific use of
nucleus is a question for your legal team in light of your facts.

What this document **is**: a faithful mapping from the Article's
technical obligations to the nucleus fields that satisfy them, written
to accelerate your internal compliance review. If you find a gap,
please file an issue against `coproduct-opensource/nucleus`.

---

## References

- Article 50 text — *Regulation (EU) 2024/1689* Article 50 §2-§6 (effective 2026-08-02)
- Draft Code of Practice on Transparency of AI-Generated Content (draft 2, 2026-03-05)
- European Commission draft guidelines (2026-05-08, consultation through 2026-06-03)
- C2PA Technical Specification v2.3 (2026-02-XX)
- Penalties: Regulation (EU) 2024/1689 Article 99 §3
