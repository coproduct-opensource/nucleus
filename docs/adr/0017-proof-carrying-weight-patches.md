# ADR 0017 — Proof-carrying weight patches: a model may propose a change to its own checkpoint; it may not release one

- Status: Proposed (2026-11-20). The implementation plan was approved by the owner on
  2026-11-20; this record's status is the owner's to change.
- Builds on: ADR 0007 (make the defect unwritable), ADR 0008 (declared, attested, checked),
  ADR 0009 (the public/private line), ADR 0013 (the eval cell).
- Prior art: `docs/research/weight-patch-prior-art.md`.

## Context

Published work now shows a language model, given its own weights, its graded answers and the
ability to run itself, proposing a direct edit to those weights that raises its held-out
accuracy. The same work shows smaller models submitting edits that take their accuracy to
zero, and says an edit should be confirmed by a person before it is used. Nothing in that work
enforces the confirmation. The editor, the measurement and the decision to use the result sit
in one process.

A weight edit is the case the runtime exists for. The proposer is the thing being changed, so
its own account of what it changed is the one account that cannot be relied on. What Nucleus
already has is the other half: isolation with digest-pinned inputs, signed receipts with an
identity outside the workload, and verifiers a stranger can run.

What it does not have, checked on `main` at `d8d6fef3e`:

| Needed | On `main` |
|---|---|
| A digest for a checkpoint, and for a change to one | None. `nucleus-provenance` has `ArtifactKind::Model` and checks a signature over a digest someone else computed. |
| The set of tensors a change wrote, as evidence | None. `portcullis` `SinkScope.allowed_paths` is path-shaped, and an empty list there means unrestricted. |
| A receipt that cites the receipt before it | None. `nucleus_receipt::Session.parent_chain` holds identities, not receipt hashes, and the node passes it empty. |
| An approver authenticated as distinct from the proposer | Partly. `EscalationPolicy` compares identity chains that are not authenticated; the host's effect approvals authenticate one operator. |
| An accelerator in a pod | None. `ResourceSpec` has no device field and the microVM tier has no passthrough. |

## Decision

### D1. Four roles, four keys, and a registry

A release is the work of an **editor** (proposes), a **runner** (applies and measures the
write set), an **evaluator** (measures behaviour) and a **deployer** (grants authority to
propose, and approves). The registry that moves the serving pointer signs with a fifth key.

The gate refuses a chain in which two roles are signed by one key. Separation is decided on
signatures. A name in a receipt is never evidence of who signed it (C-2).

### D2. A change is a program, and the checkpoint digest does not depend on files

`nucleus-weight-patch` defines:

- a **tensor digest** over a tensor's name, element type, shape and bytes, and a **checkpoint
  digest** over the sorted list of tensor digests;
- a **patch program**: data, not code, naming each tensor it changes. The first operation adds
  a scalar to every element, for single precision and its 16-bit truncation, with the rounding
  written out on bit patterns so the output is the same bytes on every platform;
- the **measured write set**: the tensors whose digest differs between base and output.

The write set is never taken from the program or from the editor (C-1, C-2). A declared write
set cannot be empty (B-2).

Two checks follow, by two different parties. The runner checks *measured ⊆ declared*. The
gate checks *declared ⊆ permitted by the release policy*. The policy is the deployer's.

### D3. The receipt chain

Each body is carried in a `nucleus_receipt::Receipt` and embeds the root hash of the receipt
before it.

| # | Body | Signed by | Binds |
|---|---|---|---|
| 1 | Proposal grant | deployer | the editor's key, the base digest, the policy digest, a run budget, an expiry, and the previous release receipt (absent only for the first release) |
| 2 | Patch manifest | editor | the grant, the base digest, the program digest, the declared writes, the expected output digest |
| 3 | Apply receipt | runner | the manifest, the measured writes, the output digest, an outcome |
| 4 | Evaluation receipt | evaluator | the apply receipt, the base and candidate digests, the suite digest and version, the decoding configuration, the seed list, the harness image, the transcripts, the results |
| 5 | Approval | deployer | the candidate digest, the evaluation receipt, the policy digest, a single-use id, an expiry |
| 6 | Promotion or rollback receipt | registry | the previous and new digests, a generation number, receipts 1–5 |

The runner signs a refusal as well as a success. A patch that wrote outside its declaration
leaves a receipt saying so.

`nucleus-receipt` is not changed. The bodies carry their own schema names inside an existing
projection, as `nucleus.execution.v1` does. A dedicated projection variant is a later decision
with its own cost (the verifier SDK pin).

### D4. The gate consumes a right, and has three answers

Promotion takes a `PromotionRight` **by value** (C-4). Only the chain verifier mints one
(C-1). The verdict is `Promoted`, `Refused(reason)` or `CouldNotLook` (A-1, A-2), and the
reasons are a closed enum matched without a wildcard (B-3, E-2).

The registry keeps the current digest, the previous digest and a generation. A promotion is a
compare-and-swap on the generation. Rollback promotes the retained previous digest and writes
its own receipt. The server loads only the digest the pointer names, measures what it loaded,
and reports digest and generation with every response.

### D5. Authority to propose is issued per base and does not carry over

A grant names one base digest. When a promoted checkpoint becomes the next editor it holds no
authority from the release that produced it. The deployer issues a fresh grant, scoped to the
new base, citing the promotion receipt. A manifest verifies only against a grant whose base is
the pointer's current digest.

### D6. Where each step runs, and what tier it is

- **Apply** needs no accelerator. It runs in a microVM pod with the base on the read-only,
  digest-pinned data disk. The node's execution receipt is attached to the apply receipt.
- **Generation** (the editor's own runs, and evaluation) needs an accelerator. `ResourceSpec`
  gains an accelerator count that the container driver honours and every other driver
  refuses. Those pods run at container isolation and their receipts say so. The strongest
  option, accelerator passthrough into a microVM, does not exist on this runtime; this is the
  runner-up, named as such.

### D7. Neutral core here, the named model elsewhere (ADR 0009)

This repository holds the model-agnostic crates and a synthetic checkpoint for tests. The
named model, the inference stack, the evaluation suite and the signed release record live in a
separate fixture repository, linked from `docs/evidence/`.

## What a release record establishes, and what it does not

**Recomputed by anyone holding the base and the record:**

- the candidate digest, by replaying the program;
- the write set;
- every score, from the recorded transcripts;
- every signature, and the link from each receipt to the one before.

**Attested by the party that signed it, not recomputable:**

- the transcripts themselves. Sampling on an accelerator is not bit-reproducible across
  hardware. Matched seeds make base and candidate comparable on one machine; they do not make
  the text reproducible on another.

**Not claimed:**

- That the candidate is better, or safe. The chain establishes what changed, what was
  measured and who authorized the effect. The benchmark measures how the candidate behaved
  under the tested conditions, and nothing outside them.
- That the roles were operated by separate parties in the demonstration. One operator holds
  all the keys there. The record is checkable by a stranger with only the public keys; that
  the design supports separate operation is a property of the design, not something the
  demonstration shows.
- That the server's memory holds the digest it reports. The server measures the files it
  loads, inside a pod whose inputs are pinned; nothing here measures the loaded weights in
  place.
- That the first reproduced patch is the published one verbatim. The publication gives the
  edit in a sentence and no parameter names. The record states the reading used and the
  tensor names found in the checkpoint.

## Sequence

1. `nucleus-weight-patch`: digests, reader, program, apply, write set.
2. `nucleus-release-gate`: the six bodies, their verifiers, the chain walk, policy, gate,
   pointer store, release log, rollback, and a replay verifier binary.
3. The registry service and server, and the whole validation list on a synthetic checkpoint in
   CI: replay, promotion, the refusals (no approval; evaluation for another candidate; a write
   outside the allowed set; an approval by the editor; an expired or spent grant), rollback,
   and a second round linked to the first.
4. The accelerator count, and a live run of apply and evaluation in real pods.
5. The fixture repository: a small model end to end, then the size the publication reports,
   then a second round with the promoted checkpoint as editor.

Each refusal is driven red on its real defect before its green is trusted (A-19).

## Owner-only

- The fixture repository's name and visibility.
- Accelerator machine types and spend caps.
- Whether the weight-patch bodies get their own projection variant.

## Consequences

- A checkpoint gains an identity that does not depend on how it is stored, and a change to one
  gains an identity that can be replayed.
- "Which tensors may a model change in itself" becomes a policy a deployer signs, checked
  against a measurement, instead of a rule stated in a prompt.
- Accelerator workloads enter the runtime at the container tier. That is a weaker tier than
  the default, and every receipt from it carries the tier.
- The gate adds a second consumer of the chain-walk and sealed-witness patterns. If a third
  appears, the pattern should become a shared crate rather than a third copy (G).
