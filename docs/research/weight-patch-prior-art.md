# Prior art: editing weights directly, and attesting what was edited

Recorded 2026-11-20 for ADR 0018. Sources were read through search summaries and, for the
first item, a partial read of the full text; where a figure comes from a summary and not the
text, it is marked. Model and organization names are left out on purpose (this repository
names no model vendor); the identifiers below are enough to find each source.

## Editing weights without training

**"Language Models Can Rewrite Their Own Weights"** — arXiv 2611.21885 (preprint, 16 Nov
2026, not peer reviewed).

- An open-weight model at four sizes (2B, 4B, 9B, 27B) is given its weights, graded answers to
  practice problems, and a session in which it can run code and a bounded number of forward
  passes.
- Headline: the 27B model's own edit raises held-out accuracy from 57.2% to 63.8% (490
  problems, 8 answers each, paired seeds, one-sided sign-flip permutation test). *From a
  summary of the results table:* the edit is "time-step bias +0.5 in all 48 linear-attention
  layers".
- Decoding: temperature 0.6, nucleus 0.95, top-20, a 16,384-token limit. An answer "loops"
  when it runs out of tokens while repeating.
- Session budget: 20 forward passes, 200 code runs, 160 turns, 3.5 hours. Edits to the input
  embedding, the final normalization and the output layer are not allowed, nor is rescaling a
  whole tensor.
- Smaller sizes: the 2B model submits nothing; the 4B model withdraws its edits; the 9B
  model's submitted edit takes it from 47.5% to 0.0%.
- The paper says an edit should be confirmed by a person before it is used.
- **Not given:** parameter names or shapes for the edit, the patch as code, seed values, any
  code release. No recursive round (an edited model editing itself again) and no separate
  regression suite on unrelated tasks.

What this fixes for us: the evaluation protocol to match, the policy deny-list to start from,
and the fact that "reproduce the patch" needs the tensor names read out of the real
checkpoint.

**"Sparks of Weight-Space Programming"** — research blog post, 2 Nov 2026, no paper.

- A stronger model reads and edits the weights of small networks, including a 0.8B language
  model: removing one direction from 64 output columns in two layers (0.016% of the weights)
  with no gradients. Reported gains on a math benchmark and an instruction-following
  benchmark are large. Not independently replicated; press coverage reports a dispute over
  whether the largest result relied on ordinary engineering.
- Released: experiment logs and the edited small checkpoint. No read/write library.

What this fixes for us: the second operation a patch program will need (remove a direction
from a matrix), which is a matrix product and therefore needs a fixed summation order to be
replayable. It is out of scope for the first program version.

**"Keel: A Frontier Model Teaches a Vision-Language Model by Rewriting Its Weights"** —
arXiv 2611.25257. A stronger model repairs a smaller model's looping by direct edits. Same
shape as the above with a different editor.

## Locate-and-edit methods

**ROME, MEMIT and their unification** — arXiv 2403.14236; scaling failures in arXiv
2401.07453; general-ability damage in arXiv 2401.04700.

- These edit specific weights to change a stored fact. The two main methods share one
  objective and differ in the constraint.
- Reported failure modes: an edit bleeds into unrelated facts; many edits in sequence degrade
  the model gradually and then abruptly; edited facts transfer poorly to reasoning that
  depends on them.

What this fixes for us: a release threshold on the target task is not enough. The evaluation
receipt carries a regression suite on unrelated tasks, and the second-round comparison exists
because sequential edits are where this literature finds the damage.

## Signing models and attesting evaluations

**Model signing with a transparency log** — the open model-signing library and its
write-ups (2025).

- A model directory is hashed into a manifest, wrapped in an in-toto statement, signed, and
  the signature recorded in an append-only log. Keyless signing binds a workload identity.
- It establishes that a checkpoint was not altered after signing. It says nothing about what
  a change did, and its authors note that signing does not make a serialization format safe
  to load.
- Signed evaluation results and model cards are named as future work for a standards group,
  not as something that exists.

What this fixes for us: export shape. Each receipt body can be offered as an in-toto
statement with the checkpoint as subject (`nucleus-envelope` already has the statement and
envelope types), so a record is readable by tooling that knows nothing about Nucleus. The
part with no prior standard is the evaluation receipt bound to a candidate digest, and the
promotion decision bound to both.

## What we did not find

- A system in which the proposer of a weight edit, the party that applies it, the party that
  measures it and the party that releases it hold separate keys.
- A write-set check on tensors: a measured list of what a change touched, compared with what
  it was allowed to touch.
- A recursive round under a release gate.

Absence from a search is not absence from the literature. These are the gaps this work
assumes, stated so that a reader who knows of a counterexample can say so.
