#!/usr/bin/env bash
# The independent implementation must actually be RUN, and must agree.
#
# WHY: `examples/independent-conformance/conform.py` is the artifact behind the
# open-commerce claim — a re-implementation that checks the vectors without
# executing nucleus code. Nothing ran it (#2736). `grep -rl conform.py` over
# `.github/`, `scripts/`, `ci/` and the justfile returned nothing; the only
# references were prose, including `corpus_is_load_bearing.rs` citing it as
# "Demonstrated, not hypothesised". A doc comment is not an execution.
#
# It is not a decorative artifact. Per #2359 it FOUND a defect: a truncating
# payout implementation passed the old 14-case corpus and fails the current one,
# including `payout/remainder-dust-dropped`, where truncation said ACCEPT to an
# operator skimming a micro-USD per split. If nucleus's verdicts drift from the
# independent implementation again, this is what notices.
#
# Tree-only by design: python3 and a checked-in JSON file, no cargo, so it runs
# in the fast guard job rather than behind a build. The other half of #2736 —
# that the checked-in corpus matches what the generator emits — is a Rust test
# (`the_checked_in_vectors_are_what_the_generator_emits`) rather than a step
# here, because it belongs next to the generator it guards.
set -euo pipefail
cd "$(dirname "$0")/.."

CORPUS="examples/independent-conformance/vectors.json"
IMPL="examples/independent-conformance/conform.py"

# Anti-vacuity floor, and the reason this is not just `python3 conform.py`.
# `evaluate` returns None for a case the independent implementation cannot
# re-derive (`disclosure_required` is an IFC decision these fields do not carry),
# and those are skipped, not failed. So a corpus in which every case skipped
# would print "agreement on every checked vector" over an empty set and exit 0.
# 13 is what the current 16-case corpus checks.
#
# RATCHET UP as the corpus grows. Never lower this to make a run pass: a drop
# means either the corpus lost cases or `evaluate` stopped deciding ones it used
# to, and both are the finding.
MIN_CHECKED=13

for f in "$CORPUS" "$IMPL"; do
  if [ ! -f "$f" ]; then
    echo "::error::$f is missing — the open-commerce claim rests on it"
    exit 1
  fi
done

if ! python3 "$IMPL" "$CORPUS" --min-checked="$MIN_CHECKED"; then
  echo "::error::the independent implementation disagrees with the nucleus corpus"
  echo "  This is the check that found the truncating-payout defect in #2359."
  echo "  A disagreement means one of the two moved: either nucleus changed a"
  echo "  verdict, or $IMPL no longer re-derives it. Do not"
  echo "  silence this by editing the corpus to match the implementation."
  exit 1
fi
