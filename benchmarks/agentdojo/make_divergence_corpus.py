#!/usr/bin/env python3
"""Generate the kernel-vs-mirror divergence corpus.

This script exists to settle one question with evidence rather than by reading
code: **does the in-tree Python exposure mirror agree with the kernel nucleus
actually runs?**

It emits two aligned artifacts:

  corpus.jsonl          tool-call traces in `nucleus-flow-replay` schema
  mirror-verdicts.json  what `portcullis_defense.exposure` decided for each step

The Rust side replays `corpus.jsonl` through `Kernel::decide_term_with_flow` —
the function the live HTTP chokepoint calls — and compares against the fixture.

Run once, commit both outputs. The mirror is deleted afterwards; the fixture is
the preserved record of what it used to say, which is why it is committed rather
than regenerated on demand.

    python3 make_divergence_corpus.py --out ../../crates/nucleus-flow-replay/corpus
"""

from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
import sys
import types
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# THE MAPPING TABLE.
#
# AgentDojo has ~80 fine-grained tools; nucleus has 14 coarse `Operation`s. That
# collapse is lossy and it *determines the score*, so the table is data here —
# published, auditable, and diffable — rather than buried in code. A reader who
# disputes a row can see exactly which result it moved.
#
# `ingest` is the flow node a SUCCESSFUL call contributes. `None` means the call
# consumes nothing (a pure outbound action).
# ─────────────────────────────────────────────────────────────────────────────
TOOL_MAPPING: dict[str, dict[str, str | None]] = {
    # Untrusted external content — adversarial integrity in nucleus.
    "get_webpage":                    {"operation": "web_fetch",  "ingest": "web_content"},
    "download_file":                  {"operation": "web_fetch",  "ingest": "web_content"},
    "get_rating_reviews_for_hotels":  {"operation": "web_fetch",  "ingest": "web_content"},
    # Private reads — trusted integrity, raises confidentiality.
    "get_received_emails":            {"operation": "read_files", "ingest": "file_read"},
    "read_channel_messages":          {"operation": "read_files", "ingest": "file_read"},
    "get_file_by_id":                 {"operation": "read_files", "ingest": "file_read"},
    "search_contacts_by_name":        {"operation": "read_files", "ingest": "file_read"},
    # Consequential outbound actions — the things a gate must be able to stop.
    "send_email":                     {"operation": "write_files", "ingest": None},
    "send_channel_message":           {"operation": "write_files", "ingest": None},
    "post_webpage":                   {"operation": "write_files", "ingest": None},
    "share_file":                     {"operation": "write_files", "ingest": None},
    "create_file":                    {"operation": "write_files", "ingest": None},
    # Neutral — carries no exposure label in the mirror.
    "delete_email":                   {"operation": "write_files", "ingest": None},
    "get_current_day":                {"operation": "read_files",  "ingest": None},
}

# One representative per behavioural class, so the cross-product stays small
# enough to read but still covers every ordering that matters.
REPRESENTATIVES = [
    "get_webpage",           # untrusted ingest
    "get_received_emails",   # private ingest
    "send_email",            # exfil action
    "get_current_day",       # neutral read
    "delete_email",          # neutral action
]


def load_mirror():
    """Import the pure-Python mirror without its package __init__ (which pulls
    in agentdojo). The mirror itself has no third-party dependencies."""
    here = Path(__file__).parent
    pkg = types.ModuleType("pd")
    pkg.__path__ = [str(here / "portcullis_defense")]
    sys.modules["pd"] = pkg

    def load(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        sys.modules[name] = mod
        return mod

    load("pd.tool_map", here / "portcullis_defense" / "tool_map.py")
    return load("pd.exposure", here / "portcullis_defense" / "exposure.py")


def build_sequences(max_len: int = 3) -> list[list[str]]:
    """All orderings up to `max_len` over the representative alphabet.

    Order matters enormously here — an outbound action before an untrusted
    ingest is a different decision from the same action after it — so this is a
    product, not a combination.
    """
    seqs: list[list[str]] = []
    for n in range(1, max_len + 1):
        seqs.extend(list(p) for p in itertools.product(REPRESENTATIVES, repeat=n))
    return seqs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True, help="output directory")
    ap.add_argument("--max-len", type=int, default=3)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    mirror = load_mirror()
    sequences = build_sequences(args.max_len)

    traces_path = args.out / "corpus.jsonl"
    verdicts_path = args.out / "mirror-verdicts.json"

    mirror_records = []
    with traces_path.open("w") as tf:
        for trace_id, seq in enumerate(sequences):
            # --- nucleus trace ---
            steps = []
            for i, tool in enumerate(seq):
                m = TOOL_MAPPING[tool]
                step = {
                    "step": i,
                    "tool": tool,
                    "operation": m["operation"],
                    "subject": f"{tool}/{i}",
                }
                if m["ingest"]:
                    step["ingest"] = m["ingest"]
                    # Fixed payload: the content is irrelevant to the decision,
                    # and varying it would make the corpus non-reproducible.
                    step["content"] = f"content-{tool}"
                steps.append(step)
            tf.write(json.dumps({"trace": trace_id, "steps": steps}) + "\n")

            # --- mirror verdicts over the SAME sequence ---
            state = mirror.ExposureSet.empty()
            verdicts = []
            for i, tool in enumerate(seq):
                denied = bool(mirror.should_deny(state, tool))
                verdicts.append({"step": i, "tool": tool,
                                 "verdict": "deny" if denied else "allow"})
                # Mirror the live ordering: a refused call never executed, so it
                # contributes no exposure.
                if not denied:
                    state = mirror.apply_record(state, tool)
            mirror_records.append({"trace": trace_id, "verdicts": verdicts})

    verdicts_path.write_text(json.dumps({
        "_provenance": (
            "Verdicts produced by portcullis_defense.exposure, the pure-Python "
            "mirror of exposure_core::should_deny. That mirror was DELETED after "
            "this fixture was generated: it reimplemented a function with no "
            "live-path callers, and its policy did not match that function "
            "either. This file is the preserved record of what it decided, kept "
            "so the divergence against the real kernel stays checkable."
        ),
        "traces": mirror_records,
    }, indent=2) + "\n")

    print(f"wrote {len(sequences)} traces -> {traces_path}")
    print(f"wrote mirror verdicts       -> {verdicts_path}")


if __name__ == "__main__":
    main()
