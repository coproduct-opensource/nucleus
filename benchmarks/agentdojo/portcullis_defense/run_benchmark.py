#!/usr/bin/env python3
"""Run AgentDojo benchmark with Portcullis exposure-lattice defense.

The harness is model-agnostic: it speaks the chat-completions protocol to
whatever endpoint `LLM_API_BASE` names, and never branches on a provider.

    export LLM_API_BASE=https://your-endpoint.example/v1
    export LLM_API_TOKEN=...        # omit for unauthenticated local endpoints
    export LLM_MODEL=your-model-id

Usage:
    # Dry run — verify tool mapping coverage (no LLM calls, no endpoint needed)
    python -m portcullis_defense.run_benchmark --dry-run

    # Run a single suite
    python -m portcullis_defense.run_benchmark --suite workspace

    # Run all suites
    python -m portcullis_defense.run_benchmark --all

    # Run without defense (baseline comparison)
    python -m portcullis_defense.run_benchmark --suite workspace --no-defense

    # Override the model for one run
    python -m portcullis_defense.run_benchmark --suite workspace --model your-model-id

    # Specific attack type
    python -m portcullis_defense.run_benchmark --suite workspace --attack important_instructions
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger("portcullis.bench")

SUITE_NAMES = ["workspace", "travel", "banking", "slack"]

ATTACK_TYPES = [
    "important_instructions",
    "tool_knowledge",
    "injecagent",
    "direct",
]


def check_tool_coverage() -> None:
    """Check which tools in each suite are mapped and which are unmapped."""
    from agentdojo.task_suite import get_suite

    from .tool_map import TOOL_MAP

    for suite_name in SUITE_NAMES:
        suite = get_suite("v1", suite_name)
        tool_names = [t.name for t in suite.tools]
        mapped = [n for n in tool_names if n in TOOL_MAP]
        unmapped = [n for n in tool_names if n not in TOOL_MAP]
        pct = round(100 * len(mapped) / len(tool_names), 1) if tool_names else 0

        print(f"\n{'=' * 60}")
        print(f"  {suite_name}: {len(tool_names)} tools, {len(mapped)} mapped ({pct}%)")
        print(f"{'=' * 60}")

        if unmapped:
            for u in unmapped:
                print(f"  UNMAPPED: {u}")
        else:
            print("  All tools mapped!")

        # Show label distribution
        from .tool_map import ExposureLabel
        counts = {label: 0 for label in ExposureLabel}
        neutral = 0
        for name in tool_names:
            label = TOOL_MAP.get(name)
            if label is not None:
                counts[label] += 1
            else:
                neutral += 1
        for label, count in counts.items():
            print(f"  {label.name}: {count}")
        print(f"  Neutral: {neutral}")


def make_llm_element(model: str | None = None):
    """Create an LLM pipeline element from environment configuration.

    The harness speaks ONE wire protocol — chat-completions — to whatever
    endpoint it is pointed at. It does not know, branch on, or name any model
    provider: the endpoint may be self-hosted (vLLM, Ollama, llama.cpp) or a
    managed service, and swapping between them is a change of `LLM_API_BASE`,
    not a change of code.

    This is deliberate. Nucleus is vendor-agnostic by project policy, and a
    benchmark harness that dispatched on model-name prefixes and read
    provider-specific credential variables would encode exactly the coupling
    the rest of the project refuses.

    Configuration:
        LLM_API_BASE   endpoint URL (required)
        LLM_API_TOKEN  bearer token (optional — omit for unauthenticated local endpoints)
        LLM_MODEL      model identifier as the endpoint names it (required unless --model given)
    """
    import os

    base_url = os.environ.get("LLM_API_BASE")
    if not base_url:
        raise RuntimeError(
            "LLM_API_BASE not set — point it at any chat-completions-compatible "
            "endpoint (self-hosted or managed). See --help."
        )

    model = model or os.environ.get("LLM_MODEL")
    if not model:
        raise RuntimeError("No model given: pass --model or set LLM_MODEL.")

    try:
        from openai import OpenAI as ChatCompletionsClient
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError(
            "A chat-completions protocol client is required to run the "
            "benchmark. Install the harness's optional 'llm' extra."
        ) from exc

    from agentdojo.agent_pipeline import OpenAILLM as ChatCompletionsLLM

    # No default token: an unauthenticated local endpoint is a first-class case,
    # and the client requires *some* value.
    client = ChatCompletionsClient(
        base_url=base_url,
        api_key=os.environ.get("LLM_API_TOKEN") or "unused",
    )
    return ChatCompletionsLLM(client, model)


def run_suite(
    suite_name: str,
    model: str | None,
    attack_name: str,
    with_defense: bool = True,
    logdir: Path | None = None,
) -> dict[str, Any]:
    """Run a single AgentDojo suite with or without Portcullis defense."""
    import os

    from agentdojo.agent_pipeline import (
        AgentPipeline,
        InitQuery,
        ToolsExecutionLoop,
        ToolsExecutor,
    )
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections
    from agentdojo.task_suite import get_suite

    # Resolve the model up front so the run name and the summary record what was
    # ACTUALLY exercised — a result labelled with a null model is unusable
    # evidence, and this harness exists to produce comparable numbers.
    model = model or os.environ.get("LLM_MODEL")
    suite = get_suite("v1", suite_name)
    llm = make_llm_element(model)

    if with_defense:
        from .defense import PortcullisDefense
        defense = PortcullisDefense()
        pipeline = AgentPipeline(
            elements=[
                InitQuery(),
                llm,
                ToolsExecutionLoop(
                    elements=[defense, ToolsExecutor(), llm],
                ),
            ],
        )
        pipeline.name = f"{model}-portcullis"
    else:
        defense = None
        pipeline = AgentPipeline(
            elements=[
                InitQuery(),
                llm,
                ToolsExecutionLoop(
                    elements=[ToolsExecutor(), llm],
                ),
            ],
        )
        pipeline.name = f"{model}-baseline"

    attack = load_attack(attack_name, suite, pipeline)

    logger.info(
        "Running %s | model=%s | defense=%s | attack=%s",
        suite_name, model, "portcullis" if with_defense else "none", attack_name,
    )

    from agentdojo.logging import OutputLogger

    log_path = str(logdir) if logdir else None
    with OutputLogger(logdir=log_path):
        results = benchmark_suite_with_injections(
            agent_pipeline=pipeline,
            suite=suite,
            attack=attack,
            logdir=logdir,
            force_rerun=True,
        )

    # Compute metrics
    n_utility = len(results["utility_results"])
    n_utility_pass = sum(results["utility_results"].values())
    n_security = len(results["security_results"])
    n_security_pass = sum(results["security_results"].values())

    summary: dict[str, Any] = {
        "suite": suite_name,
        "model": model,
        "attack": attack_name,
        "defense": "portcullis" if with_defense else "none",
        "utility": {
            "total": n_utility,
            "passed": n_utility_pass,
            "rate": round(n_utility_pass / n_utility, 3) if n_utility else 0,
        },
        "security": {
            "total": n_security,
            "passed": n_security_pass,
            "rate": round(n_security_pass / n_security, 3) if n_security else 0,
        },
    }

    if defense is not None:
        summary["portcullis"] = {
            "allowed": defense.stats.allowed,
            "blocked": defense.stats.blocked,
            "blocked_tools": defense.stats.blocked_tools,
        }

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run AgentDojo benchmark with Portcullis exposure-lattice defense"
    )
    parser.add_argument("--suite", type=str, choices=SUITE_NAMES, help="Suite to run")
    parser.add_argument("--all", action="store_true", help="Run all suites")
    parser.add_argument("--model", type=str, default=None,
                        help="Model identifier as the endpoint names it (default: $LLM_MODEL)")
    parser.add_argument("--attack", type=str, default="important_instructions",
                        help="Attack type (important_instructions, tool_knowledge, etc.)")
    parser.add_argument("--dry-run", action="store_true", help="Check tool coverage only")
    parser.add_argument("--no-defense", action="store_true", help="Run without defense (baseline)")
    parser.add_argument("--logdir", type=str, default=None, help="Directory for benchmark logs")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(name)s %(levelname)s %(message)s",
    )

    if args.dry_run:
        check_tool_coverage()
        return

    if not args.suite and not args.all:
        parser.error("--suite or --all required (unless --dry-run)")

    suites = SUITE_NAMES if args.all else [args.suite]
    logdir = Path(args.logdir) if args.logdir else None

    all_results = []
    for suite_name in suites:
        result = run_suite(
            suite_name,
            args.model,
            args.attack,
            with_defense=not args.no_defense,
            logdir=logdir,
        )
        all_results.append(result)
        print(json.dumps(result, indent=2))

    if len(all_results) > 1:
        total_utility = sum(r["utility"]["passed"] for r in all_results)
        total_utility_n = sum(r["utility"]["total"] for r in all_results)
        total_security = sum(r["security"]["passed"] for r in all_results)
        total_security_n = sum(r["security"]["total"] for r in all_results)
        print(f"\n{'=' * 60}")
        print(f"  TOTALS")
        print(f"  Utility:  {total_utility}/{total_utility_n} ({round(100*total_utility/total_utility_n, 1)}%)")
        print(f"  Security: {total_security}/{total_security_n} ({round(100*total_security/total_security_n, 1)}%)")
        print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
