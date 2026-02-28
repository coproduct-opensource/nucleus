#!/usr/bin/env python3
"""
Delegation Forest -- Hierarchical Permission Demo
==================================================

Demonstrates nucleus's delegation model where an orchestrator pod spawns
sub-pods whose capabilities are *clamped* to the orchestrator's own
ceiling via a monotonic meet (lattice intersection).

Key concepts:
  - The orchestrator has Intent.ORCHESTRATE: it can read files and manage
    sub-pods, but it CANNOT write files or execute commands directly.
  - Sub-pods requested with permissive profiles (e.g. "fix_issue") are
    automatically clamped so they never exceed the parent's delegation
    ceiling.
  - Cancelling the orchestrator cascades to all live sub-pods.

Run:
    export NUCLEUS_NODE_URL="http://localhost:9400"
    pip install -e sdk/python
    python examples/delegation_forest.py
"""

from __future__ import annotations

import os
import sys
import textwrap
import yaml

from nucleus_sdk import Nucleus, Intent
from nucleus_sdk.auth import HmacAuth
from nucleus_sdk.intent import profile_for_intent, INTENT_PROFILES
from nucleus_sdk.models import PodSpec
from nucleus_sdk.errors import NucleusError, AccessDenied


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


def step(msg: str) -> None:
    print(f"\n>>> {msg}")


def pretty_caps(label: str, ops: list[str]) -> None:
    joined = ", ".join(ops) if ops else "(none)"
    print(f"  {label:20s}: {joined}")


def _print_capability_table() -> None:
    banner("Capability Comparison")
    all_ops = sorted({
        op
        for prof in INTENT_PROFILES.values()
        for op in prof.allowed_ops + prof.gated_ops
    })
    header = f"  {'intent':20s}" + "".join(f" {op:>14s}" for op in all_ops)
    print(header)
    print("  " + "-" * len(header))
    for intent in Intent:
        prof = profile_for_intent(intent)
        row = f"  {intent.value:20s}"
        for op in all_ops:
            if op in prof.allowed_ops:
                marker = "Y"
            elif op in prof.gated_ops:
                marker = "gated"
            else:
                marker = "-"
            row += f" {marker:>14s}"
        print(row)


# ---------------------------------------------------------------------------
# Build sub-pod specs as YAML strings
# ---------------------------------------------------------------------------

def _codegen_spec(work_dir: str) -> str:
    """Sub-pod that wants to generate code (write + run)."""
    pod = PodSpec(
        work_dir=work_dir,
        timeout_seconds=600,
        profile="codegen",
        labels={"role": "codegen-worker", "parent": "orchestrator"},
        task="Implement the FooBar module with unit tests.",
        budget_max_usd=0.50,
    )
    return yaml.dump(pod.to_dict(), default_flow_style=False)


def _reviewer_spec(work_dir: str) -> str:
    """Sub-pod that only needs read access for code review."""
    pod = PodSpec(
        work_dir=work_dir,
        timeout_seconds=300,
        profile="code_review",
        labels={"role": "reviewer", "parent": "orchestrator"},
        task="Review the FooBar module for correctness and style.",
        budget_max_usd=0.25,
    )
    return yaml.dump(pod.to_dict(), default_flow_style=False)


def _researcher_spec() -> str:
    """Sub-pod with web research capabilities."""
    pod = PodSpec(
        work_dir=".",
        timeout_seconds=300,
        profile="web_research",
        labels={"role": "researcher", "parent": "orchestrator"},
        task="Research best practices for error handling in async runtimes.",
        network_allow=["*"],
        dns_allow=["*"],
        budget_max_usd=0.10,
    )
    return yaml.dump(pod.to_dict(), default_flow_style=False)


def _researcher_spec_local() -> str:
    """Sub-pod for research on local driver (no network config)."""
    pod = PodSpec(
        work_dir=".",
        timeout_seconds=300,
        profile="web_research",
        labels={"role": "researcher", "parent": "orchestrator", "fallback": "local"},
        task="Research best practices for error handling in async runtimes.",
        budget_max_usd=0.10,
    )
    return yaml.dump(pod.to_dict(), default_flow_style=False)


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def main() -> None:
    node_url = os.environ.get("NUCLEUS_NODE_URL", "")
    if not node_url:
        print("ERROR: Set NUCLEUS_NODE_URL (e.g. http://localhost:9400)")
        sys.exit(1)

    auth_secret = os.environ.get("NUCLEUS_AUTH_SECRET", "")
    auth = HmacAuth(secret=auth_secret.encode(), actor="delegation-demo") if auth_secret else None
    nuc = Nucleus(node_url=node_url, auth=auth)

    # ------------------------------------------------------------------
    # 1. Show the intent catalogue
    # ------------------------------------------------------------------
    banner("Intent Catalogue")
    for intent in Intent:
        prof = profile_for_intent(intent)
        print(f"\n  [{intent.value}] -- {prof.description}")
        pretty_caps("allowed", prof.allowed_ops)
        pretty_caps("gated", prof.gated_ops)
        if prof.notes:
            print(f"  {'notes':20s}: {prof.notes}")

    # ------------------------------------------------------------------
    # 2. Open an orchestrator session
    # ------------------------------------------------------------------
    banner("Create Orchestrator Pod")
    try:
        session = nuc.intent(Intent.ORCHESTRATE)
    except Exception as exc:
        print(f"\n  Could not connect to nucleus-node at {node_url}: {exc}")
        print("  Skipping live demo — showing capability comparison instead.\n")
        _print_capability_table()
        return
    orch_profile = session.profile
    step(f"Orchestrator profile: {orch_profile.profile}")
    pretty_caps("allowed", orch_profile.allowed_ops)

    # ------------------------------------------------------------------
    # 3. Verify isolation -- orchestrator cannot write or execute
    # ------------------------------------------------------------------
    banner("Verify Orchestrator Isolation")
    step("Attempting file write (should be denied)...")
    try:
        session.write("/tmp/nucleus_test.txt", "should not work")
        print("  UNEXPECTED: write succeeded (policy not enforced?)")
    except (AccessDenied, NucleusError) as exc:
        print(f"  Correctly denied: {exc}")

    step("Attempting command execution (should be denied)...")
    try:
        session.run(["echo", "hello"])
        print("  UNEXPECTED: run succeeded (policy not enforced?)")
    except (AccessDenied, NucleusError) as exc:
        print(f"  Correctly denied: {exc}")

    step("Reading a file (should be allowed)...")
    try:
        contents = session.read("/etc/hostname")
        print(f"  Read OK: {contents[:80]!r}")
    except NucleusError as exc:
        print(f"  Read result: {exc}")

    # ------------------------------------------------------------------
    # 4. Spawn sub-pods via the proxy's pod management API
    # ------------------------------------------------------------------
    banner("Spawn Sub-Pods (Delegation Forest)")

    proxy = nuc.proxy_at(session._proxy.base_url)
    work_dir = os.getcwd()
    sub_pods: list[str] = []

    for name, spec_fn in [
        ("codegen-worker", lambda: _codegen_spec(work_dir)),
        ("reviewer", lambda: _reviewer_spec(work_dir)),
        ("researcher", _researcher_spec),
    ]:
        step(f"Creating sub-pod: {name}")
        spec_yaml = spec_fn()
        print(textwrap.indent(spec_yaml, "    "))
        try:
            result = proxy.create_pod(
                spec_yaml=spec_yaml,
                reason=f"Delegation forest demo -- {name}",
            )
            pod_id = result.get("pod_id", result.get("id", "unknown"))
            sub_pods.append(str(pod_id))
            print(f"  Created pod_id={pod_id}")

            # Show effective (clamped) capabilities if returned
            effective = result.get("effective_ops")
            if effective:
                pretty_caps("requested", yaml.safe_load(spec_yaml).get("spec", {}).get("policy", {}).get("name", "?"))
                pretty_caps("effective (clamped)", effective)
        except NucleusError as exc:
            if name == "researcher" and "firecracker" in str(exc).lower():
                print(f"  Network policy rejected (local driver); retrying without network config...")
                spec_yaml = _researcher_spec_local()
                try:
                    result = proxy.create_pod(
                        spec_yaml=spec_yaml,
                        reason=f"Delegation forest demo -- {name} (local fallback)",
                    )
                    pod_id = result.get("pod_id", result.get("id", "unknown"))
                    sub_pods.append(str(pod_id))
                    print(f"  Created pod_id={pod_id} (local fallback, no network)")
                except NucleusError as retry_exc:
                    print(f"  Pod creation result (retry): {retry_exc}")
            else:
                print(f"  Pod creation result: {exc}")

    # ------------------------------------------------------------------
    # 5. List and inspect sub-pods
    # ------------------------------------------------------------------
    banner("Inspect Sub-Pods")
    step("Listing all managed pods...")
    try:
        pods = proxy.list_pods()
        for pod in pods:
            print(f"  pod_id={pod.id}  state={pod.state}")
    except NucleusError as exc:
        print(f"  list_pods result: {exc}")

    for pod_id in sub_pods:
        step(f"Status for pod {pod_id}...")
        try:
            status = proxy.pod_status(pod_id)
            print(f"  {status}")
        except NucleusError as exc:
            print(f"  status result: {exc}")

    # ------------------------------------------------------------------
    # 6. Capability comparison table
    # ------------------------------------------------------------------
    _print_capability_table()

    # ------------------------------------------------------------------
    # 7. Cascading cancel
    # ------------------------------------------------------------------
    banner("Cascading Cancel")
    for pod_id in reversed(sub_pods):
        step(f"Cancelling pod {pod_id}...")
        try:
            proxy.cancel_pod(pod_id, reason="Demo complete -- cascading teardown")
            print(f"  Cancelled.")
        except NucleusError as exc:
            print(f"  cancel result: {exc}")

    step("All sub-pods cancelled. Orchestrator teardown complete.")
    print()


if __name__ == "__main__":
    main()
