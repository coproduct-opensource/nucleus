# Hardening Checklist (Demo Readiness)

This checklist defines **pass/fail criteria** for calling the demo “fully hardened,”
including the goal of a static envelope around a dynamic agent.
Each item includes a current status and evidence pointer.

Status key: `DONE`, `PARTIAL`, `TODO`.

## 1) Enforcement Path (Policy -> Physics)

- **All side effects go through nucleus-tool-proxy**
  - Pass: CLI/tool adapters can only execute file/command/network ops via the proxy API.
  - Current: `DONE` (CLI uses node + MCP; no unsafe direct mode).
  - Evidence: `crates/nucleus-cli/src/run.rs`
- **CLI hard-fail if not enforced**
  - Pass: No unsafe flags; enforced mode is the default path.
  - Current: `DONE` (unsafe flag removed).
  - Evidence: `crates/nucleus-cli/src/run.rs`
- **Node API requires signed requests**
  - Pass: nucleus-node rejects unsigned HTTP/gRPC calls.
  - Current: `DONE` (auth secret required).
  - Evidence: `crates/nucleus-node/src/main.rs`, `crates/nucleus-node/src/auth.rs`

## 2) Network Egress Control

- **Default-deny enforced for Firecracker pods**
  - Pass: netns iptables default DROP even without `spec.network`.
  - Current: `DONE`.
  - Evidence: `crates/nucleus-node/src/main.rs`, `crates/nucleus-node/src/net.rs`
- **IPv6 is denied or disabled**
  - Pass: ip6tables mirrors default-deny OR guest IPv6 is disabled.
  - Current: `TODO`.
  - Evidence: `crates/nucleus-node/src/net.rs`, guest init
- **DNS allowlisting**
  - Pass: explicit hostname allowlist enforced (ipset/dnsmasq or equivalent).
  - Current: `TODO`.
  - Evidence: `crates/nucleus-node/src/net.rs`, `crates/nucleus-spec/src/lib.rs`

## 3) Approvals (AskFirst)

- **Approvals are cryptographically signed**
  - Pass: approvals require signed tokens with nonce + expiry, verified in proxy.
  - Current: `DONE` (approval secret required; nonce + expiry enforced).
  - Evidence: `crates/nucleus-tool-proxy/src/main.rs`
- **Approval replay protection**
  - Pass: nonce cache + expiry enforced for all approvals.
  - Current: `DONE` (nonce required for approvals).
  - Evidence: `crates/nucleus-tool-proxy/src/main.rs`

## 4) Isolation (VM Boundary)

- **Rootfs is read-only**
  - Pass: image configured read-only; scratch is explicit and limited.
  - Current: `DONE` (when image spec requests it).
  - Evidence: `scripts/firecracker/build-rootfs.sh`, `crates/nucleus-node/src/main.rs`
- **Guest has no extra services**
  - Pass: init runs tool-proxy only.
  - Current: `DONE`.
  - Evidence: `crates/nucleus-guest-init/src/main.rs`
- **Seccomp enforced**
  - Pass: seccomp profile configured and verified.
  - Current: `PARTIAL` (config supported; verification pending).
  - Evidence: `crates/nucleus-node/src/main.rs`, `crates/nucleus-spec/src/lib.rs`

## 4.5) Monotone Security Posture (Immutability)

- **No privilege relaxation after creation**
  - Pass: permission state can only tighten or the pod is terminated.
  - Current: `PARTIAL` (policy normalization enforced; no runtime guardrail).
  - Evidence: `crates/lattice-guard/src/lattice.rs`, `crates/nucleus-cli/src/run.rs`
- **Network policy drift detection**
  - Pass: host checks iptables drift and fails closed on deviation.
  - Current: `DONE`.
  - Evidence: `crates/nucleus-node/src/net.rs`, `crates/nucleus-node/src/main.rs`
- **Seccomp immutability documented**
  - Pass: docs explicitly state seccomp is fixed at Firecracker spawn.
  - Current: `DONE`.
  - Evidence: `docs/architecture/overview.md`, `README.md`

## 5) Audit + Integrity

- **Audit log signatures**
  - Pass: log entries are signed; verification tool exists.
  - Current: `PARTIAL` (signatures enforced; verifier pending).
  - Evidence: `crates/nucleus-tool-proxy/src/main.rs`
- **Remote append-only storage**
  - Pass: logs shipped to append-only store (or immutability proof).
  - Current: `TODO`.

## 6) Formal Assurance Gates

- **ν laws proven in CI**
  - Pass: Kani proof job runs in CI and blocks merges on failure.
  - Current: `PARTIAL` (Kani proofs exist, nightly job runs; merge gate pending).
  - Evidence: `crates/lattice-guard/src/kani.rs`
- **Fuzzing in CI**
  - Pass: cargo-fuzz targets run with time budget; known bypasses blocked.
  - Current: `PARTIAL` (targets exist; CI gate pending).
  - Evidence: `fuzz/`

## 7) Demo Verification Script

- **Network policy test**
  - Pass: `scripts/firecracker/test-network.sh` passes with allow/deny.
  - Current: `DONE` (manual).
  - Evidence: `scripts/firecracker/test-network.sh`

## Exit Criteria (Full Hardened Demo)

All items above at `DONE`, and:
- Enforced CLI path is the default.
- IPv6 + DNS allowlisting are covered.
- Signed approvals + audit verification are implemented.
- CI gates (Kani + fuzz + integration tests) are in place.
