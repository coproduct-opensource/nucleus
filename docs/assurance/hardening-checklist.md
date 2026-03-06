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
  - Current: `DONE` (guest IPv6 disabled at boot).
  - Evidence: `crates/nucleus-node/src/main.rs`
- **DNS allowlisting**
  - Pass: explicit hostname allowlist enforced (ipset/dnsmasq or equivalent).
  - Current: `DONE` (dnsmasq proxy with pinned hostname resolution).
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
  - Pass: seccomp profile configured and verified post-spawn.
  - Current: `DONE` (config applied via `apply_seccomp_flags`; post-spawn `/proc/{pid}/status` verification checks mode=2).
  - Evidence: `crates/nucleus-node/src/main.rs` (verify_seccomp_active, apply_seccomp_flags), `crates/nucleus-spec/src/lib.rs` (SeccompSpec)

## 4.5) Monotone Security Posture (Immutability)

- **No privilege relaxation after creation**
  - Pass: permission state can only tighten or the pod is terminated.
  - Current: `DONE` (Verus-proven E1-E3 enforcement boundary + runtime debug_assert).
  - Evidence: `crates/portcullis-verified/src/lib.rs` (E1: taint monotonicity, E2: trace monotonicity, E3: denial monotonicity), `crates/portcullis/src/guard.rs` (debug_assert in execute_and_record)
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
  - Current: `DONE` (signatures enforced; verifier available).
  - Evidence: `crates/nucleus-tool-proxy/src/main.rs`, `crates/nucleus-audit/src/main.rs`
- **Remote append-only storage**
  - Pass: logs shipped to append-only store (or immutability proof).
  - Current: `DONE` (S3AuditBackend with `if_none_match("*")` append-only semantics; behind `remote-audit` feature flag).
  - Evidence: `crates/portcullis/src/s3_audit_backend.rs`, `crates/nucleus-spec/src/lib.rs` (AuditSinkSpec)

## 6) Formal Assurance Gates

- **ν laws proven in CI**
  - Pass: Verus/Kani proof jobs run in CI and block merges on failure.
  - Current: `DONE` (297 Verus proofs + 14 Kani harnesses; both are required merge checks on main).
  - Evidence: `.github/workflows/verus.yml`, `.github/workflows/kani-nightly.yml`, `crates/portcullis-verified/src/lib.rs`, `crates/portcullis/src/kani.rs`
- **Fuzzing in CI**
  - Pass: cargo-fuzz targets run with time budget; known bypasses blocked.
  - Current: `DONE` (3 fuzz targets × 30s; Fuzz is a required merge check on main).
  - Evidence: `fuzz/`, `.github/workflows/ci.yml`

## 6.5) Web Ingress Control

- **MIME type gating on web_fetch**
  - Pass: only text and structured data MIME types are allowed; binary formats blocked.
  - Current: `DONE` (allowlist: text/*, application/json, application/xml, etc.).
  - Evidence: `crates/nucleus-tool-proxy/src/main.rs` (web_fetch handler)
- **Taint provenance on fetched content**
  - Pass: all web-fetched content is tagged with `X-Nucleus-Taint: UntrustedContent` + source domain.
  - Current: `DONE`.
  - Evidence: `crates/nucleus-tool-proxy/src/main.rs` (response headers)
- **URL pattern allowlisting**
  - Pass: per-pod URL pattern allowlist via `NetworkSpec.url_allow`.
  - Current: `DONE` (glob-style matching; empty = allow all permitted domains).
  - Evidence: `crates/nucleus-spec/src/lib.rs` (NetworkSpec), `crates/nucleus-tool-proxy/src/main.rs`

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
