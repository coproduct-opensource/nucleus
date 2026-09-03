# Rubric ledger — one microVM per agent tool call

State for [`agent-tool-call-isolation.md`](agent-tool-call-isolation.md). A loop
iteration takes the lowest-numbered row that is not `PASS`, does it, and appends
its result.

`status` is `PASS`, `FAIL`, or `BLOCKED: <reason>`. **A `FAIL` row is never
overwritten** — a retry is a new row. The record of what did not work is the
most valuable thing in this file.

Host of record: aarch64, KVM, 4 vCPU, 7.9 GiB (`nucleus-kvm`). Host binaries,
guest rootfs and harness must be built from one tree; skew presents as
`401 invalid signature`, not as a version error (#2396).

| # | status | date | evidence |
| --- | --- | --- | --- |
| 1 | PASS | 2026-09-02 | Ramp on 4 vCPU / 7.9 GiB: N=1 5,580ms 1/1 · N=5 10,902ms 5/5 · N=10 0/10 · N=25 0/25 · N=50 5/50. RSS 50 MiB/pod vs 512 MiB configured (10x). All N>=10 failures were `proxy health check timed out after 30s`, not capacity. With the timeout raised: N=10 → 10/10 in 74s, confirming the wall is a fixed timeout under CPU contention. Guest startup `unaccounted=76,081ms of 85,858ms` (89%). |
| 2 | FAIL | 2026-09-02 | `toolcall` implemented and runs. Pod up in **3,011 ms** clean (vs 5,580 ms under load). glob 200 in 197ms; both refusals correct (`.ssh/id_rsa` 403 `path_denied`, uncredentialed `web_fetch` 403). Read FAILED: the sandbox root contains only `audit`, and reading it is 403 `path_denied` -- it is the audit-log directory, correctly blocked as sensitive. **There is no file in the sandbox a `codegen` pod may read**, so the read path cannot be proven without first creating one. Write is also blocked: 403 `approval_required` -- `write_files` is `LowRisk` in `codegen`, which needs an approval token via `/v1/approve`. |
| 2b | FAIL | 2026-09-03 | Probed three path forms against a live pod. NONE accepted: `audit` -> 403 `path_denied`; `./audit` -> 403 `path_denied`; `/work/audit` -> 403 **`sandbox_escape`**, so **`/work` is NOT the sandbox root** despite being the spec's `work_dir`. Probing the lattice directly shows it PERMITS all of these (`audit`, `./audit`, `perf-1.txt` all `can_access=true`; only `.ssh/id_rsa` is blocked), so the refusal comes from the pod's effective policy and the message names a layer, not a rule -- #2400. Cannot presently tell why a read is refused, which blocks iteration 2. |
| 2c | TODO | | Unblock, revised. The write path needs `/v1/approve`, which is Ed25519 over `{round}.{timestamp}.{actor}.{body}` with a drand round (`nucleus-tool-proxy/src/auth.rs:396`); the approver private key lives host-side at `/var/lib/nucleus/state/approval_signing_key.der`, so the harness CAN legitimately act as approver. Prerequisite: #2400 (so a refusal says which rule fired) and #2401 (the lattice half, merged into that chain). |
| 3 | TODO | | |
| 4 | TODO | | |
| 5 | TODO | | |
| 6 | TODO | | |
| 7 | TODO | | |
| 8 | TODO | | |
| 9 | TODO | | |
| 10 | TODO | | |
| 11 | TODO | | |
| 12 | TODO | | |
| 13 | TODO | | |
| 14 | TODO | | |
| 15 | TODO | | |
| 16 | TODO | | |
| 17 | TODO | | |
| 18 | TODO | | |
| 19 | TODO | | |
| 20 | TODO | | |
| 21 | TODO | | |
| 22 | TODO | | |
| 23 | TODO | | |
| 24 | TODO | | |
| 25 | TODO | | |
| 26 | TODO | | |
| 27 | TODO | | |
| 28 | TODO | | |
| 29 | TODO | | |
| 30 | TODO | | |
| 31 | TODO | | |
| 32 | TODO | | |
| 33 | TODO | | |
| 34 | TODO | | |
| 35 | TODO | | |
| 36 | TODO | | |
| 37 | TODO | | |
| 38 | TODO | | |
| 39 | TODO | | |
| 40 | TODO | | |

## Open defects blocking iterations

| issue | blocks | note |
| --- | --- | --- |
| #2395 | 8, 27–32 | A `guest_cid` other than 3 panics the guest. Harmless while every pod shares CID 3, but any per-pod CID scheme trips it. |
| #2396 | all | `nucleus setup` silently replaces locally-built binaries; the symptom is `401 invalid signature`. |
| #2400 | 2, 2b, 3 | A path refusal names a layer ("blocked by the path lattice"), not the rule that fired. Until it does, a refused read cannot be diagnosed. |
| #2402 | -- | The `[sandbox]` redaction branch never runs in production (`sanitize_error_message(msg, None)`), so denial messages must withhold the sandbox root themselves rather than rely on it. |
