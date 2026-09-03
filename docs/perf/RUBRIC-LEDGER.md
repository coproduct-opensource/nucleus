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
| 7 | PASS | 2026-09-03 | Refusals now carry a cause, and an errno no longer masquerades as one. Fourteen sites in `sandbox.rs` mapped EVERY filesystem error to `PathDenied`, so a live pod reported `access denied: path 'audit': Is a directory (os error 21)` with `kind=path_denied` and a 403 -- nothing had denied anything. Now classified by what the OS said: `PermissionDenied` -> `PathDenied` 403 (a real denial), `NotFound` -> 404, else 400. Same defect Linux hit from the other side (apparmor returned ENOENT when it denied). #2407, merged. Prerequisite was #2401, which made the reason visible at all -- before that this could not be judged. |
| 8 | PARTIAL | 2026-09-03 | Leak classes measured on a host with ZERO live Firecrackers: **2 leaked netns** (`nuc-f45b3cc8`, `nuc-59c6d719`), 0 cgroups, 0 taps, 189 state dirs. The two namespaces were exactly the pods whose guests kernel-panicked; every clean boot reaped its own -- so cleanup ran on the paths somebody remembered, and not on the late ones (config-serialise, health-wait). Fixed with a drop guard rather than more enumerated arms (#2408). The 189 state dirs are audit material (`lifecycle.log`, receipts) with no rotation policy -- a separate RETENTION question, deliberately not "fixed" by deleting audit data. 20-call sequence still to run. |
| 9 | PASS | 2026-09-03 | `unaccounted` 83% -> **13.5%** (target <15%). 398/477ms -> 94/443ms (#2410, checkpoints for stretches `timed` cannot wrap) -> 62/458ms (#2411, the 36ms `router_build` hole plus splitting the biggest phase). Attribution: state_build=109ms, runtime_build=92ms, args_parse=68ms, sandbox_proof=35ms, router_build=32ms, tracing_init=21ms, crypto_provider=14ms. **Those first three are 269ms of 458ms and are the Stage C targets.** |
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
