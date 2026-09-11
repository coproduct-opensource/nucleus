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
| 2c | PASS | 2026-09-09 | **All checks passed** on a live aarch64/KVM pod (`nucleus-kvm`), pod up in 3,001 ms: `glob` 200; `read audit/nucleus-audit.log` **200 with real bytes**; unapproved write **403** (the gate holds); `/v1/approve` 200; **approved write 200**; **read-back == written 200**; forbidden read 403; uncredentialed `web_fetch` 403. So the pod both reads and writes its workspace, and one human approval buys exactly one write. Three separate causes had to be named, and two of them were wrong beliefs recorded in rows 2 and 2b rather than defects:<br><br>**(i) "There is no file in the sandbox a `codegen` pod may read" (row 2) is false.** There is: `audit/nucleus-audit.log`. Row 2 read the *directory* `audit`, which is `EISDIR`, and #2407 (row 7) had already fixed that from being reported as a denial — it now answers 400 `path_unusable`, and the harness walks on to the next glob match, which serves bytes. No sandbox change was needed for the read half at all.<br><br>**(ii) "`/work` is NOT the sandbox root" (row 2b) does not follow from its evidence.** `/work/audit` returned `sandbox_escape` because `Sandbox::check_policy` rejects **any absolute path** before the root is ever consulted (`crates/nucleus/src/sandbox.rs`, the `path.is_absolute()` arm). The probe therefore said nothing about where the root is; `/work` *is* the root, and the relative form is what to use.<br><br>**(iii) The write half was two real defects, both #2406.** The kernel's `Verdict::RequiresApproval` never read the `ApprovalRegistry` that `/v1/approve` writes to, so an approved retry was refused with the operation string the caller had just approved — visible in this pod's own signed mediation receipts as seq 7 `write_files` `requires_approval`, seq 8 the approve call `allow`, seq 9 `write_files` `requires_approval` again. Fixing that exposed the second: the two approval gates named the same act differently — the kernel `WriteFiles <path>`, the sandbox `write <path>`, because `check_write_capability` composed its key from the *method verb* rather than from the `Operation` it already had. Both are fixed by one rule: an approval is named `{Operation:?} {subject}` everywhere (`Sandbox::approval_key`), and the peek/spend split gives one grant one write. Prerequisites #2400 and #2401 turned out not to block this — the receipts, not the error text, are what localised it. |
| 3 | PASS | 2026-09-09 | Same run as 2c. The full mediated sequence — discover, read, refuse, approve, write, read back, refuse the forbidden, refuse the uncredentialed — runs end to end on one pod with no step skipped and no failure. Timings: glob 199 ms, read 102 ms, write 166 ms, read-back 105 ms, refusals 44–71 ms. Non-vacuity is inside the same run rather than argued: the unapproved write is refused **403** and the approved one succeeds **200**, so the gate is demonstrably load-bearing, not merely absent. |
| 4 | TODO | | |
| 5 | TODO | | |
| 6 | TODO | | |
| 7 | PASS | 2026-09-03 | Refusals now carry a cause, and an errno no longer masquerades as one. Fourteen sites in `sandbox.rs` mapped EVERY filesystem error to `PathDenied`, so a live pod reported `access denied: path 'audit': Is a directory (os error 21)` with `kind=path_denied` and a 403 -- nothing had denied anything. Now classified by what the OS said: `PermissionDenied` -> `PathDenied` 403 (a real denial), `NotFound` -> 404, else 400. Same defect Linux hit from the other side (apparmor returned ENOENT when it denied). #2407, merged. Prerequisite was #2401, which made the reason visible at all -- before that this could not be judged. |
| 8 | PASS | 2026-09-03 | Leak classes measured on a host with ZERO live Firecrackers: **2 leaked netns** (`nuc-f45b3cc8`, `nuc-59c6d719`), 0 cgroups, 0 taps, 189 state dirs. The two namespaces were exactly the pods whose guests kernel-panicked; every clean boot reaped its own -- so cleanup ran on the paths somebody remembered, and not on the late ones (config-serialise, health-wait). Fixed with a drop guard rather than more enumerated arms (#2408). The 189 state dirs are audit material (`lifecycle.log`, receipts) with no rotation policy -- a separate RETENTION question, deliberately not "fixed" by deleting audit data. 20-call sequence still to run. |
| 9 | PASS | 2026-09-03 | `unaccounted` 83% -> **13.5%** (target <15%). 398/477ms -> 94/443ms (#2410, checkpoints for stretches `timed` cannot wrap) -> 62/458ms (#2411, the 36ms `router_build` hole plus splitting the biggest phase). Attribution: state_build=109ms, runtime_build=92ms, args_parse=68ms, sandbox_proof=35ms, router_build=32ms, tracing_init=21ms, crypto_provider=14ms. **Those first three are 269ms of 458ms and are the Stage C targets.** |
| 10 | TODO | | |
| 11 | PASS | 2026-09-03 | Named, with milliseconds rather than adjectives: **state_build 109ms** (attestation verifier, node client, delegation ceiling, credential loading), **runtime_build 92ms**, **args_parse 68ms** (49 clap args, all using `env =`). Together 269ms of a 458ms boot. Next three: sandbox_proof 35ms, router_build 32ms, tracing_init 21ms. Caveat recorded honestly -- `mark` measures wall-clock, and on a 1-vCPU guest a single sample cannot separate CPU cost from descheduling, so these rank the phases rather than prove their CPU cost. |
| 12 | TODO | | |
| 13 | PARTIAL | 2026-09-03 | The measured failure is gone; the clause it was written around is met. With NO explicit override, **N=10 goes 0/10 -> 10/10 in 74.6s** (#2415, health budget scales with live microVMs, capped 8x). Regression side clean: N=1 3,011 -> 3,013ms, N=5 10,902 -> 10,384ms -- both inside the +/-3% run-to-run noise, so scaling the deadline did not disturb the uncontended path. `largest clean burst` 5 -> 10. **Still PARTIAL**: iteration 13 asks for edge-triggered readiness, and this is an adaptive deadline instead -- the host still polls. N=25/50 unmeasured against this change, so the ceiling has moved, not gone. |
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
| #2406 | 2c, 3 | **CLOSED 2026-09-09.** A granted approval did not satisfy the retry it was granted for. Two causes: the kernel gate never consulted the `ApprovalRegistry`, and the two gates spelled the same approval differently. Fixed by consulting it and by unifying on `Sandbox::approval_key`. |
| #2402 | -- | The `[sandbox]` redaction branch never runs in production (`sanitize_error_message(msg, None)`), so denial messages must withhold the sandbox root themselves rather than rely on it. |
