# Posture for an adversarial model

Nucleus's headline guarantee is non-interference over a proven information-flow
lattice. That guarantee has an adversary in mind, and it is worth naming which
one — because the answer changes what the runtime is doing for you.

This document exists because the boundary was real but only recorded in a test
name and a design-delta table (#2738). It is stated here instead.

## Two adversaries

**The confused deputy.** The model is working for you. An attacker gets
content in front of it — a poisoned web page, a hostile issue comment, a
malicious tool description — and tries to turn a privileged action against you.
This is indirect prompt injection, and it is what the lattice is for.

Against this adversary the guarantee is structural. The ingest is mediated, so
the session carrying the attacker's instructions is `Adversarial`, and the
`BashExec` floor refuses the spawn outright:

```rust
assert_eq!(SinkClass::BashExec.required_integrity(), IntegLevel::Untrusted,
    "BashExec must refuse an adversarial-tainted session from spawning a shell");
```

No shell starts. There is nothing downstream to contain.

**The hostile principal.** The model is not a deputy. It is abliterated,
backdoored, fine-tuned against you, or simply misaligned — and it can read this
repository, which for this threat model means the adversary has the source.

Against this adversary the lattice does not help, and the reason is precise: the
session is **clean by construction**. Your own prompt is `Trusted`/`Directive`.
Nothing tainted it. So the model spawns a shell legitimately, and from that
moment:

- the lattice sees nothing the shell does — one `(RunBash, BashExec)` authority
  buys arbitrary syscalls in the guest, and `bash -c 'curl | sh'` never reaches
  `NetEffect::fetch`;
- the command-text taint classifier (`command_output_is_external`) is a
  heuristic that states its own evadability, and it only decides whether output
  is *labelled*, not whether the command *runs*;
- the actual perimeter is the pod's netns/iptables default-deny, whose semantics
  are **trusted, not proven** (see `docs/production-delta.md`).

A network fence around an untrusted process is a real boundary, and #2365 makes
every pod prove it has one rather than assume it. But it is a much narrower
claim than non-interference, and it should not be read as the same result.

## What to do about it

**Remove the capability rather than track the flow.** A flow-time denial fires
only when the session is tainted, and this adversary's session never is. Arity
is the defence: what is absent cannot be misused.

Use the **`untrusted-model`** profile:

```yaml
run_bash:     never   # no exec surface at all
spawn_agent:  never   # no delegation to a less-constrained child
manage_pods:  never
web_fetch:    never   # a URL is a channel
web_search:   never
git_push:     never
create_pr:    never
git_commit:   never
```

`read_files`, `write_files`, `edit_files`, `glob_search` and `grep_search`
remain, so the profile is still useful for the work people actually want a
constrained model to do. It is not `never` everywhere, which would be a profile
nobody adopts.

### Why no `NUCLEUS_PARANOID_TOOL_IO=1` here

#2738 asked for this posture to default `NUCLEUS_PARANOID_TOOL_IO=1` so that no
heuristic sits in the path. Under `run_bash: never` there is no heuristic to
default: `/v1/run` maps to `Operation::RunBash` at the run gate, `RunBash` is not
in scope, so the request is denied before a command runs and
`should_observe_command_output` is never consulted for that pod. The heuristic is
out of the path *by construction* rather than by configuration.

It is still worth setting for any profile that **does** permit exec — `codegen`,
`local-dev`, `test-runner`, `release`, `safe-pr-fixer` — where the classifier's
stated evasion (obfuscated program names) is a white-box target. Making that a
per-profile field rather than a process-wide environment variable is #2738
item 3, and is not done here.

## What this does not claim

- **It bounds reach, not authorship.** The model still chooses what to write
  through `write_files`/`edit_files`, and content written to disk is content.
  Pair this with `paths.blocked` and with review of the diff, exactly as you
  would for an untrusted contributor.
- **Its in-guest syscall mediation is two classes wide.** Since #2907 the
  guest derives a seccomp policy from the pod's lattice
  (`portcullis::SeccompPolicy`) and installs it with the workload denylist:
  under `run_bash: never` a child cannot `execve` (the runtime starts it
  through one pinned descriptor), and under `web_fetch: never` with no declared
  egress it cannot open an `AF_INET`/`AF_INET6` socket. Both answer `EPERM`.
  That is the start of #2738 item 4, not all of it: `write_files: never`
  (write-mode `open` outside the scratch), argument-level socket narrowing to
  the ports a profile names, and a live adversary-probe stage that sees the
  derived filter bite on real KVM are still open on #2907. Firecracker itself
  runs under a seccomp filter and `verify --tier2` checks it.
- **Workload identity rests on arrival order, not on peer authentication.**
  Until #2724 a workload inside the pod could fetch the pod's SVID private key,
  policy certificate, task token, caller token and DLC credentials over vsock.
  Every per-pod value is now served ONCE (`ServedLedger`), to guest-init, before
  the workload exists, and guest-init refuses to boot if any was already taken.
  The vsock port on the world-readable `/proc/cmdline` still lets a workload
  connect, and what it can still get is public or its own: the trust bundle,
  the SVID's public chain, its pod spec, a ping, its pod listing, and receipt
  shipping (signed receipts are verified later, so a forged one proves
  nothing). The transport carries no peer credentials (virtio-vsock clears
  them), so a design that needs to serve a secret AFTER boot would need a
  bearer nonce handed to guest-init, and none does today.
