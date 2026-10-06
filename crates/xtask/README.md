# xtask

The workspace task runner — a Rust-native replacement for ad-hoc shell scripts.

Following the repo's "Rust-based tooling first" convention, build/CI/dev
orchestration that used to live in `scripts/*.sh` is migrated here one command at
a time so it is cross-platform, type-checked, and unit-testable.

## Running

```bash
cargo xtask <command>     # via the .cargo/config.toml alias
just xtask <command>      # via the justfile recipe (same thing)
cargo xtask --help        # list commands
```

## Commands

| Command | Description |
|---|---|
| `scripts` | Inventory every `*.sh` in the repo and flag which are port candidates vs. which must stay shell. Effectively the migration backlog. |

| `agent-builder up\|status\|down` | Operator tooling: the disposable build VM (see below). |

## What gets ported (and what doesn't)

Orchestration scripts — build/CI/dev glue — get ported here. Scripts that are
shell *by nature* are intentionally **not** ported and are listed in
`KEEP_AS_SHELL` in [`src/main.rs`](src/main.rs):

- anything that runs *inside* the Firecracker guest or at boot
  (`scripts/firecracker/*.sh`)
- in-container smoke tests (`scripts/container/smoke-test.sh`)
- the GitHub-action entrypoint (`scripts/action-entrypoint.sh`)
- the curl-bootstrap installer (`scripts/install.sh`)

Run `cargo xtask scripts` to see the current PORT-vs-KEEP split.

> Security-gate scripts (e.g. `ci/no-vendor-strings.sh`, `ci/alg-pin-check.sh`)
> are ported only via a **reviewed** PR with verified shell↔Rust equivalence —
> never as an unattended change, since a silent behavior drift could weaken a
> gate.

## Adding a command

1. Add a variant to the `Command` enum in [`src/main.rs`](src/main.rs) with a
   `///` doc comment (clap turns it into `--help` text).
2. Add its match arm in `main()` and implement the handler function.
3. Keep the logic pure/testable where possible and add a `#[cfg(test)]` test.
4. If it replaces a shell script, add/keep a `just` recipe that calls
   `cargo xtask <command>`, update any CI/doc callers, and remove the old script
   (or leave a thin shim if an external caller depends on it).

## Notes

- `publish = false` — this is a dev-only crate, never published to crates.io.
- The workspace root is located relative to `CARGO_MANIFEST_DIR`, so commands
  work regardless of the current directory.

## Operator tooling: agent build VM

`cargo xtask agent-builder` is **operator tooling**, not part of the runtime and not a
gate: nothing in nucleus depends on it. It drives the `gcloud` CLI to keep one disposable
build VM — the machine agents compile and test on instead of a laptop — and it names no
project, region or machine shape. Those come from flags or environment variables:

```bash
export AGENT_BUILDER_PROJECT=<project>
export AGENT_BUILDER_ZONES=<zone>,<fallback-zone>     # tried in order on capacity/quota errors
export AGENT_BUILDER_MACHINE_TYPE=<arm64 machine type>
export AGENT_BUILDER_DISK_TYPE=<disk type>
export AGENT_BUILDER_SERVICE_ACCOUNT=<sa email>      # least privilege: the cache bucket only

cargo xtask agent-builder up       # create from the image family (or adopt a running one), wait until ready
cargo xtask agent-builder status   # every instance labelled role=agent-builder
cargo xtask agent-builder down     # delete it -- refused unless it carries role=agent-builder
```

What is fixed rather than configurable, because an idle build VM costs money silently:
the VM is spot, `--max-run-duration 12h`, `--instance-termination-action DELETE`, and
labelled `role=agent-builder`. `create` refuses to run if any of those is missing from its
own command line, and `down` deletes only an instance whose label it has just read back.

`up` boots from the newest image in `--image-family` (default `nucleus-agent-builder`),
an image the operator bakes with the pinned toolchain, build tools, a pre-fetched cargo
registry and a compiler cache configured as `RUSTC_WRAPPER`. The boot-time script only
refreshes the baked `~/nucleus` clone and writes `/var/tmp/provisioned`; `up` waits for
that marker over an IAP tunnel and prints how long creation and provisioning took. The
image bake itself is operator-side and lives outside this repository.
