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
