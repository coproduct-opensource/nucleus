# gatehouse, in one step

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@v5
  - uses: coproduct-opensource/nucleus/.github/actions/gatehouse@main
    with:
      run: cargo test --workspace
```

That runs the command the gatehouse way and reports, in the step summary:

- the verdict (`held` / `failed`), from a run over the scope materialized from the commit
  (nothing outside it exists), with the declared environment and the command's own timeout;
- a receipt signed by a key this run alone holds, included in a hosted transparency log with
  an inclusion proof, and **verified on this runner** against the tenant's trust;
- whether the same command run plainly agreed (the shadow line), and the run attempt, so
  re-runs and flips are counted per gate on the control plane.

The run's identity is its GitHub OIDC token: no key, no secret, no prior account. The tenant
is named after the repository. The step fails only when it could not look (no OIDC token, a
refused exchange, a runner that errored, a receipt that could not be verified); a gate that
does not hold is reported, never a red, until you make it required.

| input | default | |
|---|---|---|
| `run` | required | the shell line to run |
| `name` | the job id | the gate's name |
| `scope` | `**` | newline-separated globs the command may read |
| `timeout` | `3600` | seconds |
| `env` | | `KEY=VALUE` lines the command sees (declared, hashed); `PATH`, `HOME`, and `RUSTUP_HOME`/`CARGO_HOME` when present are set |
| `git-history` | `false` | let the command read git history |
| `compare` | `true` | also run the command plainly and report agreement |
| `control-url` | `https://gatehouse-controld.fly.dev` | the control plane |
| `version` / `binaries` | `v0.1.0` / `coproduct-opensource/gatehouse-action` | the release the static binaries come from, checked against its `SHA256SUMS` |
| `bin-dir` | | use `gate` and `gatehouse-runner` from this directory instead (a build from source) |

Outputs: `verdict`, `verified`, `receipt_index`, `agree`, `tenant`.

What it is not: the receipt is developer tier, and the party trusts the hosted log's checkpoint
on first use. Installing the gatehouse App runs the gates in the service's own sandboxes at
NodeAttested; `gate trust adopt` lets you hold your own witnessed checkpoint. Both are upgrades,
neither is a prerequisite.
