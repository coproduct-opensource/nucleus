# Working on nucleus from an ephemeral container

Companion to `CLAUDE.md`, which covers what the project *is* — vendor
neutrality, architecture, the gates-are-Rust mandate. This file covers what the
*environment* can do, and it exists because each of the facts below cost a
session to establish and none of them is discoverable by reading the tree.

Everything here was measured, not inferred. Where something was not measured it
says so.

## What a sandboxed container can and cannot run

**It can boot a node.** It cannot boot a Tier 2 pod. Those are different
questions and conflating them wastes a lot of time: KVM gates *pod launches*,
not `nucleus-node` itself.

Establish which you are on before concluding anything:

```sh
systemd-detect-virt                 # `docker` inside a Firecracker VM is typical
uname -r                            # a `-fc-` kernel means you are already in a microVM
ls /dev/kvm /dev/vhost-vsock        # both required for Tier 2
grep -oE 'vmx|svm' /proc/cpuinfo    # empty means no nested virtualisation
```

With no `/dev/kvm`, no `/dev/vhost-vsock` and no `vmx`/`svm`, Tier 2 is
genuinely impossible and `verify --tier2` cannot pass. **Everything short of a
microVM still works**, including the whole HTTP/mTLS surface, the CLI client
path, and — via the local driver — a real pod lifecycle.

`crates/nucleus-node/src/host_requirements.rs` is the tree's own statement of
what a launch needs; its `unmet` half is pure and runs anywhere.

## Booting a node, verified

Only two arguments lack defaults:

```sh
cargo build -p nucleus-node
./target/debug/nucleus-node \
  --state-dir /tmp/nstate --listen 127.0.0.1:8080 \
  --proxy-auth-secret <any> --proxy-approval-secret <any>
```

On first boot it creates `<state-dir>/ca/{ca-cert,ca-key}.pem`, four signing
keys, and self-issues `spiffe://nucleus.local/ns/system/sa/node`. **No external
SPIRE agent is involved and none is needed** — a sandbox typically has no SPIFFE
identity of its own (no `SPIFFE_*` env, no workload-API socket); nucleus mints
its own.

### The listener is mTLS-only, and its route is `/v1/health`

Measured against a live node:

| request | result |
|---|---|
| plaintext `http://…:8080/v1/health` | `curl: (1) Received HTTP/0.9 when not allowed` |
| `https://` with no client cert | `tlsv13 alert certificate required` |
| mTLS `GET /health` | **403** |
| mTLS `GET /v1/health` | **200** `{"status":"ok"}` |

A probe that speaks plaintext, or asks `/health`, cannot succeed against any
healthy node. Two shipped commands had exactly that defect (#2788, #2734), and
both reported it as *the node* being unreachable.

### Minting a client identity without running `setup`

`setup` is the supported path; this is the short one when you only need to talk
to a node you just started. The SAN must be a SPIFFE **URI**, not a DNS name —
the node's own certificate carries no DNS/IP SAN either, which is why callers
skip hostname verification.

```sh
cat > san.cnf <<'EOF'
[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[dn]
CN = nucleus-cli
[v3]
subjectAltName = URI:spiffe://nucleus.local/ns/system/sa/cli
extendedKeyUsage = clientAuth
keyUsage = critical, digitalSignature, keyEncipherment
EOF
openssl ecparam -name prime256v1 -genkey -noout -out cli-key.pem
openssl req -new -key cli-key.pem -out cli.csr -config san.cnf
openssl x509 -req -in cli.csr -CA <state-dir>/ca/ca-cert.pem \
  -CAkey <state-dir>/ca/ca-key.pem -CAcreateserial \
  -out cli-cert.pem -days 1 -extfile san.cnf -extensions v3
```

Drop `cli-cert.pem`, `cli-key.pem` and the CA as `trust-bundle.pem` into
`~/.config/nucleus/identity/` and the CLI finds them by itself
(`node.rs::apply_provisioned_identity_defaults`): `nucleus node health` then
answers. Note `~/.config/nucleus`, **never** `dirs::config_dir()` — see
`config::nucleus_dir`'s doc comment for the defect that rule exists to prevent.

## A real pod lifecycle without KVM

The `local-driver` feature runs a pod as a process rather than a microVM. It is
not a default feature and the node refuses it without the flag:

```sh
cargo build -p nucleus-node --features local-driver
cargo build -p nucleus-tool-proxy
./target/debug/nucleus-node --state-dir /tmp/nstate --listen 127.0.0.1:8088 \
  --driver local --allow-local-driver \
  --tool-proxy-path "$PWD/target/debug/nucleus-tool-proxy" \
  --proxy-auth-secret <any> --proxy-approval-secret <any>
```

A minimal spec that is accepted — `command` is **not** a field, and the error
says so:

```json
{"apiVersion":"nucleus/v1","kind":"Pod","metadata":{"name":"probe"},
 "spec":{"work_dir":"/tmp/probe-work"}}
```

`POST /v1/pods` then issues a real authority (`parent=Root`, `chain_depth=1`),
spawns a tool-proxy, and returns its address. `GET /v1/pods`, `GET
/v1/pods/{id}/receipt` and `POST /v1/pods/{id}/cancel` all work from there;
cancel removes the pod, so read the receipt first.

**This matters for coverage.** `pod_api.rs` and `pod_receipt.rs` are reachable
end-to-end this way, with a genuine `NodeState` and `IdentityManager` rather
than a fake, and CI's coverage job runs `--all-features`, which compiles
`local-driver`. The full receipt path additionally needs a pod that exits on its
own and leaves `.nucleus-exit-report.json` — not yet demonstrated.

## Running the tests the way CI does

**`--all-features`, always, for `nucleus-tool-proxy`.** `mod mcp` is
`#[cfg(feature = "mcp")]`, so `cargo test -p nucleus-tool-proxy` compiles 404
tests and `--all-features` compiles 421. A green default-feature run has
silently skipped the MCP boundary. (`nucleus-cli` has no `[features]` at all, so
there the two are identical.)

Reproducing a feature-driven defect can need the feature named explicitly:
selecting a package that *transitively* enables it is not enough. For
`serde_json/preserve_order`, `-p <crate> --features serde_json/preserve_order`
reproduces; adding a cedar-bearing package to the same invocation does not.

## The ratchets, and one thing the coverage gate does not exclude

- **Line ratchet** (`scripts/check-line-ratchet.sh`, `.line-ratchet.toml`):
  several files sit *exactly* at their ceiling. Check before adding lines,
  including comment lines. Ceilings move with a dated note saying why; the
  direction they are meant to move is down. When a merge from main brings in
  someone else's comments, follow the ceiling rather than delete their prose.
- **Coverage** (`coverage-matrix.yml`): `--fail-under-lines 83` workspace-wide.
  Its `--ignore-filename-regex '(tests/|kani\.rs|main\.rs)'` excludes test
  *directories* and `main.rs` but **not** in-file `#[cfg(test)] mod tests`, so
  test code counts as covered lines on both sides of the ratio. Adding `L` lines
  of executed test code lowers the production lines still needed by `0.17 * L`.
  Worth knowing before reading a percentage as a statement about production
  coverage.

## Disk

The writable allowance is fixed and small relative to a Rust workspace, so `df`
misleads: "Avail" at 0 with low "Used" means the allowance is spent.

- `rm -rf target/debug` reclaims ~20 GB and is the usual fix for `ENOSPC`.
- `export CARGO_INCREMENTAL=0` — the incremental directory alone reached 10 GB.
- `cargo llvm-cov --workspace` writes a *separate* `target/llvm-cov-target` and
  exhausts the allowance before it finishes. Per-crate (`-p nucleus-node`) fits.
  Workspace coverage is a number only CI can produce from here.

## Known-broken on main, so you do not re-diagnose it

`cargo check --workspace --all-targets` fails in
`crates/portcullis-core/src/prov_export.rs` (`cannot find module or crate
serde_json`), while `cargo check -p portcullis-core --all-targets` alone passes
— a workspace feature-resolution effect. Reproduced on a pristine checkout of
`main`; not caused by whatever you are working on.
