# Apple Container microVM host

`nucleus microvm-host` exposes the Apple Container backend for a Firecracker
node on macOS. It requires Apple Silicon M3 or newer, macOS 26 or newer, and
Apple Container 1.4.1 or newer with its service running. These are the backend's
validated minimums. The default Apple Container kernel lacks the KVM devices
needed to launch a pod; supply a kernel built from
[`docker/Containerfile.l1-kernel`](../../docker/Containerfile.l1-kernel).

The host image and L1 kernel are currently local build artifacts. There is no
published image digest selected by this command. Use a host image containing
matched node and guest artifacts, Firecracker/jailer, and `nucleus-hostctl` as
the `run-node` entrypoint. The older release pairing in
`docker/Containerfile.microvm-host` is not a current source-built guest.

That release recipe also builds from a staged flat context, never the
repository root:

```sh
cargo xtask microvm-host-release-context --out /tmp/nucleus-release-context
container build --file /tmp/nucleus-release-context/Containerfile \
  --tag nucleus-microvm-host:release /tmp/nucleus-release-context
```

The staging writes the recipe, `kvm-probe.c`, and the tracked workspace
sources as one `nucleus-source.tar` that the recipe `ADD`s. Its last build step
runs `nucleus-hostctl input-manifest`. That step writes
`/usr/share/nucleus/host-inputs.json` from the installed bytes, refuses a guest
kernel that is not the pinned one, and fails the build if `nucleus-hostctl` or
any pinned input is missing.

## Assemble a local host image

Build the ARM64 Linux host tools from this checkout:

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo zigbuild \
  -p nucleus-node -p nucleus-cli -p nucleus-mcp -p nucleus-microvm-host \
  --target aarch64-unknown-linux-musl
```

Prepare a directory containing `nucleus-node`, `nucleus`, `nucleus-mcp`,
`nucleus-hostctl`, and the pinned ARM64 `firecracker` and `jailer` executables.
The Rust tools are in `target/aarch64-unknown-linux-musl/debug`. Firecracker's
version is declared in `nucleus_spec::vmm_version`; the node checks it at launch.
Use the pinned guest kernel and a workload-capable guest rootfs assembled with
the matching guest runtime. The existing [rootfs builder](../../scripts/firecracker/build-rootfs.sh)
accepts explicit guest binary paths; booting an old image is not evidence that
it can receive and execute a current node's workload specification.

```sh
cargo run -p xtask -- microvm-host-context \
  --bin-dir /absolute/path/to/host-binaries \
  --guest-kernel /absolute/path/to/vmlinux \
  --guest-rootfs /absolute/path/to/rootfs.ext4 \
  --out /tmp/nucleus-host-context

container build --cpus 2 --memory 2g \
  --file /tmp/nucleus-host-context/Containerfile \
  --tag nucleus-microvm-host:local /tmp/nucleus-host-context
```

The output directory must not already exist. Staging copies only the declared
inputs, checks static ARM64 ELF executables and the pinned guest kernel digest,
checks the rootfs superblock, and records every input's SHA-256 and length in
`manifest.json`. It preserves sparse zero extents when copying large rootfs
images. The manifest is also installed at `/usr/share/nucleus/host-inputs.json`.
It records supplied bytes; it does not attest their build origin or establish
guest/runtime compatibility. Validate the intended workload after assembly.

The context uses flat, explicitly named files. On the validated Apple Container
installation, a directory-only `COPY` omitted nested files; the explicit-file
recipe was verified by comparing hashes inside the built image. The recipe
installs OS packages but downloads no replacement node, VMM or guest artifacts,
and contains no default authentication secrets. `microvm-host up` provisions
those secrets for the installation. Both host recipes enable host enforcement,
including the requirement that guests execute the admitted host workload rather
than a spec baked into their rootfs.

Workspace seeding additionally needs mke2fs tar-input support. Both host recipes
install e2fsprogs and libext2fs2 `1.47.2-3~bpo12+1` from Debian bookworm-backports
and explicitly install `libarchive13`, which mke2fs loads at runtime. Bookworm's
default 1.47.0 is refused by `nucleus-hostctl seed`; installing only that default
package does not provide a working workspace builder.

## Bring up the host

```sh
nucleus microvm-host up \
  --image nucleus-microvm-host:local \
  --kernel /absolute/path/to/linux_arm64/Image
```

Keep the kernel's build `config` beside `Image`; the command checks its required
features before creating anything. It checks host prerequisites, prepares a
persistent CA and client identity, creates or restarts its owned container,
probes KVM, and checks `/v1/health` over mTLS. Successful stdout is JSON with
`state: ready`, `node_url`, `identity_dir`, `state_dir` and relay port mappings.
Logs and errors go to stderr. An error exits nonzero and does not report readiness.

The trusted host leaves `/proc/sys` writable so the node can configure forwarding
inside pod network namespaces. It retains Apple's other default read-only paths
and default masked paths, and uses its existing capabilities. This changes the
host's mount policy; workloads still run inside nested Firecracker microVMs.
An owned host with the older read-only policy is treated as configuration drift
and replaced on readiness, so finish active pods before updating the CLI.

The default connection is `--connection published-loopback`. If local published
ports do not work but the Mac can reach the container network, explicitly choose
`--connection container-ip`. The CLI reads the owned container's current IPv4
assignment on its default network and checks the same mTLS node endpoint there.
It refuses a missing or ambiguous assignment. KVM probing, certificate checks and
node health are required for both routes; there is no automatic fallback.
The returned `node_url` identifies the verified route. Container addresses can
change after restart, so use a fresh readiness result instead of saving an IP.
The `relay_ports` field still reports the published port mappings; run's relay
connection uses the selected route and the corresponding container or host port.

The defaults are four CPUs, 4096 MiB of memory and a 120-second readiness timeout.
`--cpus`, `--memory-mib` and `--ready-timeout-secs` override them. CPU and memory
settings apply when creating a container; they do not resize an existing host.
Host-side state defaults to `~/.config/nucleus/microvm-host`; `--state-dir`
selects another directory. Preserve this directory along with the state volume.
Current client credentials are reused byte for byte; missing, invalid or
within-30-days-of-expiry credentials are renewed under the same CA. A partial
CA pair refuses startup and must be restored; `up` does not replace its remaining
half. Client files are replaced atomically one at a time. If renewal is interrupted
between files, the next `up` validates and repairs the client identity.

For an isolated development installation, add `--development`. It uses
`nucleus-dev-microvm-host`, its separate state volume, and
`~/.config/nucleus/microvm-host-dev`. The normal installation uses
`nucleus-microvm-host`. Existing containers without the matching ownership label
are refused. A changed image or incompatible owned container is replaced while
retaining its state volume; active pods should be finished before changing images.

## Seed a guest workspace

`microvm-host seed` copies a selected directory into the ready host and uses
`nucleus-hostctl` to build its scratch disk. Pass the same host-settings JSON as
`run --apple-host-config` and explicitly match the workload and node jailer
owners:

```sh
nucleus microvm-host seed --host-config host.json /absolute/path/to/project \
  --workload-uid 1000 --workload-gid 1000 \
  --jailer-uid 123 --jailer-gid 100 --free-mib 1024 > workspace.json
```

The command copies the entire directory, including hidden files; select a tree
containing only the inputs intended for the guest. Keep the source stable during
transfer. It leaves the source unchanged and creates a new disk under the
standard host's `/srv/state/scratch` directory. It reports `image.scratch_path`
and `image.scratch_digest`; copy those fields into the PodSpec image and match
the configured workload UID/GID. The node still checks the path, digest and
jailer permissions at admission. Each command creates a separate disk so two
pods do not accidentally share one writable workspace.

Successful seeding removes its temporary input copy. A failed operation reports
its staging and disk paths for inspection. Each transfer/build has a ten-minute
limit; a timeout is an error, not evidence of a completed image. The completed
disk remains until explicitly removed after the pod has stopped. Collect signed
execution/artifact evidence before cancelling the pod. Seeding is a snapshot,
not live directory synchronization, and does not automatically upload `run --dir`.

## Connect and inspect

Use the same host-settings JSON directly with node commands:

```sh
nucleus node --apple-host-config host.json health
nucleus node --apple-host-config host.json create workload.yaml
nucleus node --apple-host-config host.json workload POD_ID collect \
  --wait-secs 120 --output receipt.json --logs-dir raw-logs
nucleus node --apple-host-config host.json cancel POD_ID
```

Every invocation starts/checks the selected host, requires KVM and mTLS health,
and resolves its current address and complete client identity. This also works
for workload admission, logs and operator effect approvals. Do not combine it
with an explicit node URL, identity flags or legacy secrets. It changes only the
current command's connection; it does not write global CLI configuration. These
commands may start an owned stopped host. Use `microvm-host status` for read-only
container inspection.

`--logs-dir` saves exact `stdout.bin` and `stderr.bin` bytes in a new private
directory before publishing the receipt file. Both streams must be available;
an empty stream is saved as an empty file. Existing directories and receipt
files are never overwritten. A filesystem failure may leave partial logs and
reports their location; it does not cancel the pod. Collecting these files does
not verify them. Use `nucleus-audit verify-logs` with independently prepared
expectations before relying on their contents.

Alternatively, use the returned URL and identity directory explicitly:

```sh
nucleus node --url https://127.0.0.1:RETURNED_PORT \
  --tls-cert /RETURNED_IDENTITY_DIR/cli-cert.pem \
  --tls-key /RETURNED_IDENTITY_DIR/cli-key.pem \
  --trust-bundle /RETURNED_IDENTITY_DIR/trust-bundle.pem health

nucleus microvm-host status --image nucleus-microvm-host:local
```

For `nucleus run`, select the returned identity directory with
`--identity-dir /RETURNED_IDENTITY_DIR` (or `NUCLEUS_IDENTITY_DIR`) and the node
URL with `--node-url`. The directory must contain all three identity files;
missing or invalid files are an error, with no fallback to the default identity.
The default remains `~/.config/nucleus/identity` when no directory is selected.
The selector cannot be used with `--local`.

This selects authentication for node calls only. To have `run` start/check the
Apple host and acquire a relay, use the explicit host configuration below.

`status` only reads container state. `running` is not a health assertion;
`health_checked` is false. Run `up` again to verify readiness. Add
`--development` when inspecting the development installation.

Stop an idle host with `nucleus stop --apple-host-config host.json`. This retains
its container and volume. `nucleus start --apple-host-config host.json` restarts
it and checks readiness. Host readiness does not prove that a model-driven
coding journey has completed; `shell` does not yet select this backend automatically.

## Select the Apple host for a run

Save an explicit host configuration, using the same inputs as `microvm-host up`:

```json
{
  "image": "nucleus-microvm-host:local",
  "kernel": "/absolute/path/to/linux_arm64/Image",
  "state_dir": "/absolute/path/to/host-state",
  "development": true,
  "connection": "published-loopback",
  "cpus": 4,
  "memory_mib": 4096,
  "ready_timeout_secs": 120
}
```

Only `image` and `kernel` are required. Other fields use the same defaults as
`up`; omit `state_dir` to use the normal or development state directory. Relative
kernel and state paths in JSON resolve beside that JSON file. Paths supplied
directly as `microvm-host up` arguments still resolve from the current directory.
JSON field names use underscores.

```sh
nucleus run "check the project" --apple-host-config host.json --dry-run
nucleus run --agent <PROGRAM> "check the project" --apple-host-config host.json
```

A real run launches the agent CLI you name with `--agent` (or `NUCLEUS_AGENT`);
nucleus has no default. See [examples/agents/](../../examples/agents/README.md).

Dry-run validates configuration without creating host state or starting a host.
A real run requires successful host preflight, KVM probing and mTLS health through
the selected connection before creating a pod. Set `"connection": "container-ip"`
to use the current container address for both the node and the relay. The selected host supplies the node URL and
identity; do not combine this option with `--node-url`, `--identity-dir`, legacy
node credentials, `--local` or `--hook`. `--goal` and `--grant` use the same run
connection path after their existing authorization step.

The default guest artifact paths come from the local image recipe. Override them
with `--kernel-path` and `--rootfs-path` only for a differently assembled image.
The run holds a relay slot for the pod's container-local proxy through the agent
session and pod cancellation. The host image must contain the current
`nucleus-hostctl` with `relay --ready-file`: each new relay must acknowledge its
own bound port and target before a forwarded health response is accepted. An
older relay still occupying a slot cannot stand in for the new one.

Runs cancel their pods on ordinary success and failure, and report cancellation
failures with the pod ID. Ctrl-C during the host agent wait stops and reaps that
child, then cancels the pod and releases the relay. This does not terminate
arbitrary detached descendants. Process crashes still require operator cleanup. This connection option preserves the existing host-side agent/MCP run
model; it does not add workspace transfer or run the agent itself inside the
microVM. `--dir` selects the host agent's working directory. Apple runs use `/work`
inside the guest by default; `--guest-work-dir /absolute/guest/path` selects another
existing guest directory. The host's canonical path is not a guest path (for
example, macOS resolves `/tmp` to `/private/tmp`). Workspaces and artifacts still
need the existing node/guest provisioning path. Selecting `/work` does not copy
the host project into it. It also does not yet collect execution evidence before teardown. The two
complete guest-harness journeys remain a separate release requirement.

## Configure and check the installation

After building the local image and saving `host.json`, run:

```sh
nucleus setup --apple-host-config host.json
nucleus verify --tier2
nucleus node health
nucleus run "check the project" --dry-run
```

Setup checks host readiness, boots a short supervised workload and verifies its
signed execution receipt plus exact stdout/stderr with the shared verifier. The
check requires Firecracker execution, a distinct workload UID, exit 0 and the
expected Linux output. It predicts the admitted program from the selected
image's input manifest and the shared policy/isolation rules. The signer is
enrolled through the authenticated node admission endpoint, separately from the
receipt; trust comes from this installation's provisioned CA and selected image,
not external platform attestation.

After the check and confirmed pod cancellation, setup saves the host selection
in the global configuration. It preserves existing settings and comments and
refuses to replace a file edited while verification ran. Use global `--config`
for a separate CLI configuration. Subsequent `setup` calls use the saved Apple
selection. Apple setup uses the image, kernel and state from JSON; Lima VM,
artifact-download and secret-rotation options are rejected.

`--skip-verify` explicitly skips the guest workload check. Host readiness is
still required, and the result reports `verification_skipped: true` with no
workload verification. Verification failures leave the config unchanged and
cancel the temporary pod once its ID is known. A cancellation failure names the
pod for operator cleanup. Process crashes or interruption during the initial
create request can still require manual inspection. This is an installation
check; it does not run either model-driven coding journey.

`verify --tier2` repeats this same signed-workload check using the saved Apple
selection without rewriting configuration. To select a host for just one check,
use `verify --tier2 --apple-host-config host.json`. Its JSON result identifies
`backend: apple-container` and the verified workload. It may restart the owned
host and cancels its temporary pod when done. This checks supervised execution;
it is not the legacy Linux/Lima conformance suite. Explicit `--here` or
`--vm-name` selects that legacy path even when an Apple default is saved.

## Start, diagnose and stop the saved installation

After setup saves the Apple selection, ordinary lifecycle commands use it:

```sh
nucleus start
nucleus doctor
nucleus stop
```

`start` applies the same ownership, configuration, KVM and mTLS readiness checks
as `microvm-host up`. Its JSON reports the current node address. `doctor` only
observes the existing host and checks KVM and mTLS health; it never starts or
replaces a container or provisions credentials. It reports a stopped host as an
error and does not claim workload verification. Use `verify --tier2` for that.

`stop` stops only a matching owned host, retaining its container, state volume,
CA and identity. Repeating it is safe. Finish pods and collect their evidence
first: stopping the host terminates live workloads, and in-memory pod history
is not recovered by restart. A missing old kernel file does not prevent stopping
an otherwise matching host. A foreign or mismatched container is refused.

`start` and `stop` accept `--apple-host-config host.json` for an explicit selection.
An explicit `--vm-name nucleus` selects Lima instead of a saved Apple host; the
two selectors conflict. Apple start uses the readiness timeout in host JSON and
rejects Lima's `--no-wait` and `--timeout` options. Apple stop rejects `--force`
and `--stop-vm`. A selected Apple host failure never falls back to Lima.
Use global `--config` to select another installation for all three commands.

## Save the host selection manually

To make this host the default for `run`, `node` and lifecycle commands, add its configuration path
to `~/.config/nucleus/config.toml` (or the file selected by global `--config`):

```toml
[node]
apple_host_config = "host.json"
```

The path resolves beside the TOML file. Keep the JSON file available: each command
reads it and checks the host's current address, KVM and mTLS identity. The saved
selection also applies to `run --goal` and `run --grant` after their existing
authorization checks. `run --dry-run` validates the selection without starting
anything. `node` commands may start the owned host, as with the explicit flag.

Explicit connection flags override this default: `--node-url` or `--identity-dir`
for `run`; `--url` or the identity flags (`--tls-cert`, `--tls-key`,
`--trust-bundle`) for `node`. Neither command takes a shared node secret: the
node's API is mTLS-only. Corresponding environment variables count as explicit input.
`run --local` and `run --hook` use their selected mode. An explicit
`--apple-host-config` selects that file instead. A saved host that fails readiness
returns an error; it does not switch to Lima or another node. `setup` also uses
this saved selection; `shell` does not yet use it.

Without an Apple selection, `node` now reads `node.url` from the same global
configuration. An explicit `--url` still wins, even if it equals the built-in
localhost default. `nucleus config` displays the resolved saved host path.

## Published-port troubleshooting

If KVM succeeds but `up` times out checking mTLS health, inspect
`container logs nucleus-microvm-host` and `container system logs --last 5m`.
A listening node can still be unreachable through the published loopback port.
`container-runtime-linux` reporting `No route to host` is consistent with a
macOS Local Network permission issue; check **System Settings → Privacy &
Security → Local Network** for that helper. Apple Container's
[upstream report](https://github.com/apple/container/issues/2029) describes this
pattern. It is a diagnostic lead, not proof that every forwarding failure has
the same cause. With the default connection, `up` continues to refuse readiness until
its published endpoint answers over mTLS. The explicit `container-ip` connection
was validated on this host and provides another checked route; it does not repair
the published-port forwarding service.

## Reclaim unused state-volume blocks

A pod's `spec.timeout_seconds` now also bounds execution on updated nodes.
The deadline starts before launch and uses a monotonic clock. The reaper checks
every ten seconds and cancels expired running pods, then applies its existing
descendant cleanup. Slow driver operations or failed cleanup can delay teardown;
capacity remains reserved until teardown succeeds. This is periodic cleanup,
not a hard real-time deadline. Timeout events appear in the node's unsigned
`lifecycle.log`; they are not signed evidence of successful execution.
Choose enough time for boot, work, operator approval and evidence collection.
`collect --wait-secs` only bounds observation and does not extend pod lifetime.
Existing local images need a rebuilt node to acquire this behavior.

Cancelled and failed pods can leave the Apple state volume physically large even
when their image files were deleted. On a discard-capable volume, reclaim unused
filesystem blocks from the running host with:

```sh
container exec nucleus-dev-microvm-host fstrim -v /srv
```

Use the installation's actual container name. This preserves allocated files and
state. The reported trim range is not the number of physical host bytes recovered;
check host disk usage separately. In local validation, the development volume
shrank from 3.9 GiB to 38 MiB after trimming. If a prior disk-full event left the
container root with `emergency_ro` in its mount options, stop the idle host and run
`microvm-host up` again after recovering space. A read-only builder likewise needs
an idle builder restart; neither restart substitutes for recovering space first.
