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
those secrets for the installation. The local recipe enables host enforcement,
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

Use the returned URL and identity directory with the existing node commands:

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

Stop an idle host with `container stop nucleus-microvm-host` (or the development
name). This retains its container and volume. `up` restarts it. This command does
not select the backend automatically for `setup` or `shell`, nor does host
readiness prove that a model-driven coding journey has completed.

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
paths resolve from the current directory. JSON field names use underscores.

```sh
nucleus run "check the project" --apple-host-config host.json --dry-run
nucleus run "check the project" --apple-host-config host.json
```

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
failures with the pod ID. Process crashes still require timeout or operator
cleanup. This connection option preserves the existing host-side agent/MCP run
model; it does not add workspace transfer or run the agent itself inside the
microVM. `--dir` selects the host agent's working directory. Apple runs use `/work`
inside the guest by default; `--guest-work-dir /absolute/guest/path` selects another
existing guest directory. The host's canonical path is not a guest path (for
example, macOS resolves `/tmp` to `/private/tmp`). Workspaces and artifacts still
need the existing node/guest provisioning path. Selecting `/work` does not copy
the host project into it. It also does not yet collect execution evidence before teardown. The two
complete guest-harness journeys remain a separate release requirement.

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
