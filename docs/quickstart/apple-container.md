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

## Connect and inspect

Use the returned URL and identity directory with the existing node commands:

```sh
nucleus node --url https://127.0.0.1:RETURNED_PORT \
  --tls-cert /RETURNED_IDENTITY_DIR/cli-cert.pem \
  --tls-key /RETURNED_IDENTITY_DIR/cli-key.pem \
  --trust-bundle /RETURNED_IDENTITY_DIR/trust-bundle.pem health

nucleus microvm-host status --image nucleus-microvm-host:local
```

`status` only reads container state. `running` is not a health assertion;
`health_checked` is false. Run `up` again to verify readiness. Add
`--development` when inspecting the development installation.

Stop an idle host with `container stop nucleus-microvm-host` (or the development
name). This retains its container and volume. `up` restarts it. This command does
not yet select the backend automatically for `setup`, `shell` or `run`, nor does
host readiness prove that a model-driven coding journey has completed.

## Published-port troubleshooting

If KVM succeeds but `up` times out checking mTLS health, inspect
`container logs nucleus-microvm-host` and `container system logs --last 5m`.
A listening node can still be unreachable through the published loopback port.
`container-runtime-linux` reporting `No route to host` is consistent with a
macOS Local Network permission issue; check **System Settings → Privacy &
Security → Local Network** for that helper. Apple Container's
[upstream report](https://github.com/apple/container/issues/2029) describes this
pattern. It is a diagnostic lead, not proof that every forwarding failure has
the same cause. `up` continues to refuse readiness until its published endpoint
answers over mTLS.
