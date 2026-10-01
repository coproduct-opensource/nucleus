#!/usr/bin/env python3
"""The escape canary: every probe here is something the sandbox MUST refuse, run from
inside the gate's own pod so that a passing run is evidence in the signed receipt that the
confinement held on the machine that produced the verdict -- not an assertion by the repo.

A gate step runs this first. It prints one structured line per probe (probe, category,
expected, observed, verdict) and a final summary, and exits:
  * 0  only if EVERY probe was REFUSED (the sandbox held);
  * 1  if any probe SUCCEEDED that must fail (a real escape), the probe's name in the line;
  * 2  if any probe COULD-NOT-LOOK -- it could not actually exercise the refusal. A probe
       that cannot run is not a pass: an environment where the canary is inert would hide a
       hole exactly as a hole would. (2 outranks 1 only in the message; both are failures.)

It is deliberately stdlib-only (socket, os, ctypes) so it adds no dependency to the gate and
runs identically inside the pod and, as the weakened control, on a bare host -- where the
network probes SUCCEED and it exits non-zero naming them, which is how we know it bites.

Vendor-neutral: it names nucleus's own guest contract (the workload-API vsock port, the
read-only base, the noexec tmpfs layers) and no third party.
"""

import ctypes
import ctypes.util
import errno
import json
import os
import socket
import stat
import struct
import sys

REFUSED = "refused"
BREACH = "BREACH"
CANNOT_LOOK = "could-not-look"

_results = []


def record(probe, category, expected, observed, verdict):
    line = {
        "probe": probe,
        "category": category,
        "expected": expected,
        "observed": observed,
        "verdict": verdict,
    }
    _results.append(line)
    print(json.dumps(line, sort_keys=True), flush=True)


def _libc():
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


# ── Network: nothing leaves the pod ─────────────────────────────────────────────────────────
# The gate declares net=none and the step runs in a fresh network namespace with only loopback.
# A connection that SUCCEEDS is exfiltration or SSRF; the refusal is the point.

def probe_tcp(probe, category, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((host, port))
    except OSError as e:
        record(probe, category, "refused", f"connect {host}:{port} failed: {errno.errorcode.get(e.errno, e.errno)}", REFUSED)
        return
    except Exception as e:  # noqa: BLE001 -- any non-OSError is the probe failing to run
        record(probe, category, "refused", f"probe error: {e!r}", CANNOT_LOOK)
        return
    finally:
        s.close()
    record(probe, category, "refused", f"connected to {host}:{port}", BREACH)


def probe_udp_dns(host, port):
    probe, category = "net_udp_dns_public", "network"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    # A minimal DNS A query for example.com.
    query = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01"
    )
    try:
        s.sendto(query, (host, port))
        data, _ = s.recvfrom(512)
    except OSError as e:
        record(probe, category, "refused", f"udp to {host}:{port} failed: {errno.errorcode.get(e.errno, e.errno)}", REFUSED)
        return
    except Exception as e:  # noqa: BLE001
        record(probe, category, "refused", f"probe error: {e!r}", CANNOT_LOOK)
        return
    finally:
        s.close()
    record(probe, category, "refused", f"got {len(data)} bytes of DNS reply", BREACH)


def probe_dns_resolve(name):
    probe, category = "net_dns_resolve", "network"
    try:
        infos = socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
    except OSError as e:
        record(probe, category, "refused", f"getaddrinfo({name}) failed: {errno.errorcode.get(e.errno, e.errno)}", REFUSED)
        return
    except Exception as e:  # noqa: BLE001
        record(probe, category, "refused", f"probe error: {e!r}", CANNOT_LOOK)
        return
    addrs = sorted({i[4][0] for i in infos})
    record(probe, category, "refused", f"resolved {name} to {addrs}", BREACH)


# ── Filesystem: the base is read-only and the host is not in the guest ───────────────────────

def probe_write_readonly(probe, path):
    category = "filesystem"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o644)
    except OSError as e:
        code = errno.errorcode.get(e.errno, e.errno)
        verdict = REFUSED if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM) else CANNOT_LOOK
        record(probe, category, "refused (EROFS/EACCES)", f"open({path}) for write failed: {code}", verdict)
        return
    except Exception as e:  # noqa: BLE001
        record(probe, category, "refused (EROFS/EACCES)", f"probe error: {e!r}", CANNOT_LOOK)
        return
    os.close(fd)
    try:
        os.unlink(path)
    except OSError:
        pass
    record(probe, category, "refused (EROFS/EACCES)", f"created a writable file at {path}", BREACH)


def probe_read_host_secret(probe, paths):
    # Node/host credentials and runtime dirs live on the HOST; the Firecracker guest is a
    # separate kernel and must not be able to open any of them. Absence IS the refusal here.
    category = "credentials"
    for path in paths:
        try:
            with open(path, "rb") as f:
                data = f.read(64)
        except FileNotFoundError:
            continue
        except OSError as e:
            if e.errno in (errno.EACCES, errno.EPERM):
                continue
            record(probe, category, "refused (absent/denied)", f"{path}: unexpected {errno.errorcode.get(e.errno, e.errno)}", CANNOT_LOOK)
            return
        except Exception as e:  # noqa: BLE001
            record(probe, category, "refused (absent/denied)", f"probe error: {e!r}", CANNOT_LOOK)
            return
        record(probe, category, "refused (absent/denied)", f"READ host credential {path} ({len(data)} bytes)", BREACH)
        return
    record(probe, category, "refused (absent/denied)", "every host credential path is absent or denied", REFUSED)


SECRET_MARKERS = (
    "AUTH_SECRET", "APPROVAL_SECRET", "SANDBOX_TOKEN", "BROKER_SECRET",
    "MEDIATION", "SIGNING_KEY", "PRIVATE_KEY", "APP_KEY", "TASK_TOKEN",
    "CALLER_TOKEN", "auth_secret", "approval_secret",
)


def probe_no_secret_in(probe, path):
    category = "credentials"
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError as e:
        record(probe, category, "no secret present", f"{path}: {errno.errorcode.get(e.errno, e.errno)} (not readable)", REFUSED)
        return
    except Exception as e:  # noqa: BLE001
        record(probe, category, "no secret present", f"probe error: {e!r}", CANNOT_LOOK)
        return
    text = blob.replace(b"\x00", b" ").decode("latin-1")
    hits = [m for m in SECRET_MARKERS if m in text]
    if hits:
        record(probe, category, "no secret present", f"{path} carries secret markers {hits}", BREACH)
    else:
        record(probe, category, "no secret present", f"{path} carries no secret marker", REFUSED)


# ── Exec: the writable layers are noexec ─────────────────────────────────────────────────────

def probe_noexec(probe, directory):
    category = "exec"
    path = os.path.join(directory, "escape-canary-exe")
    try:
        with open(path, "wb") as f:
            f.write(b"#!/bin/sh\necho canary-ran\n")
        os.chmod(path, 0o755)
    except OSError as e:
        record(probe, category, "refused (EACCES, noexec)", f"could not stage an executable in {directory}: {errno.errorcode.get(e.errno, e.errno)}", CANNOT_LOOK)
        return
    except Exception as e:  # noqa: BLE001
        record(probe, category, "refused (EACCES, noexec)", f"probe error: {e!r}", CANNOT_LOOK)
        return
    try:
        pid = os.fork()
        if pid == 0:
            try:
                os.execv(path, [path])
            except OSError:
                os._exit(13)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
    except Exception as e:  # noqa: BLE001
        record(probe, category, "refused (EACCES, noexec)", f"fork/exec harness error: {e!r}", CANNOT_LOOK)
        return
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 13:
        record(probe, category, "refused (EACCES, noexec)", f"exec from {directory} refused by the mount", REFUSED)
    elif os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        record(probe, category, "refused (EACCES, noexec)", f"EXECUTED a file staged in {directory}", BREACH)
    else:
        record(probe, category, "refused (EACCES, noexec)", f"unexpected child status {status}", CANNOT_LOOK)


# ── Privilege: no real host authority ────────────────────────────────────────────────────────

def probe_mount():
    probe, category = "priv_mount", "privilege"
    libc = _libc()
    target = "/mnt"
    try:
        os.makedirs(target, exist_ok=True)
    except OSError:
        target = "/tmp"
    ctypes.set_errno(0)
    rc = libc.mount(b"none", target.encode(), b"tmpfs", 0, None)
    e = ctypes.get_errno()
    if rc == 0:
        record(probe, category, "refused (EPERM)", f"mounted a tmpfs on {target}", BREACH)
        libc.umount(target.encode())
    elif e in (errno.EPERM, errno.EACCES):
        record(probe, category, "refused (EPERM)", f"mount refused: {errno.errorcode.get(e, e)}", REFUSED)
    else:
        record(probe, category, "refused (EPERM)", f"mount failed with {errno.errorcode.get(e, e)}", REFUSED)


def probe_raw_socket():
    probe, category = "priv_raw_socket", "privilege"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        record(probe, category, "refused (EPERM, no CAP_NET_RAW)", "raw socket refused: EPERM", REFUSED)
        return
    except OSError as e:
        record(probe, category, "refused (EPERM, no CAP_NET_RAW)", f"raw socket failed: {errno.errorcode.get(e.errno, e.errno)}", REFUSED)
        return
    except Exception as e:  # noqa: BLE001
        record(probe, category, "refused (EPERM, no CAP_NET_RAW)", f"probe error: {e!r}", CANNOT_LOOK)
        return
    s.close()
    record(probe, category, "refused (EPERM, no CAP_NET_RAW)", "opened a raw ICMP socket", BREACH)


def probe_mknod_device():
    probe, category = "priv_mknod_device", "privilege"
    path = "/tmp/escape-canary-dev"
    try:
        os.unlink(path)
    except OSError:
        pass
    try:
        # vda (253,0) / vdb etc.: a block device node is a host-authority operation.
        os.mknod(path, stat.S_IFBLK | 0o600, os.makedev(253, 0))
    except PermissionError:
        record(probe, category, "refused (EPERM, no CAP_MKNOD)", "mknod of a block device refused: EPERM", REFUSED)
        return
    except OSError as e:
        record(probe, category, "refused (EPERM, no CAP_MKNOD)", f"mknod failed: {errno.errorcode.get(e.errno, e.errno)}", REFUSED)
        return
    except Exception as e:  # noqa: BLE001
        record(probe, category, "refused (EPERM, no CAP_MKNOD)", f"probe error: {e!r}", CANNOT_LOOK)
        return
    # The node existing is not yet the escape; reading raw disk bytes through it is.
    opened = False
    try:
        fd = os.open(path, os.O_RDONLY)
        os.read(fd, 16)
        os.close(fd)
        opened = True
    except OSError:
        opened = False
    try:
        os.unlink(path)
    except OSError:
        pass
    if opened:
        record(probe, category, "refused (EPERM, no CAP_MKNOD)", "created AND read a raw block device node", BREACH)
    else:
        record(probe, category, "refused (EPERM, no CAP_MKNOD)", "mknod made a node but the device could not be read", REFUSED)


# ── Other processes: a separate kernel, nothing of the host or node is visible ───────────────

HOST_PROCS = ("nucleus-node", "firecracker", "jailer", "gatehouse-agent",
              "gatehouse-nucleus", "controller", "containerd", "dockerd", "sshd")


def probe_foreign_processes():
    probe, category = "proc_foreign_visibility", "processes"
    found = []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError as e:
        record(probe, category, "no host/node process visible", f"/proc unreadable: {errno.errorcode.get(e.errno, e.errno)}", CANNOT_LOOK)
        return
    for p in pids:
        try:
            with open(f"/proc/{p}/comm") as f:
                comm = f.read().strip()
        except OSError:
            continue
        for h in HOST_PROCS:
            if h in comm:
                found.append(f"{p}:{comm}")
    if found:
        record(probe, category, "no host/node process visible", f"host/node processes visible: {found}", BREACH)
    else:
        record(probe, category, "no host/node process visible", f"{len(pids)} guest pids, none host/node", REFUSED)


def probe_ptrace_init():
    probe, category = "proc_ptrace_init", "processes"
    libc = _libc()
    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    ctypes.set_errno(0)
    rc = libc.ptrace(PTRACE_ATTACH, 1, 0, 0)
    e = ctypes.get_errno()
    if rc == 0:
        libc.ptrace(PTRACE_DETACH, 1, 0, 0)
        record(probe, category, "refused (EPERM)", "attached to pid 1 (guest-init)", BREACH)
    elif e in (errno.EPERM, errno.EACCES, errno.ESRCH):
        record(probe, category, "refused (EPERM)", f"ptrace(pid 1) refused: {errno.errorcode.get(e, e)}", REFUSED)
    else:
        record(probe, category, "refused (EPERM)", f"ptrace failed with {errno.errorcode.get(e, e)}", REFUSED)


# ── The workload API: a second SVID fetch does not yield the private key (nucleus #3080) ──────

VMADDR_CID_HOST = 2
WORKLOAD_API_PORT = 15012


def _fetch_svid_once(af_vsock):
    """One FETCH_SVID over a fresh vsock connection. Returns (ok, reply_or_reason)."""
    try:
        s = socket.socket(af_vsock, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((VMADDR_CID_HOST, WORKLOAD_API_PORT))
    except OSError as e:
        return False, f"cannot reach workload API vsock {VMADDR_CID_HOST}:{WORKLOAD_API_PORT}: {errno.errorcode.get(e.errno, e.errno)}"
    try:
        s.sendall(b"FETCH_SVID\n")
        chunks = []
        while True:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
            if b"\n" in b or sum(len(c) for c in chunks) > 1 << 20:
                break
        raw = b"".join(chunks).strip()
    except OSError as e:
        return False, f"workload API I/O failed: {errno.errorcode.get(e.errno, e.errno)}"
    finally:
        s.close()
    if not raw:
        return False, "workload API returned nothing"
    try:
        return True, json.loads(raw.split(b"\n", 1)[0].decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        return False, f"unparseable reply ({raw[:80]!r}): {e!r}"


def probe_svid_key_refused():
    # nucleus #3080: the SVID private key is served at most once (to guest-init, which asks
    # first). A LATER FETCH_SVID from the workload must be refused the key. We ask twice from
    # the workload over two connections -- the latch is shared across connections -- and assert
    # the SECOND carries no private key, whatever the first did. On an unpatched node both carry
    # the key; that is the escape this probe exists to catch.
    probe, category = "svid_key_later_fetch", "identity"
    af_vsock = getattr(socket, "AF_VSOCK", None)
    if af_vsock is None:
        record(probe, category, "no private_key on a later FETCH_SVID", "python lacks AF_VSOCK", CANNOT_LOOK)
        return
    ok1, first = _fetch_svid_once(af_vsock)
    if not ok1:
        # Could not even reach the identity API to exercise the refusal: not a pass.
        record(probe, category, "no private_key on a later FETCH_SVID", first, CANNOT_LOOK)
        return
    first_had_key = isinstance(first, dict) and bool(first.get("private_key"))
    ok2, second = _fetch_svid_once(af_vsock)
    if not ok2:
        record(probe, category, "no private_key on a later FETCH_SVID", f"second fetch: {second}", CANNOT_LOOK)
        return
    note = "first fetch carried the key" if first_had_key else "first fetch carried no key"
    if isinstance(second, dict) and second.get("private_key"):
        record(probe, category, "no private_key on a later FETCH_SVID",
               f"a later FETCH_SVID served the SVID PRIVATE KEY again ({note})", BREACH)
    elif isinstance(second, dict) and second.get("certificate_chain"):
        record(probe, category, "no private_key on a later FETCH_SVID",
               f"later fetch served the chain only, no private_key ({note})", REFUSED)
    elif isinstance(second, dict) and second.get("error"):
        record(probe, category, "no private_key on a later FETCH_SVID",
               f"later fetch refused: {str(second['error'])[:100]} ({note})", REFUSED)
    else:
        record(probe, category, "no private_key on a later FETCH_SVID",
               f"later reply had neither key nor chain nor error: {str(second)[:100]}", CANNOT_LOOK)


def main():
    uid = os.getuid()
    print(json.dumps({"canary": "gatehouse-escape-canary", "uid": uid,
                      "note": "every line below is something the sandbox must refuse"}),
          flush=True)

    # Network
    probe_tcp("net_tcp_public", "network", "1.1.1.1", 443)
    probe_tcp("net_tcp_dns_public", "network", "8.8.8.8", 53)
    probe_udp_dns("8.8.8.8", 53)
    probe_dns_resolve("example.com")
    probe_tcp("net_node_metadata", "network", "169.254.169.254", 80)

    # Filesystem
    probe_write_readonly("write_rootfs_etc", "/etc/escape-canary")
    probe_write_readonly("write_rootfs_bin", "/usr/local/bin/escape-canary")
    probe_write_readonly("write_host_build_dir", "/opt/nucleus-build/escape-canary")

    # Credentials / host runtime dirs
    probe_read_host_secret("read_host_node_state", [
        "/srv/gatehouse/runtime/state/executor_signing_key.der",
        "/srv/gatehouse/runtime/state/ca/ca-key.pem",
        "/srv/gatehouse/runtime/node.env",
        "/persist/gatehouse/runtime/state/executor_signing_key.der",
        "/root/.config/gcloud/credentials.db",
        "/var/lib/nucleus/state",
    ])
    probe_no_secret_in("read_proc_cmdline", "/proc/cmdline")
    probe_no_secret_in("read_init_environ", "/proc/1/environ")

    # Exec from noexec layers
    probe_noexec("exec_noexec_tmp", "/tmp")
    probe_noexec("exec_noexec_run", "/run")

    # Privilege
    probe_mount()
    probe_raw_socket()
    probe_mknod_device()

    # Other processes
    probe_foreign_processes()
    probe_ptrace_init()

    # Workload-API identity
    probe_svid_key_refused()

    breaches = [r for r in _results if r["verdict"] == BREACH]
    blind = [r for r in _results if r["verdict"] == CANNOT_LOOK]
    summary = {
        "summary": True,
        "probes": len(_results),
        "refused": sum(1 for r in _results if r["verdict"] == REFUSED),
        "breaches": [r["probe"] for r in breaches],
        "could_not_look": [r["probe"] for r in blind],
    }
    print(json.dumps(summary, sort_keys=True), flush=True)
    if breaches:
        print(f"ESCAPE CANARY FAILED: the sandbox did NOT refuse: {summary['breaches']}", file=sys.stderr)
        sys.exit(1)
    if blind:
        print(f"ESCAPE CANARY FAILED: could not look (a blind probe is not a pass): {summary['could_not_look']}", file=sys.stderr)
        sys.exit(2)
    print("ESCAPE CANARY HELD: every probe was refused by the sandbox.", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
