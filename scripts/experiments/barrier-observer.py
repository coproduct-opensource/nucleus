#!/usr/bin/env python3
"""Host half of the M3 check.

Firecracker's vsock is UDS-backed: a guest connection to port N arrives as a
Unix connection on `<uds_path>_N`. Not AF_VSOCK — the first version of this used
that and every guest connect was reset.

The measurement is taken the instant SNAPSHOT_READY arrives and nowhere else:
reading the superblock before or after proves nothing about the ordering.
"""
import os, socket, subprocess, sys, time

UDS, PORT, SCRATCH = sys.argv[1], int(sys.argv[2]), sys.argv[3]
path = "%s_%d" % (UDS, PORT)

def mount_count(p):
    out = subprocess.run(["dumpe2fs", "-h", p], capture_output=True, text=True)
    for line in out.stdout.splitlines():
        if line.startswith("Mount count:"):
            return line.split(":", 1)[1].strip()
    return "UNREADABLE"

try: os.unlink(path)
except OSError: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path); s.listen(16)
print("observer on %s" % path, flush=True)
print("BEFORE-BOOT mount_count=%s" % mount_count(SCRATCH), flush=True)

deadline = time.time() + 40
saw = False
while time.time() < deadline:
    s.settimeout(max(1, deadline - time.time()))
    try: conn, _ = s.accept()
    except Exception: continue
    try:
        data = conn.recv(4096).decode(errors="replace").strip()
    except Exception:
        conn.close(); continue
    cmd = data.splitlines()[0] if data else ""
    if cmd.startswith("SNAPSHOT_READY"):
        # THE MEASUREMENT.
        print("AT-BARRIER mount_count=%s" % mount_count(SCRATCH), flush=True)
        saw = True
        conn.sendall(b'{"status":"ok"}\n')
    else:
        print("cmd=%s -> refused" % cmd, flush=True)
        conn.sendall(b'{"error":"not provisioned for this experiment"}\n')
    conn.close()
print("SAW_BARRIER=%s" % saw, flush=True)
print("AFTER-RUN mount_count=%s" % mount_count(SCRATCH), flush=True)
