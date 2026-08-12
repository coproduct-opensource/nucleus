#!/usr/bin/env bash
# C2 G4 — cross-pod non-interference, proven on a REAL Firecracker boot.
#
# `scripts/cross-pod-scoped-check.sh` proves the auth+filter composition KVM-free
# over the local-driver HTTP path. This proves the remaining thing only a KVM
# host can show: that a BOOTED pod, calling scoped `POD_LIST` over its OWN real
# workload-API vsock socket, is served a listing scoped to its lineage — its own
# child INCLUDED, a non-lineage sibling EXCLUDED — not the operator view.
#
# THE PROPERTY (over the real vsock transport):
#   A ∈ A's-listing  ∧  C ∈ A's-listing  ∧  B ∉ A's-listing
#   ∧  {A,B,C} ⊆ operator  ∧  A's-listing ⊊ operator
# where C is A's child and B a non-lineage sibling. C-inclusion is the tooth that
# a self-only filter cannot satisfy; B-exclusion is the isolation; the operator
# control proves B and C genuinely exist; the strict subset proves scoping (not
# fail-open).
#
# TOPOLOGY. The jailer gives each pod its own socket, so A, C and B boot
# CONCURRENTLY. A is created first (C needs A's id as its parent); C (child, via
# the x-nucleus-parent-pod-id header the node records from the operator) and B
# (sibling) are then created in parallel so both REGISTER inside A's boot window.
# The probe POLLS POD_LIST and reports the largest scoped view it settles on, so
# a child still registering when the probe first fires is not missed — a sibling
# can never enter that view, so a larger view is strictly more of A's own lineage.
#
# INPUTS (taken as given — built by the caller / CI, like boot-harness.sh). The
# rootfs MUST bake `nucleus-podlist-probe` and carry `podlist-probe-pod.yaml`
# (orchestrator + enable_pod_mgmt) as /etc/nucleus/pod.yaml.
#   KERNEL, ROOTFS, NODE_BIN   (defaults under $FC_DIR=$HOME/fc)
#
# Usage: [FC_DIR=… KERNEL=… ROOTFS=… NODE_BIN=…] scripts/firecracker/podlist-boot-check.sh
set -uo pipefail

FC_DIR="${FC_DIR:-$HOME/fc}"
KERNEL="${KERNEL:-$FC_DIR/vmlinux}"
ROOTFS="${ROOTFS:-$FC_DIR/podlist-rootfs.ext4}"
NODE_BIN="${NODE_BIN:-$FC_DIR/nucleus-node}"
STATE_DIR="${STATE_DIR:-$FC_DIR/state-podlist-check}"
# Keep this base SHORT: the jailer nests the per-pod vsock socket at
# <base>/firecracker/<uuid>/root/vsock.sock_<port>, and a long base overruns the
# ~108-char AF_UNIX path limit — the socket then fails to bind and the guest's
# workload API is unreachable (a 502 on the pod's health check that looks like an
# auth/routing problem, not a path-length one).
JAIL_DIR="${JAIL_DIR:-$FC_DIR/jail}"
ADDR="${NODE_ADDR:-127.0.0.1:9900}"
SECRET="${AUTH_SECRET:-harness-node-secret}"

die() { echo "podlist-boot-check: $*" >&2; exit 1; }
for f in "$KERNEL" "$ROOTFS" "$NODE_BIN"; do [ -s "$f" ] || die "missing input $f"; done
[ -e /dev/kvm ] || die "no /dev/kvm — this must run on a Linux host with KVM"
command -v firecracker >/dev/null || die "firecracker is not on PATH"
command -v jailer >/dev/null || die "jailer is not on PATH (needed for concurrent pods)"

sudo pkill -x nucleus-node 2>/dev/null || true
sudo pkill -x firecracker 2>/dev/null || true
sudo pkill -x jailer 2>/dev/null || true
sudo rm -rf "$STATE_DIR" "$JAIL_DIR"; mkdir -p "$STATE_DIR" "$JAIL_DIR"
# Each pod gets its OWN writable rootfs copy: the jailer hard-links a writable
# drive into the jail, so a shared file would make concurrent guests write one
# inode. The chroot base is on the same filesystem, as the jailer requires.
for p in a b c; do sudo rm -f "$FC_DIR/rootfs-check-$p.ext4"; cp "$ROOTFS" "$FC_DIR/rootfs-check-$p.ext4"; done

# Jailer ON (the node default) — per-pod socket => concurrent boots.
sudo -b env RUST_LOG="${RUST_LOG:-warn}" \
    NUCLEUS_FIRECRACKER_PATH="$(command -v firecracker)" \
    NUCLEUS_JAILER_PATH="$(command -v jailer)" \
    NUCLEUS_JAILER_CHROOT_BASE="$JAIL_DIR" \
    NUCLEUS_FIRECRACKER_NETNS=false \
    "$NODE_BIN" --listen "$ADDR" --state-dir "$STATE_DIR" --auth-secret "$SECRET" \
    --proxy-auth-secret "$SECRET" --proxy-approval-secret "$SECRET" \
    --identity-workload-api-socket "$FC_DIR/wapi.sock" > "$FC_DIR/node-podlist-check.log" 2>&1
sleep 5
pgrep -x nucleus-node >/dev/null || { tail -20 "$FC_DIR/node-podlist-check.log"; die "node did not start"; }

# create <name> <rootfs> [parent_pod_id] -> prints pod id
create() {
    local name=$1 rootfs=$2 parent=${3:-}
    cat > "$FC_DIR/$name.json" <<JSON
{"apiVersion":"nucleus/v1","kind":"Pod","metadata":{"name":"$name","labels":{"enable_pod_mgmt":"true"}},"spec":{"work_dir":"/work","timeout_seconds":120,"policy":{"type":"profile","name":"orchestrator"},"image":{"kernel_path":"$KERNEL","rootfs_path":"$rootfs","read_only":false},"vsock":{"guest_cid":3,"port":5005}}}
JSON
    PARENT="$parent" python3 - "$FC_DIR/$name.json" "$SECRET" "$ADDR" <<'PY'
import hmac,hashlib,sys,os,time,json,urllib.request,urllib.error
spec,secret,addr=sys.argv[1],sys.argv[2].encode(),sys.argv[3]
body=open(spec,"rb").read(); ts,actor=str(int(time.time())),"boot-harness"
sig=hmac.new(secret,ts.encode()+b"."+actor.encode()+b"."+body,hashlib.sha256).hexdigest()
h={"content-type":"application/json","x-nucleus-timestamp":ts,"x-nucleus-actor":actor,"x-nucleus-signature":sig}
p=os.environ.get("PARENT","")
if p: h["x-nucleus-parent-pod-id"]=p   # operator-set lineage: node records parent=A
req=urllib.request.Request(f"http://{addr}/v1/pods",data=body,method="POST",headers=h)
try: print(json.load(urllib.request.urlopen(req,timeout=120))["id"])
except urllib.error.HTTPError as e: sys.stderr.write("CREATE %d %s\n"%(e.code,e.read().decode()[:300])); sys.exit(1)
PY
}

operator_ids() {
    python3 - "$SECRET" "$ADDR" <<'PY'
import hmac,hashlib,sys,time,json,urllib.request,urllib.error
secret,addr=sys.argv[1].encode(),sys.argv[2]
ts,actor=str(int(time.time())),"boot-harness"
sig=hmac.new(secret,ts.encode()+b"."+actor.encode()+b".",hashlib.sha256).hexdigest()
req=urllib.request.Request(f"http://{addr}/v1/pods",method="GET",headers={"x-nucleus-timestamp":ts,"x-nucleus-actor":actor,"x-nucleus-signature":sig})
try:
    d=json.load(urllib.request.urlopen(req,timeout=30)); pods=d if isinstance(d,list) else d.get("pods",[])
    print(",".join(sorted(p["id"] for p in pods)))
except urllib.error.HTTPError as e: sys.stderr.write("OP %d %s\n"%(e.code,e.read().decode()[:200]))
PY
}

echo "podlist-boot-check: booting A (orchestrator, the probe)"
A="$(create orch-a "$FC_DIR/rootfs-check-a.ext4")"; [ -n "$A" ] || die "A was not created"
echo "podlist-boot-check: booting child C + sibling B in parallel"
( create child-c "$FC_DIR/rootfs-check-c.ext4" "$A" > "$FC_DIR/c.id" 2>"$FC_DIR/c.err" ) &
( create sibling-b "$FC_DIR/rootfs-check-b.ext4"           > "$FC_DIR/b.id" 2>"$FC_DIR/b.err" ) &
wait
C="$(cat "$FC_DIR/c.id" 2>/dev/null)"; B="$(cat "$FC_DIR/b.id" 2>/dev/null)"
[ -n "$C" ] || die "child C was not created: $(cat "$FC_DIR/c.err" 2>/dev/null)"
[ -n "$B" ] || die "sibling B was not created: $(cat "$FC_DIR/b.err" 2>/dev/null)"

sleep 14   # A boots (~7s to probe) and the probe polls until C/B settle.

ALOG="$(sudo find "$STATE_DIR" "$JAIL_DIR" -path "*$A*" -name firecracker.log 2>/dev/null | head -1)"
[ -n "$ALOG" ] || die "no firecracker.log for A ($A)"
# `tr -d` strips the guest console's trailing CR so the id set compares cleanly.
IDS="$(sudo grep -aoE 'NUCLEUS_PODLIST_PROBE: PASS self=[^ ]+ ids=[^ ]+' "$ALOG" 2>/dev/null | tail -1 | sed -E 's/.*ids=//' | tr -d '[:space:]')"
OP="$(operator_ids)"

echo "  A(orch) =$A"
echo "  C(child)=$C"
echo "  B(sib)  =$B"
echo "  A's booted POD_LIST ids = [$IDS]"
echo "  operator ids            = [$OP]"

errs=""
[ -n "$IDS" ] || errs+="\n  A's probe did not PASS (no ids sentinel) — it did not settle on a scoped listing over vsock; check $ALOG"
case ",$IDS," in *",$A,"*) : ;; *) errs+="\n  A ($A) is NOT in its own booted listing — the query did not authenticate as A" ;; esac
case ",$IDS," in *",$C,"*) : ;; *) errs+="\n  child C ($C) is NOT in A's booted listing — the live filter is NOT lineage-scoped (a self-only filter looks exactly like this)" ;; esac
case ",$IDS," in *",$B,"*) errs+="\n  sibling B ($B) IS in A's booted listing — cross-pod isolation FAILED over the real vsock" ;; esac
case ",$OP," in *",$A,"*) : ;; *) errs+="\n  operator view is missing A ($A)" ;; esac
case ",$OP," in *",$B,"*) : ;; *) errs+="\n  operator view is missing B ($B) — cannot conclude B was EXCLUDED vs never present" ;; esac
case ",$OP," in *",$C,"*) : ;; *) errs+="\n  operator view is missing C ($C) — cannot conclude C-inclusion means anything" ;; esac
[ "$IDS" != "$OP" ] || errs+="\n  A's booted listing equals the operator view — no scoping occurred (fail-open)"

if [ -n "$errs" ]; then
    echo -e "FAILED: cross-pod isolation did not hold on the real boot:$errs" >&2
    exit 1
fi

echo "OK: on a real Firecracker boot, pod A's POD_LIST over its own vsock returned"
echo "A and its child C but EXCLUDED sibling B — a strict subset of the operator"
echo "view that sees all three. The listing is lineage-scoped over the real"
echo "transport (self + children), not self-only and not fail-open."
