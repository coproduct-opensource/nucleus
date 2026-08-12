#!/usr/bin/env bash
# C2 G4 — cross-pod non-interference, proven on a REAL Firecracker boot.
#
# `scripts/cross-pod-scoped-check.sh` proves the auth+filter composition KVM-free
# over the local-driver HTTP path (and, with child C, that the filter is
# lineage-scoped rather than self-only). This proves the remaining thing only a
# KVM host can show: that a BOOTED pod, calling the scoped `POD_LIST` over its
# OWN real workload-API vsock socket, is served a listing confined to itself —
# not the operator view.
#
# THE PROPERTY (over the real vsock transport):
#   A ∈ A's-listing  ∧  B ∉ A's-listing  ∧  {A,B} ⊆ operator  ∧  A's-listing ⊊ operator
# i.e. A's booted view is SCOPED, not fail-open. The lineage-INCLUSION half
# (a child C ∈ A's view — the self-only tooth) is enforced KVM-free by
# `cross-pod-scoped-check.sh` over the SAME `scope_to_caller` filter this path
# runs, so it is not re-proven here; this run is the transport + exclusion proof.
#
# WHY TWO BOOTS, SEQUENCED. Without the jailer the node uses a fixed
# /run/firecracker.socket, so only one microVM boots at a time. B is created
# first; it boots, its own probe runs and it exits (freeing the socket) while it
# LINGERS in the node registry; then A boots and queries. That B lingers is what
# makes B's absence from A's listing an EXCLUSION rather than "B never existed" —
# and the operator control below asserts B is still there.
#
# INPUTS (taken as given — built by the caller / CI, like boot-harness.sh). The
# rootfs MUST bake `nucleus-podlist-probe` and carry `podlist-probe-pod.yaml`
# (orchestrator + enable_pod_mgmt) as /etc/nucleus/pod.yaml, so the workload is
# the probe and the node mints each pod a caller token (whence its pod_id).
#   KERNEL, ROOTFS, NODE_BIN   (defaults under $FC_DIR=$HOME/fc)
#
# Usage: [FC_DIR=… KERNEL=… ROOTFS=… NODE_BIN=…] scripts/firecracker/podlist-boot-check.sh
set -uo pipefail

FC_DIR="${FC_DIR:-$HOME/fc}"
KERNEL="${KERNEL:-$FC_DIR/vmlinux}"
ROOTFS="${ROOTFS:-$FC_DIR/podlist-rootfs.ext4}"
NODE_BIN="${NODE_BIN:-$FC_DIR/nucleus-node}"
STATE_DIR="${STATE_DIR:-$FC_DIR/state-podlist-check}"
ADDR="${NODE_ADDR:-127.0.0.1:9900}"
SECRET="${AUTH_SECRET:-harness-node-secret}"

die() { echo "podlist-boot-check: $*" >&2; exit 1; }
for f in "$KERNEL" "$ROOTFS" "$NODE_BIN"; do [ -s "$f" ] || die "missing input $f"; done
[ -e /dev/kvm ] || die "no /dev/kvm — this must run on a Linux host with KVM"
command -v firecracker >/dev/null || die "firecracker is not on PATH"

sudo pkill -f nucleus-node 2>/dev/null || true
sudo pkill -x firecracker 2>/dev/null || true
sudo rm -rf "$STATE_DIR" /run/firecracker.socket
mkdir -p "$STATE_DIR"

sudo -b env RUST_LOG="${RUST_LOG:-warn}" \
    NUCLEUS_FIRECRACKER_PATH="$(command -v firecracker)" \
    NUCLEUS_FIRECRACKER_NETNS=false NUCLEUS_FIRECRACKER_JAILER=false \
    "$NODE_BIN" --listen "$ADDR" --state-dir "$STATE_DIR" --auth-secret "$SECRET" \
    --proxy-auth-secret harness-proxy-secret --proxy-approval-secret harness-approval-secret \
    --identity-workload-api-socket "$FC_DIR/wapi.sock" > "$FC_DIR/node-podlist-check.log" 2>&1
sleep 5
pgrep -f nucleus-node >/dev/null || { tail -20 "$FC_DIR/node-podlist-check.log"; die "node did not start"; }

# Create a pod via the signed /v1/pods path; prints its id. Both pods are
# node-created (parent=None), so neither is the other's lineage — B is a genuine
# non-lineage sibling of A.
create() {
    local name=$1
    local spec="$FC_DIR/$name.json"
    cat > "$spec" <<JSON
{"apiVersion":"nucleus/v1","kind":"Pod","metadata":{"name":"$name","labels":{"enable_pod_mgmt":"true"}},"spec":{"work_dir":"/work","timeout_seconds":120,"policy":{"type":"profile","name":"orchestrator"},"image":{"kernel_path":"$KERNEL","rootfs_path":"$ROOTFS","read_only":false},"vsock":{"guest_cid":3,"port":5005}}}
JSON
    python3 - "$spec" "$SECRET" "$ADDR" <<'PY'
import hmac,hashlib,sys,time,json,urllib.request,urllib.error
spec,secret,addr=sys.argv[1],sys.argv[2].encode(),sys.argv[3]
body=open(spec,"rb").read(); ts,actor=str(int(time.time())),"boot-harness"
sig=hmac.new(secret,ts.encode()+b"."+actor.encode()+b"."+body,hashlib.sha256).hexdigest()
req=urllib.request.Request(f"http://{addr}/v1/pods",data=body,method="POST",headers={"content-type":"application/json","x-nucleus-timestamp":ts,"x-nucleus-actor":actor,"x-nucleus-signature":sig})
try: print(json.load(urllib.request.urlopen(req,timeout=120))["id"])
except urllib.error.HTTPError as e: sys.stderr.write("CREATE %d %s\n"%(e.code,e.read().decode()[:300])); sys.exit(1)
PY
}

# The operator (no pod identity) view — every pod on the node.
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

echo "podlist-boot-check: booting sibling B"
B="$(create sibling-b)"; [ -n "$B" ] || die "B was not created"
sleep 13   # B boots, its probe runs, B exits and lingers; socket frees.

echo "podlist-boot-check: booting orchestrator A (the probe)"
A="$(create orch-a)"; [ -n "$A" ] || die "A was not created"
sleep 15

ALOG="$(sudo find "$STATE_DIR" -path "*$A*" -name firecracker.log 2>/dev/null | head -1)"
[ -n "$ALOG" ] || die "no firecracker.log for A ($A)"
# A's own booted view, drained from the guest console: `ids=<comma-list>`.
# `tr -d` strips the guest console's trailing CR (\r\n line endings) and any
# stray whitespace, so the id set compares cleanly.
IDS="$(sudo grep -aoE 'NUCLEUS_PODLIST_PROBE: PASS self=[^ ]+ ids=[^ ]+' "$ALOG" 2>/dev/null | head -1 | sed -E 's/.*ids=//' | tr -d '[:space:]')"
OP="$(operator_ids)"

echo "  A=$A"
echo "  B=$B"
echo "  A's booted POD_LIST ids = [$IDS]"
echo "  operator ids            = [$OP]"

errs=""
[ -n "$IDS" ] || errs+="\n  A's probe did not PASS (no ids sentinel) — it did not fetch a scoped listing over vsock; check $ALOG"
case ",$IDS," in *",$A,"*) : ;; *) errs+="\n  A ($A) is NOT in its own booted listing — the query did not authenticate as A" ;; esac
case ",$IDS," in *",$B,"*) errs+="\n  sibling B ($B) IS in A's booted listing — cross-pod isolation FAILED over the real vsock" ;; esac
case ",$OP," in *",$A,"*) : ;; *) errs+="\n  operator view is missing A ($A)" ;; esac
case ",$OP," in *",$B,"*) : ;; *) errs+="\n  operator view is missing B ($B) — cannot conclude B was EXCLUDED vs never present" ;; esac
# Strict subset: A's booted view is smaller than operator (scoping happened).
[ "$IDS" != "$OP" ] || errs+="\n  A's booted listing equals the operator view — no scoping occurred (fail-open)"

if [ -n "$errs" ]; then
    echo -e "FAILED: cross-pod isolation did not hold on the real boot:$errs" >&2
    exit 1
fi

echo "OK: on a real Firecracker boot, pod A's POD_LIST over its own vsock returned"
echo "A and EXCLUDED sibling B — a strict subset of the operator view that sees both."
echo "The scoped listing is served over the real transport, not fail-open."
