#!/usr/bin/env bash
# C9 TPM DevID Inc 3 brick 2 — AK↔EK binding proven against a REAL TPM.
#
# The pure unit tests (`credential_activation_tests`) prove nucleus's
# MakeCredential construction binds the AK name (STORAGE-KDFa + integrity HMAC).
# This proves the thing only a TPM can: that nucleus's `make_credential_ecc`
# output is byte-accepted by a real TPM's `TPM2_ActivateCredential`, and that the
# binding BITES — a credential built for one AK cannot be activated on another,
# and a tampered blob is rejected. Producer = nucleus, verifier = the TPM (the
# same producer≠verifier discipline as the residency verifier).
#
# swtpm is a userspace software TPM — no KVM, no hardware needed; it is only a
# PRODUCER/VERIFIER of the blobs, never in nucleus's TCB.
#
# Usage: scripts/tpm-credential-activation-check.sh   (needs swtpm + tpm2-tools)
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

for t in swtpm tpm2_startup tpm2_createek tpm2_createak tpm2_activatecredential; do
    command -v "$t" >/dev/null || { echo "SKIP: $t not installed"; exit 0; }
done

EX="${TPM_MAKECRED_BIN:-}"
if [[ -z "$EX" ]]; then
    echo "building nucleus-identity example tpm_makecred (--features tpm-devid)…"
    cargo build -q --example tpm_makecred -p nucleus-identity --features tpm-devid \
        || { echo "ERROR: build failed"; exit 1; }
    EX="$PWD/target/debug/examples/tpm_makecred"
fi
[[ -x "$EX" ]] || { echo "ERROR: missing $EX"; exit 1; }

W="$(mktemp -d)"; PORT="${TPM_PORT:-2325}"
SW=""
cleanup() { [[ -n "$SW" ]] && kill "$SW" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT INT TERM

swtpm socket --tpm2 --server "type=tcp,port=$PORT" --ctrl "type=tcp,port=$((PORT+1))" \
    --flags not-need-init --tpmstate "dir=$W" >/dev/null 2>&1 &
SW=$!; sleep 1
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$PORT"
cd "$W"

tpm2_startup -c || { echo "ERROR: tpm2_startup"; exit 1; }
tpm2_createek -G ecc -c ek.ctx -u ek.pub >/dev/null; tpm2_flushcontext -t
tpm2_createak -C ek.ctx -c ak1.ctx -u ak1.pub -n ak1.name -G ecc >/dev/null; tpm2_flushcontext -t
tpm2_createak -C ek.ctx -c ak2.ctx -u ak2.pub -n ak2.name -G ecc >/dev/null; tpm2_flushcontext -t

SECRET="00112233445566778899aabbccddeeff"
# NUCLEUS builds the credential for AK1.
"$EX" ek.pub "$(xxd -p ak1.name | tr -d '\n')" "$SECRET" cred1.out || { echo "ERROR: make_credential"; exit 1; }

# Activate <ak.ctx> <cred file>: writes rec.bin on success, nothing on failure.
activate() {
    rm -f rec.bin
    tpm2_startauthsession --policy-session -S s.ctx >/dev/null 2>&1
    tpm2_policysecret -S s.ctx -c e >/dev/null 2>&1
    tpm2_activatecredential -c "$1" -C ek.ctx -i "$2" -o rec.bin -P"session:s.ctx" >/dev/null 2>&1
    tpm2_flushcontext s.ctx >/dev/null 2>&1 || true
}
recovered_secret() { [[ -f rec.bin && "$(xxd -p rec.bin | tr -d '\n')" == "$SECRET" ]]; }

errs=""
# Positive: nucleus-made credential, real TPM activates, recovers our secret.
activate ak1.ctx cred1.out
recovered_secret || errs+="\n  POSITIVE failed: the TPM did not recover nucleus's secret — make_credential_ecc is not byte-accepted"
# Bite 1 — wrong AK: a credential for AK1 must NOT activate on AK2.
activate ak2.ctx cred1.out
recovered_secret && errs+="\n  WRONG-AK leaked: a credential for AK1 activated on AK2 — the AK-name binding does not bite"
# Bite 2 — tampered: a flipped credential byte must be rejected.
cp cred1.out tamp.out
printf '\xff' | dd of=tamp.out bs=1 seek=20 count=1 conv=notrunc >/dev/null 2>&1
activate ak1.ctx tamp.out
recovered_secret && errs+="\n  TAMPERED leaked: a corrupted credential blob still activated — the integrity HMAC does not bite"

if [[ -n "$errs" ]]; then
    echo -e "FAILED: TPM credential-activation check:$errs" >&2
    exit 1
fi
echo "OK: nucleus's make_credential_ecc is accepted by a real TPM's ActivateCredential"
echo "(secret recovered), and the AK↔EK binding BITES — a credential for one AK does"
echo "not activate on another, and a tampered credential is rejected."
