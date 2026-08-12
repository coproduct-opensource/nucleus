#!/usr/bin/env bash
# Produce a REAL TPM2_Certify residency fixture via swtpm + tpm2-tools.
# Emits base64 of: AK pub, subject pub, TPMS_ATTEST (certify), signature.
set -euo pipefail

echo "=== installing swtpm + tpm2-tools ==="
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq swtpm tpm2-tools >/dev/null 2>&1
echo "installed: $(swtpm --version | head -1); $(tpm2_startup --version 2>&1 | head -1)"

W="$(mktemp -d)"; cd "$W"
mkdir -p tpmstate
echo "=== starting swtpm ==="
swtpm socket --tpmstate dir="$W/tpmstate" \
  --ctrl type=tcp,port=2322 --server type=tcp,port=2321 \
  --tpm2 --flags not-need-init,startup-clear >/dev/null 2>&1 &
SWPID=$!
sleep 1
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
trap 'kill $SWPID 2>/dev/null; rm -rf "$W"' EXIT

echo "=== primary (parent) ==="
tpm2_createprimary -C o -G ecc256 -g sha256 -c primary.ctx >/dev/null
tpm2_flushcontext -t >/dev/null   # keep only the .ctx on disk; avoid duplicate resident primaries

echo "=== AK (signing key, restricted-off so it can certify) ==="
tpm2_create -C primary.ctx -G ecc256 -g sha256 \
  -u ak.pub -r ak.priv \
  -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' >/dev/null
tpm2_flushcontext -t >/dev/null
tpm2_load -C primary.ctx -u ak.pub -r ak.priv -c ak.ctx >/dev/null
tpm2_flushcontext -t >/dev/null

echo "=== subject DevID key (fixedtpm|fixedparent = non-exportable) ==="
tpm2_create -C primary.ctx -G ecc256 -g sha256 \
  -u subj.pub -r subj.priv \
  -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' >/dev/null
tpm2_flushcontext -t >/dev/null
tpm2_load -C primary.ctx -u subj.pub -r subj.priv -c subj.ctx >/dev/null
tpm2_flushcontext -t >/dev/null

echo "=== TPM2_Certify: AK certifies the subject key's residency ==="
tpm2_certify -C ak.ctx -c subj.ctx -g sha256 -o attest.bin -s sig.bin >/dev/null
tpm2_flushcontext -t >/dev/null

echo "=== artifact sizes ==="
ls -l ak.pub subj.pub attest.bin sig.bin | awk '{print $5, $9}'

echo "=== BASE64 ARTIFACTS (capture these) ==="
for f in ak.pub subj.pub attest.bin sig.bin; do
  echo "---BEGIN $f---"
  base64 -w0 "$f"; echo
  echo "---END $f---"
done

echo "=== human-readable attest (tpm2_print) ==="
tpm2_print -t TPMS_ATTEST attest.bin 2>/dev/null || tpm2_print attest.bin 2>/dev/null || echo "(tpm2_print unavailable)"
