# TPM 2.0 DevID residency fixture (real swtpm output)

Ground-truth artifacts from a genuine TPM2_Certify, produced by `regen.sh`
(swtpm 0.10 + tpm2-tools 5.7 on Linux). The AK certifies that the subject
(DevID) key is TPM-resident; `fixedtpm|fixedparent` in the subject's
attributes is the non-exportability property the verifier enforces.

- `ak.pub.b64`     — TPM2B_PUBLIC of the attestation key (ECC P-256), base64
- `subj.pub.b64`   — TPM2B_PUBLIC of the certified subject key, base64
- `attest.bin.b64` — TPM2B_ATTEST (TPMS_ATTEST, type=TPM_ST_ATTEST_CERTIFY), base64
- `sig.bin.b64`    — TPMT_SIGNATURE (ECDSA over the attest), base64

Decoded attest (reference): magic=ff544347 (TPM_GENERATED), type=8017
(TPM_ST_ATTEST_CERTIFY); attested.certify.name = 000b || SHA-256(subject TPMT_PUBLIC).

NOTE: swtpm's EK is NOT manufacturer-signed. This fixture proves protocol
correctness of residency verification, NOT silicon binding. `HardwareRootedKey`
remains `not_proven` until a real EK-manufacturer root is checked (Inc 3).
