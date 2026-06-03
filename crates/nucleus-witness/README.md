# nucleus-witness

A [C2SP `tlog-witness`](https://c2sp.org/tlog-witness) server. It mints
Ed25519 **cosignatures** over transparency-log checkpoints, enforcing the
spec status matrix so it only ever cosigns a checkpoint that is signed by
a trusted log key, extends the last checkpoint it cosigned (RFC 6962
consistency proof), and is not a rollback.

This crate is **auth-sensitive**: a cosignature is minted with a witness
private key. The correctness of the status matrix and the adversarial
negative tests is the whole point — see `tests/status_matrix.rs`.

## The status matrix (`POST /add-checkpoint`)

| Code | Condition |
|------|-----------|
| **404** | checkpoint origin is unknown (not in the trusted-origins set) |
| **403** | no signature from a trusted key for the origin, OR a sig line whose key name+ID match a trusted key but whose signature fails to verify |
| **400** | `old` size > checkpoint size |
| **409** | `old` size ≠ the witness's last-cosigned size for the origin; OR `old` size == checkpoint size but the root hashes differ |
| **422** | the Merkle consistency proof does not verify (old→new) |
| **200** | otherwise: update last-cosigned `(size, root)`, return one or more `cosignature/v1` lines |

The pure decision lives in `server::decide` (unit-testable without HTTP);
the axum handler maps the `Decision` to a status + body.

### Request body

```
old <N>\n
<0..=63 base64 consistency-proof-hash lines, each \n-terminated>
\n                                  ← blank line separator
<checkpoint signed-note>            ← origin / size / base64(root) / [ext...] / blank / `— <name> <base64>` sig lines
```

### 200 response

One or more cosignature/v1 lines:

```
— <witness-name> base64(keyID(4) || timestamp(8, big-endian) || ed25519_sig(64))
```

where the signed message is `cosignature/v1\ntime <unix>\n<full checkpoint
note body>` and `keyID = SHA-256(name || 0x0A || 0x04 || pubkey)[:4]`. The
timestamp is non-zero. (ML-DSA-44 is a future C2SP SHOULD — not
implemented; Ed25519 only.)

## Deployment model: single-tenant split-trust

Run **your own k-of-n witnesses** across diverse regions / clouds / HSMs.
The value is **failure-domain diversity**, not federation with other
organizations: no single region outage, cloud-account compromise, or
key-store breach can forge or roll back your log, because a quorum of
independently-hosted witnesses must each cosign. A verifier configured
with a Sigsum k-of-n policy (see `nucleus_lineage::policy`) then cannot be
shown a forged or rolled-back log without a threshold compromise.

## Dormant metering seam (documented, NOT implemented)

A valid cosignature over a real checkpoint is a unit of *proven work* —
the natural meter point for a future **parallel paid tier**: priced by
VCG/Pigou, settled over x402 / L402. That tier would meter ONLY proven
cosignatures and run *alongside* (never tax) any volunteer commons — the
Tor lesson. None of that billing logic exists here; this is a forward
note so the seam isn't designed shut.

C2SP itself flags **witness sustainability / funding as an unsolved open
problem**. The paid-tier seam above is one possible answer, not a settled
one.

## State persistence

The MVP store (`store::InMemoryStore`) is in-memory behind the
`OriginStore` trait. It is **not persistent** — a restart resets each
origin's last-cosigned position to "never seen", which would let a
producer replay an old checkpoint as a first submission. Production MUST
back the store with durable storage (litewitness uses sqlite); the trait
boundary makes that a drop-in without touching the status matrix.

## Crypto reuse

No cryptography is reinvented. Signed-note parsing/formatting, key-ID
derivation, and checkpoint-body bytes come from `nucleus-lineage`;
RFC 6962 consistency verification comes from `ct-merkle`. The only
net-new logic is the C2SP status matrix and the cosignature/v1 framing.
