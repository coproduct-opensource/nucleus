# Native Olog snapshot

The `olog-store` and `olog-ledger` manifests declare MIT licenses. These local
source snapshots make the public runtime independently buildable without a
private repository path or external database engine. They use the Olog 0.1.0
ordered map and ledger; there is no SQLite adapter.

The snapshot includes fallible reads, refusal of corrupt manifests/WAL records,
truncation and synchronization of incomplete WAL tails, and exclusive ledger
writer locking. Source hashes at introduction (2026-10-10):

- `olog-store/src/lib.rs`: `a2c759608c4af48006e23bc6240b22226e449c63dddd57c9765adc8c075b1c02`
- `olog-ledger/src/lib.rs`: `dd33df12c2f4d790767c10e80970900a94c6a106d35d38f1572afb4367e7442a`

Retain the upstream package metadata and tests when updating these snapshots.

## Publication (2026-10-31)

This snapshot first landed in commit `f4f84964e`, whose message says "local only, contains
private olog vendor". That message is wrong about intent: on 2026-10-31 the owner ruled that the
snapshot is public under the MIT license its manifests declare. It was already on public branches
of this repository, and it stays. Future updates follow the same terms.
