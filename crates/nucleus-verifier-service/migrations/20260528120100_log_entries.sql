-- Append-only log of verification events. Iter-1 of task #69.
--
-- Each row commits to the previous row via a SHA-256 hash chain:
--   entry_hash = SHA-256(prev_hash || envelope_hash_bytes || ts_ms_be_bytes)
-- which gives the "given the tip, all prior entries are committed"
-- property without yet requiring a full Merkle tree. Iter-2 upgrades
-- to a proper RFC 9162 / tlog-tiles Merkle root + signed STH.
--
-- seq is monotonically increasing from 1 (sqlite AUTOINCREMENT
-- semantics — never reused even after DELETE; required for
-- consistency-proof semantics in iter-2).

CREATE TABLE log_entries (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    envelope_hash TEXT NOT NULL,
    prev_hash     BLOB NOT NULL,                  -- 32 bytes; all-zeros for seq=1
    entry_hash    BLOB NOT NULL,                  -- 32 bytes; chain head after this row
    ts_ms         INTEGER NOT NULL,               -- unix ms
    FOREIGN KEY (envelope_hash) REFERENCES verifications(envelope_hash)
);

CREATE INDEX idx_log_entries_envelope_hash ON log_entries(envelope_hash);
