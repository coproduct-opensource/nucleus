-- Initial schema for the verifier-service persistence layer.
--
-- `verifications` records every bundle that hit the verifier service.
-- It's the substrate for:
--   - the hash-lookup endpoint (#68)         — read by envelope_hash
--   - the append-only verification log (#69) — leaf = (envelope_hash, ok, submitted_at)
--   - the retention sweeper (#72)            — DELETE WHERE submitted_at < ...
--
-- envelope_hash is the SHA-256 hex of the canonical bundle hash,
-- stored as TEXT for trivial URL-routing on /v1/bundles/{hash}/verify.
-- ok is 0/1 (sqlite has no native boolean).

CREATE TABLE verifications (
    envelope_hash      TEXT PRIMARY KEY NOT NULL,
    submitted_at       INTEGER NOT NULL,           -- unix seconds
    payload_size_bytes INTEGER NOT NULL,           -- of the bundle JSON
    ok                 INTEGER NOT NULL CHECK (ok IN (0, 1)),
    error_kind         TEXT,                       -- discriminant of VerifyBundleError when ok=0; NULL otherwise
    report_json        TEXT                        -- VerificationReport on success; NULL on failure
);

CREATE INDEX idx_verifications_submitted_at ON verifications(submitted_at);
CREATE INDEX idx_verifications_ok ON verifications(ok);
