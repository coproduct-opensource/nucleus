# Adversarial reviews

Persona-driven adversarial review notes and their machine-readable outputs
(`*-claims.json` / `*-results.json`), kept out of the repo root for readability.
These are point-in-time analysis artifacts, not build inputs — nothing in the
build, CI, or mdbook (`docs/`) references them.

## `north-star-frontier/` (2026-09-08)

A 22-agent mapping of nucleus and gatehouse against the agency-authorization
North Star ("any model should be able to do as much useful real-world work as
its principal is willing to authorize, while being structurally incapable of
exceeding that authorization"): six subsystem maps (`read-*.md`), five
state-of-the-art surveys (`sota-*.md`), five per-clause gap analyses
(`gap-*.md`) each with a skeptical verification (`verify-gap-*.md`), and
`SYNTHESIS.md` — the deduplicated gap table, eight architectural themes, a
sequenced roadmap, and the five-clause ledger structure that
`docs/north-star.md` now carries. Point-in-time; file:line references are as
of the commit that added them.
