# Open statements

A statement is a claim about this repository's code, written in Lean and not yet
proved. Each one is a row of `open-statements.toml` at the repository root and a
module in this directory. Anyone may prove one; a proof is an ordinary pull
request.

## A row

| field | meaning |
|---|---|
| `id` | `S<digits>`; names the module `Statements.S<id>` |
| `package` | the Lean package directory, relative to the repository root |
| `module` | `Statements.S<id>` |
| `claim` | `Statements.S<id>.claim` |
| `permitted_axioms` | the axioms a proof may use: `propext`, `Classical.choice`, `Quot.sound` |
| `maximum_artifact_bytes` | an upper bound on the exported proof's size |
| `statement_sha256` | SHA-256 of the statement's export (below) |
| `status` | `open`, `posted`, `settled`, `merged` or `withdrawn` |
| `artifact_keccak256` | once `settled`: Keccak-256 of the accepted proof's export |
| `settlement` | once `settled`: an opaque reference string, not interpreted here |

The statement's export is `lean4export` 3.1.0 (Lean 4.30.0) run on the module
with the permitted axioms and the claim as roots, then converted to the export
format's v2 encoding. Anyone can recompute it from a commit.

## Status only moves forward

`open < posted < settled < merged`, and `withdrawn`, which is terminal, is
reachable only from `open` or `posted`. A new row is `open`. Once a row is
`posted`, it may not be removed, renamed, re-digested or given more axioms, and
the claim's whole closure is frozen: changing any declaration the claim depends
on changes its export, so it is a statement change. The way out is to withdraw
the row and add a new one. An `open` or `withdrawn` row may be removed.

## A module

`Statements/S<id>.lean` defines `Statements.S<id>.claim : Prop`, and any helper
definitions the claim needs, in namespace `Statements.S<id>`. The claim is a
`def`, never a `theorem` with a proof hole, so nothing depends on it and the
axiom audit is unaffected.

A proof goes in `Statements/S<id>/Proof.lean` as
`theorem Statements.S<id>.proof : Statements.S<id>.claim`, using only the
permitted axioms.

## Building

`Statements.lean` imports every row's module (and, once one lands, its proof),
and the `Statements` library in `lakefile.lean` builds from it in the proven-tier
workflow job, with its sorry ban and axiom audits. Adding a row adds an import
there and a row to `open-statements.toml`; no lakefile or workflow edit.

The library uses an explicit root rather than `globs`, because
`crates/xtask/src/lean_tier.rs` derives the audited tier from roots and refuses a
library it cannot read.
