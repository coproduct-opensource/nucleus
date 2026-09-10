#!/usr/bin/env bash
#
# No workflow may pipe a downloaded script into an interpreter.
#
# `curl … | sh` hands whatever bytes the remote serves at that instant straight
# to a shell with the runner's privileges. There is no version, no checksum, and
# no moment at which the content could be inspected — so the thing CI executes is
# not a thing anyone reviewed. It is the plainest form of the supply-chain risk
# this repo otherwise takes seriously: every Lean workflow pins elan v4.2.4 and
# verifies its SHA-256 first, and the actions are pinned by commit SHA rather
# than tag.
#
# Three instances had survived that convention, and the elan one shows why the
# gate is worth having rather than the convention alone:
#
#     ifc-lean.yml   curl …/elan/MASTER/elan-init.sh | sh -s -- -y
#     ci.yml  (x2)   curl …/wasm-pack/installer/init.sh -sSf | sh
#
# `master` is a MUTABLE ref. Twelve sibling workflows already installed elan from
# a pinned, checksummed release tarball with a comment naming Scorecard
# Pinned-Dependencies as the reason; this one kept fetching whatever that branch
# happened to hold. Nothing caught it, because zizmor runs at `--min-severity
# high` and audits workflow STRUCTURE (template injection, unpinned `uses:`,
# permissions) rather than shell content inside a `run:` block.
#
# The fixes, both of which are the pattern already used elsewhere in the repo:
#   - a pinned release + `sha256sum -c -` before executing (elan)
#   - `taiki-e/install-action` at a pinned SHA with a pinned tool version, which
#     verifies checksums itself (wasm-pack)
#
# Exit 0 clean, 1 on any piped installer.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# A download (curl/wget) whose output is piped into a shell or interpreter.
# Deliberately narrow: it matches the pipe itself, not every mention of curl,
# so fetching to a file and checksumming it — the pattern we WANT — still passes.
pattern='(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da)?sh|(curl|wget)[^|]*\|[[:space:]]*(python3?|perl|ruby|node)'

found=0
for f in .github/workflows/*.yml .github/workflows/*.yaml; do
    [[ -e "$f" ]] || continue
    # A comment line is prose ABOUT the pattern, not an instance of it — this
    # file's own header would otherwise trip the gate it defines, and so would
    # the `not curl … | sh` note in ci.yml explaining why that install changed.
    while IFS= read -r hit; do
        printf '%s\n' "$f:$hit"
        found=1
    done < <(grep -nE "$pattern" "$f" | grep -vE '^[0-9]+:[[:space:]]*#')
done

if [[ "$found" == 1 ]]; then
    cat >&2 <<'MSG'

ERROR: a workflow pipes a downloaded script into an interpreter.

Fetch to a file and verify it before running it:

    curl -sSfL https://…/tool-v1.2.3.tar.gz -o /tmp/tool.tar.gz
    echo "<sha256>  /tmp/tool.tar.gz" | sha256sum -c -
    tar -xzf /tmp/tool.tar.gz -C /tmp

or install it with the SHA-pinned action this repo already uses:

    - uses: taiki-e/install-action@<sha> # vX.Y.Z
      with:
        tool: <tool>@<version>

MSG
    exit 1
fi

echo "OK: no workflow pipes a downloaded script into an interpreter"
