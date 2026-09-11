#!/usr/bin/env python3
"""Reject compiler overrides in owned Lean sources, including Aeneas output.

Native evaluation must not silently substitute a different implementation for
the definition checked by the kernel. Dependencies in .lake are outside this
source lint; the per-theorem axiom audit remains a separate gate.
"""

import re
import sys
from pathlib import Path


def code_only(source):
    """Blank nested comments and strings while preserving diagnostic lines."""
    out = list(source)
    i = depth = 0
    quoted = False
    while i < len(source):
        if depth:
            if source.startswith("/-", i):
                out[i:i + 2] = "  "
                depth += 1
                i += 2
            elif source.startswith("-/", i):
                out[i:i + 2] = "  "
                depth -= 1
                i += 2
            else:
                if source[i] != "\n":
                    out[i] = " "
                i += 1
        elif quoted:
            if source[i] == "\\":
                out[i:i + 2] = ["\n" if c == "\n" else " " for c in source[i:i + 2]]
                i += 2
            else:
                quoted = source[i] != '"'
                if source[i] != "\n":
                    out[i] = " "
                i += 1
        elif source.startswith("/-", i):
            out[i:i + 2] = "  "
            depth = 1
            i += 2
        elif source.startswith("--", i):
            end = source.find("\n", i)
            if end == -1:
                end = len(source)
            out[i:end] = " " * (end - i)
            i = end
        elif source[i] == '"':
            quoted = True
            out[i] = " "
            i += 1
        else:
            i += 1
    if depth or quoted:
        raise ValueError("unterminated comment or string")
    return "".join(out)


def violations(source):
    code = code_only(source)
    for attribute in re.finditer(r"(?:@\s*|\battribute\s*)\[([^\]]*)\]", code):
        for forbidden in re.finditer(r"\b(?:implemented_by|extern|csimp)\b", attribute[1]):
            yield code.count("\n", 0, attribute.start(1) + forbidden.start()) + 1, forbidden[0]


def self_test():
    for attribute in ("implemented_by", "extern", "csimp"):
        for source in (
            f"@[{attribute} replacement] def f := 1",
            f"@[inline,\n /- nested /- comment -/ -/ {attribute} replacement] def f := 1",
            f"attribute [{attribute} replacement] f",
            f"local attribute [\n{attribute} replacement] f",
        ):
            assert list(violations(source)), source
    assert not list(violations('''
/- @[implemented_by f] /- attribute [csimp] f -/ -/
-- @[extern "f"]
def exampleText := "@[implemented_by f]"
@[simp] theorem clean : True := by trivial
'''))
    assert list(violations('-- comment\n@[csimp] theorem x := rfl')) == [(2, 'csimp')]
    for source in ('/- missing end', 'def s := "missing end'):
        try:
            list(violations(source))
        except ValueError:
            pass
        else:
            raise AssertionError("malformed source passed")
    print("ok: all three planted overrides rejected; comments and strings ignored")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent
    files = sorted(p for p in root.rglob("*.lean") if ".lake" not in p.relative_to(root).parts)
    if not files:
        print(f"::error::no Lean sources found in {root}")
        return 1
    failed = False
    for path in files:
        try:
            for line, attribute in violations(path.read_text()):
                print(f"::error file={path},line={line}::compiler override {attribute} is forbidden")
                failed = True
        except (OSError, UnicodeError, ValueError) as error:
            print(f"::error file={path}::{error}")
            failed = True
    if not failed:
        print(f"ok: {len(files)} owned Lean sources contain no compiler overrides")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
