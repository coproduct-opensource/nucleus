#!/usr/bin/env python3
"""Reject external-state elaboration in the owned sources of audited Lean roots.

This syntactic lint is deliberately narrower than a purity proof. Dependencies
(including the audit metaprogram) are outside its scope; independent kernel
replay remains a separate check. Bare #eval and #guard_msgs are permitted.
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
    patterns = (
        r"\bIO\s*\.\s*(?:FS\b|getEnv\b)",
        r"(?m)^\s*(?:builtin_)?initialize\b",
        r"(?:#eval|\brun_cmd\b)[^\n]*\bIO\b",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, code):
            yield code.count("\n", 0, match.start()) + 1, match[0].strip()


def sources(project, roots):
    files = set()
    for root in roots.split(","):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", root):
            raise ValueError(f"invalid audited root: {root!r}")
        module = root.replace(".", "/")
        found = set()
        for base in [project, *project.glob("generated*")]:
            direct = base / (module + ".lean")
            if direct.is_file():
                found.add(direct)
            directory = base / module
            if directory.is_dir():
                found.update(p for p in directory.rglob("*.lean") if ".lake" not in p.parts)
        if not found:
            raise ValueError(f"no owned Lean sources for audited root {root}")
        files.update(found)
    return sorted(files)


def self_test():
    for source in ('def x := IO.getEnv "X"', '#eval IO.FS.readFile "x"',
                   'initialize cache : IO.Ref Nat ← IO.mkRef 0',
                   'run_cmd IO.println "x"', '#eval IO.println "x"',
                   'def x := IO /- gap -/ .getEnv "X"'):
        assert list(violations(source)), source
    assert not list(violations('\n'.join([
        '-- IO.getEnv "X"', '/- IO.FS /- initialize -/ -/',
        'def text := "IO.getEnv"', '#eval 1 + 1',
        '#guard_msgs in #eval 1 + 1'])))
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory)
        (project / 'Proof.lean').write_text('theorem clean : True := by trivial')
        (project / 'Research.lean').write_text('#eval IO.println "allowed outside audit"')
        assert sources(project, 'Proof') == [project / 'Proof.lean']
        try:
            sources(project, 'Missing')
        except ValueError:
            pass
        else:
            raise AssertionError('empty root passed')
    print('ok: external-state fixtures rejected; pure evaluation and unselected research allowed')


def main():
    if sys.argv[1:] == ['--self-test']:
        self_test()
        return 0
    if len(sys.argv) != 3:
        raise ValueError('usage: check-lean-external-state.py PROJECT ROOT[,ROOT...]')
    files = sources(Path(sys.argv[1]), sys.argv[2])
    failed = False
    for path in files:
        for line, construct in violations(path.read_text()):
            print(f'::error file={path},line={line}::external-state construct forbidden: {construct}')
            failed = True
    if not failed:
        print(f'ok: {len(files)} audited Lean source files contain no external-state constructs')
    return int(failed)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, UnicodeError) as error:
        print(f'::error::{error}')
        sys.exit(1)
