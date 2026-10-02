#!/usr/bin/env python3
"""Run one scope shard of nucleus's test suite: stub what the selection left out, then exec the run.

    scripts/test-shard.py --workspace-features <argv...>
        e.g. scripts/test-shard.py --workspace-features cargo nextest run ... -p a -p b

Give every workspace member a target cargo can load when its sources are not in this selection,
then `exec` the argv -- one step, so a shard pays one step's overhead, not two.

`--workspace-features` builds the selected packages with the WORKSPACE's feature unification
(cargo's `resolver.feature-unification = "workspace"`, cargo#14774), not the selection's. Without
it `-p a -p b` unifies features over a and b alone, and the shard compiles different binaries from
the ones the whole-workspace gate tests: measured on nucleus 2fc73eda, 359 of 1056 units (37 test
binaries) for one shard and 382 of 1568 (140 test binaries) for the other differ from
`cargo test --workspace`'s. With it, 0 of 1262 and 0 of 1569 do: every unit -- package, target,
profile, features, and the same for each dependency, recursively -- is one the full gate builds.
The setting is unstable in cargo 1.96, so it is enabled for this process tree only, through
cargo's own config environment, and the channel override is scoped to the same exec.

A `test-*` shard gate (.gatehouse/pipeline.writ) runs on a MATERIALIZED selection: the pod holds
exactly the files its scope names, and the scope names every member's Cargo.toml (cargo loads the
whole workspace to resolve one package, and `--locked` holds the resolve to Cargo.lock) but only
the sources of the crates its tests can reach. Cargo refuses to load a member whose manifest
names, or implies, a target file that is absent ("no targets specified in the manifest"), so this
writes an EMPTY file at each such path and nothing else:

  * it touches only a member whose directory holds its Cargo.toml and NOTHING else -- a member
    outside the selection -- and never overwrites a path that exists;
  * what it writes is a function of the manifests alone, which are in every shard's scope, so the
    shard's verdict stays a function of its scope hash;
  * an empty stub is only ever COMPILED if something in the shard depends on that crate, which
    the scope derivation says nothing does. If it is wrong, the build fails (red), it does not
    pass: an empty crate exports nothing a dependent could use.

Prints one line per stub, and the count, on stderr.
"""
import os
import sys
import tomllib

MAIN = "fn main() {}\n"


def wanted(member, man):
    out = []
    lib = man.get("lib")
    if lib is not None:
        out.append(lib.get("path", "src/lib.rs"))
    bins = man.get("bin", [])
    for b in bins:
        out.append(b.get("path") or f"src/bin/{b['name']}.rs")
    for kind in ("test", "bench", "example"):
        for t in man.get(kind, []):
            if "path" in t:
                out.append(t["path"])
    build = man.get("package", {}).get("build")
    if isinstance(build, str):
        out.append(build)
    has_root = any(os.path.exists(os.path.join(member, p)) for p in ("src/lib.rs", "src/main.rs"))
    if lib is None and not bins and not has_root:
        out.append("src/lib.rs")
    return out


def selected(argv, ws_members, names):
    """The members cargo will test: `--workspace` minus every `--exclude`, else the `-p`s."""
    if "--workspace" in argv:
        out = set(names.values())
        for i, a in enumerate(argv):
            if a == "--exclude" and i + 1 < len(argv):
                out.discard(argv[i + 1])
        return out
    return {argv[i + 1] for i, a in enumerate(argv) if a in ("-p", "--package") and i + 1 < len(argv)}


def main(root, argv=()):
    ws = tomllib.load(open(os.path.join(root, "Cargo.toml"), "rb"))["workspace"]
    names = {}
    for member in ws["members"]:
        man = tomllib.load(open(os.path.join(root, member, "Cargo.toml"), "rb"))
        names[member] = man["package"]["name"]
    want = selected(list(argv), ws["members"], names)
    stubbed = set()
    n = 0
    for member in ws["members"]:
        d = os.path.join(root, member)
        # Only a member OUTSIDE the selection: its directory holds its manifest and nothing else.
        # A member inside the selection is never touched, whatever its manifest implies.
        if sorted(os.listdir(d)) != ["Cargo.toml"]:
            continue
        stubbed.add(names[member])
        man = tomllib.load(open(os.path.join(d, "Cargo.toml"), "rb"))
        for rel in wanted(d, man):
            p = os.path.normpath(os.path.join(d, rel))
            if os.path.lexists(p):
                continue
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "x") as f:
                f.write(MAIN if p.endswith("main.rs") or "/bin/" in p else "")
            print(f"stub {os.path.relpath(p, root)}", file=sys.stderr)
            n += 1
    print(f"test-shard: {n} stub(s)", file=sys.stderr)
    # A package this shard TESTS whose sources are not here would be tested as an empty stub and
    # pass with no tests. That is the shape a new crate takes until the shard gates are
    # regenerated (its directory is in no scope yet), and it must be a red, not a quiet green.
    missing = sorted(want & stubbed)
    if missing:
        sys.exit(f"test-shard: {missing} selected for testing but not in this shard's selection; "
                 "regenerate with scripts/gatehouse-test-shards.py")


WORKSPACE_FEATURES = {
    "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS": "nightly",
    "CARGO_UNSTABLE_FEATURE_UNIFICATION": "true",
    "CARGO_RESOLVER_FEATURE_UNIFICATION": "workspace",
}


if __name__ == "__main__":
    argv = sys.argv[1:]
    if argv[:1] == ["--workspace-features"]:
        argv = argv[1:]
        os.environ.update(WORKSPACE_FEATURES)
    if not argv:
        sys.exit("usage: test-shard.py [--workspace-features] <argv...>")
    main(".", argv)
    sys.stdout.flush()
    sys.stderr.flush()
    os.execvp(argv[0], argv)
