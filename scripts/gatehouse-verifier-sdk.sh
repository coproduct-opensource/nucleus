#!/bin/sh
# Build sdks/verifier-js the way nucleus's canonical CI builder does, so that
# crates/nucleus-verifier-service/embedded-wasm.pins verify on a builder that is not that
# runner — gatehouse's arm64 Firecracker gate lane.
#
# Four things decide the bytes (measured 2026-09-17, gatehouse probe/wasm-repro): the source
# paths the compiler sees, the host triple cargo hashes into -C metadata
# (rust-lang/cargo#13922), the wasm-bindgen binary (the official release stamps its commit into
# the producers section) and wasm-opt (pinned by wasm-pack 0.13.1). The gate image provides the
# builder's paths, the release wasm-bindgen and a rustc that reports the builder's host to
# cargo; this script mounts the source where the builder had it and builds there.
#
# Anywhere without that image (a developer machine, the GitHub shadow lane) it is the plain
# build CI runs.
set -eu

# ── Keeping a seed's SDK output at the seed's instant ─────────────────────────────────────────
# A seeded gate restamps its sources by CONTENT against the manifest the seed carries
# (`/cache/.gatehouse/seed-sources.sha256`, lines `<sha256>  <path relative to the source root>`),
# so a file byte-equal to the seed's copy keeps the seed's old mtime and cargo sees it as fresh.
# wasm-pack then rewrites every file under sdks/verifier-js/pkg/ on every run -- byte-identical
# output, measured 7 of 7 files -- and the fresh mtime undoes that restamp:
# nucleus-verifier-service's build script watches pkg/nucleus_verifier_wasm.js (rerun-if-changed)
# and its routes.rs `include_bytes!`/`include_str!`s two pkg files, so the crate and everything
# above it rebuilt on every seeded run for bytes that had not changed.
#
# restamp_seed_pkg puts back the pre-stamp instant (1230768000, 2009-01-01T00:00:00Z, older than
# the seed's own 2010 stamp) on EXACTLY the pkg files whose sha256 matches the manifest. A file
# that differs, is unlisted, is a symlink, or lies outside pkg/ is left alone, so it keeps
# wasm-pack's fresh mtime and cargo rebuilds from it as before.
#
# SOUNDNESS. Back-dating a file tells cargo "the outputs you hold were built from this". That is
# true here, and only here, because this script is step 0 of the clippy and test-libs gates
# (.gatehouse/pipeline.writ, .gatehouse/gates/{clippy,test-libs}.json): no cargo step has written the
# seed's target dir in this pod yet, wasm-pack builds into its own target dir (its own subdir of
# the gate's, below; the workspace's units never live there and none of them reads pkg/), and a
# file byte-equal to the seed's source yields the same compilation as the seed's did. Two guards
# keep it from running anywhere else:
#   - The manifest exists only in a seeded gate pod. Without it (a developer machine, the shadow
#     lane, an unseeded gate) the restamp is a no-op, and outside the gate image it is not reached
#     at all: that branch `exec`s wasm-pack.
#   - Position in the step list is a property of the plan, not of this script, so the script
#     checks it: if anything in the target dir cargo would use is newer than this pod's boot,
#     cargo has already run here and the restamp is skipped. The SDK's own subdir is left out of
#     that look: this script has just written it, and nothing in it is built from pkg/. Any doubt
#     (no /proc/uptime, a failed find) also skips it. Skipping only costs the rebuild this exists
#     to avoid; it is never wrong.
PRESTAMP=200901010000.00 # `touch -t` under TZ=UTC0: 1230768000, 2009-01-01T00:00:00Z

# ── The SDK's compiled units live in the gate's target dir ────────────────────────────────────
# wasm-pack compiles ~107 crates (15 workspace, 92 registry) on every run. A gate's cached path is
# its CARGO_TARGET_DIR -- that is what a seed carries -- and wasm-pack used to build beside the
# source, in sdks/verifier-js/target, which no seed can serve. So when the caller names a target
# dir, the SDK's units live in its subdir SDK_TARGET and a seed minted by these steps carries them.
#
# The bytes must not move: crates/nucleus-verifier-service/embedded-wasm.pins pins this build, and
# the wasm embeds absolute paths. So cargo is NOT pointed somewhere else. The subdir is bind-mounted
# over sdks/verifier-js/target inside the same namespace that puts the source at the CI path, so
# cargo, rustc and wasm-bindgen see exactly the paths they saw before and only the storage moves.
SDK_TARGET=verifier-js-sdk

# ── ...and so does wasm-opt's output ──────────────────────────────────────────────────────────
# With the compile served, step 0 is ~23 s of `wasm-opt -O` (measured on 3 vCPUs; wasm-bindgen is
# 0.4 s) re-deriving the bytes the seed's mint already derived. wasm-opt is a function of its
# binary, its arguments and its input bytes, so its output is memoized under exactly those, in
# the SDK's target dir: `install_wasm_opt_memo` puts a wrapper where wasm-pack looks for wasm-opt
# (the copy of the image's cache under /work/.cache, never the image itself). A miss runs the real
# binary and records its output; a hit copies the recorded output. The wrapper falls through to the
# real binary unchanged for any call it cannot key: no `-o`, no memo dir, or an output path that
# already exists (an in-place run, whose input the key would not see). And what it produces is
# still checked downstream: nucleus-verifier-service's build.rs refuses a _bg.wasm off the pin.
WASM_OPT_MEMO_DIR=wasm-opt-memo

# wasm_opt_memo_wrapper: the wrapper's text. It reads WASM_OPT_MEMO and runs "$0.real".
wasm_opt_memo_wrapper() {
  cat <<'WRAPPER'
#!/bin/sh
# wasm-opt, memoized by gatehouse-verifier-sdk.sh: same binary, arguments and input -> same output.
set -eu
real=$0.real memo=${WASM_OPT_MEMO:-} out= prev=
for a in "$@"; do
  [ "$prev" = -o ] && out=$a
  prev=$a
done
if [ -z "$memo" ] || [ -z "$out" ] || [ -e "$out" ]; then exec "$real" "$@"; fi
h() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -c1-64; }
key=$({
  h <"$real"
  for a in "$@"; do
    printf '%s\0' "$a"
    if [ "$a" != "$out" ] && [ -f "$a" ]; then h <"$a"; fi
  done
} | h)
if [ -f "$memo/$key" ]; then
  cp "$memo/$key" "$out"
  echo "wasm-opt: output reused from $memo/$key" >&2
  exit 0
fi
"$real" "$@"
mkdir -p "$memo" && cp "$out" "$memo/.$key.$$" && mv "$memo/.$key.$$" "$memo/$key" || true
WRAPPER
}

# install_wasm_opt_memo <wasm-pack cache dir>: wrap every cached wasm-opt binary in it.
install_wasm_opt_memo() {
  for opt in "$1"/wasm-opt-*/bin/wasm-opt; do
    [ -f "$opt" ] && [ ! -L "$opt" ] && [ ! -e "$opt.real" ] || continue
    mv "$opt" "$opt.real"
    wasm_opt_memo_wrapper >"$opt"
    chmod 755 "$opt"
  done
}

sum256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -c1-64
}

# restamp_seed_pkg <manifest> <source root> <target dir> <boot reference file>
restamp_seed_pkg() {
  manifest=$1 root=$2 target=$3 bootref=$4
  [ -f "$manifest" ] || return 0
  if [ -e "$target" ]; then
    # A target path that is not a literal -path pattern fails to prune, which only skips the restamp.
    newer=$(find "$target" -mindepth 1 -maxdepth 3 -path "$target/$SDK_TARGET" -prune \
      -o -newer "$bootref" -print -quit 2>/dev/null) || newer=unknown
    [ -f "$bootref" ] || newer=unknown
    if [ -n "$newer" ]; then
      echo "gatehouse-verifier-sdk: not restamping sdks/verifier-js/pkg: cargo has written $target in this pod ($newer)" >&2
      return 0
    fi
  fi
  [ -d "$root/sdks/verifier-js/pkg" ] && [ ! -L "$root/sdks/verifier-js/pkg" ] || return 0
  # Paths resolve against <source root>, which is what the manifest's relative paths are
  # relative to -- not against whatever the cwd happens to be.
  while IFS= read -r line || [ -n "$line" ]; do
    want=${line%%  *}
    rel=${line#*  }
    [ "$rel" != "$line" ] || continue
    case $want in *[!0-9a-f]*) continue ;; esac
    [ ${#want} -eq 64 ] || continue
    case $rel in sdks/verifier-js/pkg/*) ;; *) continue ;; esac
    case "/$rel/" in */../* | */./*) continue ;; esac
    f=$root/$rel
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    [ "$(sum256 <"$f")" = "$want" ] || continue
    TZ=UTC0 touch -t "$PRESTAMP" -- "$f"
  done <"$manifest"
}

# A file whose mtime is this pod's boot, less a second. Fails when the boot cannot be known.
boot_reference() {
  up=$(cut -d. -f1 /proc/uptime 2>/dev/null) && [ -n "$up" ] || return 1
  stamp=$(date -u -d "@$(($(date +%s) - up - 1))" +%Y%m%d%H%M.%S 2>/dev/null) || return 1
  TZ=UTC0 touch -t "$stamp" -- "$1"
}

self_test() {
  t=$(mktemp -d)
  trap 'rm -rf "$t"' EXIT
  src=$t/src pkg=$t/src/sdks/verifier-js/pkg
  mkdir -p "$pkg" "$t/src/crates" "$t/target/debug/deps"
  printf 'same' >"$pkg/nucleus_verifier_wasm.js"
  printf 'same too' >"$pkg/with space.wasm"
  printf 'rebuilt differently' >"$pkg/changed.js"
  printf 'unlisted' >"$pkg/unlisted.js"
  printf 'outside' >"$t/src/crates/outside.rs"
  ln -s ../../../crates/outside.rs "$pkg/link.js"
  {
    printf '%s  %s\n' "$(printf 'same' | sum256)" sdks/verifier-js/pkg/nucleus_verifier_wasm.js
    printf '%s  %s\n' "$(printf 'same too' | sum256)" 'sdks/verifier-js/pkg/with space.wasm'
    printf '%s  %s\n' "$(printf 'what the seed had' | sum256)" sdks/verifier-js/pkg/changed.js
    printf '%s  %s\n' "$(printf 'outside' | sum256)" crates/outside.rs
    printf '%s  %s\n' "$(printf 'outside' | sum256)" sdks/verifier-js/pkg/link.js
    printf '%s  %s' "$(printf 'outside' | sum256)" sdks/verifier-js/pkg/../../../crates/outside.rs
  } >"$t/manifest"
  TZ=UTC0 touch -t "$PRESTAMP" "$t/prestamp"
  TZ=UTC0 touch -t 202001010000.00 "$t/boot"
  TZ=UTC0 touch -t 201001010000.00 "$t/target/debug/deps/libseed.rlib" "$t/target/debug/deps" "$t/target/debug"
  old() { [ -z "$(find "$1" -newer "$t/prestamp")" ]; }
  fail() { echo "self-test: $*" >&2; exit 1; }

  # 1. Cargo has run in this pod: a target entry newer than boot. Nothing may move.
  touch "$t/target/debug/deps/libfresh.rlib"
  restamp_seed_pkg "$t/manifest" "$src" "$t/target" "$t/boot" 2>/dev/null
  for f in "$pkg"/* "$t/src/crates/outside.rs"; do old "$f" && fail "restamped $f after cargo ran"; done
  rm "$t/target/debug/deps/libfresh.rlib"
  TZ=UTC0 touch -t 201001010000.00 "$t/target/debug/deps"

  # 1b. Only the SDK's own build has run: its subdir is fresh, the workspace's units are not.
  #     That is step 0 itself, so the restamp still applies (checked in case 3).
  mkdir -p "$t/target/$SDK_TARGET/release"
  touch "$t/target/$SDK_TARGET/release/libsdk.rlib"

  # 2. No manifest: a no-op.
  restamp_seed_pkg "$t/absent" "$src" "$t/target" "$t/boot"
  for f in "$pkg"/*; do old "$f" && fail "restamped $f with no manifest"; done

  # 3. The seeded step 0: exactly the byte-equal pkg files take the old instant.
  restamp_seed_pkg "$t/manifest" "$src" "$t/target" "$t/boot"
  old "$pkg/nucleus_verifier_wasm.js" || fail "a matching file kept its fresh mtime"
  old "$pkg/with space.wasm" || fail "a matching file with a space kept its fresh mtime"
  old "$pkg/changed.js" && fail "a file that differs from the seed was restamped"
  old "$pkg/unlisted.js" && fail "an unlisted file was restamped"
  old "$t/src/crates/outside.rs" && fail "a file outside pkg/ was restamped (by name, symlink or ..)"
  echo "ok: self-test -- only byte-equal pkg files restamped, the SDK's own fresh target notwithstanding; none with no manifest or after cargo ran"

  # 4. The wasm-opt memo: a miss runs the real binary, a hit does not, any change in input, args or
  #    binary misses, and calls it cannot key go straight through.
  w=$t/wasm-pack/wasm-opt-0/bin calls=$t/calls memo=$t/memo
  mkdir -p "$w"
  # A stand-in wasm-opt: logs each run, writes its input plus its remaining arguments to -o's path.
  {
    echo '#!/bin/sh'
    echo "echo run >>'$calls'"
    cat <<'FAKE'
i=$1; shift; shift; o=$1; shift; { cat "$i"; echo "$@"; } >"$o"
FAKE
  } >"$w/wasm-opt"
  chmod 755 "$w/wasm-opt"
  install_wasm_opt_memo "$t/wasm-pack"
  install_wasm_opt_memo "$t/wasm-pack" # twice is once
  [ -x "$w/wasm-opt.real" ] && [ ! -e "$w/wasm-opt.real.real" ] || fail "wasm-opt was not wrapped exactly once"
  runs() { if [ -f "$calls" ]; then wc -l <"$calls" | tr -d ' '; else echo 0; fi; }
  opt() { rm -f "$t/out.wasm"; WASM_OPT_MEMO=$memo "$w/wasm-opt" "$t/in.wasm" -o "$t/out.wasm" "$@" 2>/dev/null; }
  printf 'module a' >"$t/in.wasm"
  opt -O && [ "$(runs)" = 1 ] || fail "a memo miss did not run wasm-opt"
  first=$(sum256 <"$t/out.wasm")
  opt -O && [ "$(runs)" = 1 ] || fail "a memo hit ran wasm-opt"
  [ "$(sum256 <"$t/out.wasm")" = "$first" ] || fail "a memo hit gave different bytes"
  opt -Oz && [ "$(runs)" = 2 ] || fail "different arguments reused the memo"
  printf 'module b' >"$t/in.wasm"
  opt -O && [ "$(runs)" = 3 ] || fail "a different input reused the memo"
  [ "$(cat "$t/out.wasm")" = "module b-O" ] || fail "a miss did not give the real output"
  echo '# changed' >>"$w/wasm-opt.real"
  opt -O && [ "$(runs)" = 4 ] || fail "a different wasm-opt binary reused the memo"
  WASM_OPT_MEMO='' "$w/wasm-opt" "$t/in.wasm" -o "$t/out2.wasm" -O && [ "$(runs)" = 5 ] || fail "no memo dir did not run wasm-opt"
  : >"$t/out.wasm"
  WASM_OPT_MEMO=$memo "$w/wasm-opt" "$t/in.wasm" -o "$t/out.wasm" -O 2>/dev/null && [ "$(runs)" = 6 ] || fail "an existing output was served from the memo"
  echo "ok: self-test -- wasm-opt is reused only for the same binary, arguments and input"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

tools=/opt/gate-tools
if [ ! -f "$tools/pins.json" ] || [ ! -x "$tools/bin/rustc-ci-host" ]; then
  exec wasm-pack build sdks/verifier-js --target web --release
fi
# The manifest is JSON, so read it with a JSON parser when the image has one. The sed fallback
# tolerates whitespace around the colon, which the first version did not: the gate tools image
# started pretty-printing pins.json on 2026-09-17 and `"ci_workspace": "..."` stopped matching
# `"ci_workspace":"..."`. The field came back empty, the bind mount target was the empty string,
# and every clippy and test-core run failed with `mount: : mount point does not exist` followed by
# cargo resolving the workspace root as a registry. A parser that only works for one pretty-printer
# is a contract nobody wrote down.
field() {
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg k "$1" '.[$k] // empty' "$tools/pins.json"
  else
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$tools/pins.json"
  fi
}
workspace=$(field ci_workspace)
registry=$(field ci_registry)
test -n "$workspace" && test -n "$registry"
mkdir -p /work/.cache /work/cargo-js
cp -a "$tools/cache/." /work/.cache/
sed "s#^directory = .*#directory = \"$registry\"#" /opt/nucleus-build/cargo-js/config.toml > /work/cargo-js/config.toml
src=$(pwd -P)
# The SDK's target dir: a subdir of the caller's, when it names one (see SDK_TARGET above).
sdk_target=
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  sdk_target=$CARGO_TARGET_DIR/$SDK_TARGET
  mkdir -p "$sdk_target" "$src/sdks/verifier-js/target"
  install_wasm_opt_memo /work/.cache/.wasm-pack
fi
unshare -Urm sh -c '
  mount --bind "$1" "$2"
  if [ -n "$3" ]; then mount --bind "$3" "$2/sdks/verifier-js/target"; fi
  cd "$2"
  exec env -u CARGO_TARGET_DIR RUSTC=/opt/gate-tools/bin/rustc-ci-host RUSTUP_HOME=/usr/local/rustup \
    RUSTUP_TOOLCHAIN=1.96.1 CARGO_HOME=/work/cargo-js XDG_CACHE_HOME=/work/.cache \
    WASM_OPT_MEMO=${3:+$3/'"$WASM_OPT_MEMO_DIR"'} \
    wasm-pack build sdks/verifier-js --target web --release' sh "$src" "$workspace" "$sdk_target" || exit $?
# wasm-pack succeeded. Back-date its byte-identical output to the seed's instant (see the top of
# this file for why that is sound only here). The bind mount above shares inodes with $src, so
# the files are restamped at the paths the manifest names, relative to the source root.
bootref=$(mktemp)
if boot_reference "$bootref"; then
  restamp_seed_pkg /cache/.gatehouse/seed-sources.sha256 "$src" "${CARGO_TARGET_DIR:-$src/target}" "$bootref"
else
  echo "gatehouse-verifier-sdk: not restamping sdks/verifier-js/pkg: this pod's boot time is unknown" >&2
fi
rm -f "$bootref"
