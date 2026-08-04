// UI test harness via dylint_testing, mirroring the sibling `nucleus-mediation-lint`.
//
// IGNORED BY DEFAULT, and the reason matters.
//
// On macOS this cannot run at all: the lint dylib resolves `rustc_driver` through
// `@rpath`, which `DYLD_FALLBACK_LIBRARY_PATH` does not satisfy. `DYLD_LIBRARY_PATH`
// does satisfy it — direct `dlopen` succeeds — but SIP strips `DYLD_*` from the child
// processes compiletest spawns. The sibling `nucleus-mediation-lint` fails identically
// on the same host, so this is pre-existing and not specific to this crate.
//
// There is also no committed `ui/main.stderr` snapshot: generating one requires
// running the harness, which is exactly what cannot be done here. Committing a
// hand-written or empty snapshot would be a fabricated baseline, so there is none.
//
// To enable: on Linux, run `cargo test --test ui -- --ignored`; the harness prints
// `Actual stderr saved to <PATH>`; copy that over `ui/main.stderr` and drop the
// `#[ignore]`. Until then the fixtures are exercised via `cargo dylint` directly —
// see README, "Running it".
#[test]
#[ignore = "needs a Linux host (macOS SIP blocks the dylib load) and a generated ui/main.stderr baseline"]
fn ui() {
    dylint_testing::ui::Test::src_base(env!("CARGO_PKG_NAME"), "ui")
        .rustc_flags(["--edition=2024"])
        .run();
}
