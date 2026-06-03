// UI test harness via dylint_testing (Research Report 1, §3).
//
// Compiles every `ui/*.rs` fixture with the `aeneas_eligible` lint loaded and diffs
// the emitted diagnostics against the sibling `ui/*.stderr` snapshot.
//
// We use the `Test` builder (not the bare `ui_test` helper) so we can pass
// `--edition=2024`: compiletest does NOT inherit this crate's edition, and the
// fixtures use `async fn`, which is a hard error under the default edition 2015.
//
// To (re)generate ui/main.stderr: run `cargo test --test ui`; on a mismatch the
// harness prints `Actual stderr saved to <PATH>` — copy that file over
// ui/main.stderr. NOTE: `-- --bless` does NOT pass through the libtest harness
// here (libtest rejects the flag before compiletest sees it); the copy-the-
// printed-path workflow is the verified-working one. (Matches ui/main.rs.)

#[test]
fn ui() {
    dylint_testing::ui::Test::src_base(env!("CARGO_PKG_NAME"), "ui")
        .rustc_flags(["--edition=2024"])
        .run();
}
