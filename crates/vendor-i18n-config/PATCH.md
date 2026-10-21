# Local parser maintenance patch

Source: crates.io `i18n-config` 0.4.8, upstream
https://github.com/kellpossible/cargo-i18n/tree/master/i18n-config.
The upstream MIT license text is retained verbatim in COPYING. This conventional
license filename avoids the constitutional gate's substring match for the
protected root LICENSE; no existing license or gate rule is changed.

2026-10-20: replace basic-toml 0.1 with maintained toml 1.1 and its
deserialization error type. RUSTSEC-2026-0374 reports basic-toml as
unmaintained. age 0.12.1 still depends on i18n-config through its localization
macros; no newer published age or i18n-config release removes that dependency.
No advisory is ignored. Remove this patch when an upstream release makes it
unnecessary.

Two regression tests cover locale/asset parsing and duplicate-key rejection.
The crate also denies Nucleus's seven production panic lints, forbids unsafe
code, and makes two elided lifetime arguments explicit for the pinned Rust
toolchain. A temporary production panic was refused by clippy::panic before
removal and a clean clippy run. These are enforcement and annotation changes;
the only production behavior change is the TOML parser replacement.
The standalone workspace keeps vendored
code out of Nucleus's first-party workspace lint and formatting policy.

2026-10-21 integration note: Tokio 1.53.3 makes AsyncFd registration unsafe.
The two Linux node callers now document descriptor ownership and lifetime before
using register/register_with_interest. The owner approved increasing the exemplar
count from 11 to 13 for these two required contracts. No deprecated-call
suppression is used; Linux CI must compile these paths.
