# Local parser maintenance patch

Source: crates.io `i18n-config` 0.4.8, upstream
https://github.com/kellpossible/cargo-i18n/tree/master/i18n-config.
The upstream MIT license is retained in LICENSE.txt.

2026-10-20: replace basic-toml 0.1 with maintained toml 1.1 and its
deserialization error type. RUSTSEC-2026-0374 reports basic-toml as
unmaintained. age 0.12.1 still depends on i18n-config through its localization
macros; no newer published age or i18n-config release removes that dependency.
No advisory is ignored. Remove this patch when an upstream release makes it
unnecessary.

Two regression tests cover locale/asset parsing and duplicate-key rejection.
The production source is otherwise unchanged. The standalone workspace keeps vendored
code out of Nucleus's first-party workspace lint and formatting policy.
