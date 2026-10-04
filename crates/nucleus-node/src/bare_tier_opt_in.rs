//! The local driver's bare-tier opt-in (owner decision, 2026-10-02: every
//! bare execution traces to an explicit opt-in).

use crate::driver::DriverKind;

/// The local driver's bare-tier opt-in, as a typed value.
///
/// The local driver runs each tool-proxy as a plain host process, so the
/// proxy's children are on the bare tier. The node grants that only when the
/// operator chose BOTH the local driver and `--allow-local-driver` (the
/// existing "no VM isolation" acknowledgement); every other combination is
/// `Absent`, and the proxy then refuses a bare child by name. Exhaustive, no
/// `_` arm (ADR 0007 B-3).
pub(crate) fn local_driver_opt_in(driver: &DriverKind, allowed: bool) -> nucleus::UnsandboxedOptIn {
    match (driver, allowed) {
        (DriverKind::Local, true) => nucleus::UnsandboxedOptIn::Explicit,
        (DriverKind::Local, false)
        | (DriverKind::Firecracker | DriverKind::Container | DriverKind::AppleVz, true | false) => {
            nucleus::UnsandboxedOptIn::Absent
        }
    }
}

/// The tool-proxy flag that carries [`local_driver_opt_in`]'s answer: the
/// flag for `Explicit`, nothing for `Absent`.
pub(crate) fn unsandboxed_proxy_flag(opt_in: nucleus::UnsandboxedOptIn) -> Option<&'static str> {
    match opt_in {
        nucleus::UnsandboxedOptIn::Explicit => Some("--unsandboxed"),
        nucleus::UnsandboxedOptIn::Absent => None,
    }
}

/// The local driver's `--unsandboxed` is a typed decision, made once, and the
/// flag appears on a tool-proxy's command line only for the one combination
/// that chose the bare host tier.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_allowed_local_driver_opts_its_proxies_in() {
        assert_eq!(
            local_driver_opt_in(&DriverKind::Local, true),
            nucleus::UnsandboxedOptIn::Explicit
        );
        for (driver, allowed) in [
            (DriverKind::Local, false),
            (DriverKind::Firecracker, true),
            (DriverKind::Firecracker, false),
            (DriverKind::Container, true),
            (DriverKind::AppleVz, true),
        ] {
            assert_eq!(
                local_driver_opt_in(&driver, allowed),
                nucleus::UnsandboxedOptIn::Absent,
                "{driver:?} / allowed={allowed}"
            );
        }
    }

    #[test]
    fn the_flag_is_passed_for_explicit_and_only_for_explicit() {
        assert_eq!(
            unsandboxed_proxy_flag(nucleus::UnsandboxedOptIn::Explicit),
            Some("--unsandboxed")
        );
        assert_eq!(
            unsandboxed_proxy_flag(nucleus::UnsandboxedOptIn::Absent),
            None
        );
    }

    /// The node fixture (`--driver local --allow-local-driver`) is the
    /// deliberate case, so its state carries the opt-in.
    #[test]
    fn the_local_driver_fixture_carries_the_opt_in() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::pod_api::handler_tests::state(&dir);
        assert_eq!(
            state.local_driver_opt_in,
            nucleus::UnsandboxedOptIn::Explicit
        );
    }
}
