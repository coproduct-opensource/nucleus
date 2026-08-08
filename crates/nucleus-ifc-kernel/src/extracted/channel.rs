//! Channel admission — the slice **FM-5 phase 2**'s completeness theorem is
//! proven over after Charon→Aeneas→Lean extraction.
//!
//! # The property
//!
//! FM-5 (`super::identity`) proves the material×principal decision: no `Secret`
//! material may be *delivered* to the workload. The typed launch builder
//! (`nucleus-tool-proxy::workload`) then forces every dimension the child
//! inherits — environment, argv, cwd, stdio, inherited fds, uid — through one
//! admitted path. What that leaves *tested and structural* rather than *proved*
//! is the **channel enumeration itself**: nothing states that the set of
//! channels is closed, so "a new inherited fd or socket bypasses the model by
//! never entering the taxonomy" is an argument, not a theorem.
//!
//! This module makes the channels a proved-total object. A `#[repr(u8)]`
//! [`ChannelKind`] enumerates the dimensions the child inherits, and
//! [`channel_admits`] decides, for each channel, which material may cross it to
//! which principal. The completeness theorem then quantifies over ALL channels:
//! a new channel forces an exhaustive `match` arm (it will not compile
//! otherwise), and a channel that carried secret material to the workload would
//! fail the flagship. This is FM-5's material-dimension guarantee lifted to the
//! channel dimension.
//!
//! # The modelling decisions, stated so they can be disagreed with
//!
//! **`Env` is the only material-carrying channel, and its admission IS
//! [`ident_may_deliver`].** Environment values are arbitrary strings, so the
//! env channel can in principle carry any material — bounded exactly by the
//! FM-5 relation. Restating that relation here rather than delegating would
//! risk drift; the anti-drift theorem pins `channel_admits Env = ident_may_deliver`.
//!
//! **`Argv` and `Cwd` carry public operator data only.** The command line and
//! working directory are written by the operator's PodSpec; they are modelled
//! as admitting a material iff it is `Public`. A future design that wanted argv
//! to carry a secret token would have to relabel here — turning that change
//! into a red theorem first, which is the point.
//!
//! **`Cmdline` (the guest kernel command line, `/proc/cmdline`) carries public
//! per-node config only.** It is world-readable inside the guest, so whatever
//! rides it structurally reaches the workload — there is no "deliver to the
//! runtime but not the agent" on this channel. Modelled exactly like `Argv`:
//! admits a material iff it is `Public`. That is faithful because the node now
//! writes only per-node public configuration there (`approval_pubkeys`, the
//! audit S3 bucket/region/endpoint, the workload-API port); every per-pod
//! secret that used to ride it — `auth_secret`, `approval_secret`, the AWS
//! audit credentials, the task token, the dead Tier-3 `sandbox_token` — was
//! moved to the workload API or retired. A future change that put a `Secret`
//! back on the command line would have to relabel it here to type-check the
//! flagship, turning the regression into a red theorem, which is the point.
//!
//! **`Stdio`, `ExtraFd` and `Uid` are material-closed** — they carry no
//! `MaterialKind` value at all. `Stdio` is `null`/pipe (a disposition, not a
//! value); `ExtraFd = false` is the formal statement of the `close_range`
//! structural closure the launch builder installs (every inherited fd above
//! 0/1/2 is shut before exec); `Uid` is a number, not material.
//!
//! # What this model does NOT claim
//!
//! Mounts are not a modelled channel — the workload's mount namespace is the
//! VM's job (jailer + read-only root + nosuid/nodev/noexec tmpfs), fenced here
//! as in FM-5. Covert channels (timing, sizes, proxy responses) are capacity
//! questions, out of scope. And this proves the *relation* over channels, not
//! that the spawn code consults it — the typed builder and the
//! `workload_identity_isolation` lint carry that structurally. The strongest
//! empirical form, an in-guest probe of the real child's `/proc/self/{fd,
//! environ}`, is the named follow-on.
//!
//! Scalar-only, like every other module in `extracted/` — Aeneas emits derived
//! comparisons and collection operations as opaque axioms, and an unspecified
//! axiom on this path would undermine the very claim being made.

use super::identity::{MaterialKind, Principal, ident_may_deliver, mat_label};
use super::ifc_confidentiality::ConfLevel;

/// A dimension the spawned workload child inherits from the runtime.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// Environment variables — the one channel that carries material values.
    Env = 0,
    /// Command-line arguments — operator-written strings, public.
    Argv = 1,
    /// The working directory — an operator-written string, public.
    Cwd = 2,
    /// stdin/stdout/stderr — `null`/pipe dispositions, no material value.
    Stdio = 3,
    /// Inherited file descriptors above 0/1/2 — closed by construction
    /// (`close_range`) before exec, so nothing crosses.
    ExtraFd = 4,
    /// The uid/gid boundary — a number, not material.
    Uid = 5,
    /// The guest kernel command line (`/proc/cmdline`) — world-readable inside
    /// the guest, carrying per-node public config only. Reaches the workload
    /// structurally, so it admits a material iff that material is `Public`.
    Cmdline = 6,
}

/// Numeric rank, so no derived comparison reaches the proof as an opaque axiom.
pub fn chanrank(c: ChannelKind) -> u8 {
    match c {
        ChannelKind::Env => 0,
        ChannelKind::Argv => 1,
        ChannelKind::Cwd => 2,
        ChannelKind::Stdio => 3,
        ChannelKind::ExtraFd => 4,
        ChannelKind::Uid => 5,
        ChannelKind::Cmdline => 6,
    }
}

/// Whether a material kind is `Public` — the label argv/cwd may carry.
pub fn is_public(m: MaterialKind) -> bool {
    matches!(mat_label(m), ConfLevel::Public)
}

/// May material `m` cross channel `c` to principal `p`?
///
/// The whole decision, and deliberately bound to FM-5: the env channel
/// delegates to [`ident_may_deliver`], so the taxonomy is a corollary of the
/// confidentiality axis, not a second model of it. argv/cwd carry public data
/// only; stdio/extra-fds/uid carry no material at all.
pub fn channel_admits(c: ChannelKind, m: MaterialKind, p: Principal) -> bool {
    match c {
        ChannelKind::Env => ident_may_deliver(m, p),
        ChannelKind::Argv | ChannelKind::Cwd | ChannelKind::Cmdline => {
            is_public(m) && ident_may_deliver(m, p)
        }
        ChannelKind::Stdio | ChannelKind::ExtraFd | ChannelKind::Uid => false,
    }
}

/// Whether material `m` may cross channel `c` to the workload.
///
/// Exists so the security-relevant instance has a name of its own and can be
/// stated as a theorem without a reader having to name the principal.
pub fn channel_reaches_workload(c: ChannelKind, m: MaterialKind) -> bool {
    channel_admits(c, m, Principal::Workload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANNELS: [ChannelKind; 7] = [
        ChannelKind::Env,
        ChannelKind::Argv,
        ChannelKind::Cwd,
        ChannelKind::Stdio,
        ChannelKind::ExtraFd,
        ChannelKind::Uid,
        ChannelKind::Cmdline,
    ];
    const MATERIALS: [MaterialKind; 11] = [
        MaterialKind::SvidCert,
        MaterialKind::SvidPrivateKey,
        MaterialKind::TrustBundle,
        MaterialKind::TaskToken,
        MaterialKind::BrokerSecret,
        MaterialKind::ApprovalSecret,
        MaterialKind::SandboxToken,
        MaterialKind::DlcCredentials,
        MaterialKind::ProxyAuthSecret,
        MaterialKind::EgressEnv,
        MaterialKind::OrdinaryData,
    ];
    const PRINCIPALS: [Principal; 3] = [
        Principal::Host,
        Principal::GuestRuntime,
        Principal::Workload,
    ];

    /// **THE FM-5 phase-2 PROPERTY.** No channel delivers any Secret-labelled
    /// material to the workload — the completeness lift across ALL channels.
    #[test]
    fn no_channel_delivers_secret_to_the_workload() {
        for c in CHANNELS {
            for m in MATERIALS {
                if mat_label(m) == ConfLevel::Secret {
                    assert!(
                        !channel_reaches_workload(c, m),
                        "channel {c:?} delivers Secret material {m:?} to the workload"
                    );
                }
            }
        }
    }

    /// Exhaustive over the whole domain — 7 channels x 11 materials x 3
    /// principals. Small enough to enumerate, so there is no reason to sample.
    #[test]
    fn the_delivery_relation_is_pinned_over_its_entire_domain() {
        for c in CHANNELS {
            for m in MATERIALS {
                for p in PRINCIPALS {
                    let expected = match c {
                        ChannelKind::Env => ident_may_deliver(m, p),
                        ChannelKind::Argv | ChannelKind::Cwd | ChannelKind::Cmdline => {
                            is_public(m) && ident_may_deliver(m, p)
                        }
                        ChannelKind::Stdio | ChannelKind::ExtraFd | ChannelKind::Uid => false,
                    };
                    assert_eq!(
                        channel_admits(c, m, p),
                        expected,
                        "channel table changed at ({c:?}, {m:?}, {p:?}) — if this is \
                         deliberate, restate the table AND the Lean theorems"
                    );
                }
            }
        }
    }

    /// **The command line carries no Secret to the workload.** `/proc/cmdline`
    /// is world-readable in the guest, so the model treats it as reaching the
    /// workload and admitting a material iff it is `Public` — the same shape as
    /// argv. This is the FM-5-phase-2 property specialised to the channel the
    /// C1 ledger row was demoted for, and it is faithful because the node now
    /// writes only per-node public config there.
    #[test]
    fn the_cmdline_carries_no_secret_to_the_workload() {
        for m in MATERIALS {
            if mat_label(m) == ConfLevel::Secret {
                assert!(
                    !channel_reaches_workload(ChannelKind::Cmdline, m),
                    "the kernel command line must not deliver Secret material {m:?} to the workload"
                );
            }
        }
        // Non-vacuity: it still carries public config (the trust bundle is the
        // Public material a real cmdline value like the CA path would be).
        assert!(channel_reaches_workload(
            ChannelKind::Cmdline,
            MaterialKind::TrustBundle
        ));
    }

    /// The env channel is EXACTLY the FM-5 relation — no fork. If it ever
    /// diverges, this is what fails.
    #[test]
    fn env_admission_is_exactly_ident_may_deliver() {
        for m in MATERIALS {
            for p in PRINCIPALS {
                assert_eq!(
                    channel_admits(ChannelKind::Env, m, p),
                    ident_may_deliver(m, p)
                );
            }
        }
    }

    /// The `close_range` structural closure, as a property: no material crosses
    /// an inherited fd, to anyone.
    #[test]
    fn no_fd_carries_anything() {
        for m in MATERIALS {
            for p in PRINCIPALS {
                assert!(!channel_admits(ChannelKind::ExtraFd, m, p));
            }
        }
    }

    /// stdio and uid carry no material either.
    #[test]
    fn stdio_and_uid_are_material_closed() {
        for m in MATERIALS {
            for p in PRINCIPALS {
                assert!(!channel_admits(ChannelKind::Stdio, m, p));
                assert!(!channel_admits(ChannelKind::Uid, m, p));
            }
        }
    }

    /// Non-vacuity: the env channel still carries the workload's own proxy HMAC
    /// (Internal), and argv still carries public data — the boundary is not
    /// "refuse everything".
    #[test]
    fn the_carrying_channels_still_carry() {
        assert!(channel_reaches_workload(
            ChannelKind::Env,
            MaterialKind::ProxyAuthSecret
        ));
        assert!(channel_reaches_workload(
            ChannelKind::Argv,
            MaterialKind::OrdinaryData
        ));
    }

    /// `as u8` parity with the explicit rank function, so Lean never sees a
    /// derived `Ord`.
    #[test]
    fn chanrank_matches_the_discriminant() {
        for c in CHANNELS {
            assert_eq!(chanrank(c), c as u8);
        }
    }
}
