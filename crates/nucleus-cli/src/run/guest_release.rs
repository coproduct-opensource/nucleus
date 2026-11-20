//! Which guest a pod run is judged against, and on whose word (#3223).
//!
//! The capabilities `--egress` and an eval cell need are the guest rootfs's
//! (`tier2_artifacts::GuestCapability`), and the rootfs is on the node. So the
//! node says which guest it boots (`/v1/health`, `nucleus_spec::guest_release`)
//! and the run is judged against that. `--guest-release` stays, as the run's
//! own claim: checked against the node's report and refused by name when they
//! disagree, never silently preferred over it or under it. When the node
//! cannot say, the claim is all there is, and a run that depends on the guest
//! without one is refused rather than judged against the pinned release, which
//! nothing ties to the node (ADR 0007 A-1).

use std::fmt;
use std::path::Path;

use anyhow::{Result, bail};
use nucleus_spec::guest_release::{GuestOrigin, LOCAL_BUILD, NodeGuestReport, NodeHealth};
use nucleus_spec::tier2_artifacts::{self, GuestSkew, GuestUse};

/// The guest a run is judged against, and on whose word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GuestBasis {
    /// The node reported it, bound to the digest of the rootfs it boots.
    Reported(GuestOrigin),
    /// `--guest-release`: the run's own claim, before the node is asked or
    /// because the node could not say.
    Asserted(GuestOrigin),
}

/// A guest that lacks what a use of it demands, by the one decider.
#[derive(Debug)]
pub(super) struct SkewRefusal {
    cause: String,
    skew: GuestSkew,
    asserted: bool,
}

impl SkewRefusal {
    /// Whether the guest judged was the run's own claim, so the claim is what
    /// to correct.
    pub(super) fn asserted(&self) -> bool {
        self.asserted
    }
}

impl fmt::Display for SkewRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; {}", self.cause, self.skew)
    }
}

impl GuestBasis {
    /// What `--guest-release` claims, if it was given.
    pub(super) fn asserted(flag: Option<&str>) -> Option<Self> {
        flag.map(|raw| Self::Asserted(GuestOrigin::from_flag(raw)))
    }

    /// Judge the guest for `uses` by `guest_skew_for`, the one decider for
    /// guest skew (#3075). A local build carries what its tree carries, which
    /// no release table describes, so it is not judged.
    ///
    /// # Errors
    /// The release lacks a capability the uses demand, or cannot be ordered.
    pub(super) fn skew_for(&self, uses: &[GuestUse]) -> Result<(), SkewRefusal> {
        let (origin, which, asserted) = match self {
            Self::Reported(origin) => (origin, "the node's guest release", false),
            Self::Asserted(origin) => (origin, "guest release", true),
        };
        let release = match origin {
            GuestOrigin::LocalBuild => return Ok(()),
            GuestOrigin::Release { version } => version,
        };
        tier2_artifacts::guest_skew_for(release, uses).map_err(|skew| {
            let cause = match &skew {
                GuestSkew::Lacks { missing, .. } => {
                    let names: Vec<String> = missing.iter().map(|c| format!("{c:?}")).collect();
                    format!("{which} does not ship {}", names.join(", "))
                }
                GuestSkew::Unorderable { .. } => format!("{which} cannot be checked"),
            };
            SkewRefusal {
                cause,
                skew,
                asserted,
            }
        })
    }
}

/// What the node said when asked which guest it boots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NodeAnswer {
    /// The node's report.
    Reported(NodeGuestReport),
    /// The node answered and predates the report.
    NotReported,
    /// The node could not be asked.
    Unanswered(String),
}

/// Ask the node (`GET /v1/health`). Never fails: a node that cannot be asked
/// is an answer, and [`reconcile`] decides what it costs the run.
pub(super) async fn ask(client: &reqwest::Client, node_url: &str) -> NodeAnswer {
    let url = format!("{}/v1/health", node_url.trim_end_matches('/'));
    let response = match client.get(&url).send().await {
        Ok(response) => response,
        Err(e) => return NodeAnswer::Unanswered(format!("GET {url}: {e}")),
    };
    if !response.status().is_success() {
        return NodeAnswer::Unanswered(format!("GET {url}: {}", response.status()));
    }
    match response.json::<NodeHealth>().await {
        Ok(NodeHealth {
            guest: Some(report),
            ..
        }) => NodeAnswer::Reported(report),
        Ok(NodeHealth { guest: None, .. }) => NodeAnswer::NotReported,
        Err(e) => NodeAnswer::Unanswered(format!("GET {url}: {e}")),
    }
}

/// Decide the guest a run boots from the node's answer, with `flag`
/// (`--guest-release`) as a cross-check of it.
///
/// - The node reports the guest at `rootfs` (the file this run boots): that
///   guest, and a flag naming another one is refused by name.
/// - The node cannot say: the flag's claim if there is one; otherwise `None`
///   when the run makes no use of the guest beyond what the node itself checks
///   at boot (`needs_guest` false), and a refusal when it does.
///
/// # Errors
/// The flag disagrees with the node's report, or the run depends on the guest
/// and neither the node nor the flag says which it is.
pub(super) fn reconcile(
    answer: &NodeAnswer,
    rootfs: &Path,
    flag: Option<&str>,
    needs_guest: bool,
) -> Result<Option<GuestBasis>> {
    let reported = match answer {
        NodeAnswer::Reported(NodeGuestReport::Known {
            origin,
            rootfs_path,
            ..
        }) if rootfs_path == rootfs => Ok(origin),
        NodeAnswer::Reported(NodeGuestReport::Known { rootfs_path, .. }) => Err(format!(
            "it reports the guest at {}, and this run boots {}",
            rootfs_path.display(),
            rootfs.display()
        )),
        NodeAnswer::Reported(NodeGuestReport::Unknown { reason, .. }) => Err(reason.to_string()),
        NodeAnswer::NotReported => Err("it predates reporting its guest (#3223)".to_string()),
        NodeAnswer::Unanswered(e) => Err(format!("it was not asked: {e}")),
    };
    match (reported, flag) {
        (Ok(origin), None) => Ok(Some(GuestBasis::Reported(origin.clone()))),
        (Ok(origin), Some(flag)) => {
            if GuestOrigin::from_flag(flag).same_guest(origin) {
                Ok(Some(GuestBasis::Reported(origin.clone())))
            } else {
                bail!(
                    "--guest-release {flag} disagrees with the node, which reports that it boots \
                     {origin}. Drop --guest-release to use the node's report, or correct it."
                )
            }
        }
        (Err(why), Some(flag)) => {
            tracing::warn!(
                guest_release = flag,
                "the node cannot say which guest it boots ({why}); judging the guest by \
                 --guest-release, which nothing checked"
            );
            Ok(GuestBasis::asserted(Some(flag)))
        }
        (Err(_), None) if !needs_guest => Ok(None),
        (Err(why), None) => bail!(
            "the node cannot say which guest it boots: {why}. This run depends on the guest's \
             capabilities, so it is refused rather than judged against a release nothing ties \
             to the node. Re-run `nucleus setup` so the node records the guest it installs, or \
             state it with --guest-release VERSION|{LOCAL_BUILD}."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_spec::guest_release::UnknownGuest;
    use std::path::PathBuf;

    const ROOTFS: &str = "/var/lib/nucleus/artifacts/rootfs.ext4";

    fn known(version: &str) -> NodeAnswer {
        NodeAnswer::Reported(NodeGuestReport::Known {
            origin: GuestOrigin::Release {
                version: version.into(),
            },
            rootfs_path: PathBuf::from(ROOTFS),
            rootfs_sha256: "0".repeat(64),
        })
    }

    fn reconciled(answer: &NodeAnswer, flag: Option<&str>) -> Result<Option<GuestBasis>> {
        reconcile(answer, Path::new(ROOTFS), flag, true)
    }

    /// #3223's acceptance, at the decision: with no flag, the guest judged is
    /// the one the node reports. A node on a guest with the adapter passes
    /// `--egress`; one on 2.3.0 is refused by name, as the node's release.
    #[test]
    fn with_no_flag_the_node_reported_guest_is_judged() {
        let ok = reconciled(&known("2.7.0"), None).unwrap().unwrap();
        assert_eq!(
            ok,
            GuestBasis::Reported(GuestOrigin::Release {
                version: "2.7.0".into()
            })
        );
        ok.skew_for(&[GuestUse::AgentEgress]).unwrap();

        let old = reconciled(&known("2.3.0"), None).unwrap().unwrap();
        let refused = old.skew_for(&[GuestUse::AgentEgress]).unwrap_err();
        assert!(!refused.asserted());
        let msg = refused.to_string();
        assert!(
            msg.contains("the node's guest release does not ship EgressAdapterUpstreams"),
            "{msg}"
        );
        assert!(msg.contains("v2.3.0"), "{msg}");
    }

    /// A flag that disagrees with the node is refused, naming both; one that
    /// agrees (in either spelling) yields the node's report.
    #[test]
    fn a_flag_that_disagrees_with_the_node_is_refused_by_name() {
        for flag in ["2.6.0", LOCAL_BUILD, "latest"] {
            let err = reconciled(&known("2.7.0"), Some(flag))
                .unwrap_err()
                .to_string();
            assert!(err.contains(&format!("--guest-release {flag}")), "{err}");
            assert!(err.contains("release v2.7.0"), "{err}");
        }
        for flag in ["2.7.0", "v2.7.0"] {
            assert!(matches!(
                reconciled(&known("2.7.0"), Some(flag)).unwrap(),
                Some(GuestBasis::Reported(_))
            ));
        }
        let local = NodeAnswer::Reported(NodeGuestReport::Known {
            origin: GuestOrigin::LocalBuild,
            rootfs_path: PathBuf::from(ROOTFS),
            rootfs_sha256: "0".repeat(64),
        });
        assert!(reconciled(&local, Some("2.7.0")).is_err());
        assert_eq!(
            reconciled(&local, Some(LOCAL_BUILD)).unwrap(),
            Some(GuestBasis::Reported(GuestOrigin::LocalBuild))
        );
    }

    /// A node that cannot say is never read as the pin: a run that depends on
    /// the guest is refused with the reason, unless the flag states the guest,
    /// and a run that does not is not judged at all.
    #[test]
    fn a_node_that_cannot_say_is_never_read_as_a_release() {
        let cannot_say = [
            NodeAnswer::Reported(NodeGuestReport::Unknown {
                rootfs_path: PathBuf::from(ROOTFS),
                reason: UnknownGuest::NoRecord,
            }),
            NodeAnswer::NotReported,
            NodeAnswer::Unanswered("connection refused".into()),
            // A report about another file is not a report about this run's.
            NodeAnswer::Reported(NodeGuestReport::Known {
                origin: GuestOrigin::Release {
                    version: "2.7.0".into(),
                },
                rootfs_path: PathBuf::from("/var/lib/nucleus/artifacts/other.ext4"),
                rootfs_sha256: "0".repeat(64),
            }),
        ];
        for answer in &cannot_say {
            let err = reconciled(answer, None).unwrap_err().to_string();
            assert!(err.contains("cannot say which guest"), "{answer:?}: {err}");
            assert!(err.contains("--guest-release"), "{err}");
            assert_eq!(
                reconciled(answer, Some("2.3.0")).unwrap(),
                Some(GuestBasis::Asserted(GuestOrigin::Release {
                    version: "2.3.0".into()
                }))
            );
            assert_eq!(
                reconcile(answer, Path::new(ROOTFS), None, false).unwrap(),
                None
            );
        }
        let err = reconciled(&cannot_say[0], None).unwrap_err().to_string();
        assert!(err.contains("rootfs.release.json"), "{err}");
    }
}
