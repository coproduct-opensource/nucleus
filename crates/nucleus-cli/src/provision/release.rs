//! Whether the guest release this CLI pins can be installed, decided once,
//! before anything is downloaded or touched.
//!
//! # Why this exists
//!
//! `GUEST_RELEASE` is bumped BEFORE its tag is cut (see its doc comment), so a
//! CLI built from `main` in that window points `setup` at a release that does
//! not exist. It surfaced as a download failure three steps into setup — after
//! the Lima VM, Firecracker and the kernel — with a message about an HTTP
//! status rather than about the pin. `doctor` said nothing at all.
//!
//! [`lookup_release`] asks once, and both `setup` and `doctor` read its answer
//! through [`plan_release`] (ADR 0007 G-1: one decider per fact).

use std::time::Duration;

use nucleus_spec::tier2_artifacts::{self, GuestSkew};

/// How long the release API may take to answer. `setup` and `doctor` both wait
/// on it up front, so an unreachable API must become [`ReleaseLookup::CouldNotLook`]
/// rather than a hang.
const RELEASE_API_TIMEOUT: Duration = Duration::from_secs(20);

/// One release asset, with the digest the release API reports for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    pub(super) url: String,
    pub(super) name: String,
    pub(super) digest: String,
}

/// What asking the release host about a release found.
///
/// Three answers, not a `bool` (ADR 0007 A-1): "the API said there is no such
/// release" and "the API could not be reached" call for different fixes —
/// build locally versus retry — and folding them together is how a network
/// blip would be reported as an unpublished release, or the reverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseLookup {
    /// The release exists; these are its assets.
    Published(Vec<ReleaseAsset>),
    /// The API answered 404 for the release's tag: looked, and it is not there.
    NotPublished {
        /// The newest published release, for the message.
        latest: LatestRelease,
    },
    /// The question was not answered: a transport error, a status other than
    /// 404, or a body that is not a release.
    CouldNotLook {
        /// What went wrong, as the transport or parser said it.
        reason: String,
    },
}

/// The newest published release, as far as the API would say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatestRelease {
    /// Its version, without the `v`.
    Version(String),
    /// The second lookup failed too. Only ever decoration on a refusal that has
    /// already been decided, so it never changes the verdict.
    Unknown {
        /// Why.
        reason: String,
    },
}

/// Why `setup` will not install the pinned guest release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnservableRelease {
    /// The release predates something this build's node requires.
    Skew(GuestSkew),
    /// Looked, and the release is not published.
    NotPublished {
        /// The version this CLI pins.
        pinned: String,
        /// The newest one that is.
        latest: LatestRelease,
    },
    /// Could not look.
    CouldNotLook {
        /// The version this CLI pins.
        pinned: String,
        /// Why the lookup failed.
        reason: String,
    },
}

impl std::fmt::Display for UnservableRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnservableRelease::Skew(skew) => write!(f, "{skew}"),
            UnservableRelease::NotPublished { pinned, latest } => {
                let latest = match latest {
                    LatestRelease::Version(v) => v.clone(),
                    LatestRelease::Unknown { reason } => format!("unknown: {reason}"),
                };
                write!(
                    f,
                    "this CLI pins guest release {pinned}, which is not published yet \
                     (latest: {latest}) — use the released CLI, or build the guest locally \
                     with --artifacts local.\n{}.",
                    tier2_artifacts::REBUILD_THE_GUEST
                )
            }
            UnservableRelease::CouldNotLook { pinned, reason } => write!(
                f,
                "could not ask {} whether guest release {pinned} is published: {reason}\n\
                 This is a failure to reach the release API, not a missing release. Retry \
                 when it is reachable, or build the guest locally with --artifacts local.",
                tier2_artifacts::RELEASE_REPO
            ),
        }
    }
}

impl std::error::Error for UnservableRelease {}

/// Decide whether release `version` can be installed, before any download.
///
/// The skew check comes first and needs no network: a release this build
/// cannot serve is refused whether or not it is published. `lookup` is a
/// parameter so every arm is testable without the API; production passes
/// [`lookup_release`].
pub fn plan_release(
    version: &str,
    lookup: impl FnOnce(&str) -> ReleaseLookup,
) -> Result<Vec<ReleaseAsset>, UnservableRelease> {
    tier2_artifacts::guest_skew(version).map_err(UnservableRelease::Skew)?;
    match lookup(version) {
        ReleaseLookup::Published(assets) => Ok(assets),
        ReleaseLookup::NotPublished { latest } => Err(UnservableRelease::NotPublished {
            pinned: version.to_string(),
            latest,
        }),
        ReleaseLookup::CouldNotLook { reason } => Err(UnservableRelease::CouldNotLook {
            pinned: version.to_string(),
            reason,
        }),
    }
}

/// Ask the release API for release `version`.
///
/// The digests it returns are an **integrity** check, not a provenance one —
/// they travel from the same place the bytes do. `gh attestation verify` is the
/// check that binds an asset to the workflow that built it.
pub fn lookup_release(version: &str) -> ReleaseLookup {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(RELEASE_API_TIMEOUT))
        .build()
        .into();
    let api = format!(
        "https://api.github.com/repos/{}/releases",
        tier2_artifacts::RELEASE_REPO
    );
    classify(get_json(&agent, &format!("{api}/tags/v{version}")), || {
        latest_from(get_json(&agent, &format!("{api}/latest")))
    })
}

fn get_json(agent: &ureq::Agent, url: &str) -> Result<serde_json::Value, ureq::Error> {
    agent
        .get(url)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "nucleus-cli")
        .call()?
        .into_body()
        .read_json()
}

/// The three-way verdict on one release-API response. Pure, so each arm is
/// tested on a constructed response.
fn classify(
    response: Result<serde_json::Value, ureq::Error>,
    latest: impl FnOnce() -> LatestRelease,
) -> ReleaseLookup {
    match response {
        Ok(body) => match assets_of(&body) {
            Some(assets) => ReleaseLookup::Published(assets),
            None => ReleaseLookup::CouldNotLook {
                reason: "the release API answered with something that is not a release \
                         (no `assets` array)"
                    .to_string(),
            },
        },
        // 404 is the API saying the tag has no release. Every other status —
        // 403 and 429 are rate limits — is the API declining to say.
        Err(ureq::Error::StatusCode(404)) => ReleaseLookup::NotPublished { latest: latest() },
        Err(e) => ReleaseLookup::CouldNotLook {
            reason: e.to_string(),
        },
    }
}

fn latest_from(response: Result<serde_json::Value, ureq::Error>) -> LatestRelease {
    match response {
        Ok(body) => match body.get("tag_name").and_then(|t| t.as_str()) {
            Some(tag) => LatestRelease::Version(tag.trim_start_matches('v').to_string()),
            None => LatestRelease::Unknown {
                reason: "the latest-release answer has no tag_name".to_string(),
            },
        },
        Err(e) => LatestRelease::Unknown {
            reason: e.to_string(),
        },
    }
}

fn assets_of(body: &serde_json::Value) -> Option<Vec<ReleaseAsset>> {
    let assets = body.get("assets")?.as_array()?;
    Some(
        assets
            .iter()
            .filter_map(|a| {
                Some(ReleaseAsset {
                    url: a.get("browser_download_url")?.as_str()?.to_string(),
                    name: a.get("name")?.as_str()?.to_string(),
                    // Reported as "sha256:<hex>"; keep only the hex. A missing
                    // digest stays empty and is refused per asset at install.
                    digest: a
                        .get("digest")
                        .and_then(|d| d.as_str())
                        .unwrap_or_default()
                        .trim_start_matches("sha256:")
                        .to_string(),
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn latest_2_2_0() -> LatestRelease {
        LatestRelease::Version("2.2.0".into())
    }

    fn never_looked(_: &str) -> ReleaseLookup {
        panic!("the lookup must not run")
    }

    /// A 404 is "looked, and it is missing", and the refusal names the pin,
    /// the newest published release, and both ways out.
    #[test]
    fn an_unpublished_pin_is_refused_by_name_before_any_download() {
        let err = plan_release(tier2_artifacts::GUEST_RELEASE, |_| {
            classify(Err(ureq::Error::StatusCode(404)), latest_2_2_0)
        })
        .expect_err("a 404 for the pinned tag must refuse");
        assert_eq!(
            err,
            UnservableRelease::NotPublished {
                pinned: tier2_artifacts::GUEST_RELEASE.into(),
                latest: latest_2_2_0(),
            }
        );
        let msg = err.to_string();
        assert!(
            msg.contains(&format!(
                "pins guest release {}, which is not published yet (latest: 2.2.0)",
                tier2_artifacts::GUEST_RELEASE
            )),
            "{msg}"
        );
        assert!(msg.contains("use the released CLI"), "{msg}");
        assert!(msg.contains("--artifacts local"), "{msg}");
    }

    /// A transport failure is "could not look", which is a different refusal
    /// with a different fix: it must not claim the release is missing.
    #[test]
    fn a_failed_lookup_is_not_reported_as_an_unpublished_release() {
        let looked = classify(Err(ureq::Error::ConnectionFailed), || {
            panic!("no latest-release lookup when the first one could not run")
        });
        assert!(
            matches!(looked, ReleaseLookup::CouldNotLook { .. }),
            "{looked:?}"
        );
        let err = plan_release(tier2_artifacts::GUEST_RELEASE, |_| looked)
            .expect_err("could not look must refuse");
        assert!(
            matches!(err, UnservableRelease::CouldNotLook { .. }),
            "{err:?}"
        );
        let msg = err.to_string();
        assert!(!msg.contains("not published"), "{msg}");
        assert!(msg.contains("not a missing release"), "{msg}");
    }

    /// A rate limit is the API declining to answer, not a 404.
    #[test]
    fn a_rate_limited_lookup_could_not_look() {
        for status in [403, 429, 500] {
            let looked = classify(Err(ureq::Error::StatusCode(status)), || {
                panic!("only a 404 asks for the latest release")
            });
            assert!(
                matches!(looked, ReleaseLookup::CouldNotLook { .. }),
                "{status}: {looked:?}"
            );
        }
    }

    /// A body that is not a release is not a release with no assets.
    #[test]
    fn a_body_without_assets_could_not_look() {
        let looked = classify(Ok(serde_json::json!({"message": "?"})), latest_2_2_0);
        assert!(
            matches!(looked, ReleaseLookup::CouldNotLook { .. }),
            "{looked:?}"
        );
    }

    #[test]
    fn a_published_release_yields_its_assets() {
        let body = serde_json::json!({"assets": [{
            "browser_download_url": "https://example.invalid/a",
            "name": "a",
            "digest": format!("sha256:{}", "0".repeat(64)),
        }]});
        let assets = plan_release(tier2_artifacts::GUEST_RELEASE, |_| {
            classify(Ok(body), || {
                panic!("no latest-release lookup when published")
            })
        })
        .expect("published");
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].name, "a");
        assert_eq!(assets[0].digest, "0".repeat(64));
    }

    /// An unknown latest release decorates the refusal; it does not change it.
    #[test]
    fn an_unknown_latest_release_still_refuses_as_unpublished() {
        let err = plan_release(tier2_artifacts::GUEST_RELEASE, |_| {
            classify(Err(ureq::Error::StatusCode(404)), || {
                latest_from(Err(ureq::Error::ConnectionFailed))
            })
        })
        .expect_err("still unpublished");
        assert!(
            matches!(err, UnservableRelease::NotPublished { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("latest: unknown"), "{err}");
    }

    #[test]
    fn the_latest_release_drops_its_v() {
        assert_eq!(
            latest_from(Ok(serde_json::json!({"tag_name": "v2.2.0"}))),
            latest_2_2_0()
        );
    }

    /// A guest this build cannot serve is refused before the API is asked.
    #[test]
    fn a_skewed_release_is_refused_without_a_lookup() {
        let err = plan_release("2.2.0", never_looked).expect_err("2.2.0 predates #2365");
        assert!(matches!(err, UnservableRelease::Skew(_)), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains("#2365") && msg.contains("#2379"), "{msg}");
    }
}
