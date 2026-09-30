//! Registry references: `registry/repository@sha256:…` to import, `registry/repository:tag`
//! to resolve.
//!
//! The spelling rules are #3078's (`nucleus_spec::OciReference`): the registry host is
//! always written out, short names are refused rather than expanded, and Docker Hub has
//! exactly one spelling, `docker.io/library/<name>`. That parser is not on this branch's
//! base; when it lands, [`ImageName`] folds into it (G-1: one decider per spelling).
//!
//! The digest itself is decided by [`nucleus_oci_rootfs::PinnedReference`]: this module
//! splits a reference, it never re-parses a digest.

use nucleus_oci_rootfs::{PinnedReference, Sha256Digest};

/// Registry hosts that are other names for `docker.io`. Refused, so one registry has one spelling.
const DOCKER_HUB_ALIASES: &[&str] = &[
    "index.docker.io",
    "registry-1.docker.io",
    "registry.hub.docker.com",
];

/// Where `docker.io`'s distribution API is actually served.
const DOCKER_HUB_API_HOST: &str = "registry-1.docker.io";

/// The distribution spec's bound on `registry/repository`.
const MAX_NAME_LEN: usize = 255;

/// A registry and a repository in it, spelled the one accepted way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageName {
    registry: String,
    repository: String,
}

/// A reference pinned by digest: what `nucleus image import` fetches.
#[derive(Clone, Debug)]
pub struct PinnedImage {
    pub name: ImageName,
    pub pinned: PinnedReference,
}

/// A reference by tag: what `nucleus image resolve` turns into a digest.
#[derive(Clone, Debug)]
pub struct TaggedImage {
    pub name: ImageName,
    pub tag: String,
}

/// Why a reference was refused.
#[derive(Debug, thiserror::Error)]
pub enum ReferenceError {
    #[error("reference {0:?} contains whitespace or a control character")]
    Whitespace(String),
    #[error(
        "reference {0:?} has no digest; a tag can move, so an import is pinned as \
         `registry/repository@sha256:<hex>` (`nucleus image resolve` prints one)"
    )]
    TagOnly(String),
    #[error(
        "reference {0:?} does not name its registry; short names are expanded differently by \
         different tools, so write the host out (e.g. `docker.io/library/<name>`)"
    )]
    Shorthand(String),
    #[error(
        "reference {reference:?}: single-name repositories on docker.io live under `library/`; \
         write `docker.io/library/{repository}`"
    )]
    DockerHubLibrary {
        reference: String,
        repository: String,
    },
    #[error(
        "reference {reference:?}: {registry:?} is another name for Docker Hub; spell it `docker.io`"
    )]
    DockerHubAlias { reference: String, registry: String },
    #[error(
        "reference {reference:?}: registry {registry:?} must be lowercase DNS labels with an optional port"
    )]
    BadRegistry { reference: String, registry: String },
    #[error(
        "reference {reference:?}: repository component {component:?} must be lowercase \
         alphanumerics joined by `.`, `_`, `__` or `-`"
    )]
    BadComponent {
        reference: String,
        component: String,
    },
    #[error("reference {reference:?}: {tag:?} is not a valid tag")]
    BadTag { reference: String, tag: String },
    #[error("reference {0:?}: `registry/repository` exceeds {MAX_NAME_LEN} characters")]
    TooLong(String),
    #[error("reference {0:?} carries a digest; `resolve` takes `registry/repository:tag`")]
    AlreadyPinned(String),
    #[error("reference {reference:?}: {source}")]
    Digest {
        reference: String,
        #[source]
        source: nucleus_oci_rootfs::ImportError,
    },
}

impl ImageName {
    /// The registry as written (`docker.io`, `registry.example:5000`).
    pub fn registry(&self) -> &str {
        &self.registry
    }

    /// The repository path within the registry.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The `host[:port]` the distribution API is served from.
    pub fn api_host(&self) -> &str {
        if self.registry == "docker.io" {
            DOCKER_HUB_API_HOST
        } else {
            &self.registry
        }
    }

    /// `registry/repository@<digest>`: the one spelling of a pinned reference.
    pub fn pinned(&self, digest: Sha256Digest) -> String {
        format!("{}/{}@{digest}", self.registry, self.repository)
    }

    /// Parse `registry/repository`, with no tag and no digest.
    fn parse(name: &str, reference: &str) -> Result<Self, ReferenceError> {
        let Some((registry, repository)) = name.split_once('/') else {
            return Err(ReferenceError::Shorthand(reference.to_owned()));
        };
        let is_host = registry.contains('.') || registry.contains(':') || registry == "localhost";
        if !is_host {
            return Err(ReferenceError::Shorthand(reference.to_owned()));
        }
        check_registry(registry, reference)?;
        if registry == "docker.io" && !repository.contains('/') {
            return Err(ReferenceError::DockerHubLibrary {
                reference: reference.to_owned(),
                repository: repository.to_owned(),
            });
        }
        for component in repository.split('/') {
            check_component(component, reference)?;
        }
        if registry
            .len()
            .saturating_add(1)
            .saturating_add(repository.len())
            > MAX_NAME_LEN
        {
            return Err(ReferenceError::TooLong(reference.to_owned()));
        }
        Ok(Self {
            registry: registry.to_owned(),
            repository: repository.to_owned(),
        })
    }
}

fn refuse_whitespace(s: &str) -> Result<(), ReferenceError> {
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ReferenceError::Whitespace(s.to_owned()));
    }
    Ok(())
}

/// Split `name[:tag]` at the tag's colon: the last `:` after the last `/`.
fn split_tag(name: &str) -> (&str, Option<&str>) {
    let last_slash = name.rfind('/').unwrap_or(0);
    match name.rfind(':') {
        Some(colon) if colon > last_slash => (
            name.get(..colon).unwrap_or(name),
            name.get(colon.saturating_add(1)..),
        ),
        Some(_) | None => (name, None),
    }
}

impl PinnedImage {
    /// Parse `registry/repository[:tag]@sha256:<hex>`. A tag, if written, is a label only.
    pub fn parse(s: &str) -> Result<Self, ReferenceError> {
        refuse_whitespace(s)?;
        let Some((name, _)) = s.split_once('@') else {
            return Err(ReferenceError::TagOnly(s.to_owned()));
        };
        let pinned = PinnedReference::parse(s).map_err(|source| ReferenceError::Digest {
            reference: s.to_owned(),
            source,
        })?;
        let (name, tag) = split_tag(name);
        if let Some(tag) = tag {
            check_tag(tag, s)?;
        }
        Ok(Self {
            name: ImageName::parse(name, s)?,
            pinned,
        })
    }
}

impl TaggedImage {
    /// Parse `registry/repository:tag`. A digest is refused: it needs no resolving.
    pub fn parse(s: &str) -> Result<Self, ReferenceError> {
        refuse_whitespace(s)?;
        if s.contains('@') {
            return Err(ReferenceError::AlreadyPinned(s.to_owned()));
        }
        let (name, tag) = split_tag(s);
        let Some(tag) = tag else {
            // No implicit `latest`: the tag being resolved is written down.
            return Err(ReferenceError::BadTag {
                reference: s.to_owned(),
                tag: String::new(),
            });
        };
        check_tag(tag, s)?;
        Ok(Self {
            name: ImageName::parse(name, s)?,
            tag: tag.to_owned(),
        })
    }
}

fn check_registry(registry: &str, reference: &str) -> Result<(), ReferenceError> {
    if DOCKER_HUB_ALIASES.contains(&registry) {
        return Err(ReferenceError::DockerHubAlias {
            reference: reference.to_owned(),
            registry: registry.to_owned(),
        });
    }
    let bad = || ReferenceError::BadRegistry {
        reference: reference.to_owned(),
        registry: registry.to_owned(),
    };
    let (host, port) = match registry.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (registry, None),
    };
    let label_ok = |l: &str| {
        !l.is_empty()
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !host.split('.').all(label_ok) {
        return Err(bad());
    }
    if let Some(port) = port {
        let ok = !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|p| p != 0);
        if !ok {
            return Err(bad());
        }
    }
    Ok(())
}

/// A repository path component: `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`.
fn check_component(c: &str, reference: &str) -> Result<(), ReferenceError> {
    let bad = || ReferenceError::BadComponent {
        reference: reference.to_owned(),
        component: c.to_owned(),
    };
    let bytes = c.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) else {
        return Err(bad());
    };
    if !alnum(first) || !alnum(last) {
        return Err(bad());
    }
    let mut rest = bytes;
    while let Some((&b, tail)) = rest.split_first() {
        if alnum(b) {
            rest = tail;
            continue;
        }
        // A separator run: `.`, `_`, `__`, or any number of `-`.
        let run = rest.iter().take_while(|&&x| x == b).count();
        let ok = match b {
            b'.' => run == 1,
            b'_' => run <= 2,
            b'-' => true,
            _ => false,
        };
        if !ok {
            return Err(bad());
        }
        rest = rest.get(run..).unwrap_or_default();
    }
    Ok(())
}

/// A tag: `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
fn check_tag(tag: &str, reference: &str) -> Result<(), ReferenceError> {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let ok = tag.len() <= 128
        && tag.as_bytes().first().is_some_and(|&b| word(b))
        && tag.bytes().all(|b| word(b) || b == b'.' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(ReferenceError::BadTag {
            reference: reference.to_owned(),
            tag: tag.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn pinned_references_parse() {
        for (r, registry, repository, api) in [
            (
                format!("registry.example/app@{D}"),
                "registry.example",
                "app",
                "registry.example",
            ),
            (
                format!("registry.example:5000/a/b:1.2@{D}"),
                "registry.example:5000",
                "a/b",
                "registry.example:5000",
            ),
            (
                format!("localhost:5000/app@{D}"),
                "localhost:5000",
                "app",
                "localhost:5000",
            ),
            (
                format!("docker.io/library/busybox@{D}"),
                "docker.io",
                "library/busybox",
                "registry-1.docker.io",
            ),
        ] {
            let p = PinnedImage::parse(&r).unwrap_or_else(|e| panic!("{r}: {e}"));
            assert_eq!(p.name.registry(), registry);
            assert_eq!(p.name.repository(), repository);
            assert_eq!(p.name.api_host(), api);
            assert_eq!(p.pinned.digest().to_string(), D);
        }
    }

    #[test]
    fn tag_only_and_shorthand_are_refused() {
        assert!(matches!(
            PinnedImage::parse("registry.example/app:v1"),
            Err(ReferenceError::TagOnly(_))
        ));
        for r in [
            format!("busybox@{D}"),
            format!("library/busybox@{D}"),
            format!("team/app@{D}"),
        ] {
            assert!(
                matches!(PinnedImage::parse(&r), Err(ReferenceError::Shorthand(_))),
                "{r}"
            );
        }
        assert!(matches!(
            PinnedImage::parse(&format!("docker.io/busybox@{D}")),
            Err(ReferenceError::DockerHubLibrary { .. })
        ));
        for alias in DOCKER_HUB_ALIASES {
            assert!(matches!(
                PinnedImage::parse(&format!("{alias}/library/busybox@{D}")),
                Err(ReferenceError::DockerHubAlias { .. })
            ));
        }
        for bad in [
            format!("Registry.example/app@{D}"),
            format!("registry.example/App@{D}"),
            format!("registry.example/a..b@{D}"),
            format!("registry.example:0/app@{D}"),
            format!("registry.example/app @{D}"),
            "registry.example/app@sha256:abc".to_owned(),
        ] {
            assert!(
                PinnedImage::parse(&bad).is_err(),
                "must be refused: {bad:?}"
            );
        }
    }

    #[test]
    fn tagged_references_parse_and_digests_are_refused() {
        let t = TaggedImage::parse("registry.example:5000/team/app:v1.2").unwrap();
        assert_eq!(t.name.registry(), "registry.example:5000");
        assert_eq!(t.name.repository(), "team/app");
        assert_eq!(t.tag, "v1.2");
        assert!(matches!(
            TaggedImage::parse("registry.example:5000/team/app"),
            Err(ReferenceError::BadTag { .. })
        ));
        assert!(matches!(
            TaggedImage::parse(&format!("registry.example/app@{D}")),
            Err(ReferenceError::AlreadyPinned(_))
        ));
        assert!(matches!(
            TaggedImage::parse("busybox:1.36"),
            Err(ReferenceError::Shorthand(_))
        ));
    }
}
