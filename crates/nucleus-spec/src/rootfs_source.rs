//! Where a pod's root filesystem comes from: a file on the node, or an OCI image (2026-09-29).
//!
//! # Why an enum and not a second optional field
//!
//! Until now `ImageSpec` named its rootfs with one required `rootfs_path`. Adding OCI as a sibling
//! `Option` would make four states out of two — path, OCI, BOTH, and NEITHER — and every consumer
//! would have to decide what the last two mean. That is A-family territory (ADR 0007): a sum
//! type with a lost case, spelled as two options. So the in-memory type is [`RootfsSource`], with
//! exactly the two cases there are, and the two-options shape exists only on the WIRE, in
//! [`ImageSpecWire`], whose one job is to refuse both-and-neither at parse time.
//!
//! The wire keeps `rootfs_path` spelled exactly as before, and serializes with the new key
//! skipped when absent, so every existing spec parses unchanged and re-serializes to the same
//! bytes (pinned by `an_existing_path_spec_serializes_byte_identically`). Anything that hashed a
//! serialized spec before this change hashes the same bytes after it.
//!
//! # Why the reference must carry a digest
//!
//! A tag is a mutable name: `registry.example/app:v1` is whatever the registry says today. The
//! rest of `ImageSpec` names artifacts by content (`ArtifactDigest`), and an OCI source that
//! named them by a movable label would be the one hole in that. So a reference without
//! `@sha256:…` is refused, and a reference WITH a tag keeps the tag only as a label for humans —
//! the digest is authoritative, and nothing reads the tag to decide what to fetch.
//!
//! # Why short names are refused rather than normalized
//!
//! Container tooling expands `ubuntu` to `docker.io/library/ubuntu`, and treats
//! `index.docker.io` and `docker.io` as one registry. Copying that expansion would put a second
//! decider for "which registry is meant" into this crate, one that has to agree with every other
//! tool's forever (G). Refusing is reversible — a later change can accept a shorthand — and
//! accepting is not. So a reference must name its registry host, and must name it in the one
//! spelling this crate compares: `docker.io/library/ubuntu@sha256:…`, never `ubuntu@…`,
//! `library/ubuntu@…`, `docker.io/ubuntu@…` or `index.docker.io/library/ubuntu@…`. Equal
//! references are then equal strings, the same reason `ArtifactDigest` refuses uppercase hex.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ArtifactDigest, ImageSpec};

/// The root filesystem a pod boots, by kind of source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootfsSource {
    /// A filesystem image already on the node. Wire key: `rootfs_path`.
    Path(PathBuf),
    /// A filesystem image published as an OCI artifact. Wire key: `rootfs_oci`.
    ///
    /// A node needs an image store to turn this into a file it can boot. Until one exists
    /// a node refuses the pod at create rather than guessing a path for it.
    Oci(OciRootfs),
}

/// An OCI-published root filesystem, named by content at every step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciRootfs {
    /// Where to fetch it: `registry/repository[:tag]@sha256:…`. The digest is required and is
    /// what gets fetched; it may name an image index rather than a single manifest.
    pub reference: OciReference,
    /// The image manifest the guest filesystem is taken from. Differs from the reference's
    /// digest when the reference names an index (one manifest per platform).
    pub manifest_digest: OciDigest,
    /// The layer, within that manifest, that carries the guest filesystem image — in this
    /// crate's own `sha-256:` spelling, because it is the artifact the node will hold.
    pub guest_layer_digest: ArtifactDigest,
}

/// An OCI content digest, written `sha256:<64 lowercase hex>`.
///
/// A distinct type from [`ArtifactDigest`] on purpose. The two spell the same algorithm
/// differently (`sha256:` is the OCI image-spec spelling, `sha-256:` this crate's), and a value
/// copied from a registry into an artifact pin — or back — must be a type error rather than a
/// string that parses as the wrong thing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct OciDigest(String);

impl OciDigest {
    /// The `sha256:…` form, as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The 64 hex characters, without the algorithm prefix.
    pub fn hex(&self) -> &str {
        self.0.split_once(':').map_or("", |(_, h)| h)
    }

    /// Parse and validate. The only accepted algorithm today is `sha256`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let Some((alg, hex)) = s.split_once(':') else {
            return Err(format!("OCI digest must be `sha256:<hex>`, got {s:?}"));
        };
        if alg != "sha256" {
            return Err(format!(
                "unsupported OCI digest algorithm {alg:?} (only `sha256` is understood)"
            ));
        }
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "sha256 digest must be 64 hex characters, got {} in {s:?}",
                hex.len()
            ));
        }
        if hex.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(format!(
                "digest hex must be lowercase so equal digests compare equal: {s:?}"
            ));
        }
        Ok(Self(s.to_string()))
    }
}

impl<'de> Deserialize<'de> for OciDigest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// A digest-pinned OCI reference: `registry/repository[:tag]@sha256:<hex>`.
///
/// Parsed once, at deserialize, so an ill-formed reference is a rejected spec rather than a
/// fetch that fails later on some other machine. See the module docs for why the digest is
/// required and why the registry must be written out.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OciReference {
    registry: String,
    repository: String,
    tag: Option<String>,
    digest: OciDigest,
}

/// Registry hosts that are other names for `docker.io`. Refused, so one registry has one spelling.
const DOCKER_HUB_ALIASES: &[&str] = &[
    "index.docker.io",
    "registry-1.docker.io",
    "registry.hub.docker.com",
];

/// The distribution spec's bound on `registry/repository`.
const MAX_NAME_LEN: usize = 255;

impl OciReference {
    /// The registry host, with port if one was written.
    pub fn registry(&self) -> &str {
        &self.registry
    }

    /// The repository path within the registry.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The tag, if one was written. A label only: [`Self::digest`] decides what is fetched.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// The digest that decides what is fetched.
    pub fn digest(&self) -> &OciDigest {
        &self.digest
    }

    /// Parse and validate. See the module docs for what is refused and why.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(c) = s.chars().find(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!(
                "OCI reference contains {c:?}; whitespace and control characters are never part \
                 of one: {s:?}"
            ));
        }
        let Some((name, digest)) = s.split_once('@') else {
            return Err(format!(
                "OCI reference {s:?} has no digest; a tag is a mutable name, so a rootfs must be \
                 pinned as `registry/repository[:tag]@sha256:<hex>`"
            ));
        };
        let digest = OciDigest::parse(digest)?;
        let Some((registry, rest)) = name.split_once('/') else {
            return Err(shorthand(s));
        };
        let is_host = registry.contains('.') || registry.contains(':') || registry == "localhost";
        if !is_host {
            return Err(shorthand(s));
        }
        check_registry(registry, s)?;
        let (repository, tag) = match rest.rsplit_once(':') {
            Some((repo, tag)) => (repo, Some(tag)),
            None => (rest, None),
        };
        if registry == "docker.io" && !repository.contains('/') {
            return Err(format!(
                "OCI reference {s:?}: single-name repositories on docker.io live under \
                 `library/`; write `docker.io/library/{repository}` so the reference has one \
                 spelling"
            ));
        }
        for component in repository.split('/') {
            check_component(component, s)?;
        }
        if let Some(tag) = tag {
            check_tag(tag, s)?;
        }
        if registry.len() + 1 + repository.len() > MAX_NAME_LEN {
            return Err(format!(
                "OCI reference {s:?}: `registry/repository` exceeds {MAX_NAME_LEN} characters"
            ));
        }
        Ok(Self {
            registry: registry.to_string(),
            repository: repository.to_string(),
            tag: tag.map(str::to_string),
            digest,
        })
    }
}

fn shorthand(s: &str) -> String {
    format!(
        "OCI reference {s:?} does not name its registry; short names are expanded differently \
         by different tools, so write the host out (e.g. `docker.io/library/<name>@sha256:…`)"
    )
}

fn check_registry(registry: &str, s: &str) -> Result<(), String> {
    if DOCKER_HUB_ALIASES.contains(&registry) {
        return Err(format!(
            "OCI reference {s:?}: {registry:?} is another name for Docker Hub; spell it \
             `docker.io` so one registry has one spelling"
        ));
    }
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
        return Err(format!(
            "OCI reference {s:?}: registry host {host:?} must be lowercase DNS labels"
        ));
    }
    if let Some(port) = port {
        let ok = !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|p| p != 0);
        if !ok {
            return Err(format!(
                "OCI reference {s:?}: registry port {port:?} is not a port number"
            ));
        }
    }
    Ok(())
}

/// A repository path component: `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`.
fn check_component(c: &str, s: &str) -> Result<(), String> {
    let bad = || {
        format!(
            "OCI reference {s:?}: repository component {c:?} must be lowercase alphanumerics \
             joined by `.`, `_`, `__` or `-`"
        )
    };
    let bytes = c.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) else {
        return Err(bad());
    };
    if !alnum(first) || !alnum(last) {
        return Err(bad());
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if alnum(b) {
            i += 1;
            continue;
        }
        // A separator run: `.`, `_`, `__`, or any number of `-`.
        let run = bytes[i..].iter().take_while(|&&x| x == b).count();
        let ok = match b {
            b'.' => run == 1,
            b'_' => run <= 2,
            b'-' => true,
            _ => false,
        };
        if !ok {
            return Err(bad());
        }
        i += run;
    }
    Ok(())
}

/// A tag: `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
fn check_tag(tag: &str, s: &str) -> Result<(), String> {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let ok = tag.len() <= 128
        && tag.as_bytes().first().is_some_and(|&b| word(b))
        && tag.bytes().all(|b| word(b) || b == b'.' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!("OCI reference {s:?}: {tag:?} is not a valid tag"))
    }
}

impl fmt::Display for OciReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(tag) = &self.tag {
            write!(f, ":{tag}")?;
        }
        write!(f, "@{}", self.digest.as_str())
    }
}

impl Serialize for OciReference {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for OciReference {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// `ImageSpec` as written on the wire. Private in effect: nothing outside this module builds one.
///
/// Field ORDER is load-bearing: it is the order the pre-enum `ImageSpec` serialized in, with
/// `rootfs_oci` in the slot next to `rootfs_path` and both skipped when absent. That is what
/// keeps an existing spec's bytes identical.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSpecWire {
    kernel_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rootfs_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rootfs_oci: Option<OciRootfs>,
    #[serde(default)]
    boot_args: Option<String>,
    // `#[serde(default)]` on a bool is `false`, the unsafe value (#2784); see `ImageSpec::read_only`.
    #[serde(default = "crate::default_read_only")]
    read_only: bool,
    #[serde(default)]
    scratch_path: Option<PathBuf>,
    #[serde(default)]
    kernel_digest: Option<ArtifactDigest>,
    #[serde(default)]
    rootfs_digest: Option<ArtifactDigest>,
    #[serde(default)]
    scratch_digest: Option<ArtifactDigest>,
    #[serde(default)]
    data_path: Option<PathBuf>,
    #[serde(default)]
    data_digest: Option<ArtifactDigest>,
}

impl TryFrom<ImageSpecWire> for ImageSpec {
    type Error = String;

    fn try_from(w: ImageSpecWire) -> Result<Self, String> {
        // EXHAUSTIVE (E): a field added to the wire and not here is a compile error.
        let ImageSpecWire {
            kernel_path,
            rootfs_path,
            rootfs_oci,
            boot_args,
            read_only,
            scratch_path,
            kernel_digest,
            rootfs_digest,
            scratch_digest,
            data_path,
            data_digest,
        } = w;
        let rootfs = match (rootfs_path, rootfs_oci) {
            (Some(path), None) => RootfsSource::Path(path),
            (None, Some(oci)) => {
                // B-2: an absent pin is not a pass. A path rootfs may stay unpinned for the specs
                // written before pins existed; an OCI rootfs is new, so it starts pinned.
                if rootfs_digest.is_none() {
                    return Err(
                        "image.rootfs_oci requires image.rootfs_digest: the bytes that \
                                boot must be pinned, not only the layer they came from"
                            .to_string(),
                    );
                }
                // #2784: an imported artifact is shared by every pod that names it, so a
                // writable one would carry one pod's writes into the next.
                if !read_only {
                    return Err("image.rootfs_oci cannot be read_only: false — an imported \
                                rootfs is shared between pods; give the pod a scratch_path \
                                for writable storage"
                        .to_string());
                }
                RootfsSource::Oci(oci)
            }
            (Some(_), Some(_)) => {
                return Err(
                    "image names both rootfs_path and rootfs_oci; exactly one is allowed"
                        .to_string(),
                );
            }
            (None, None) => {
                return Err(
                    "image names no root filesystem: set rootfs_path or rootfs_oci".to_string(),
                );
            }
        };
        Ok(ImageSpec {
            kernel_path,
            rootfs,
            boot_args,
            read_only,
            scratch_path,
            kernel_digest,
            rootfs_digest,
            scratch_digest,
            data_path,
            data_digest,
        })
    }
}

impl From<ImageSpec> for ImageSpecWire {
    fn from(image: ImageSpec) -> Self {
        let ImageSpec {
            kernel_path,
            rootfs,
            boot_args,
            read_only,
            scratch_path,
            kernel_digest,
            rootfs_digest,
            scratch_digest,
            data_path,
            data_digest,
        } = image;
        let (rootfs_path, rootfs_oci) = match rootfs {
            RootfsSource::Path(p) => (Some(p), None),
            RootfsSource::Oci(o) => (None, Some(o)),
        };
        Self {
            kernel_path,
            rootfs_path,
            rootfs_oci,
            boot_args,
            read_only,
            scratch_path,
            kernel_digest,
            rootfs_digest,
            scratch_digest,
            data_path,
            data_digest,
        }
    }
}

#[cfg(test)]
#[path = "rootfs_source_tests.rs"]
mod tests;
