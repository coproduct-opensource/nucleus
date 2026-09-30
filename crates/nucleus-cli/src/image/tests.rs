//! `nucleus image` against an in-process fake registry.
//!
//! The fake is an axum server on 127.0.0.1 serving manifests and blobs built in
//! the test. A second server on another port plays blob storage, so a redirect
//! crosses an origin the way a registry's redirect to object storage does.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest as _, Sha256};

use nucleus_oci_rootfs::{ImportError, ImportLimits, PinnedReference, Sha256Digest};

use super::auth::{self, Credential, CredentialLookup, Secret};
use super::cache::ImageCache;
use super::reference::{PinnedImage, ReferenceError, TaggedImage};
use super::registry::{Endpoint, FetchLimits, RegistryClient, RegistryError};
use super::{ImportPlan, Source, run_import};

const TOKEN: &str = "test-token-123";
const USER: &str = "builder";
const PASS: &str = "test-password";
const REPO: &str = "team/app";

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

// ── an image, built in-test ─────────────────────────────────────────────────

struct Image {
    /// Every blob and manifest, by digest.
    blobs: BTreeMap<String, Vec<u8>>,
    /// Digest → media type, for the manifests and the index.
    manifests: BTreeMap<String, String>,
    /// The pinned digest: an index over amd64 + arm64.
    index: String,
    /// The amd64 manifest.
    manifest: String,
    /// The amd64 layer.
    layer: String,
}

fn layer_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (path, body) in files {
        let mut h = tar::Header::new_ustar();
        h.set_path(path).unwrap();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_uid(1000);
        h.set_gid(1000);
        h.set_mtime(1_700_000_000);
        h.set_cksum();
        b.append(&h, *body).unwrap();
    }
    b.into_inner().unwrap()
}

fn build_image() -> Image {
    let mut blobs = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    let mut platform_manifest = |arch: &str, payload: &[u8]| -> (String, String, usize) {
        let layer = layer_tar(&[("srv/app/data", payload), ("etc/motd", b"hi\n")]);
        let layer_digest = sha(&layer);
        let config = serde_json::to_vec(&serde_json::json!({
            "architecture": arch,
            "os": "linux",
            "config": { "User": "1000:1000", "Cmd": ["/srv/app/run"] },
            "rootfs": { "type": "layers", "diff_ids": [layer_digest] },
        }))
        .unwrap();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": sha(&config),
                "size": config.len(),
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": layer.len(),
            }],
        }))
        .unwrap();
        let digest = sha(&manifest);
        let len = manifest.len();
        blobs.insert(sha(&config), config);
        blobs.insert(layer_digest.clone(), layer);
        blobs.insert(digest.clone(), manifest);
        (digest, layer_digest, len)
    };
    let (amd, amd_layer, amd_len) = platform_manifest("amd64", b"amd64 payload");
    let (arm, _, arm_len) = platform_manifest("arm64", b"arm64 payload");
    let index = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": amd, "size": amd_len,
                "platform": { "architecture": "amd64", "os": "linux" },
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": arm, "size": arm_len,
                "platform": { "architecture": "arm64", "os": "linux", "variant": "v8" },
            },
        ],
    }))
    .unwrap();
    let index_digest = sha(&index);
    manifests.insert(
        amd.clone(),
        "application/vnd.oci.image.manifest.v1+json".to_owned(),
    );
    manifests.insert(arm, "application/vnd.oci.image.manifest.v1+json".to_owned());
    manifests.insert(
        index_digest.clone(),
        "application/vnd.oci.image.index.v1+json".to_owned(),
    );
    blobs.insert(index_digest.clone(), index);
    Image {
        blobs,
        manifests,
        index: index_digest,
        manifest: amd,
        layer: amd_layer,
    }
}

/// Write `image` as an OCI layout directory whose `index.json` names the pinned index.
fn write_layout(image: &Image, dir: &Path) {
    std::fs::create_dir_all(dir.join("blobs/sha256")).unwrap();
    std::fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
    for (digest, bytes) in &image.blobs {
        let hex = digest.strip_prefix("sha256:").unwrap();
        std::fs::write(dir.join("blobs/sha256").join(hex), bytes).unwrap();
    }
    let index = &image.blobs[&image.index];
    std::fs::write(
        dir.join("index.json"),
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": image.index,
                "size": index.len(),
            }],
        }))
        .unwrap(),
    )
    .unwrap();
}

// ── the fake registry ───────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    Anonymous,
    /// 401 with a Bearer challenge; the realm wants Basic `USER:PASS`.
    Bearer,
}

/// One request the fake saw: its path and its Authorization header.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    authorization: Option<String>,
}

struct Fake {
    blobs: BTreeMap<String, Vec<u8>>,
    manifests: BTreeMap<String, String>,
    tags: BTreeMap<String, String>,
    auth: AuthMode,
    /// Redirect `/blobs/` to this base URL (another origin).
    redirect_blobs_to: Option<String>,
    /// Serve these digests with their bytes altered.
    corrupt: Vec<String>,
    /// Send a Docker-Content-Digest that is not the body's.
    lie_about_digest: bool,
    addr: Mutex<Option<SocketAddr>>,
    seen: Mutex<Vec<Seen>>,
}

impl Fake {
    fn new(image: &Image) -> Self {
        Self {
            blobs: image.blobs.clone(),
            manifests: image.manifests.clone(),
            tags: BTreeMap::from([("v1".to_owned(), image.index.clone())]),
            auth: AuthMode::Anonymous,
            redirect_blobs_to: None,
            corrupt: Vec::new(),
            lie_about_digest: false,
            addr: Mutex::new(None),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn body(&self, digest: &str) -> Option<Vec<u8>> {
        let mut bytes = self.blobs.get(digest)?.clone();
        if self.corrupt.iter().any(|d| d == digest) {
            if let Some(last) = bytes.last_mut() {
                *last ^= 0xff;
            }
        }
        Some(bytes)
    }
}

fn authorization(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

async fn handle(State(fake): State<Arc<Fake>>, req: Request) -> Response {
    let path = req.uri().path().to_owned();
    let authz = authorization(req.headers());
    fake.seen.lock().unwrap().push(Seen {
        path: path.clone(),
        authorization: authz.clone(),
    });
    let addr = fake.addr.lock().unwrap().unwrap();

    if path == "/token" {
        let expected = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASS}")));
        if authz.as_deref() != Some(expected.as_str()) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        return axum::Json(serde_json::json!({ "token": TOKEN })).into_response();
    }
    if let Some(digest) = path.strip_prefix("/storage/") {
        return match fake.body(digest) {
            Some(b) => b.into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let Some(rest) = path.strip_prefix(&format!("/v2/{REPO}/")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if fake.auth == AuthMode::Bearer && authz.as_deref() != Some(format!("Bearer {TOKEN}").as_str())
    {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                header::WWW_AUTHENTICATE,
                format!(
                    r#"Bearer realm="http://{addr}/token",service="fake-registry",scope="repository:{REPO}:pull""#
                ),
            )
            .body(Body::empty())
            .unwrap();
    }
    if let Some(reference) = rest.strip_prefix("manifests/") {
        let digest = fake
            .tags
            .get(reference)
            .cloned()
            .unwrap_or_else(|| reference.to_owned());
        let (Some(media_type), Some(body)) = (fake.manifests.get(&digest), fake.body(&digest))
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let header_digest = if fake.lie_about_digest {
            sha(b"something else")
        } else {
            digest.clone()
        };
        return Response::builder()
            .header(header::CONTENT_TYPE, media_type)
            .header("docker-content-digest", header_digest)
            .body(Body::from(body))
            .unwrap();
    }
    if let Some(digest) = rest.strip_prefix("blobs/") {
        if let Some(base) = &fake.redirect_blobs_to {
            return Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(header::LOCATION, format!("{base}/storage/{digest}"))
                .body(Body::empty())
                .unwrap();
        }
        return match fake.body(digest) {
            Some(b) => b.into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    StatusCode::NOT_FOUND.into_response()
}

/// Serve `fake` on 127.0.0.1 from a background runtime; returns `host:port`.
fn serve(fake: Arc<Fake>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    *fake.addr.lock().unwrap() = Some(addr);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let app = axum::Router::new().fallback(handle).with_state(fake);
            axum::serve(listener, app).await.unwrap();
        });
    });
    addr.to_string()
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn plan(cache: &Path, insecure: &[String], credentials: CredentialLookup) -> ImportPlan {
    ImportPlan {
        cache: ImageCache::open(cache).unwrap(),
        arch: nucleus_oci_rootfs::Arch::Amd64,
        limits: ImportLimits::standard(),
        insecure: insecure.to_vec(),
        credentials,
    }
}

fn basic() -> CredentialLookup {
    CredentialLookup::Found(Credential::Basic {
        username: USER.to_owned(),
        password: Secret::new(PASS),
    })
}

fn pinned(host: &str, digest: &str) -> PinnedImage {
    PinnedImage::parse(&format!("{host}/{REPO}@{digest}")).unwrap()
}

/// The registry error inside an import failure, if that is what it was.
fn registry_error(err: &anyhow::Error) -> Option<&RegistryError> {
    if let Some(r) = err.downcast_ref::<RegistryError>() {
        return Some(r);
    }
    match err.downcast_ref::<ImportError>()? {
        ImportError::Source { source, .. } => source.downcast_ref::<RegistryError>(),
        _ => None,
    }
}

fn digest(s: &str) -> Sha256Digest {
    Sha256Digest::parse(s).unwrap()
}

// ── tests ───────────────────────────────────────────────────────────────────

/// One decider for the rootfs bytes: a registry and a layout of the same image
/// flatten to the same tar, byte for byte, with the same record.
#[test]
fn registry_import_equals_layout_import() {
    crypto();
    let image = build_image();
    let fake = Arc::new(Fake::new(&image));
    let host = serve(fake.clone());

    let dir = tempfile::tempdir().unwrap();
    let via_registry = run_import(
        Source::Registry(pinned(&host, &image.index)),
        &plan(
            &dir.path().join("a"),
            std::slice::from_ref(&host),
            CredentialLookup::None,
        ),
    )
    .unwrap();

    let layout = dir.path().join("layout");
    write_layout(&image, &layout);
    let via_layout = run_import(
        Source::Layout(layout, PinnedReference::parse(&image.index).unwrap()),
        &plan(&dir.path().join("b"), &[], CredentialLookup::None),
    )
    .unwrap();

    assert_eq!(
        via_registry.record.rootfs.digest,
        via_layout.record.rootfs.digest
    );
    assert_eq!(
        std::fs::read(via_registry.tar()).unwrap(),
        std::fs::read(via_layout.tar()).unwrap()
    );
    assert_eq!(via_registry.record, via_layout.record);
    // Non-vacuity: the platform was selected from the index, and the tar is not empty.
    assert_eq!(via_registry.record.index_digest, Some(digest(&image.index)));
    assert_eq!(via_registry.record.manifest_digest, digest(&image.manifest));
    assert!(via_registry.record.rootfs.bytes > 0);
    // Filed under its own digest, with the record beside it.
    assert!(
        via_registry
            .dir
            .ends_with(via_registry.record.rootfs.digest.hex())
    );
    let record: nucleus_oci_rootfs::ImportRecord =
        serde_json::from_slice(&std::fs::read(via_registry.dir.join("import.json")).unwrap())
            .unwrap();
    assert_eq!(record, via_registry.record);
    // Only the amd64 side of the index was fetched.
    let paths: Vec<String> = fake.seen().into_iter().map(|s| s.path).collect();
    assert!(paths.iter().any(|p| p.ends_with(&image.layer)));
    assert_eq!(
        paths.iter().filter(|p| p.contains("/blobs/")).count(),
        2,
        "config + one layer: {paths:?}"
    );

    // A second import is served from the cache: no new request.
    let before = fake.seen().len();
    run_import(
        Source::Registry(pinned(&host, &image.index)),
        &plan(&dir.path().join("a"), &[host], CredentialLookup::None),
    )
    .unwrap();
    assert_eq!(fake.seen().len(), before);
}

/// A blob whose bytes do not hash to its digest is refused while streaming, and
/// nothing is left in the cache (red-first: remove the digest comparison in
/// `stream_verified` and this reds, because the blob lands in the cache).
#[test]
fn wrong_digest_blob_is_refused_and_not_cached() {
    crypto();
    let image = build_image();
    let mut fake = Fake::new(&image);
    fake.corrupt.push(image.layer.clone());
    let fake = Arc::new(fake);
    let host = serve(fake);
    let dir = tempfile::tempdir().unwrap();
    let plan = plan(
        dir.path(),
        std::slice::from_ref(&host),
        CredentialLookup::None,
    );

    let err = run_import(Source::Registry(pinned(&host, &image.index)), &plan).unwrap_err();
    assert!(
        matches!(
            registry_error(&err),
            Some(RegistryError::DigestMismatch { expected, .. }) if *expected == digest(&image.layer)
        ),
        "{err:#}"
    );
    assert!(plan.cache.blob(digest(&image.layer)).is_none());
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0,
        "no partial download left behind"
    );
    // The verified blobs before it were kept.
    assert!(plan.cache.blob(digest(&image.manifest)).is_some());
}

/// A pinned manifest with the wrong bytes is refused before anything reads it.
#[test]
fn wrong_digest_manifest_is_refused() {
    crypto();
    let image = build_image();
    let mut fake = Fake::new(&image);
    fake.corrupt.push(image.index.clone());
    let host = serve(Arc::new(fake));
    let dir = tempfile::tempdir().unwrap();
    let client = RegistryClient::new(
        pinned(&host, &image.index).name,
        &[host],
        CredentialLookup::None,
        FetchLimits::from_import(&ImportLimits::standard()),
    )
    .unwrap();
    let cache = ImageCache::open(dir.path()).unwrap();
    let err = client
        .fetch(Endpoint::Manifest, digest(&image.index), &cache)
        .unwrap_err();
    assert!(matches!(err, RegistryError::DigestMismatch { .. }), "{err}");
    assert!(cache.blob(digest(&image.index)).is_none());
}

/// Bearer flow: 401 + challenge → token from the realm with Basic credentials read
/// from a docker config.json → every retried request carries the token.
#[test]
fn bearer_token_flow_with_docker_config_credentials() {
    crypto();
    let image = build_image();
    let mut fake = Fake::new(&image);
    fake.auth = AuthMode::Bearer;
    let fake = Arc::new(fake);
    let host = serve(fake.clone());
    let dir = tempfile::tempdir().unwrap();

    let config = dir.path().join("config.json");
    let encoded = STANDARD.encode(format!("{USER}:{PASS}"));
    std::fs::write(
        &config,
        format!(r#"{{"auths":{{"{host}":{{"auth":"{encoded}"}}}}}}"#),
    )
    .unwrap();
    let credentials = auth::lookup(&host, &|_| None, Some(&config)).unwrap();
    assert_eq!(credentials, basic());

    let staged = run_import(
        Source::Registry(pinned(&host, &image.index)),
        &plan(
            &dir.path().join("cache"),
            std::slice::from_ref(&host),
            credentials,
        ),
    )
    .unwrap();
    assert!(staged.record.rootfs.bytes > 0);

    let seen = fake.seen();
    let tokens = seen.iter().filter(|s| s.path == "/token").count();
    assert_eq!(tokens, 1, "one token for the whole import: {seen:?}");
    let v2: Vec<&Seen> = seen.iter().filter(|s| s.path.starts_with("/v2/")).collect();
    assert_eq!(v2.first().and_then(|s| s.authorization.clone()), None);
    assert!(
        v2.iter()
            .skip(1)
            .all(|s| s.authorization.as_deref() == Some(format!("Bearer {TOKEN}").as_str())),
        "{v2:?}"
    );
}

/// Without credentials, a registry that demands them is refused by name, and a
/// configured-but-unrun credential helper is named in the refusal.
#[test]
fn missing_credentials_are_named() {
    crypto();
    let image = build_image();
    let mut fake = Fake::new(&image);
    fake.auth = AuthMode::Bearer;
    let host = serve(Arc::new(fake));
    let dir = tempfile::tempdir().unwrap();

    // Anonymous against the realm: the realm refuses.
    let err = run_import(
        Source::Registry(pinned(&host, &image.index)),
        &plan(
            dir.path(),
            std::slice::from_ref(&host),
            CredentialLookup::None,
        ),
    )
    .unwrap_err();
    assert!(
        matches!(
            registry_error(&err),
            Some(RegistryError::Unauthorized { .. })
        ),
        "{err:#}"
    );
    // A Basic challenge with only a helper configured: the helper is named.
    let client = RegistryClient::new(
        pinned(&host, &image.index).name,
        &[host],
        CredentialLookup::HelperNotRun {
            helper: "example-helper".into(),
        },
        FetchLimits::from_import(&ImportLimits::standard()),
    )
    .unwrap();
    let url = reqwest::Url::parse("http://127.0.0.1:1/v2/").unwrap();
    let err = client.answer(&url, r#"Basic realm="r""#).unwrap_err();
    assert!(
        matches!(&err, RegistryError::NoCredentials { helper: Some(h), .. } if h == "example-helper"),
        "{err}"
    );
}

/// A blob redirected to storage on another origin gets NO Authorization header,
/// while the registry's own requests do (red-first: make `authorizes` return true
/// and the storage server sees the bearer token).
#[test]
fn redirect_to_another_origin_carries_no_authorization() {
    crypto();
    let image = build_image();
    let storage = Arc::new(Fake::new(&image));
    let storage_host = serve(storage.clone());
    let mut fake = Fake::new(&image);
    fake.auth = AuthMode::Bearer;
    fake.redirect_blobs_to = Some(format!("http://{storage_host}"));
    let fake = Arc::new(fake);
    let host = serve(fake.clone());
    let dir = tempfile::tempdir().unwrap();

    run_import(
        Source::Registry(pinned(&host, &image.index)),
        &plan(dir.path(), &[host.clone(), storage_host.clone()], basic()),
    )
    .unwrap();

    let at_storage = storage.seen();
    assert_eq!(at_storage.len(), 2, "config + layer: {at_storage:?}");
    assert!(
        at_storage.iter().all(|s| s.authorization.is_none()),
        "credential leaked to blob storage: {at_storage:?}"
    );
    // Non-vacuity: the registry's own blob requests did carry it.
    assert!(
        fake.seen()
            .iter()
            .filter(|s| s.path.contains("/blobs/"))
            .all(|s| s.authorization.as_deref() == Some(format!("Bearer {TOKEN}").as_str()))
    );
}

/// Plain http is refused unless the host was named: for the registry, and for a
/// redirect target.
#[test]
fn http_is_refused_without_insecure_registry() {
    crypto();
    let image = build_image();
    let storage = Arc::new(Fake::new(&image));
    let storage_host = serve(storage.clone());
    let fake = Arc::new(Fake::new(&image));
    let host = serve(fake.clone());
    let dir = tempfile::tempdir().unwrap();

    // No flag: the client speaks https, and a plain-http registry never serves it.
    let err = run_import(
        Source::Registry(pinned(&host, &image.index)),
        &plan(&dir.path().join("a"), &[], CredentialLookup::None),
    )
    .unwrap_err();
    assert!(
        matches!(registry_error(&err), Some(RegistryError::Transport { url, .. }) if url.starts_with("https://")),
        "{err:#}"
    );
    assert!(fake.seen().is_empty(), "nothing was served over http");

    // The registry is allowed, the redirect target is not.
    let mut redirecting = Fake::new(&image);
    redirecting.redirect_blobs_to = Some(format!("http://{storage_host}"));
    let rhost = serve(Arc::new(redirecting));
    let err = run_import(
        Source::Registry(pinned(&rhost, &image.index)),
        &plan(
            &dir.path().join("b"),
            std::slice::from_ref(&rhost),
            CredentialLookup::None,
        ),
    )
    .unwrap_err();
    assert!(
        matches!(registry_error(&err), Some(RegistryError::InsecureUrl { host, .. }) if *host == storage_host),
        "{err:#}"
    );
    assert!(storage.seen().is_empty());
}

/// A tag-only reference is refused before any request is made.
#[test]
fn tag_only_import_is_refused_before_the_network() {
    let image = build_image();
    let fake = Arc::new(Fake::new(&image));
    let host = serve(fake.clone());
    let dir = tempfile::tempdir().unwrap();
    let err = super::import(super::ImportArgs {
        reference: format!("{host}/{REPO}:v1"),
        oci_layout: None,
        oci_archive: None,
        arch: Some(super::ArchArg::Amd64),
        cache_dir: Some(dir.path().to_owned()),
        guest_layer: None,
        image_root: None,
        registry: super::RegistryOpts {
            insecure_registry: vec![host],
            registry_config: Some(dir.path().join("absent.json")),
        },
    })
    .unwrap_err();
    assert!(
        matches!(
            err.downcast_ref::<ReferenceError>(),
            Some(ReferenceError::TagOnly(_))
        ),
        "{err:#}"
    );
    assert!(fake.seen().is_empty());
}

/// `resolve` pins a tag to the digest of the bytes served, and refuses a registry
/// whose Docker-Content-Digest disagrees with them.
#[test]
fn resolve_prints_the_digest_of_the_served_bytes() {
    crypto();
    let image = build_image();
    let host = serve(Arc::new(Fake::new(&image)));
    let tagged = TaggedImage::parse(&format!("{host}/{REPO}:v1")).unwrap();
    let got =
        super::resolve_with(&tagged, std::slice::from_ref(&host), CredentialLookup::None).unwrap();
    assert_eq!(got, digest(&image.index));
    assert_eq!(
        tagged.name.pinned(got),
        format!("{host}/{REPO}@{}", image.index)
    );

    let mut liar = Fake::new(&image);
    liar.lie_about_digest = true;
    let lhost = serve(Arc::new(liar));
    let tagged = TaggedImage::parse(&format!("{lhost}/{REPO}:v1")).unwrap();
    let err = super::resolve_with(&tagged, &[lhost], CredentialLookup::None).unwrap_err();
    assert!(
        matches!(
            err.downcast_ref::<RegistryError>(),
            Some(RegistryError::DigestHeaderMismatch { .. })
        ),
        "{err:#}"
    );
}

/// A blob larger than the limit is refused while streaming.
#[test]
fn oversized_blob_is_refused() {
    crypto();
    let image = build_image();
    let host = serve(Arc::new(Fake::new(&image)));
    let dir = tempfile::tempdir().unwrap();
    let client = RegistryClient::new(
        pinned(&host, &image.index).name,
        &[host],
        CredentialLookup::None,
        FetchLimits {
            max_manifest_bytes: 1 << 20,
            max_blob_bytes: 16,
        },
    )
    .unwrap();
    let cache = ImageCache::open(dir.path()).unwrap();
    let err = client
        .fetch(Endpoint::Blob, digest(&image.layer), &cache)
        .unwrap_err();
    assert!(matches!(err, RegistryError::TooLarge { .. }), "{err}");
    assert!(cache.blob(digest(&image.layer)).is_none());
}
