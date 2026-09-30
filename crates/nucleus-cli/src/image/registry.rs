//! A thin OCI distribution-spec v2 client: GET a manifest, GET a blob, nothing else.
//!
//! # What it guarantees
//!
//! - **Every byte is verified before it is kept.** A manifest or blob is streamed to
//!   a temporary file in the cache while it is hashed, and renamed into
//!   `blobs/sha256/<hex>` only when its sha256 is the digest that was asked for. A
//!   wrong digest leaves nothing behind ([`RegistryError::DigestMismatch`]).
//! - **Credentials go to the registry's own origin, and to its token realm, and
//!   nowhere else.** Redirects are followed by this module, not by the HTTP
//!   library, and `Authorization` is attached only when the target's
//!   scheme+host+port is the registry's. A blob redirected to storage on another
//!   host gets no `Authorization` header ([`RegistryClient::authorizes`]).
//! - **Plain http is refused** unless the host was named with
//!   `--insecure-registry`: for the registry itself, for a redirect target, and for
//!   a token realm (which receives the credential).
//! - **Everything is bounded**: manifests by the importer's metadata limit, blobs by
//!   its content limit, token responses by a fixed 64 KiB.
//!
//! # What it does not do
//!
//! Push, list tags, follow a tag for an import (tags are resolved only by
//! `nucleus image resolve`, which prints a digest to pin), run credential helpers,
//! or resume a partial download.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::Url;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, LOCATION, WWW_AUTHENTICATE};
use sha2::{Digest as _, Sha256};

use nucleus_oci_rootfs::Sha256Digest;

use super::auth::{Challenge, Credential, CredentialLookup, parse_challenge};
use super::cache::ImageCache;
use super::reference::ImageName;

/// The manifest media types this client asks for: OCI index/manifest, docker v2 list/manifest.
pub const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json";

/// How many redirects one request may follow.
const MAX_REDIRECTS: usize = 5;
/// A token endpoint's answer is a small JSON object.
const MAX_TOKEN_BYTES: u64 = 65_536;
/// A metadata round trip (manifest, token).
const METADATA_TIMEOUT: Duration = Duration::from_secs(120);
/// One blob, start to finish.
const BLOB_TIMEOUT: Duration = Duration::from_secs(3600);
/// Connecting to any host.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Bounds on what one registry may make this process download.
///
/// No `Default` (B-1): [`FetchLimits::from_import`] derives them from the importer's
/// own limits, so the two cannot disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchLimits {
    /// One manifest or index.
    pub max_manifest_bytes: u64,
    /// One config or layer blob.
    pub max_blob_bytes: u64,
}

impl FetchLimits {
    /// A manifest is bounded like any image JSON; a blob like the whole uncompressed budget,
    /// which no single layer can usefully exceed.
    pub fn from_import(limits: &nucleus_oci_rootfs::ImportLimits) -> Self {
        Self {
            max_manifest_bytes: limits.max_metadata_bytes,
            max_blob_bytes: limits.max_uncompressed_bytes,
        }
    }
}

/// Which endpoint a digest is fetched from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// `/v2/<name>/manifests/<digest>`: an index or a manifest.
    Manifest,
    /// `/v2/<name>/blobs/<digest>`: a config or a layer.
    Blob,
}

impl Endpoint {
    fn path(self) -> &'static str {
        match self {
            Self::Manifest => "manifests",
            Self::Blob => "blobs",
        }
    }
}

/// Why a registry request failed. One variant per reason (A-3).
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("{url} is plain http; pass `--insecure-registry {host}` to allow http to that host")]
    InsecureUrl { url: String, host: String },
    #[error("{url}: {source}")]
    Transport {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{url}: the registry answered {status}")]
    Status { url: String, status: u16 },
    #[error("{url}: not found in the registry")]
    NotFound { url: String },
    #[error(
        "{url}: the registry requires credentials and none are configured{}",
        helper.as_ref().map(|h| format!(" (credential helper `{h}` is configured but is not run; set NUCLEUS_REGISTRY_USERNAME/PASSWORD or an `auths` entry)")).unwrap_or_default()
    )]
    NoCredentials { url: String, helper: Option<String> },
    #[error("{url}: the registry refused the credentials")]
    Unauthorized { url: String },
    #[error("{url}: unsupported authentication challenge {challenge:?}")]
    UnsupportedChallenge { url: String, challenge: String },
    #[error("token realm {url}: {detail}")]
    Token { url: String, detail: String },
    #[error("{url}: more than {MAX_REDIRECTS} redirects")]
    TooManyRedirects { url: String },
    #[error("{url}: redirect with no usable Location")]
    BadRedirect { url: String },
    #[error("{what}: exceeds the limit of {limit} bytes")]
    TooLarge { what: String, limit: u64 },
    #[error("{what}: content hashes to {actual}, expected {expected}")]
    DigestMismatch {
        what: String,
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
    #[error("{url}: Docker-Content-Digest says {header}, content hashes to {actual}")]
    DigestHeaderMismatch {
        url: String,
        header: String,
        actual: Sha256Digest,
    },
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: io::Error,
    },
}

/// What a request should carry, once the registry has said.
#[derive(Clone, Debug)]
enum AuthState {
    /// Nothing yet: the first request goes anonymous.
    Anonymous,
    /// `Authorization: Basic …`.
    Basic(String),
    /// `Authorization: Bearer …`.
    Bearer(String),
}

impl AuthState {
    fn header(&self) -> Option<String> {
        match self {
            Self::Anonymous => None,
            Self::Basic(b) => Some(format!("Basic {b}")),
            Self::Bearer(t) => Some(format!("Bearer {t}")),
        }
    }
}

/// `scheme://host:port`, the unit credentials are scoped to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Origin {
    fn of(url: &Url) -> Self {
        Self {
            scheme: url.scheme().to_owned(),
            host: url.host_str().unwrap_or_default().to_ascii_lowercase(),
            port: url.port_or_known_default(),
        }
    }
}

/// One repository on one registry, with the credential for it.
pub struct RegistryClient {
    http: Client,
    name: ImageName,
    base: Url,
    origin: Origin,
    insecure: BTreeSet<String>,
    credential: CredentialLookup,
    auth: RefCell<AuthState>,
    limits: FetchLimits,
}

/// `host[:port]` of a URL, as `--insecure-registry` spells it.
fn host_port(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    }
}

impl RegistryClient {
    /// A client for `name`. `insecure` lists the `host[:port]`s that may be spoken to over http.
    pub fn new(
        name: ImageName,
        insecure: &[String],
        credential: CredentialLookup,
        limits: FetchLimits,
    ) -> Result<Self, RegistryError> {
        let insecure: BTreeSet<String> = insecure.iter().map(|h| h.to_ascii_lowercase()).collect();
        let host = name.api_host().to_owned();
        let scheme = if insecure.contains(&host) {
            "http"
        } else {
            "https"
        };
        let base_str = format!("{scheme}://{host}/v2/");
        let base = Url::parse(&base_str).map_err(|e| RegistryError::Io {
            what: base_str.clone(),
            source: io::Error::other(e),
        })?;
        let http = Client::builder()
            // Redirects are followed by `send`, which decides per hop whether the
            // credential may go along. The library's own policy would decide that
            // itself, somewhere this module cannot test.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(None)
            .build()
            .map_err(|source| RegistryError::Transport {
                url: base_str,
                source,
            })?;
        Ok(Self {
            http,
            origin: Origin::of(&base),
            name,
            base,
            insecure,
            credential,
            auth: RefCell::new(AuthState::Anonymous),
            limits,
        })
    }

    /// Whether a request to `url` may carry the registry credential.
    ///
    /// Only the registry's own origin. A redirect to blob storage on another host,
    /// or to the same host on another scheme or port, goes without it.
    fn authorizes(&self, url: &Url) -> bool {
        Origin::of(url) == self.origin
    }

    /// Refuse a plain-http URL whose host was not named insecure.
    fn check_scheme(&self, url: &Url) -> Result<(), RegistryError> {
        match url.scheme() {
            "https" => Ok(()),
            "http" if self.insecure.contains(&host_port(url).to_ascii_lowercase()) => Ok(()),
            _ => Err(RegistryError::InsecureUrl {
                url: url.to_string(),
                host: host_port(url),
            }),
        }
    }

    fn endpoint_url(&self, endpoint: Endpoint, reference: &str) -> Result<Url, RegistryError> {
        let path = format!("{}/{}/{reference}", self.name.repository(), endpoint.path());
        self.base.join(&path).map_err(|e| RegistryError::Io {
            what: path,
            source: io::Error::other(e),
        })
    }

    /// GET `url`, answering one auth challenge and following redirects.
    fn send(
        &self,
        url: Url,
        accept: Option<&str>,
        timeout: Duration,
    ) -> Result<Response, RegistryError> {
        let mut url = url;
        let mut challenged = false;
        let mut hops = 0usize;
        loop {
            self.check_scheme(&url)?;
            let mut req = self.http.get(url.clone()).timeout(timeout);
            if let Some(accept) = accept {
                req = req.header(ACCEPT, accept);
            }
            if self.authorizes(&url) {
                if let Some(h) = self.auth.borrow().header() {
                    req = req.header(AUTHORIZATION, h);
                }
            }
            let resp = req.send().map_err(|source| RegistryError::Transport {
                url: url.to_string(),
                source,
            })?;
            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && self.authorizes(&url) {
                if challenged {
                    return Err(RegistryError::Unauthorized {
                        url: url.to_string(),
                    });
                }
                challenged = true;
                let header = resp
                    .headers()
                    .get(WWW_AUTHENTICATE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                self.answer(&url, &header)?;
                continue;
            }
            if status.is_redirection() {
                hops = hops.saturating_add(1);
                if hops > MAX_REDIRECTS {
                    return Err(RegistryError::TooManyRedirects {
                        url: url.to_string(),
                    });
                }
                let next = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|loc| url.join(loc).ok())
                    .ok_or_else(|| RegistryError::BadRedirect {
                        url: url.to_string(),
                    })?;
                url = next;
                continue;
            }
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(RegistryError::NotFound {
                    url: url.to_string(),
                });
            }
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                return Err(RegistryError::Unauthorized {
                    url: url.to_string(),
                });
            }
            if !status.is_success() {
                return Err(RegistryError::Status {
                    url: url.to_string(),
                    status: status.as_u16(),
                });
            }
            return Ok(resp);
        }
    }

    /// Answer a `WWW-Authenticate` challenge by updating the auth state.
    pub(super) fn answer(&self, url: &Url, header: &str) -> Result<(), RegistryError> {
        let challenge =
            parse_challenge(header).ok_or_else(|| RegistryError::UnsupportedChallenge {
                url: url.to_string(),
                challenge: header.to_owned(),
            })?;
        let credential = match &self.credential {
            CredentialLookup::Found(c) => Some(c),
            CredentialLookup::None => None,
            CredentialLookup::HelperNotRun { .. } => None,
        };
        let no_credentials = || RegistryError::NoCredentials {
            url: url.to_string(),
            helper: match &self.credential {
                CredentialLookup::HelperNotRun { helper } => Some(helper.clone()),
                CredentialLookup::Found(_) | CredentialLookup::None => None,
            },
        };
        let next = match challenge {
            Challenge::Basic => match credential {
                Some(Credential::Basic { username, password }) => {
                    AuthState::Basic(STANDARD.encode(format!("{username}:{}", password.expose())))
                }
                Some(Credential::IdentityToken(_)) | None => return Err(no_credentials()),
            },
            Challenge::Bearer {
                realm,
                service,
                scope,
            } => {
                let scope =
                    scope.unwrap_or_else(|| format!("repository:{}:pull", self.name.repository()));
                AuthState::Bearer(self.token(&realm, service.as_deref(), &scope, credential)?)
            }
        };
        *self.auth.borrow_mut() = next;
        Ok(())
    }

    /// Fetch a bearer token from `realm`.
    fn token(
        &self,
        realm: &str,
        service: Option<&str>,
        scope: &str,
        credential: Option<&Credential>,
    ) -> Result<String, RegistryError> {
        let token_err = |detail: String| RegistryError::Token {
            url: realm.to_owned(),
            detail,
        };
        let mut url = Url::parse(realm).map_err(|e| token_err(e.to_string()))?;
        // The realm receives the credential: it is held to the same scheme rule.
        self.check_scheme(&url)?;
        let req: RequestBuilder = match credential {
            Some(Credential::IdentityToken(refresh)) => {
                let mut form = vec![
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh.expose()),
                    ("client_id", "nucleus"),
                    ("scope", scope),
                ];
                if let Some(service) = service {
                    form.push(("service", service));
                }
                // Form-encode with the URL encoder (reqwest's `form` is behind a feature
                // this workspace does not enable).
                let mut encoder = Url::parse("x:").map_err(|e| token_err(e.to_string()))?;
                encoder.query_pairs_mut().extend_pairs(&form);
                let body = encoder.query().unwrap_or_default().to_owned();
                self.http
                    .post(url.clone())
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(body)
            }
            Some(Credential::Basic { .. }) | None => {
                {
                    let mut q = url.query_pairs_mut();
                    if let Some(service) = service {
                        q.append_pair("service", service);
                    }
                    q.append_pair("scope", scope);
                }
                let req = self.http.get(url.clone());
                match credential {
                    Some(Credential::Basic { username, password }) => {
                        req.basic_auth(username, Some(password.expose()))
                    }
                    Some(Credential::IdentityToken(_)) | None => req,
                }
            }
        };
        let resp =
            req.timeout(METADATA_TIMEOUT)
                .send()
                .map_err(|source| RegistryError::Transport {
                    url: url.to_string(),
                    source,
                })?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(RegistryError::Unauthorized {
                url: url.to_string(),
            });
        }
        if !status.is_success() {
            return Err(RegistryError::Status {
                url: url.to_string(),
                status: status.as_u16(),
            });
        }
        let body = read_bounded(resp, MAX_TOKEN_BYTES, &format!("token from {url}"))?;
        #[derive(serde::Deserialize)]
        struct TokenResponse {
            #[serde(default)]
            token: Option<String>,
            #[serde(default)]
            access_token: Option<String>,
        }
        let parsed: TokenResponse =
            serde_json::from_slice(&body).map_err(|e| token_err(e.to_string()))?;
        parsed
            .token
            .or(parsed.access_token)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| token_err("the response carries no token".to_owned()))
    }

    /// Resolve `tag` to the digest of the manifest the registry serves for it now.
    pub fn resolve_tag(&self, tag: &str) -> Result<Sha256Digest, RegistryError> {
        let url = self.endpoint_url(Endpoint::Manifest, tag)?;
        let resp = self.send(url.clone(), Some(MANIFEST_ACCEPT), METADATA_TIMEOUT)?;
        let header = resp
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = read_bounded(
            resp,
            self.limits.max_manifest_bytes,
            &format!("manifest {url}"),
        )?;
        // The digest is of the bytes, never the header's say-so; a header that
        // disagrees is a registry this client will not pin from.
        let actual = Sha256Digest::of(&body);
        if let Some(header) = header {
            if header != actual.to_string() {
                return Err(RegistryError::DigestHeaderMismatch {
                    url: url.to_string(),
                    header,
                    actual,
                });
            }
        }
        Ok(actual)
    }

    /// Fetch `digest` from `endpoint` into the cache, verifying it while it streams.
    ///
    /// Returns the path it now has in the cache. A digest already in the cache is
    /// not fetched again; the importer re-verifies every blob it reads regardless.
    pub fn fetch(
        &self,
        endpoint: Endpoint,
        digest: Sha256Digest,
        cache: &ImageCache,
    ) -> Result<PathBuf, RegistryError> {
        if let Some(path) = cache.blob(digest) {
            return Ok(path);
        }
        let (accept, limit, timeout) = match endpoint {
            Endpoint::Manifest => (
                Some(MANIFEST_ACCEPT),
                self.limits.max_manifest_bytes,
                METADATA_TIMEOUT,
            ),
            Endpoint::Blob => (None, self.limits.max_blob_bytes, BLOB_TIMEOUT),
        };
        let url = self.endpoint_url(endpoint, &digest.to_string())?;
        let what = format!("{} {digest}", endpoint.path());
        let resp = self.send(url, accept, timeout)?;
        if resp.content_length().is_some_and(|n| n > limit) {
            return Err(RegistryError::TooLarge { what, limit });
        }
        cache.store(digest, &what, |file| {
            stream_verified(resp, file, digest, limit, &what)
        })
    }
}

/// Copy `from` into `to`, hashing as it goes; refuse past `limit` or on a wrong digest.
pub fn stream_verified(
    from: impl Read,
    to: &mut File,
    expected: Sha256Digest,
    limit: u64,
    what: &str,
) -> Result<(), RegistryError> {
    let io_err = |source: io::Error| RegistryError::Io {
        what: what.to_owned(),
        source,
    };
    let mut hasher = Sha256::new();
    let mut from = from.take(limit.saturating_add(1));
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = from.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        let chunk = buf.get(..n).ok_or_else(|| {
            io_err(io::Error::other(
                "reader reported more bytes than the buffer holds",
            ))
        })?;
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if total > limit {
            return Err(RegistryError::TooLarge {
                what: what.to_owned(),
                limit,
            });
        }
        hasher.update(chunk);
        to.write_all(chunk).map_err(io_err)?;
    }
    let actual = Sha256Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize())))
        .map_err(|e| io_err(io::Error::other(e.to_string())))?;
    if actual != expected {
        return Err(RegistryError::DigestMismatch {
            what: what.to_owned(),
            expected,
            actual,
        });
    }
    to.sync_all().map_err(io_err)
}

/// Read a whole response, refusing past `limit`.
fn read_bounded(resp: Response, limit: u64, what: &str) -> Result<Vec<u8>, RegistryError> {
    if resp.content_length().is_some_and(|n| n > limit) {
        return Err(RegistryError::TooLarge {
            what: what.to_owned(),
            limit,
        });
    }
    let mut body = Vec::new();
    resp.take(limit.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|source| RegistryError::Io {
            what: what.to_owned(),
            source,
        })?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > limit {
        return Err(RegistryError::TooLarge {
            what: what.to_owned(),
            limit,
        });
    }
    Ok(body)
}
