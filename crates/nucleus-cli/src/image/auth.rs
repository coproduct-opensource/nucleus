//! Registry credentials and `WWW-Authenticate` challenges.
//!
//! Credentials come from two places, in this order:
//!
//! 1. `NUCLEUS_REGISTRY_USERNAME` + `NUCLEUS_REGISTRY_PASSWORD`, or
//!    `NUCLEUS_REGISTRY_IDENTITY_TOKEN`, in the environment of this invocation;
//! 2. the `auths` map of the user's docker-format `config.json`
//!    (`$DOCKER_CONFIG/config.json`, else `~/.docker/config.json`): `auth` is
//!    base64 `user:password`, `identitytoken` is an OAuth2 refresh token.
//!
//! Credential helpers (`credsStore`, `credHelpers`) are **not executed**: running
//! a helper binary named by a config file is an effect this command does not take.
//! A helper that would have answered is reported by name ([`CredentialLookup::HelperNotRun`])
//! rather than silently read as "no credentials" (A-1).
//!
//! The environment is read through a caller-supplied function, never ambiently,
//! so tests pass a map instead of mutating the process (H-1).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

pub const ENV_USERNAME: &str = "NUCLEUS_REGISTRY_USERNAME";
pub const ENV_PASSWORD: &str = "NUCLEUS_REGISTRY_PASSWORD";
pub const ENV_IDENTITY_TOKEN: &str = "NUCLEUS_REGISTRY_IDENTITY_TOKEN";

/// A secret that never prints.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// A credential for one registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    /// A username and password, sent as HTTP Basic (to the registry, or to a token realm).
    Basic { username: String, password: Secret },
    /// An OAuth2 refresh token, exchanged at the token realm.
    IdentityToken(Secret),
}

/// What looking up a registry's credential found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialLookup {
    /// A usable credential.
    Found(Credential),
    /// Nothing configured for this registry: requests go anonymous.
    None,
    /// A credential helper is configured for this registry and was not run.
    HelperNotRun { helper: String },
}

/// Why credentials could not be read. Distinct from "there are none" (A-1).
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not a docker config.json: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("{path}: the `auth` entry for {key:?} is not base64 `user:password`")]
    BadAuthField { path: PathBuf, key: String },
    #[error("{ENV_USERNAME} and {ENV_PASSWORD} must be set together")]
    HalfEnv,
}

#[derive(serde::Deserialize, Default)]
struct DockerConfig {
    #[serde(default)]
    auths: BTreeMap<String, AuthEntry>,
    #[serde(default, rename = "credsStore")]
    creds_store: Option<String>,
    #[serde(default, rename = "credHelpers")]
    cred_helpers: BTreeMap<String, String>,
}

#[derive(serde::Deserialize)]
struct AuthEntry {
    #[serde(default)]
    auth: Option<String>,
    #[serde(default)]
    identitytoken: Option<String>,
}

/// Where the docker-format config lives: `$DOCKER_CONFIG/config.json`, else `~/.docker/config.json`.
pub fn default_config_path(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    match env("DOCKER_CONFIG") {
        Some(dir) => Some(PathBuf::from(dir).join("config.json")),
        None => dirs::home_dir().map(|h| h.join(".docker").join("config.json")),
    }
}

/// The keys a registry's entry may be filed under in `auths`.
fn config_keys(registry: &str) -> Vec<String> {
    let mut keys = vec![
        registry.to_owned(),
        format!("https://{registry}"),
        format!("http://{registry}"),
        format!("https://{registry}/v2/"),
        format!("https://{registry}/v1/"),
    ];
    if registry == "docker.io" {
        // Docker Hub's entry is historically filed under its v1 index URL.
        keys.insert(0, "https://index.docker.io/v1/".to_owned());
        keys.push("index.docker.io".to_owned());
        keys.push("registry-1.docker.io".to_owned());
    }
    keys
}

/// Look up the credential for `registry` (as written in the reference).
pub fn lookup(
    registry: &str,
    env: &dyn Fn(&str) -> Option<String>,
    config: Option<&Path>,
) -> Result<CredentialLookup, CredentialError> {
    if let Some(token) = env(ENV_IDENTITY_TOKEN) {
        return Ok(CredentialLookup::Found(Credential::IdentityToken(
            Secret::new(token),
        )));
    }
    match (env(ENV_USERNAME), env(ENV_PASSWORD)) {
        (Some(username), Some(password)) => {
            return Ok(CredentialLookup::Found(Credential::Basic {
                username,
                password: Secret::new(password),
            }));
        }
        (Some(_), None) | (None, Some(_)) => return Err(CredentialError::HalfEnv),
        (None, None) => {}
    }
    let Some(path) = config else {
        return Ok(CredentialLookup::None);
    };
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CredentialLookup::None),
        Err(source) => {
            return Err(CredentialError::Read {
                path: path.to_owned(),
                source,
            });
        }
    };
    let parsed: DockerConfig =
        serde_json::from_slice(&raw).map_err(|source| CredentialError::Parse {
            path: path.to_owned(),
            source,
        })?;
    from_config(registry, &parsed, path)
}

fn from_config(
    registry: &str,
    config: &DockerConfig,
    path: &Path,
) -> Result<CredentialLookup, CredentialError> {
    for key in config_keys(registry) {
        let Some(entry) = config.auths.get(&key) else {
            continue;
        };
        if let Some(token) = entry.identitytoken.as_deref().filter(|t| !t.is_empty()) {
            return Ok(CredentialLookup::Found(Credential::IdentityToken(
                Secret::new(token),
            )));
        }
        if let Some(auth) = entry.auth.as_deref().filter(|a| !a.is_empty()) {
            let bad = || CredentialError::BadAuthField {
                path: path.to_owned(),
                key: key.clone(),
            };
            let decoded = STANDARD.decode(auth).map_err(|_| bad())?;
            let decoded = String::from_utf8(decoded).map_err(|_| bad())?;
            let (username, password) = decoded.split_once(':').ok_or_else(bad)?;
            return Ok(CredentialLookup::Found(Credential::Basic {
                username: username.to_owned(),
                password: Secret::new(password),
            }));
        }
    }
    for key in config_keys(registry) {
        if let Some(helper) = config.cred_helpers.get(&key) {
            return Ok(CredentialLookup::HelperNotRun {
                helper: helper.clone(),
            });
        }
    }
    if let Some(store) = &config.creds_store {
        return Ok(CredentialLookup::HelperNotRun {
            helper: store.clone(),
        });
    }
    Ok(CredentialLookup::None)
}

/// A parsed `WWW-Authenticate` challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Challenge {
    Basic,
    Bearer {
        realm: String,
        service: Option<String>,
        scope: Option<String>,
    },
}

/// Parse one `WWW-Authenticate` header value. `None` for a scheme this client does not speak.
pub fn parse_challenge(header: &str) -> Option<Challenge> {
    let header = header.trim();
    let (scheme, params) = header.split_once(' ').unwrap_or((header, ""));
    if scheme.eq_ignore_ascii_case("basic") {
        return Some(Challenge::Basic);
    }
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let params = parse_params(params);
    Some(Challenge::Bearer {
        realm: params.get("realm")?.clone(),
        service: params.get("service").cloned(),
        scope: params.get("scope").cloned(),
    })
}

/// `k="v", k2=v2` — quoted values may contain commas (a scope list does).
fn parse_params(s: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        let Some((key, after)) = rest.split_once('=') else {
            break;
        };
        let key = key
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_ascii_lowercase();
        let after = after.trim_start();
        let (value, tail) = if let Some(quoted) = after.strip_prefix('"') {
            let mut value = String::new();
            let mut chars = quoted.char_indices();
            let mut end = quoted.len();
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        if let Some((_, escaped)) = chars.next() {
                            value.push(escaped);
                        }
                    }
                    '"' => {
                        end = i.saturating_add(1);
                        break;
                    }
                    other => value.push(other),
                }
            }
            (value, quoted.get(end..).unwrap_or_default())
        } else {
            match after.split_once(',') {
                Some((v, t)) => (v.trim().to_owned(), t),
                None => (after.trim().to_owned(), ""),
            }
        };
        out.insert(key, value);
        rest = tail.trim_start().trim_start_matches(',').trim_start();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("config.json");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn docker_config_basic_auth_is_decoded() {
        let dir = tempfile::tempdir().unwrap();
        let auth = STANDARD.encode("builder:pa:ss");
        let p = write_config(
            dir.path(),
            &format!(r#"{{"auths":{{"registry.example:5000":{{"auth":"{auth}"}}}}}}"#),
        );
        assert_eq!(
            lookup("registry.example:5000", &no_env, Some(&p)).unwrap(),
            CredentialLookup::Found(Credential::Basic {
                username: "builder".into(),
                password: Secret::new("pa:ss"),
            })
        );
        // A different registry has no entry.
        assert_eq!(
            lookup("other.example", &no_env, Some(&p)).unwrap(),
            CredentialLookup::None
        );
    }

    #[test]
    fn docker_hub_entry_under_its_v1_url_and_identity_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_config(
            dir.path(),
            r#"{"auths":{"https://index.docker.io/v1/":{"auth":"","identitytoken":"refresh-123"}}}"#,
        );
        assert_eq!(
            lookup("docker.io", &no_env, Some(&p)).unwrap(),
            CredentialLookup::Found(Credential::IdentityToken(Secret::new("refresh-123")))
        );
    }

    #[test]
    fn helpers_are_named_not_run_and_bad_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_config(
            dir.path(),
            r#"{"auths":{},"credHelpers":{"registry.example":"example-helper"}}"#,
        );
        assert_eq!(
            lookup("registry.example", &no_env, Some(&p)).unwrap(),
            CredentialLookup::HelperNotRun {
                helper: "example-helper".into()
            }
        );
        let bad = write_config(dir.path(), r#"{"auths":{"r.example":{"auth":"!!"}}}"#);
        assert!(matches!(
            lookup("r.example", &no_env, Some(&bad)),
            Err(CredentialError::BadAuthField { .. })
        ));
        let junk = write_config(dir.path(), "not json");
        assert!(matches!(
            lookup("r.example", &no_env, Some(&junk)),
            Err(CredentialError::Parse { .. })
        ));
        // Absent file: nothing configured, not an error.
        assert_eq!(
            lookup("r.example", &no_env, Some(&dir.path().join("absent.json"))).unwrap(),
            CredentialLookup::None
        );
    }

    #[test]
    fn env_wins_and_half_env_is_refused() {
        let env = |k: &str| match k {
            ENV_USERNAME => Some("u".to_owned()),
            ENV_PASSWORD => Some("p".to_owned()),
            _ => None,
        };
        assert_eq!(
            lookup("r.example", &env, None).unwrap(),
            CredentialLookup::Found(Credential::Basic {
                username: "u".into(),
                password: Secret::new("p"),
            })
        );
        let half = |k: &str| (k == ENV_USERNAME).then(|| "u".to_owned());
        assert!(matches!(
            lookup("r.example", &half, None),
            Err(CredentialError::HalfEnv)
        ));
    }

    #[test]
    fn challenges_parse() {
        assert_eq!(
            parse_challenge(
                r#"Bearer realm="https://auth.example/token",service="registry.example",scope="repository:a/b:pull,push""#
            ),
            Some(Challenge::Bearer {
                realm: "https://auth.example/token".into(),
                service: Some("registry.example".into()),
                scope: Some("repository:a/b:pull,push".into()),
            })
        );
        assert_eq!(
            parse_challenge(r#"Basic realm="registry""#),
            Some(Challenge::Basic)
        );
        assert_eq!(parse_challenge("Negotiate abc"), None);
        assert_eq!(parse_challenge(r#"Bearer service="x""#), None, "no realm");
    }

    #[test]
    fn secrets_do_not_print() {
        assert_eq!(
            format!("{:?}", Secret::new("hunter2")),
            "Secret(<redacted>)"
        );
    }
}
