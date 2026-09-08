//! Deterministic, read-only probes of the repository a goal is stated in.
//!
//! The context is what lets the rules be specific: "fix CI" in a repository
//! with `.github/workflows/` means "read GitHub Actions logs", and in one
//! without it means nothing network-shaped at all. Every probe is a file
//! read; nothing here executes a program or opens a socket.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A language ecosystem detected from its manifest file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    /// `Cargo.toml`
    Cargo,
    /// `package.json`
    Npm,
    /// `pyproject.toml`, `requirements.txt`, `setup.py`
    Python,
    /// `go.mod`
    Go,
}

/// A CI system detected from its configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiSystem {
    /// `.github/workflows/*.yml`
    GithubActions,
    /// `.gitlab-ci.yml`
    GitlabCi,
    /// `.circleci/config.yml`
    CircleCi,
}

/// One git remote, parsed from `.git/config`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GitRemote {
    /// Remote name (`origin`).
    pub name: String,
    /// Host (`github.com`).
    pub host: String,
    /// `owner/repo` when the URL had that shape.
    pub owner_repo: Option<String>,
}

/// What the compiler knows about the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoContext {
    /// Canonical root.
    pub root: PathBuf,
    /// Detected ecosystems.
    pub ecosystems: BTreeSet<Ecosystem>,
    /// Detected CI systems.
    pub ci: BTreeSet<CiSystem>,
    /// Git remotes.
    pub remotes: Vec<GitRemote>,
    /// Whether the root is a git work tree.
    pub has_git: bool,
    /// Names of MCP servers declared in known config locations.
    pub mcp_servers: BTreeSet<String>,
    /// Whether `.nucleus/egress.toml` exists.
    pub has_egress_policy: bool,
    /// `sha256` over the facts above (not the root path), so two checkouts
    /// of the same repository compile the same goal to the same grant.
    pub digest: String,
}

impl RepoContext {
    /// Whether any remote is on `host` (exact or subdomain).
    pub fn has_remote_host(&self, host: &str) -> bool {
        self.remotes
            .iter()
            .any(|r| r.host == host || r.host.ends_with(&format!(".{host}")))
    }
}

/// MCP config locations, matching `nucleus audit`.
const MCP_CONFIG_LOCATIONS: &[&str] = &[
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
];

/// Probe `root`.
pub fn probe(root: &Path) -> std::io::Result<RepoContext> {
    let root = root.canonicalize()?;
    let exists = |rel: &str| root.join(rel).exists();

    let mut ecosystems = BTreeSet::new();
    if exists("Cargo.toml") {
        ecosystems.insert(Ecosystem::Cargo);
    }
    if exists("package.json") {
        ecosystems.insert(Ecosystem::Npm);
    }
    if exists("pyproject.toml") || exists("requirements.txt") || exists("setup.py") {
        ecosystems.insert(Ecosystem::Python);
    }
    if exists("go.mod") {
        ecosystems.insert(Ecosystem::Go);
    }

    let mut ci = BTreeSet::new();
    if has_yaml(&root.join(".github/workflows")) {
        ci.insert(CiSystem::GithubActions);
    }
    if exists(".gitlab-ci.yml") {
        ci.insert(CiSystem::GitlabCi);
    }
    if exists(".circleci/config.yml") {
        ci.insert(CiSystem::CircleCi);
    }

    let has_git = root.join(".git").exists();
    let remotes = if has_git {
        parse_remotes(&root)
    } else {
        Vec::new()
    };

    let mut mcp_servers = BTreeSet::new();
    for loc in MCP_CONFIG_LOCATIONS {
        if let Ok(content) = fs::read_to_string(root.join(loc))
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&content)
            && let Some(servers) = value.get("mcpServers").and_then(|v| v.as_object())
        {
            mcp_servers.extend(servers.keys().cloned());
        }
    }

    let has_egress_policy = exists(".nucleus/egress.toml");

    let mut ctx = RepoContext {
        root,
        ecosystems,
        ci,
        remotes,
        has_git,
        mcp_servers,
        has_egress_policy,
        digest: String::new(),
    };
    ctx.digest = digest_of(&ctx);
    Ok(ctx)
}

fn has_yaml(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|rd| {
        rd.filter_map(Result::ok).any(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x == "yml" || x == "yaml")
        })
    })
}

/// Parse `[remote "<name>"] url = <url>` from `.git/config` (or the
/// `gitdir:` target of a worktree's `.git` file).
fn parse_remotes(root: &Path) -> Vec<GitRemote> {
    let git = root.join(".git");
    let config_path = if git.is_dir() {
        git.join("config")
    } else {
        match fs::read_to_string(&git) {
            Ok(s) => match s.trim().strip_prefix("gitdir:") {
                Some(dir) => {
                    let dir = dir.trim();
                    let p = if Path::new(dir).is_absolute() {
                        PathBuf::from(dir)
                    } else {
                        root.join(dir)
                    };
                    // A linked worktree's gitdir is <repo>/.git/worktrees/<n>.
                    p.parent()
                        .and_then(Path::parent)
                        .map(|common| common.join("config"))
                        .unwrap_or(p.join("config"))
                }
                None => return Vec::new(),
            },
            Err(_) => return Vec::new(),
        }
    };
    let Ok(content) = fs::read_to_string(config_path) else {
        return Vec::new();
    };
    let mut remotes = Vec::new();
    let mut current: Option<String> = None;
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("[remote \"")
            && let Some(name) = rest.strip_suffix("\"]")
        {
            current = Some(name.to_string());
            continue;
        }
        if line.starts_with('[') {
            current = None;
            continue;
        }
        if let Some(name) = &current
            && let Some(url) = line.strip_prefix("url")
        {
            let url = url.trim_start().trim_start_matches('=').trim();
            if let Some((host, owner_repo)) = parse_remote_url(url) {
                remotes.push(GitRemote {
                    name: name.clone(),
                    host,
                    owner_repo,
                });
            }
        }
    }
    remotes.sort();
    remotes
}

/// `https://github.com/o/r.git`, `git@github.com:o/r.git`, `ssh://git@host/o/r`.
fn parse_remote_url(url: &str) -> Option<(String, Option<String>)> {
    let (host, path) = if let Some(rest) = url.split_once("://").map(|(_, r)| r) {
        let rest = rest.rsplit('@').next().unwrap_or(rest);
        let (host, path) = rest.split_once('/')?;
        (host.split(':').next()?.to_string(), path.to_string())
    } else if let Some((userhost, path)) = url.split_once(':') {
        let host = userhost.rsplit('@').next().unwrap_or(userhost);
        (host.to_string(), path.to_string())
    } else {
        return None;
    };
    if host.is_empty() {
        return None;
    }
    let path = path.trim_end_matches('/').trim_end_matches(".git");
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let owner_repo = if parts.len() >= 2 {
        Some(format!(
            "{}/{}",
            parts[parts.len() - 2],
            parts[parts.len() - 1]
        ))
    } else {
        None
    };
    Some((host.to_ascii_lowercase(), owner_repo))
}

fn digest_of(ctx: &RepoContext) -> String {
    let facts = serde_json::json!({
        "ecosystems": ctx.ecosystems,
        "ci": ctx.ci,
        "remotes": ctx.remotes,
        "has_git": ctx.has_git,
        "mcp_servers": ctx.mcp_servers,
        "has_egress_policy": ctx.has_egress_policy,
    });
    let bytes = serde_json::to_vec(&facts).unwrap_or_default();
    let hash = Sha256::digest(&bytes);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_remote_urls() {
        assert_eq!(
            parse_remote_url("https://github.com/acme/widgets.git"),
            Some(("github.com".into(), Some("acme/widgets".into())))
        );
        assert_eq!(
            parse_remote_url("git@github.com:acme/widgets.git"),
            Some(("github.com".into(), Some("acme/widgets".into())))
        );
        assert_eq!(
            parse_remote_url("ssh://git@gitlab.example.com:2222/acme/widgets"),
            Some(("gitlab.example.com".into(), Some("acme/widgets".into())))
        );
        assert_eq!(parse_remote_url("nonsense"), None);
    }

    #[test]
    fn probe_detects_ecosystem_ci_and_remote() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
        fs::create_dir_all(root.join(".github/workflows")).unwrap();
        fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(
            root.join(".git/config"),
            "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:acme/widgets.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        )
        .unwrap();
        fs::write(
            root.join(".mcp.json"),
            r#"{"mcpServers":{"github":{"command":"x"},"fs":{"command":"y"}}}"#,
        )
        .unwrap();
        let ctx = probe(root).unwrap();
        assert!(ctx.ecosystems.contains(&Ecosystem::Cargo));
        assert!(ctx.ci.contains(&CiSystem::GithubActions));
        assert!(ctx.has_remote_host("github.com"));
        assert_eq!(ctx.remotes[0].owner_repo.as_deref(), Some("acme/widgets"));
        assert_eq!(ctx.mcp_servers.len(), 2);
        assert_eq!(ctx.digest.len(), 64);

        // The digest is over facts, not the path: a second checkout agrees.
        let dir2 = tempfile::tempdir().unwrap();
        let root2 = dir2.path();
        fs::write(root2.join("Cargo.toml"), "[package]\nname='y'\n").unwrap();
        fs::create_dir_all(root2.join(".github/workflows")).unwrap();
        fs::write(root2.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
        fs::create_dir_all(root2.join(".git")).unwrap();
        fs::copy(root.join(".git/config"), root2.join(".git/config")).unwrap();
        fs::copy(root.join(".mcp.json"), root2.join(".mcp.json")).unwrap();
        let ctx2 = probe(root2).unwrap();
        assert_eq!(ctx.digest, ctx2.digest);
    }

    #[test]
    fn empty_directory_is_a_valid_context() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = probe(dir.path()).unwrap();
        assert!(ctx.ecosystems.is_empty());
        assert!(ctx.ci.is_empty());
        assert!(!ctx.has_git);
        assert!(ctx.remotes.is_empty());
    }
}
