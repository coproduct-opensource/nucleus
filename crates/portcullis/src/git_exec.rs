//! What a repository can make git execute: the one list.
//!
//! Git runs code named by a repository's own files: a non-sample hook in
//! `.git/hooks/`, and a `.git/config` entry naming a program (`core.fsmonitor`,
//! `alias.*`, a filter driver, …). Any host tool that runs git in a workspace
//! (an editor's status bar, a shell prompt, a fetch the host makes) runs that
//! code with the host's authority, before any approval prompt is shown. That
//! is the "repository-borne exec config" incident class of ADR 0013.
//!
//! Two deciders read this list and nothing else (ADR 0007 G-1):
//!
//! - the command executor's consume guard (`nucleus::consume_guard`), which
//!   reverts a shell command that ADDED such an entry during a run; and
//! - the pre-mount scan [`scan`], which reports what a workspace ALREADY
//!   carries when it is handed to a pod.
//!
//! # Where the keys come from
//!
//! Every key in [`exec_key`] is cited to the git manual page that says git runs
//! its value: `git-config(1)` for the configuration reference
//! (<https://git-scm.com/docs/git-config>), and the subcommand page where the
//! variable is documented there instead. A key is here because git's own
//! documentation says it names a program, not because it looked dangerous.
//!
//! # What this does not cover
//!
//! Package-manager scripts and CI definitions also run on a host; they are
//! [`crate::EXECUTE_ON_CONSUME`]'s subject, not git's. `.gitmodules` cannot
//! name a `!command` update (git refuses one read from there since 2.24.1,
//! CVE-2019-19604), and `.gitattributes` only names a driver whose command must
//! be in config, which is scanned.

use std::fmt;
use std::ops::Range;
use std::path::{Component, Path, PathBuf};

/// A git config entry that names a program git runs, and where git says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecKey {
    /// The documented variable, with its placeholder (`filter.<driver>.smudge`).
    pub variable: &'static str,
    /// The manual page that documents it as running a program.
    pub doc: &'static str,
}

const GIT_CONFIG: &str = "git-config(1)";
const GIT_SEND_EMAIL: &str = "git-send-email(1)";
const GIT_HOOK: &str = "git-hook(1), git-config(1) hook.*";

/// The exec-bearing key `section[.sub].key = value` is, if any.
///
/// `section` and `key` are lower-cased by the caller (git compares them
/// case-insensitively); `sub` keeps its case (git compares it exactly).
/// `value` is read for the one key whose value decides it
/// (`submodule.<name>.update`, which runs a command only when it starts `!`).
///
/// One `match`, no table beside it (ADR 0007 G-1): the arm IS the list.
#[must_use]
pub fn exec_key(section: &str, sub: Option<&str>, key: &str, value: &str) -> Option<ExecKey> {
    let (variable, doc) = match (section, sub, key) {
        // git-config(1) core.*: each names a program or a hook git runs.
        ("core", None, "fsmonitor") => ("core.fsmonitor", GIT_CONFIG),
        ("core", None, "hookspath") => ("core.hooksPath", GIT_CONFIG),
        ("core", None, "sshcommand") => ("core.sshCommand", GIT_CONFIG),
        ("core", None, "editor") => ("core.editor", GIT_CONFIG),
        ("core", None, "pager") => ("core.pager", GIT_CONFIG),
        ("core", None, "askpass") => ("core.askPass", GIT_CONFIG),
        ("core", None, "gitproxy") => ("core.gitProxy", GIT_CONFIG),
        // "use the shell to execute the specified command" (git-config(1)).
        ("core", None, "alternaterefscommand") => ("core.alternateRefsCommand", GIT_CONFIG),
        ("sequence", None, "editor") => ("sequence.editor", GIT_CONFIG),
        // "git will pipe the diff through the shell command defined by this
        // configuration variable" (git-config(1)).
        ("interactive", None, "difffilter") => ("interactive.diffFilter", GIT_CONFIG),
        // An alias starting `!` is a shell command; any alias can shadow one.
        ("alias", _, _) => ("alias.*", GIT_CONFIG),
        ("pager", _, _) => ("pager.<cmd>", GIT_CONFIG),
        ("filter", Some(_), "clean") => ("filter.<driver>.clean", GIT_CONFIG),
        ("filter", Some(_), "smudge") => ("filter.<driver>.smudge", GIT_CONFIG),
        ("filter", Some(_), "process") => ("filter.<driver>.process", GIT_CONFIG),
        ("diff", Some(_), "textconv") => ("diff.<driver>.textconv", GIT_CONFIG),
        ("diff", Some(_), "command") => ("diff.<driver>.command", GIT_CONFIG),
        ("diff", None, "external") => ("diff.external", GIT_CONFIG),
        ("merge", Some(_), "driver") => ("merge.<driver>.driver", GIT_CONFIG),
        ("difftool" | "mergetool", Some(_), "cmd") => ("<diff|merge>tool.<tool>.cmd", GIT_CONFIG),
        ("difftool" | "mergetool", Some(_), "path") => ("<diff|merge>tool.<tool>.path", GIT_CONFIG),
        ("browser", Some(_), "cmd" | "path") => ("browser.<tool>.<cmd|path>", GIT_CONFIG),
        ("web", None, "browser") => ("web.browser", GIT_CONFIG),
        ("man", Some(_), "cmd" | "path") => ("man.<tool>.<cmd|path>", GIT_CONFIG),
        ("instaweb", None, "httpd" | "browser") => ("instaweb.<httpd|browser>", GIT_CONFIG),
        ("credential", _, "helper") => ("credential[.<url>].helper", GIT_CONFIG),
        // gpg.program and gpg.<format>.program: "Pathname of the program to use".
        ("gpg", _, "program") => ("gpg[.<format>].program", GIT_CONFIG),
        // "This command will be run when user.signingkey is not set".
        ("gpg", Some(_), "defaultkeycommand") => ("gpg.ssh.defaultKeyCommand", GIT_CONFIG),
        // "a shell command that will be called once to automatically add a
        // trailer"; `.command` is its deprecated spelling.
        ("trailer", Some(_), "cmd" | "command") => {
            ("trailer.<key-alias>.<cmd|command>", GIT_CONFIG)
        }
        // Config-based hooks: "The command to execute for hook.<friendly-name>".
        ("hook", Some(_), "command") => ("hook.<friendly-name>.command", GIT_HOOK),
        // --sendmail-cmd, --to-cmd, --cc-cmd, --header-cmd, and --smtp-server
        // given as an absolute path to a sendmail-like program.
        ("sendemail", _, "sendmailcmd" | "tocmd" | "cccmd" | "headercmd" | "smtpserver") => (
            "sendemail.<sendmailCmd|toCmd|ccCmd|headerCmd|smtpServer>",
            GIT_SEND_EMAIL,
        ),
        // include.path / includeIf.<cond>.path pull in a file that may set any key above.
        ("include", None, "path") => ("include.path", GIT_CONFIG),
        ("includeif", Some(_), "path") => ("includeIf.<condition>.path", GIT_CONFIG),
        // The documentation notes git ignores this one outside protected config;
        // a repository that sets it is still asking for a hook to run.
        ("uploadpack", None, "packobjectshook") => ("uploadpack.packObjectsHook", GIT_CONFIG),
        ("remote", Some(_), "uploadpack") => ("remote.<name>.uploadpack", GIT_CONFIG),
        ("remote", Some(_), "receivepack") => ("remote.<name>.receivepack", GIT_CONFIG),
        // Selects the remote helper `git-remote-<vcs>` git executes.
        ("remote", Some(_), "vcs") => ("remote.<name>.vcs", GIT_CONFIG),
        // `protocol[.<name>].allow` can enable `ext::`, which runs a command.
        ("protocol", _, "allow") => ("protocol[.<name>].allow", GIT_CONFIG),
        // "!command": the remainder is run in a shell (git-config(1) submodule.*).
        ("submodule", Some(_), "update") if value.trim_start().starts_with('!') => {
            ("submodule.<name>.update=!<command>", GIT_CONFIG)
        }
        _ => return None,
    };
    Some(ExecKey { variable, doc })
}

/// One entry of a git config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEntry {
    /// Line indices this entry spans (a value may continue with `\`).
    pub lines: Range<usize>,
    /// `section[.sub].key=value`, section and key lower-cased.
    pub entry: String,
    /// The exec-bearing key it is, if any.
    pub exec: Option<ExecKey>,
}

/// Every entry of the git config `text`, in order.
#[must_use]
pub fn config_entries(text: &str) -> Vec<ConfigEntry> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let (mut section, mut sub) = (String::new(), None::<String>);
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        let line = lines[i].trim();
        i += 1;
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let head = rest.split(']').next().unwrap_or("").trim();
            match head.split_once(char::is_whitespace) {
                Some((s, q)) => {
                    section = s.to_ascii_lowercase();
                    sub = Some(q.trim().trim_matches('"').to_string());
                }
                None => match head.split_once('.') {
                    // Legacy `[section.sub]`.
                    Some((s, q)) => {
                        section = s.to_ascii_lowercase();
                        sub = Some(q.to_string());
                    }
                    None => {
                        section = head.to_ascii_lowercase();
                        sub = None;
                    }
                },
            }
            // `[section] key = value` on the header line.
            let after = rest.split_once(']').map_or("", |(_, a)| a.trim());
            if after.is_empty() || after.starts_with('#') || after.starts_with(';') {
                continue;
            }
            push_entry(&mut out, &section, sub.as_deref(), after, start..i);
            continue;
        }
        let mut value_end = lines[start];
        while value_end.trim_end().ends_with('\\') && i < lines.len() {
            value_end = lines[i];
            i += 1;
        }
        push_entry(&mut out, &section, sub.as_deref(), line, start..i);
    }
    out
}

fn push_entry(
    out: &mut Vec<ConfigEntry>,
    section: &str,
    sub: Option<&str>,
    line: &str,
    lines: Range<usize>,
) {
    let (key, value) = line
        .split_once('=')
        .map_or((line, ""), |(k, v)| (k.trim(), v.trim()));
    let key = key.to_ascii_lowercase();
    let exec = exec_key(section, sub, &key, value);
    let name = match sub {
        Some(q) => format!("{section}.{q}.{key}"),
        None => format!("{section}.{key}"),
    };
    out.push(ConfigEntry {
        lines,
        entry: format!("{name}={value}"),
        exec,
    });
}

/// Is `rel` (relative, `/`-separated) a git config file: `config` or
/// `config.worktree` inside a `.git` directory, a submodule's
/// `.git/modules/<name>/`, or a linked worktree's `.git/worktrees/<name>/`?
#[must_use]
pub fn is_git_config(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    let (dir, name) = lower.rsplit_once('/').unwrap_or(("", lower.as_str()));
    matches!(name, "config" | "config.worktree")
        && (dir == ".git" || dir.ends_with("/.git") || dir.contains(".git/"))
}

/// Is `rel` a git hook: a file under a `hooks` directory inside a `.git`
/// directory (the repository's own, or a submodule's under `.git/modules/`)?
/// Git's `*.sample` hooks are inert (git runs a hook only by its exact name)
/// and are never one.
#[must_use]
pub fn is_git_hook(rel: &str) -> bool {
    let lower = rel.trim_start_matches("./").to_ascii_lowercase();
    if lower.ends_with(".sample") {
        return false;
    }
    let parts: Vec<&str> = lower.split('/').collect();
    let Some(git) = parts.iter().position(|p| *p == ".git") else {
        return false;
    };
    // `hooks` after the `.git` segment and before the file's own name.
    parts[git + 1..parts.len().saturating_sub(1)].contains(&"hooks")
}

/// Directories inside a `.git` that hold data git reads but never executes.
/// Neither the consume guard nor the scan walks them: they are
/// content-addressed and can be enormous.
#[must_use]
pub fn is_git_data_dir(rel_dir: &str) -> bool {
    let lower = rel_dir.to_ascii_lowercase();
    let (parent, name) = lower.rsplit_once('/').unwrap_or(("", lower.as_str()));
    let in_git = parent == ".git" || parent.ends_with("/.git") || parent.contains(".git/");
    in_git && matches!(name, "objects" | "lfs" | "logs")
}

/// Directory entries the scan walks before it reports it could not look.
pub const SCAN_MAX_ENTRIES: usize = 1_000_000;

/// One thing a workspace carries that git would execute, or that points git
/// at a place the scan cannot see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A non-sample hook file.
    Hook {
        /// Workspace-relative path.
        path: String,
    },
    /// An exec-bearing entry in a git config file.
    ConfigKey {
        /// Workspace-relative path of the config file.
        path: String,
        /// `section[.sub].key=value` as written.
        entry: String,
        /// Which documented key it is.
        key: ExecKey,
    },
    /// A gitlink (`.git` file), a `commondir` file, or a symlink in the
    /// position of a git directory, config or hook, that points somewhere the
    /// scan does not read. "Could not look" is not "looked and it was fine"
    /// (ADR 0007 A-2), so it is a finding.
    PointsOutside {
        /// Workspace-relative path.
        path: String,
        /// Where it points, as written.
        target: String,
    },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::Hook { path } => write!(f, "{path} (git hook)"),
            Finding::ConfigKey { path, entry, key } => write!(
                f,
                "{path}: {entry} ({}, {} says git runs it)",
                key.variable, key.doc
            ),
            Finding::PointsOutside { path, target } => write!(
                f,
                "{path} -> {target} (points git at a directory outside the workspace, which \
                 was not scanned)"
            ),
        }
    }
}

/// Why a workspace could not be scanned. Never a pass (ADR 0007 A-3).
#[derive(Debug)]
pub enum ScanError {
    /// The workspace root is not a readable directory, or an entry under it
    /// could not be read.
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The error.
        error: std::io::Error,
    },
    /// More than [`SCAN_MAX_ENTRIES`] entries.
    TooLarge,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Io { path, error } => {
                write!(f, "could not read {}: {error}", path.display())
            }
            ScanError::TooLarge => write!(
                f,
                "the workspace has more than {SCAN_MAX_ENTRIES} entries, so it was not scanned \
                 to the end"
            ),
        }
    }
}

impl std::error::Error for ScanError {}

/// Scan the workspace at `root` for everything git would execute from it.
///
/// Symlinks are never followed: a symlink in the position of a git
/// directory, config or hook is a [`Finding::PointsOutside`]. Nothing outside
/// `root` is read. Only the data directories of [`is_git_data_dir`] are
/// skipped; `node_modules/` and `target/` are walked, because a workspace
/// handed in by someone else is exactly where hostile config would hide.
///
/// An empty `Ok` means the scan looked everywhere and found nothing.
///
/// # Errors
///
/// [`ScanError`] when it could not look everywhere.
pub fn scan(root: &Path) -> Result<Vec<Finding>, ScanError> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |error| ScanError::Io { path, error }
    };
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut stack: Vec<String> = vec![String::new()];
    while let Some(dir) = stack.pop() {
        let abs = if dir.is_empty() {
            root.to_path_buf()
        } else {
            root.join(&dir)
        };
        for entry in std::fs::read_dir(&abs).map_err(io(&abs))? {
            seen += 1;
            if seen > SCAN_MAX_ENTRIES {
                return Err(ScanError::TooLarge);
            }
            let entry = entry.map_err(io(&abs))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if dir.is_empty() {
                name.clone()
            } else {
                format!("{dir}/{name}")
            };
            // `file_type` does not follow a symlink.
            let kind = entry.file_type().map_err(io(&entry.path()))?;
            let lower_name = name.to_ascii_lowercase();
            let is_git_entry = lower_name == ".git";
            let in_git = rel.to_ascii_lowercase().contains(".git/");
            let is_commondir = lower_name == "commondir" && in_git;
            let watched = is_git_entry || is_commondir || is_git_config(&rel) || is_git_hook(&rel);
            if kind.is_symlink() {
                if watched || (in_git && lower_name == "hooks") {
                    let target = std::fs::read_link(entry.path())
                        .map(|t| t.to_string_lossy().into_owned())
                        .map_err(io(&entry.path()))?;
                    out.push(Finding::PointsOutside { path: rel, target });
                }
                continue;
            }
            if kind.is_dir() {
                if !is_git_data_dir(&rel) {
                    stack.push(rel);
                }
                continue;
            }
            if is_git_entry || is_commondir {
                // A gitlink file (`gitdir: <path>`) or a worktree's `commondir`:
                // git reads the config and hooks of the directory it names.
                let text = std::fs::read_to_string(entry.path()).map_err(io(&entry.path()))?;
                let target = text
                    .trim()
                    .strip_prefix("gitdir:")
                    .unwrap_or(text.trim())
                    .trim()
                    .to_string();
                let base = Path::new(&rel).parent().unwrap_or(Path::new(""));
                if !stays_inside(base, &target) {
                    out.push(Finding::PointsOutside { path: rel, target });
                }
                continue;
            }
            if is_git_hook(&rel) {
                out.push(Finding::Hook { path: rel });
                continue;
            }
            if is_git_config(&rel) {
                let path = entry.path();
                let text = std::fs::read(&path).map_err(io(&path))?;
                let text = String::from_utf8_lossy(&text);
                for e in config_entries(&text) {
                    if let Some(key) = e.exec {
                        out.push(Finding::ConfigKey {
                            path: rel.clone(),
                            entry: e.entry,
                            key,
                        });
                    }
                }
            }
        }
    }
    out.sort_by_cached_key(ToString::to_string);
    Ok(out)
}

/// Does `target`, read relative to the workspace-relative directory `base`,
/// stay inside the workspace? Lexical: an absolute target never does.
fn stays_inside(base: &Path, target: &str) -> bool {
    let target = Path::new(target);
    if target.is_absolute() || target.as_os_str().is_empty() {
        return false;
    }
    let mut depth: isize = 0;
    for c in base.join(target).components() {
        match c {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

#[cfg(test)]
#[path = "git_exec_tests.rs"]
mod tests;
