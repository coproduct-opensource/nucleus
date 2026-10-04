//! How CI invokes each gate, read from the workflows: the probe must run a gate the way CI runs
//! it, or it tests something CI does not run.
//!
//! Each reader reproduces one of the shell's `grep` pipelines, including what its command
//! substitution did to the result -- `$(...)` strips trailing newlines, so a list whose LAST
//! invocation is bare reads one line shorter. That is preserved rather than fixed so that the
//! port decides exactly what the script decided; `cmdsub_lines` is where it lives.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

/// `printf '%s\n' "$(printf '%s\n' "${items[@]}")"` read back as lines.
pub fn cmdsub_lines(items: &[String]) -> Vec<String> {
    let joined = items.join("\n");
    joined
        .trim_end_matches('\n')
        .split('\n')
        .map(str::to_string)
        .collect()
}

/// `$(...)` of the items: joined, trailing newlines stripped.
pub fn cmdsub(items: &[String]) -> String {
    items.join("\n").trim_end_matches('\n').to_string()
}

fn read(p: &Path) -> String {
    fs::read(p)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// Every file under `.github/workflows/`, recursively (`grep -r`).
fn workflow_files_recursive(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(&root.join(".github/workflows"), &mut out);
    out.sort();
    out
}

/// `.github/workflows/*.yml`, in glob order.
fn workflow_ymls(root: &Path) -> Vec<PathBuf> {
    glob_one(root, ".github/workflows", "", ".yml")
}

/// Files directly in `root/dir` (or in each immediate subdirectory when `sub` is `*`) ending in
/// `ext`, sorted.
fn glob_one(root: &Path, dir: &str, prefix: &str, ext: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(root.join(dir))
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(prefix) && n.ends_with(ext))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn is_comment(line: &str) -> bool {
    line.trim_start_matches([' ', '\t']).starts_with('#')
}

/// How many workflow files mention `scripts/<gate>` at all.
pub fn script_workflow_hits(root: &Path, gate: &str) -> usize {
    let needle = format!("scripts/{gate}");
    workflow_files_recursive(root)
        .iter()
        .filter(|f| read(f).contains(&needle))
        .count()
}

/// Every non-comment invocation of `scripts/<gate>`, flags only.
pub fn script_invocations(root: &Path, gate: &str) -> Vec<String> {
    let needle = format!("scripts/{gate}");
    let re = Regex::new(&format!(r#"scripts/{}[^"'`)]*"#, regex::escape(gate)))
        .unwrap_or_else(|e| panic!("{e}"));
    let mut out = Vec::new();
    for f in workflow_files_recursive(root) {
        for line in read(&f).lines() {
            if !line.contains(&needle) || is_comment(line) {
                continue;
            }
            for m in re.find_iter(line) {
                let flags = m.as_str().replacen(&needle, "", 1);
                out.push(flags.trim().to_string());
            }
        }
    }
    cmdsub_lines(&out)
}

fn extract_xtask(lines: impl Iterator<Item = String>, sub: &str) -> Vec<String> {
    let lead = format!("xtask -- {sub}");
    let re = Regex::new(&format!(r#"xtask -- {}[^"'`|]*"#, regex::escape(sub)))
        .unwrap_or_else(|e| panic!("{e}"));
    let mut out = Vec::new();
    for line in lines {
        if !line.contains(&lead) || is_comment(&line) {
            continue;
        }
        for m in re.find_iter(&line) {
            out.push(m.as_str().replacen(&lead, "", 1).trim().to_string());
        }
    }
    out
}

/// The invocations of `xtask -- <sub>` in the workflows, a line at a time.
pub fn xtask_invocations(root: &Path, sub: &str) -> Vec<String> {
    let lines: Vec<String> = workflow_ymls(root)
        .iter()
        .flat_map(|f| read(f).lines().map(str::to_string).collect::<Vec<_>>())
        .collect();
    extract_xtask(lines.into_iter(), sub)
}

/// The same, with backslash continuations joined FIRST and runs of spaces squeezed. A workflow
/// may spell the invocation over several lines (`ck-admit.yml` writes `policy-gate` that way),
/// and a line-at-a-time scan then reports the flags CI uses as `\`.
pub fn xtask_invocations_joined(root: &Path, sub: &str) -> Vec<String> {
    let mut stream = String::new();
    for f in workflow_ymls(root) {
        let t = read(&f);
        stream.push_str(&t);
        if !t.is_empty() && !t.ends_with('\n') {
            stream.push('\n');
        }
    }
    let mut joined: Vec<String> = Vec::new();
    let mut cur: Option<String> = None;
    for line in stream.lines() {
        let piece = match cur.take() {
            Some(mut acc) => {
                acc.push(' ');
                acc.push_str(line.trim_start());
                acc
            }
            None => line.to_string(),
        };
        if let Some(stripped) = piece.strip_suffix('\\') {
            cur = Some(stripped.to_string());
        } else {
            joined.push(piece);
        }
    }
    if let Some(rest) = cur {
        joined.push(format!("{rest}\\"));
    }
    let squeezed = joined.into_iter().map(|l| {
        let mut s = String::with_capacity(l.len());
        let mut prev_space = false;
        for c in l.chars() {
            if c == ' ' && prev_space {
                continue;
            }
            prev_space = c == ' ';
            s.push(c);
        }
        s
    });
    extract_xtask(squeezed, sub)
}

/// Is `xtask -- <sub>` on any non-comment workflow line at all?
pub fn xtask_mentioned(root: &Path, sub: &str) -> bool {
    let lead = format!("xtask -- {sub}");
    workflow_ymls(root)
        .iter()
        .any(|f| read(f).lines().any(|l| l.contains(&lead) && !is_comment(l)))
}

/// The xtask half of the domain, derived from what CI runs: every `xtask -- <sub>` on a
/// non-comment stretch of a workflow, a script, or a composite action. The prober itself is
/// not a subject.
pub fn xtask_domain(root: &Path) -> BTreeSet<String> {
    let re = Regex::new(r"xtask -- ([a-z][a-z-]*)").unwrap_or_else(|e| panic!("{e}"));
    let mut files = workflow_ymls(root);
    files.extend(glob_one(root, "scripts", "", ".sh"));
    if let Ok(rd) = fs::read_dir(root.join(".github/actions")) {
        let mut dirs: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for d in dirs {
            let rel = d
                .strip_prefix(root)
                .unwrap_or(&d)
                .to_string_lossy()
                .into_owned();
            files.extend(glob_one(root, &rel, "", ".sh"));
            files.extend(glob_one(root, &rel, "", ".yml"));
        }
    }
    let mut out = BTreeSet::new();
    for f in files {
        for line in read(&f).lines() {
            // `^[^#]*xtask -- ...`: only the stretch before the first `#` counts.
            let head = line.split('#').next().unwrap_or("");
            for c in re.captures_iter(head) {
                out.insert(c[1].to_string());
            }
        }
    }
    out.remove(super::SELF_SUB);
    out
}

/// `scripts/check-*.sh`, by name, sorted.
pub fn gate_scripts(root: &Path) -> Vec<String> {
    glob_one(root, "scripts", "check-", ".sh")
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trailing_bare_invocation_is_lost_to_the_command_substitution() {
        // The shell's own behaviour, kept: `$(...)` strips the final newline, so ["--x", ""]
        // reads as one line and the bare invocation is not seen.
        assert_eq!(cmdsub_lines(&["--x".into(), String::new()]), vec!["--x"]);
        assert_eq!(
            cmdsub_lines(&[String::new(), "--x".into()]),
            vec!["", "--x"]
        );
        assert_eq!(cmdsub_lines(&[]), vec![""]);
    }

    #[test]
    fn a_comment_line_is_not_an_invocation() {
        let got = extract_xtask(
            [
                "  # xtask -- foo --bar".to_string(),
                "run: cargo xtask -- foo --baz".to_string(),
            ]
            .into_iter(),
            "foo",
        );
        assert_eq!(got, vec!["--baz"]);
    }
}
