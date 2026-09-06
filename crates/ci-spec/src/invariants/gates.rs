//! I6 — gate integrity: can each inline gate actually fail?
//!
//! A port of proofcard's Gate-Integrity rules (GI001–GI005, from the sibling
//! `proof-carrying` repository, where they were tuned against 30 public
//! repositories) plus one rule the 2026-09-05 inventory earned:
//!
//! | rule | severity | shape |
//! |---|---|---|
//! | GI001 | Critical | `V=$(cmd \|\| true)` feeding a verdict that emptiness satisfies |
//! | GI002 | High | `if grep … ; then exit 1` with nothing establishing the searched content arrived |
//! | GI003 | High | `cargo/lake/make … \| tee` under the default shell (no pipefail) |
//! | GI004 | Critical/Medium | `continue-on-error` on a gate (step scope / job scope) |
//! | GI005 | Medium | a swallowed status guarded by matching known failure text |
//! | GI006 | Critical/High | a NUMERIC test on an operand nothing proved is a non-empty integer |
//!
//! GI006 is the Proof Count Ratchet's bug class, and it corrects a claim in
//! proofcard: `[ "$V" -ne "$EXPECTED" ]` is NOT fail-closed on an empty `$V`.
//! `[` prints "integer expression expected", returns 2, and an `if` reads 2
//! as false — so the `then exit 1` never runs and the gate passes. Only
//! STRING comparisons (`!=`, `=`) are fail-closed on emptiness. A numeric
//! verdict needs its operand established first: a producer that cannot yield
//! anything but an integer (`… | wc -l`, `grep -c` on a file, an `awk … +0`
//! sum), or an explicit `[[ "$V" =~ ^[0-9]+$ ]] || exit 1`. Critical when the
//! operand is arithmetic over an unestablished input or a swallowed status
//! (the ratchet's exact shape); High when it is merely unproven (an empty
//! pin file read with `cat`).
//!
//! Every rule here is heuristic and stated as such; the false-positive
//! lessons proofcard recorded are kept: a `|| true` on a *search* is
//! idiomatic; the guard must be about the subject it names, plus one hop of
//! dataflow; negated greps are fail-closed; a grep for a *failure signature*
//! is a guard, not a verdict. Known limits: cross-STEP dataflow is not
//! modelled (a `lake build` in the previous step establishing that the files
//! a later grep reads exist), so such findings are allowlisted with that
//! reason rather than "fixed".

use crate::model::{Model, Step};
use crate::{Finding, Severity};

use super::finding;

// ── shell text ────────────────────────────────────────────────────────────

/// Strip a trailing comment, respecting quotes well enough for one-liners.
pub fn strip_comment(line: &str) -> &str {
    let b = line.as_bytes();
    let (mut sq, mut dq) = (false, false);
    for i in 0..b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'#' if !sq && !dq && (i == 0 || b[i - 1].is_ascii_whitespace()) => {
                return &line[..i];
            }
            _ => {}
        }
    }
    line
}

/// Join backslash-continued lines. Returns `(joined text, original line
/// offset)` per logical line, so findings still point at the first physical
/// line. `cargo llvm-cov … \` + `… | tee log` is ONE pipeline; analysing the
/// halves separately missed exactly the fail-open the inventory found.
fn logical_lines(script: &str) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = Vec::new();
    let mut acc: Option<(String, usize)> = None;
    for (i, raw) in script.lines().enumerate() {
        let trimmed_end = raw.trim_end();
        let continues = trimmed_end.ends_with('\\');
        let body = if continues {
            trimmed_end[..trimmed_end.len() - 1].to_string()
        } else {
            raw.to_string()
        };
        match acc.take() {
            None => {
                if continues {
                    acc = Some((body, i));
                } else {
                    out.push((body, i));
                }
            }
            Some((mut s, start)) => {
                let end = s.trim_end().len();
                s.truncate(end);
                s.push(' ');
                s.push_str(body.trim_start());
                if continues {
                    acc = Some((s, start));
                } else {
                    out.push((s, start));
                }
            }
        }
    }
    if let Some(a) = acc {
        out.push(a);
    }
    out
}

fn swallows_exit(s: &str) -> bool {
    s.contains("|| true") || s.contains("|| :") || s.contains("||true") || s.contains("|| echo")
}

fn var_name(t: &str) -> Option<String> {
    let eq = t.find('=')?;
    let lhs = t[..eq].trim();
    let name = lhs
        .trim_start_matches("local ")
        .trim_start_matches("export ")
        .trim();
    if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
        return None;
    }
    Some(name.to_string())
}

fn rhs_of(t: &str) -> &str {
    match t.find('=') {
        Some(eq) => t[eq + 1..].trim(),
        None => "",
    }
}

/// `VAR="$( ... || true)"` — the variable, when the substitution swallows its status.
fn tainted_assignment(line: &str) -> Option<String> {
    let t = strip_comment(line).trim();
    let name = var_name(t)?;
    let rhs = rhs_of(t);
    if !rhs.contains("$(") || rhs.starts_with("$((") {
        return None;
    }
    if swallows_exit(rhs) && !searches_only(rhs) {
        Some(name)
    } else {
        None
    }
}

/// `VAR=$(...)` or `VAR=$((...))` — an operand of computed shape.
fn computed_assignment(line: &str) -> Option<String> {
    let t = strip_comment(line).trim();
    let name = var_name(t)?;
    if rhs_of(t).contains("$(") {
        Some(name)
    } else {
        None
    }
}

/// Is the swallowed command nothing but a search? `grep` exits non-zero to
/// mean NO MATCH, so `|| true` restores that case under `set -e`.
fn searches_only(rhs: &str) -> bool {
    let body = substitution_body(rhs);
    matches!(last_command(body), "grep" | "rg" | "egrep" | "fgrep" | "ag")
}

fn substitution_body(rhs: &str) -> &str {
    let s = rhs
        .trim()
        .trim_start_matches('"')
        .trim_end_matches('"')
        .trim();
    let s = s.strip_prefix("$(").unwrap_or(s);
    let s = s.strip_suffix(')').unwrap_or(s);
    s.trim()
}

/// The command whose status a substitution yields: the pipeline's tail, before `||`.
fn last_command(body: &str) -> &str {
    let mut start = 0usize;
    let (mut sq, mut dq) = (false, false);
    let b = body.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'|' if !sq && !dq => {
                if b.get(i + 1).copied() == Some(b'|') {
                    return body[start..i].split_whitespace().next().unwrap_or("");
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    body[start..].split_whitespace().next().unwrap_or("")
}

/// The last pipeline stage's full text (before any `||`).
fn last_stage(body: &str) -> &str {
    let mut start = 0usize;
    let (mut sq, mut dq) = (false, false);
    let b = body.as_bytes();
    let mut i = 0usize;
    let mut end = b.len();
    while i < b.len() {
        match b[i] {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'|' if !sq && !dq => {
                if b.get(i + 1).copied() == Some(b'|') {
                    end = i;
                    break;
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    body[start..end].trim()
}

fn mentions(t: &str, var: &str) -> bool {
    t.contains(&format!("${var}")) || t.contains(&format!("${{{var}}}"))
}

const NUMERIC_OPS: [&str; 6] = ["-ne ", "-eq ", "-lt ", "-gt ", "-le ", "-ge "];

/// Does a verdict on `var` pass when `var` is empty?
///
/// | verdict | empty input | |
/// |---|---|---|
/// | `if … grep -q BAD; then exit 1` | no match, no exit | fail-open |
/// | `if [ -n "$V" ]; then exit 1` | no exit | fail-open |
/// | `if [ "$V" -ne "$E" ]; then exit 1` | `[` errors → false → no exit | **fail-open** (GI006) |
/// | `if [ "$V" != "$E" ]; then exit 1` | `"" != "3"` → exit | fail-closed |
/// | `if [ -z "$V" ]; then exit 1` | exits | fail-closed |
fn verdict_passes_on_empty(line: &str, var: &str) -> bool {
    let t = strip_comment(line);
    if !mentions(t, var) {
        return false;
    }
    let d = t.trim_start();
    if !(d.starts_with("if ") || d.starts_with("elif ")) {
        return false;
    }
    if d.contains("-z ") {
        return false;
    }
    for cmp in ["!= ", "== ", " = "] {
        if d.contains(cmp) {
            return false;
        }
    }
    if NUMERIC_OPS.iter().any(|op| d.contains(op)) {
        return true;
    }
    d.contains("grep") || d.contains("-n ")
}

/// How well an operand's source establishes it as an integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntSource {
    /// Cannot be anything but an integer (`wc -l`, `grep -c FILE`, a literal).
    Guaranteed,
    /// Could be empty or non-numeric (`cat pin`, `head -1`, unknown tool).
    Unproven,
    /// Arithmetic over an unproven input, or a swallowed status with a
    /// non-integer shape — the ratchet's own bug.
    Broken,
}

/// Classify the value `$(...)` / `$((...))` on the right-hand side.
/// `self_var` is the variable being assigned, so `total=$((total + n))` reads
/// as a self-update (its base definition is judged on its own line).
fn int_source(
    lines: &[(String, usize)],
    rhs: &str,
    depth: usize,
    self_var: Option<&str>,
) -> IntSource {
    if depth > 4 {
        return IntSource::Unproven;
    }
    let rhs = rhs.trim().trim_matches('"');
    if let Some(inner) = rhs.strip_prefix("$((").and_then(|s| s.strip_suffix("))")) {
        // Arithmetic: every identifier must itself be an integer.
        let mut worst = IntSource::Guaranteed;
        for tok in inner.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if tok.is_empty() || tok.bytes().all(|b| b.is_ascii_digit()) || Some(tok) == self_var {
                continue;
            }
            let src = source_of_var(lines, tok, depth + 1);
            worst = match (worst, src) {
                (_, IntSource::Broken) | (IntSource::Broken, _) => IntSource::Broken,
                (_, IntSource::Unproven) | (IntSource::Unproven, _) => IntSource::Broken,
                _ => IntSource::Guaranteed,
            };
        }
        return worst;
    }
    if !rhs.contains("$(") {
        // A literal or a plain variable.
        if rhs.bytes().all(|b| b.is_ascii_digit()) && !rhs.is_empty() {
            return IntSource::Guaranteed;
        }
        if let Some(v) = rhs.strip_prefix('$') {
            let v = v.trim_matches(|c| c == '{' || c == '}');
            return source_of_var(lines, v, depth + 1);
        }
        return IntSource::Unproven;
    }
    let body = substitution_body(rhs);
    let swallowed = swallows_exit(body);
    let stage = last_stage(body);
    let head = stage.split_whitespace().next().unwrap_or("");
    // A recursive `grep -c` over a DIRECTORY prints `path:count` per file —
    // not an integer — and with `|| echo 0` the shape is the ratchet's bug.
    let first = body.split('|').next().unwrap_or("").trim();
    let first_head = first.split_whitespace().next().unwrap_or("");
    if matches!(first_head, "grep" | "egrep" | "fgrep")
        && first
            .split_whitespace()
            .any(|a| a.starts_with('-') && a.contains('r') && a.contains('c'))
        && first
            .split_whitespace()
            .last()
            .is_some_and(|p| p.ends_with('/') || !p.contains('.'))
        && stage == first
    {
        return IntSource::Broken;
    }
    match head {
        "wc" => IntSource::Guaranteed,
        "tr" | "xargs" | "sed" | "cut" => {
            // Post-processing: inherit from the stage before.
            let prev = body.rsplit(" | ").nth(1).unwrap_or("");
            let ph = prev.split_whitespace().next().unwrap_or("");
            match ph {
                "wc" => IntSource::Guaranteed,
                "grep"
                    if prev
                        .split_whitespace()
                        .any(|a| a.starts_with('-') && a.contains('c')) =>
                {
                    IntSource::Guaranteed
                }
                "cat" => IntSource::Unproven,
                _ => IntSource::Unproven,
            }
        }
        "grep" | "egrep" | "fgrep" => {
            if stage
                .split_whitespace()
                .any(|a| a.starts_with('-') && a.contains('c'))
            {
                IntSource::Guaranteed
            } else if swallowed {
                IntSource::Broken
            } else {
                IntSource::Unproven
            }
        }
        "awk" => {
            if stage.contains("+0") {
                IntSource::Guaranteed
            } else {
                IntSource::Unproven
            }
        }
        _ => {
            if swallowed {
                IntSource::Broken
            } else {
                IntSource::Unproven
            }
        }
    }
}

fn source_of_var(lines: &[(String, usize)], var: &str, depth: usize) -> IntSource {
    let mut best: Option<IntSource> = None;
    for (l, _) in lines {
        let t = strip_comment(l).trim();
        if var_name(t).as_deref() != Some(var) {
            continue;
        }
        let src = int_source(lines, rhs_of(t), depth, Some(var));
        best = Some(match best {
            None => src,
            Some(b) => {
                if src == IntSource::Broken || b == IntSource::Broken {
                    IntSource::Broken
                } else if src == IntSource::Unproven || b == IntSource::Unproven {
                    IntSource::Unproven
                } else {
                    IntSource::Guaranteed
                }
            }
        });
    }
    best.unwrap_or(IntSource::Unproven)
}

/// Does `var` get established as a non-empty integer somewhere in the block?
fn integer_guarded(lines: &[(String, usize)], var: &str) -> bool {
    let texts: Vec<&str> = lines.iter().map(|(l, _)| l.as_str()).collect();
    for (i, raw) in texts.iter().enumerate() {
        let t = strip_comment(raw);
        if !mentions(t, var) {
            continue;
        }
        let d = t.trim_start();
        if t.contains("=~") && t.contains("[0-9]") {
            if t.contains("|| exit") || t.contains("|| {") {
                return true;
            }
            if d.starts_with("if ") && then_branch_fails(&texts, i) {
                return true;
            }
        }
        if d.starts_with("if ") && t.contains("-z ") && then_branch_fails(&texts, i) {
            return true;
        }
        if t.contains("-n ") && (t.contains("|| exit") || t.contains("|| {")) {
            return true;
        }
        if d.starts_with("case ") && t.contains("[!0-9]") {
            return true;
        }
    }
    false
}

/// Does the block assert that `subject` is non-empty / present, or count what
/// it holds against a declared expectation? One hop of dataflow, including
/// `for x in $SUBJECT`.
fn has_emptiness_guard(lines: &[(String, usize)], subject: &str) -> bool {
    if subject.is_empty() {
        return false;
    }
    let texts: Vec<&str> = lines.iter().map(|(l, _)| l.as_str()).collect();
    let mut derived: Vec<String> = Vec::new();
    for raw in &texts {
        let t = strip_comment(raw);
        if !t.contains(subject) {
            continue;
        }
        if let Some(name) = var_name(t.trim()) {
            derived.push(format!("${name}"));
        }
        let d = t.trim_start();
        if let Some(rest) = d.strip_prefix("for ") {
            if let Some(v) = rest.split_whitespace().next() {
                derived.push(format!("${v}"));
            }
        }
    }
    let mentions_any =
        |t: &str| t.contains(subject) || derived.iter().any(|d| t.contains(d.as_str()));

    for (i, raw) in texts.iter().enumerate() {
        let t = strip_comment(raw);
        let d = t.trim_start();
        if !mentions_any(t) {
            continue;
        }
        let fails_after = t.contains("|| exit") || t.contains("|| {");
        if d.starts_with("if ") && t.contains("-z ") && then_branch_fails(&texts, i) {
            return true;
        }
        if (t.contains("! -s ") || t.contains("! -f "))
            && d.starts_with("if ")
            && then_branch_fails(&texts, i)
        {
            return true;
        }
        if (t.contains("-s ") || t.contains("-f "))
            && (d.starts_with("if !") && then_branch_fails(&texts, i) || fails_after)
        {
            return true;
        }
        let grepq = t.contains("grep -q") || t.contains("grep -Eq") || t.contains("grep -qE");
        if grepq && ((d.starts_with("if !") && then_branch_fails(&texts, i)) || fails_after) {
            return true;
        }
        if compares_against_an_expectation(t) {
            return true;
        }
    }
    false
}

/// A count compared against something the author declared they expected.
/// `-ne 0` is not a guard: zero is what an empty result gives you. A string
/// comparison against another variable (`[ "$printed" != "$extracted" ]`)
/// counts too: it is fail-closed on emptiness and pins two measurements to
/// each other.
fn compares_against_an_expectation(line: &str) -> bool {
    for op in ["!= ", " = ", "== "] {
        let Some(rest) = line.split(op).nth(1) else {
            continue;
        };
        let rhs = rest
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(|c| c == '"' || c == '\'' || c == ']');
        if rhs.starts_with('$') && line.contains("[ ") {
            return true;
        }
    }
    for op in NUMERIC_OPS {
        let Some(rest) = line.split(op).nth(1) else {
            continue;
        };
        let rhs = rest
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(|c| c == '"' || c == '\'');
        if rhs.starts_with('$') {
            return true;
        }
        if let Ok(n) = rhs.parse::<i64>() {
            if n != 0 {
                return true;
            }
        }
    }
    false
}

const FAILURE_SIGNATURES: [&str; 3] = [
    "could not compile",
    "Compilation failed",
    "command not found",
];

fn failure_signature_guard(script: &str) -> bool {
    FAILURE_SIGNATURES.iter().any(|s| script.contains(s))
}

/// Does the `then` branch opened at `idx` contain the failure? Stops at the
/// matching `fi`, and at `else`.
fn then_branch_fails(lines: &[&str], idx: usize) -> bool {
    let mut depth = 0i32;
    for l in &lines[idx..] {
        let t = strip_comment(l);
        let d = t.trim();
        if d.starts_with("if ") {
            depth += 1;
        }
        if d == "fi" || d.starts_with("fi ") || d.starts_with("fi;") {
            depth -= 1;
            if depth <= 0 {
                return false;
            }
        }
        if depth == 1 && (d == "else" || d.starts_with("else")) {
            return false;
        }
        if depth >= 1 && (t.contains("exit 1") || t.contains("::error::")) {
            return true;
        }
    }
    false
}

fn is_redirection(tok: &str) -> bool {
    tok.starts_with('>')
        || tok.starts_with('<')
        || tok.starts_with("2>")
        || tok.starts_with("1>")
        || tok.starts_with("&>")
}

/// What this verdict reads: a variable, or the last path/file handed to `grep`.
fn verdict_subject(line: &str) -> Option<String> {
    let body = line.trim();
    for tok in body.split_whitespace() {
        if let Some(p) = tok.find('$') {
            let rest = &tok[p + 1..];
            let name: String = rest
                .trim_start_matches('{')
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(format!("${name}"));
            }
        }
    }
    let head = body.split("; then").next().unwrap_or(body);
    head.split_whitespace()
        .rfind(|t| {
            (t.contains('/') || t.contains('.')) && !t.starts_with('-') && !is_redirection(t)
        })
        .map(|t| t.trim_matches('"').to_string())
}

fn searched_thing(line: &str) -> String {
    let before = line.split("grep").next().unwrap_or("");
    for tok in before.split_whitespace() {
        let c = tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '$' && c != '_');
        if let Some(name) = c.strip_prefix('$') {
            let name = name.trim_matches(|c| c == '{' || c == '}');
            if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return format!("`${name}`");
            }
        }
    }
    "the searched input".to_string()
}

/// A pipeline whose left side does real work.
fn masks_pipeline_exit(line: &str) -> Option<String> {
    let t = strip_comment(line).trim();
    let bar = t.find(" | ")?;
    let lhs = t[..bar].trim();
    for safe in [
        "echo",
        "printf",
        "cat",
        "true",
        "yes",
        "ls",
        "find",
        "git diff --name-only",
        "git ls-files",
    ] {
        if lhs.starts_with(safe) {
            return None;
        }
    }
    for verb in [
        "lake ", "cargo ", "make ", "go ", "npm ", "python", "./", "bash ", "uvx ", "lean ",
    ] {
        if lhs.starts_with(verb) || lhs.contains(&format!(" {verb}")) {
            return Some(lhs.to_string());
        }
    }
    None
}

/// A grep verdict line, in the non-negated fail-when-found form.
fn positive_grep_verdict(t: &str) -> bool {
    let d = t.trim_start();
    if !d.starts_with("if ") || d.starts_with("if !") {
        return false;
    }
    if t.contains("&& ") {
        return false;
    }
    // A grep for a FAILURE SIGNATURE is a guard (GI005's subject), not a verdict.
    if FAILURE_SIGNATURES.iter().any(|s| t.contains(s)) {
        return false;
    }
    t.contains("grep -q")
        || t.contains("grep -Eq")
        || t.contains("grep -qE")
        || t.contains("grep -rn")
        || t.contains("grep -rE")
        || t.contains("grep -rnE")
}

// ── the rule engine ───────────────────────────────────────────────────────

/// Analyse one step. `job_coe` is the job's `continue-on-error` line when
/// set at job scope.
pub fn check_step(
    workflow: &str,
    job_id: &str,
    job_coe: Option<usize>,
    step: &Step,
) -> Vec<Finding> {
    let mut out = Vec::new();
    if !step.is_gate() {
        return out;
    }
    let Some(script) = step.run.as_deref() else {
        return out;
    };
    let subject = format!("{job_id}/{}", step.name);
    let job = job_id.to_string();

    if step.continue_on_error {
        out.push(
            finding(
                "GI004",
                Severity::Critical,
                workflow,
                step.line,
                &subject,
                "this step fails deliberately (`exit 1` / `::error::`), but `continue-on-error` \
                 on the step means the job passes anyway — a gate neutered inside a job that \
                 otherwise blocks. It reports; it does not gate"
                    .into(),
                "remove continue-on-error, or stop calling this a gate",
            )
            .in_job(&job),
        );
    } else if let Some(l) = job_coe {
        out.push(
            finding(
                "GI004",
                Severity::Medium,
                workflow,
                l,
                &format!("job `{job_id}`"),
                format!(
                    "job `{job_id}` is advisory: nothing it decides can fail the workflow, so \
                     this gate's `exit 1` changes no outcome"
                ),
                "if the advisory period is deliberate, say so where the job is declared and \
                 give it an end condition; otherwise make the job blocking",
            )
            .in_job(&job),
        );
    }

    let lines = logical_lines(script);
    let texts: Vec<&str> = lines.iter().map(|(l, _)| l.as_str()).collect();
    for (i, (raw, off)) in lines.iter().enumerate() {
        let lineno = step.line + off + 1;
        let t = strip_comment(raw);

        // GI001 / GI005 — a swallowed exit code reaching a verdict.
        if let Some(var) = tainted_assignment(raw) {
            // One hop UPSTREAM as well: `bad=$(printf '%s' "$flat" | grep …)`
            // is guarded if `$flat` (or a value derived from it) was pinned
            // against a declared expectation before `bad` was computed.
            let upstream: Vec<String> = rhs_of(t.trim())
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '{'))
                .filter_map(|tok| {
                    tok.strip_prefix('$')
                        .map(|v| format!("${}", v.trim_start_matches('{')))
                })
                .filter(|v| v.len() > 1)
                .collect();
            let guarded = has_emptiness_guard(&lines, &format!("${var}"))
                || upstream.iter().any(|u| has_emptiness_guard(&lines, u));
            let reaches = texts[i + 1..]
                .iter()
                .any(|l| verdict_passes_on_empty(l, &var))
                && !guarded;
            if reaches && failure_signature_guard(script) {
                out.push(
                    finding(
                        "GI005",
                        Severity::Medium,
                        workflow,
                        lineno,
                        &subject,
                        format!(
                            "`${var}`'s exit status is discarded, and the guard that compensates \
                             matches known failure text; a failure printing neither signature \
                             yields an empty `${var}`, a zero count, and a pass"
                        ),
                        "assert the expected result ARRIVED rather than enumerating the ways it \
                         can fail",
                    )
                    .in_job(&job),
                );
            } else if reaches {
                out.push(
                    finding(
                        "GI001",
                        Severity::Critical,
                        workflow,
                        lineno,
                        &subject,
                        format!(
                            "`${var}` is assigned from a command substitution whose exit status \
                             is discarded, then used to decide whether this step passes. If that \
                             command fails, `${var}` is empty — and the verdict is satisfied BY \
                             emptiness, so the gate PASSES"
                        ),
                        "drop the `|| true` and fail explicitly on a non-zero exit; then assert \
                         the output is what you expected, not merely that it lacks a bad string",
                    )
                    .in_job(&job),
                );
            }
        }

        // GI006 — a numeric verdict on an operand nothing established.
        if let Some(var) = computed_assignment(raw) {
            let verdict_at = texts[i + 1..].iter().enumerate().find(|(_, l)| {
                let lt = strip_comment(l);
                let d = lt.trim_start();
                (d.starts_with("if ") || d.starts_with("elif "))
                    && mentions(lt, &var)
                    && NUMERIC_OPS.iter().any(|op| lt.contains(op))
            });
            if let Some((k, _)) = verdict_at {
                let fails = then_branch_fails(&texts, i + 1 + k);
                if fails && !integer_guarded(&lines, &var) {
                    let src = int_source(&lines, rhs_of(t.trim()), 0, Some(&var));
                    if src != IntSource::Guaranteed {
                        let (sev, why) = match src {
                            IntSource::Broken => (
                                Severity::Critical,
                                format!(
                                    "`${var}` is arithmetic over (or a swallowed status from) a \
                                     producer that need not yield an integer, then compared \
                                     numerically. `[ \"\" -lt N ]` prints \"integer expression \
                                     expected\", returns 2, and `if` reads that as false — the \
                                     failing branch never runs and the gate PASSES on a broken \
                                     measurement (the Proof Count Ratchet's exact shape)"
                                ),
                            ),
                            _ => (
                                Severity::High,
                                format!(
                                    "`${var}` is compared numerically but nothing proves it is a \
                                     non-empty integer (an empty file read with `cat`, a `head` \
                                     of nothing). `[ \"\" -lt N ]` errors, `if` reads that as \
                                     false, and the gate PASSES"
                                ),
                            ),
                        };
                        out.push(
                            finding(
                                "GI006",
                                sev,
                                workflow,
                                lineno,
                                &subject,
                                why,
                                "establish the operand first: `[[ \"$V\" =~ ^[0-9]+$ ]] || { echo \
                                 \"::error::…\"; exit 1; }`",
                            )
                            .in_job(&job),
                        );
                    }
                }
            }
        }

        // GI002 — a grep verdict where FINDING NOTHING is what passes.
        if positive_grep_verdict(t) {
            let searched = searched_thing(t);
            let guarded = verdict_subject(t).is_some_and(|s| has_emptiness_guard(&lines, &s));
            if !guarded && then_branch_fails(&texts, i) {
                out.push(
                    finding(
                        "GI002",
                        Severity::High,
                        workflow,
                        lineno,
                        &subject,
                        format!(
                            "this gate fails when the pattern IS found, so finding nothing is what \
                             makes it pass — and nothing here establishes that {searched} \
                             contained what it should. An empty or missing producer (a renamed \
                             file makes grep exit 2, which `if` reads as false) is \
                             indistinguishable from a clean result"
                        ),
                        "assert the expected content arrived — a file-count floor, a `test -s`, \
                         or a count against a declared expectation — before concluding from \
                         absence",
                    )
                    .in_job(&job),
                );
            }
        }

        // GI003 — a pipeline masking the exit status that matters.
        if !step.pipefail() {
            if let Some(lhs) = masks_pipeline_exit(raw) {
                out.push(
                    finding(
                        "GI003",
                        Severity::High,
                        workflow,
                        lineno,
                        &subject,
                        format!(
                            "`{lhs}` is piped, and this step runs under GitHub's DEFAULT shell \
                             (`bash -e {{0}}`): errexit but NOT pipefail. The pipeline reports \
                             the LAST command's status, so a failure of `{lhs}` passes"
                        ),
                        "add `shell: bash` to the step (GitHub then uses `-eo pipefail`), or \
                         `set -o pipefail` in the script",
                    )
                    .in_job(&job),
                );
            }
        }
    }
    out
}

pub fn check(m: &Model) -> Vec<Finding> {
    let mut out = Vec::new();
    for w in &m.workflows {
        for j in &w.jobs {
            let job_coe = if j.continue_on_error {
                Some(j.line)
            } else {
                None
            };
            let mut seen_job_coe = false;
            for s in &j.steps {
                for f in check_step(&w.path, &j.id, job_coe, s) {
                    if f.rule == "GI004" && f.severity == Severity::Medium {
                        if seen_job_coe {
                            continue;
                        }
                        seen_job_coe = true;
                    }
                    out.push(f);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_lines_join_continuations() {
        let l = logical_lines("cargo x \\\n  --flag 2>&1 | tee log\necho ok");
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].0, "cargo x --flag 2>&1 | tee log");
        assert_eq!(l[0].1, 0);
        assert_eq!(l[1].1, 2);
    }

    #[test]
    fn int_sources() {
        let lines = logical_lines(
            "FILES=$(find x -name '*.lean' | wc -l | tr -d ' ')\n\
             CORE=$(grep -rc '#[kani::proof]' crates/portcullis-core/src/ || echo 0)\n\
             TOTAL=$((66 + CORE))\n\
             PIN=$(cat .pin | tr -d '[:space:]')\n\
             N=$(printf '%s\\n' \"$out\" | grep -c 'warning' || true)",
        );
        assert_eq!(source_of_var(&lines, "FILES", 0), IntSource::Guaranteed);
        assert_eq!(source_of_var(&lines, "CORE", 0), IntSource::Broken);
        assert_eq!(source_of_var(&lines, "TOTAL", 0), IntSource::Broken);
        assert_eq!(source_of_var(&lines, "PIN", 0), IntSource::Unproven);
        assert_eq!(source_of_var(&lines, "N", 0), IntSource::Guaranteed);
    }

    #[test]
    fn verdict_subject_skips_redirections_and_flags() {
        assert_eq!(
            verdict_subject("if grep -q \"SURVIVED\" /tmp/mutants.txt 2>/dev/null; then")
                .as_deref(),
            Some("/tmp/mutants.txt")
        );
        assert_eq!(
            verdict_subject("if grep -rnE 'p' --include='*.lean' crates/ck-policy/lean/Ck; then")
                .as_deref(),
            Some("crates/ck-policy/lean/Ck")
        );
    }
}
