//! The Lean half: theorem statements, and the Rust function each Aeneas-generated `def`
//! extracts.
//!
//! Which modules exist is not decided here: the tiers come from
//! [`crate::lean_tier::derive_workflow`], so a module this lint calls reachable is a module a
//! workflow's Lean-action build elaborates (ADR 0007 G-1).

use crate::lean_tier::strip_comments;

/// A `theorem`/`lemma` declaration, with its statement.
#[derive(Debug, PartialEq, Eq)]
pub struct Theorem {
    /// The name as declared (relative to any enclosing `namespace`).
    pub name: String,
    /// Everything between the name and the `:=` (binders and type): the statement.
    pub statement: String,
}

/// Skip an `@[…]` attribute (brackets nested) at the start of `s`.
fn skip_attribute(s: &str) -> Option<&str> {
    let rest = s.strip_prefix("@[")?;
    let mut depth = 1usize;
    for (i, c) in rest.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[i + 1..].trim_start());
                }
            }
            _ => {}
        }
    }
    None
}

/// The declaration keyword and the rest of the line, past attributes and modifiers.
fn declaration(line: &str) -> Option<(&str, &str)> {
    let mut s = line.trim_start();
    loop {
        if let Some(rest) = skip_attribute(s) {
            s = rest;
            continue;
        }
        let (word, rest) = s.split_once(char::is_whitespace).unwrap_or((s, ""));
        match word {
            "private" | "protected" | "noncomputable" | "nonrec" | "partial" | "unsafe"
            | "divergent" => {
                s = rest.trim_start();
            }
            _ => return Some((word, rest)),
        }
    }
}

/// The statement starting at `text`: up to the first `:=` outside brackets, or a `|` that
/// opens an equation, or a line at column 0 (the next command).
fn statement(text: &str) -> &str {
    let mut depth = 0i32;
    let mut prev = '\0';
    let mut line_start = false;
    for (i, c) in text.char_indices() {
        if line_start && !c.is_whitespace() && depth == 0 && (c == '|' || prev == '\n') {
            return &text[..i];
        }
        match c {
            '(' | '[' | '{' | '⟨' => depth += 1,
            ')' | ']' | '}' | '⟩' => depth -= 1,
            '=' if prev == ':' && depth == 0 => return &text[..i - 1],
            _ => {}
        }
        if c == '\n' {
            line_start = true;
        } else if !c.is_whitespace() {
            line_start = false;
        }
        prev = c;
    }
    text
}

/// Every `theorem`/`lemma` in a Lean source, comments ignored.
pub fn theorems(src: &str) -> Vec<Theorem> {
    let text = strip_comments(src);
    let mut out = Vec::new();
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let at = offset;
        offset += line.len();
        let Some((word, rest)) = declaration(line) else {
            continue;
        };
        if word != "theorem" && word != "lemma" {
            continue;
        }
        let Some(name) = rest.split_whitespace().next() else {
            continue;
        };
        // The statement starts after the name, and may run over many lines.
        let name_at = at + line.len() - rest.len() + rest.find(name).unwrap_or(0) + name.len();
        out.push(Theorem {
            name: name.replace(['«', '»'], ""),
            statement: statement(&text[name_at..]).to_string(),
        });
    }
    out
}

/// The Lean identifiers a statement uses (dots kept: `a.b.c` is one identifier).
fn identifiers(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '.' | '\'' | '!' | '?')))
        .map(|t| t.trim_matches('.'))
        .filter(|t| !t.is_empty())
}

/// The namespaces a Lean source opens or declares, file-wide: `open A B (x)` gives `A`, `B`;
/// `namespace C` gives `C`. A bare name in a statement resolves against these.
pub fn scopes(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in strip_comments(src).lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("namespace ") {
            out.extend(rest.split_whitespace().next().map(str::to_string));
        } else if let Some(rest) = line.strip_prefix("open ") {
            for word in rest.split_whitespace() {
                if word.starts_with('(') || matches!(word, "in" | "hiding" | "renaming") {
                    break;
                }
                if word != "scoped" {
                    out.push(word.to_string());
                }
            }
        }
    }
    out
}

/// Whether `statement` names `constant`: in full; by a suffix of at least two dotted segments
/// (`ExposureSet.set`); or by a name that is the constant once one of `scopes` — the
/// namespaces the file opens or declares — is put in front of it.
///
/// A bare last segment that resolves through no scope does NOT count. `set`, `eq` and
/// `decide` are names a statement uses for many things, and a mention a coincidence can
/// satisfy is the vacuity this lint exists to refuse.
pub fn mentions(statement: &str, constant: &str, scopes: &[String]) -> bool {
    identifiers(statement).any(|t| {
        t == constant
            || (t.contains('.') && constant.ends_with(&format!(".{t}")))
            || scopes.iter().any(|s| constant == format!("{s}.{t}"))
    })
}

/// One Aeneas-generated `def`, with the Rust function it was extracted from.
#[derive(Debug, PartialEq, Eq)]
pub struct Extracted {
    /// The Rust function, normalized to the symbol table's key (`crate::m::Type::f`).
    pub function: String,
    /// The Lean constant, namespace included.
    pub constant: String,
}

/// Normalize an Aeneas item path to a symbol-table key. An inherent impl
/// `{crate::m::Type<T>}` becomes `Type`; a trait impl (`{impl Trait for Type}`) or a closure
/// has no single key and yields `None`.
pub fn normalize_aeneas_path(path: &str) -> Option<String> {
    let mut segments = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let bytes = path.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'<' => depth += 1,
            b'}' | b'>' => depth -= 1,
            b':' if depth == 0 && bytes.get(i + 1) == Some(&b':') => {
                segments.push(&path[start..i]);
                start = i + 2;
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    segments.push(&path[start..]);
    let mut out = Vec::with_capacity(segments.len());
    for seg in segments {
        if let Some(inner) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if inner.starts_with("impl ") || inner.contains('#') {
                return None;
            }
            let inner = inner.split('<').next()?;
            out.push(inner.rsplit("::").next()?.to_string());
        } else if seg.is_empty() || seg.contains(['{', '}', '#', '<', ' ']) {
            return None;
        } else {
            out.push(seg.to_string());
        }
    }
    Some(out.join("::"))
}

/// The marker every Aeneas output file starts with.
const GENERATED: &str = "AUTOMATICALLY GENERATED BY AENEAS";

/// The functions an Aeneas-generated file extracts, or `None` for a hand-written file.
///
/// Read from the generated doc comment — `/-- [crate::m::f]:` — and the `def` it documents,
/// inside the file's `namespace`. Nothing is listed by hand.
pub fn extracted(src: &str) -> Option<Vec<Extracted>> {
    if !src.lines().take(3).any(|l| l.contains(GENERATED)) {
        return None;
    }
    let mut namespace = String::new();
    let mut pending: Option<String> = None;
    let mut out = Vec::new();
    for line in src.lines() {
        if let Some(ns) = line.strip_prefix("namespace ") {
            namespace = ns.trim().to_string();
            continue;
        }
        if let Some(doc) = line.strip_prefix("/-- [") {
            pending = doc
                .rsplit_once("]:")
                .and_then(|(p, _)| normalize_aeneas_path(p));
            continue;
        }
        let Some((word, rest)) = declaration(line) else {
            continue;
        };
        if matches!(
            word,
            "structure" | "inductive" | "axiom" | "opaque" | "theorem" | "instance" | "class"
        ) {
            // A documented type or axiom: the doc comment was not a function's.
            pending = None;
            continue;
        }
        if word == "def"
            && let Some(function) = pending.take()
            && let Some(name) = rest.split_whitespace().next()
        {
            let constant = if namespace.is_empty() {
                name.to_string()
            } else {
                format!("{namespace}.{name}")
            };
            out.push(Extracted { function, constant });
        }
    }
    Some(out)
}

/// The `def`/`abbrev` names a Lean source declares, as written.
pub fn definitions(src: &str) -> Vec<String> {
    strip_comments(src)
        .lines()
        .filter_map(declaration)
        .filter(|(w, _)| matches!(*w, "def" | "abbrev"))
        .filter_map(|(_, rest)| rest.split_whitespace().next())
        .map(|n| n.replace(['«', '»'], ""))
        .collect()
}
