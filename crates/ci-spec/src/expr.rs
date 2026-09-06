//! A conservative evaluator for the subset of GitHub's expression language
//! that this repository's `if:` and `cancel-in-progress:` fields use.
//!
//! Three-valued: an expression is [`Tri::True`], [`Tri::False`], or
//! [`Tri::Unknown`] for the given event. Anything the grammar does not cover
//! is an [`Undecidable`] error, which the caller reports as "could not look"
//! (exit 2) rather than as a pass — a checker that read an unfamiliar
//! expression as safe would be the vacuity it exists to find.
//!
//! Covered: `${{ }}` wrapping, `||`, `&&`, `!`, parentheses, `==`, `!=`,
//! single-quoted strings, `true`/`false`, `github.event_name`, `github.ref`,
//! `github.head_ref`, `always()`/`success()`/`failure()`/`cancelled()`, and
//! any dotted path (`needs.x.outputs.y`, `vars.X`, `steps.x.outputs.y`,
//! `runner.environment`, `inputs.x`) as an [`Tri::Unknown`] value whose
//! reference is recorded so the caller can reason about what it depends on.

use std::fmt;

/// Three-valued truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
    True,
    False,
    Unknown,
}

impl Tri {
    fn not(self) -> Tri {
        match self {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
        }
    }
    fn or(self, o: Tri) -> Tri {
        match (self, o) {
            (Tri::True, _) | (_, Tri::True) => Tri::True,
            (Tri::False, Tri::False) => Tri::False,
            _ => Tri::Unknown,
        }
    }
    fn and(self, o: Tri) -> Tri {
        match (self, o) {
            (Tri::False, _) | (_, Tri::False) => Tri::False,
            (Tri::True, Tri::True) => Tri::True,
            _ => Tri::Unknown,
        }
    }
}

/// The event the expression is evaluated under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    PullRequest,
    MergeGroup,
    Push,
}

impl Event {
    fn name(self) -> &'static str {
        match self {
            Event::PullRequest => "pull_request",
            Event::MergeGroup => "merge_group",
            Event::Push => "push",
        }
    }
    /// A representative `github.ref` for the event.
    fn git_ref(self) -> &'static str {
        match self {
            Event::PullRequest => "refs/pull/1/merge",
            Event::MergeGroup => "refs/heads/gh-readonly-queue/main/pr-1-0000000000000000",
            Event::Push => "refs/heads/main",
        }
    }
}

/// The expression could not be evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undecidable(pub String);

impl fmt::Display for Undecidable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot evaluate: {}", self.0)
    }
}

/// What an evaluation established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eval {
    pub value: Tri,
    /// `needs.<job>` ids the expression references.
    pub needs: Vec<String>,
    /// Other unknown paths referenced (`vars.X`, `steps.x.outputs.y`, ...).
    pub unknowns: Vec<String>,
    /// `always()` appears — the job runs regardless of upstream results.
    pub always: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Str(String),
    Bool(Tri),
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Str(String),
    Ident(String),
    Or,
    And,
    Not,
    Eq,
    Ne,
    LParen,
    RParen,
    Call(String),
}

fn lex(src: &str) -> Result<Vec<Tok>, Undecidable> {
    let s = src.trim();
    let s = s
        .strip_prefix("${{")
        .and_then(|r| r.strip_suffix("}}"))
        .unwrap_or(s)
        .trim();
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        match c {
            ' ' | '\t' | '\n' => i += 1,
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '!' if b.get(i + 1) == Some(&'=') => {
                out.push(Tok::Ne);
                i += 2;
            }
            '!' => {
                out.push(Tok::Not);
                i += 1;
            }
            '=' if b.get(i + 1) == Some(&'=') => {
                out.push(Tok::Eq);
                i += 2;
            }
            '|' if b.get(i + 1) == Some(&'|') => {
                out.push(Tok::Or);
                i += 2;
            }
            '&' if b.get(i + 1) == Some(&'&') => {
                out.push(Tok::And);
                i += 2;
            }
            '\'' => {
                let mut j = i + 1;
                let mut lit = String::new();
                loop {
                    match b.get(j) {
                        None => return Err(Undecidable(format!("unterminated string in `{s}`"))),
                        Some('\'') if b.get(j + 1) == Some(&'\'') => {
                            lit.push('\'');
                            j += 2;
                        }
                        Some('\'') => {
                            j += 1;
                            break;
                        }
                        Some(ch) => {
                            lit.push(*ch);
                            j += 1;
                        }
                    }
                }
                out.push(Tok::Str(lit));
                i = j;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut j = i;
                while j < b.len()
                    && (b[j].is_ascii_alphanumeric() || b[j] == '_' || b[j] == '.' || b[j] == '-')
                {
                    j += 1;
                }
                let ident: String = b[i..j].iter().collect();
                if b.get(j) == Some(&'(') {
                    // Only nullary status functions are modelled.
                    if b.get(j + 1) == Some(&')') {
                        out.push(Tok::Call(ident));
                        i = j + 2;
                        continue;
                    }
                    return Err(Undecidable(format!(
                        "function call `{ident}(...)` in `{s}`"
                    )));
                }
                out.push(Tok::Ident(ident));
                i = j;
            }
            other => return Err(Undecidable(format!("unexpected `{other}` in `{s}`"))),
        }
    }
    Ok(out)
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    event: Event,
    needs: Vec<String>,
    unknowns: Vec<String>,
    always: bool,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn bump(&mut self) -> Option<&Tok> {
        let t = self.toks.get(self.pos);
        self.pos += 1;
        t
    }

    fn or(&mut self) -> Result<Val, Undecidable> {
        let mut l = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.bump();
            let r = self.and()?;
            l = Val::Bool(truth(&l).or(truth(&r)));
        }
        Ok(l)
    }
    fn and(&mut self) -> Result<Val, Undecidable> {
        let mut l = self.cmp()?;
        while self.peek() == Some(&Tok::And) {
            self.bump();
            let r = self.cmp()?;
            l = Val::Bool(truth(&l).and(truth(&r)));
        }
        Ok(l)
    }
    fn cmp(&mut self) -> Result<Val, Undecidable> {
        let l = self.unary()?;
        match self.peek() {
            Some(Tok::Eq) | Some(Tok::Ne) => {
                let ne = self.peek() == Some(&Tok::Ne);
                self.bump();
                let r = self.unary()?;
                let eq = match (&l, &r) {
                    (Val::Str(a), Val::Str(b)) => {
                        if a == b {
                            Tri::True
                        } else {
                            Tri::False
                        }
                    }
                    (Val::Bool(Tri::Unknown), _) | (_, Val::Bool(Tri::Unknown)) => Tri::Unknown,
                    (Val::Bool(a), Val::Bool(b)) => {
                        if a == b {
                            Tri::True
                        } else {
                            Tri::False
                        }
                    }
                    // A string compared with a known boolean: GitHub coerces;
                    // `'true' == true` is true. Compare textually.
                    (Val::Str(a), Val::Bool(b)) | (Val::Bool(b), Val::Str(a)) => {
                        let bs = match b {
                            Tri::True => "true",
                            Tri::False => "false",
                            Tri::Unknown => unreachable!(),
                        };
                        if a == bs { Tri::True } else { Tri::False }
                    }
                };
                Ok(Val::Bool(if ne { eq.not() } else { eq }))
            }
            _ => Ok(l),
        }
    }
    fn unary(&mut self) -> Result<Val, Undecidable> {
        if self.peek() == Some(&Tok::Not) {
            self.bump();
            let v = self.unary()?;
            return Ok(Val::Bool(truth(&v).not()));
        }
        self.primary()
    }
    fn primary(&mut self) -> Result<Val, Undecidable> {
        match self.bump().cloned() {
            Some(Tok::LParen) => {
                let v = self.or()?;
                if self.bump() != Some(&Tok::RParen) {
                    return Err(Undecidable("missing `)`".into()));
                }
                Ok(v)
            }
            Some(Tok::Str(s)) => Ok(Val::Str(s)),
            Some(Tok::Call(f)) => match f.as_str() {
                "always" => {
                    self.always = true;
                    Ok(Val::Bool(Tri::True))
                }
                "success" | "failure" | "cancelled" => Ok(Val::Bool(Tri::Unknown)),
                other => Err(Undecidable(format!("function `{other}()`"))),
            },
            Some(Tok::Ident(id)) => Ok(self.resolve(&id)),
            Some(t) => Err(Undecidable(format!("unexpected token {t:?}"))),
            None => Err(Undecidable("unexpected end of expression".into())),
        }
    }
    fn resolve(&mut self, id: &str) -> Val {
        match id {
            "true" => Val::Bool(Tri::True),
            "false" => Val::Bool(Tri::False),
            "github.event_name" => Val::Str(self.event.name().into()),
            "github.ref" => Val::Str(self.event.git_ref().into()),
            "github.head_ref" => Val::Str(
                if self.event == Event::PullRequest {
                    "feature-branch"
                } else {
                    ""
                }
                .into(),
            ),
            _ => {
                if let Some(rest) = id.strip_prefix("needs.") {
                    let job = rest.split('.').next().unwrap_or(rest).to_string();
                    if !self.needs.contains(&job) {
                        self.needs.push(job);
                    }
                } else if !self.unknowns.contains(&id.to_string()) {
                    self.unknowns.push(id.to_string());
                }
                Val::Bool(Tri::Unknown)
            }
        }
    }
}

fn truth(v: &Val) -> Tri {
    match v {
        Val::Bool(t) => *t,
        // A non-empty string is truthy in GitHub's expressions.
        Val::Str(s) => {
            if s.is_empty() {
                Tri::False
            } else {
                Tri::True
            }
        }
    }
}

/// Evaluate `src` under `event`.
pub fn eval(src: &str, event: Event) -> Result<Eval, Undecidable> {
    let toks = lex(src)?;
    if toks.is_empty() {
        return Err(Undecidable("empty expression".into()));
    }
    let mut p = Parser {
        toks: &toks,
        pos: 0,
        event,
        needs: Vec::new(),
        unknowns: Vec::new(),
        always: false,
    };
    let v = p.or()?;
    if p.pos != toks.len() {
        return Err(Undecidable(format!("trailing tokens in `{src}`")));
    }
    Ok(Eval {
        value: truth(&v),
        needs: p.needs,
        unknowns: p.unknowns,
        always: p.always,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_name_comparisons_decide() {
        let e = eval(
            "${{ github.event_name == 'pull_request' }}",
            Event::MergeGroup,
        )
        .unwrap();
        assert_eq!(e.value, Tri::False);
        let e = eval("github.event_name != 'schedule'", Event::MergeGroup).unwrap();
        assert_eq!(e.value, Tri::True);
    }

    #[test]
    fn needs_outputs_are_unknown_and_recorded() {
        let e = eval(
            "${{ needs.changed-crates.outputs.all == 'true' || needs.changed-crates.outputs.crates != '' }}",
            Event::MergeGroup,
        )
        .unwrap();
        assert_eq!(e.value, Tri::Unknown);
        assert_eq!(e.needs, vec!["changed-crates".to_string()]);
    }

    #[test]
    fn ref_inequality_is_true_under_merge_group() {
        // The feature-matrix.yml shape: cancels a queue entry.
        let e = eval("${{ github.ref != 'refs/heads/main' }}", Event::MergeGroup).unwrap();
        assert_eq!(e.value, Tri::True);
        let e = eval("${{ github.ref != 'refs/heads/main' }}", Event::Push).unwrap();
        assert_eq!(e.value, Tri::False);
    }

    #[test]
    fn always_is_recorded() {
        let e = eval(
            "${{ always() && needs.a.result == 'success' }}",
            Event::MergeGroup,
        )
        .unwrap();
        assert!(e.always);
        assert_eq!(e.value, Tri::Unknown);
    }

    #[test]
    fn unknown_functions_are_undecidable_not_true() {
        assert!(eval("${{ contains(github.ref, 'x') }}", Event::Push).is_err());
        assert!(eval("${{ hashFiles('a') }}", Event::Push).is_err());
    }

    #[test]
    fn literal_true_and_false() {
        assert_eq!(eval("true", Event::Push).unwrap().value, Tri::True);
        assert_eq!(eval("false", Event::Push).unwrap().value, Tri::False);
    }
}
