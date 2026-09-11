//! The deterministic proposer: goal phrases × repository context → effects.
//!
//! Rules are data, and every one that fires is named in the grant's
//! provenance, so "why did it grant that?" always has an answer a person can
//! read. A rule is a set of phrases (matched as whole-word sequences in the
//! lowercased goal), an optional requirement on the repository context, and
//! the effects it proposes. Rules only ever *add* effects; the ceiling is
//! what removes them, and that happens in [`crate::compile`].

use std::collections::BTreeSet;

use portcullis::EffectId;

use crate::proposer::Proposal;
use crate::repo_context::{CiSystem, Ecosystem, RepoContext};

/// A requirement on the repository context for a rule to fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requires {
    /// The ecosystem is present.
    Ecosystem(Ecosystem),
    /// The CI system is present.
    Ci(CiSystem),
    /// Some remote is on this host.
    RemoteHost(&'static str),
    /// The root is a git work tree.
    Git,
}

impl Requires {
    fn holds(self, ctx: &RepoContext) -> bool {
        match self {
            Self::Ecosystem(e) => ctx.ecosystems.contains(&e),
            Self::Ci(c) => ctx.ci.contains(&c),
            Self::RemoteHost(h) => ctx.has_remote_host(h),
            Self::Git => ctx.has_git,
        }
    }
}

/// One rule.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// Stable id, recorded in provenance.
    pub id: &'static str,
    /// Any of these phrases in the goal fires the rule.
    pub any_of: &'static [&'static str],
    /// Context requirement, if any.
    pub requires: Option<Requires>,
    /// Effects proposed.
    pub effects: &'static [&'static str],
}

/// Effects every recognised goal gets: reading the workspace, and reading
/// git history when there is one. A goal that fires no other rule is not
/// recognised (see [`apply`]).
const BASE_EFFECTS: &[(&str, Option<Requires>)] = &[
    ("fs/read-workspace", None),
    ("git/read-history", Some(Requires::Git)),
];

/// The rule table.
pub const RULES: &[Rule] = &[
    Rule {
        id: "ci-logs",
        any_of: &[
            "ci",
            "ci build",
            "pipeline",
            "workflow",
            "github actions",
            "failing build",
            "build failing",
            "build is failing",
            "checks failing",
            "failing checks",
            "red build",
        ],
        requires: Some(Requires::Ci(CiSystem::GithubActions)),
        effects: &["github/read-ci-logs"],
    },
    Rule {
        id: "fix",
        any_of: &[
            "fix",
            "repair",
            "bug",
            "broken",
            "failing",
            "resolve",
            "make it pass",
        ],
        requires: None,
        effects: &["fs/edit-workspace", "shell/run-tests", "git/commit"],
    },
    Rule {
        id: "implement",
        any_of: &[
            "implement",
            "add",
            "write",
            "create",
            "refactor",
            "rename",
            "change",
            "update the code",
        ],
        requires: None,
        effects: &[
            "fs/edit-workspace",
            "shell/run-tests",
            "shell/run-build",
            "git/commit",
        ],
    },
    Rule {
        id: "test",
        any_of: &["test", "tests", "testing", "coverage"],
        requires: None,
        effects: &["shell/run-tests"],
    },
    Rule {
        id: "build",
        any_of: &["build", "compile"],
        requires: None,
        effects: &["shell/run-build"],
    },
    Rule {
        id: "lint",
        any_of: &["lint", "clippy", "format", "fmt", "warnings"],
        requires: None,
        effects: &["shell/run-lint", "fs/edit-workspace"],
    },
    Rule {
        id: "deps-cargo",
        any_of: &[
            "upgrade",
            "bump",
            "dependency",
            "dependencies",
            "update deps",
        ],
        requires: Some(Requires::Ecosystem(Ecosystem::Cargo)),
        effects: &[
            "web/package-registry-crates",
            "fs/edit-workspace",
            "shell/run-build",
            "shell/run-tests",
            "git/commit",
        ],
    },
    Rule {
        id: "deps-npm",
        any_of: &[
            "upgrade",
            "bump",
            "dependency",
            "dependencies",
            "update deps",
        ],
        requires: Some(Requires::Ecosystem(Ecosystem::Npm)),
        effects: &[
            "web/package-registry-npm",
            "fs/edit-workspace",
            "shell/run-build",
            "shell/run-tests",
            "git/commit",
        ],
    },
    Rule {
        id: "deps-pypi",
        any_of: &[
            "upgrade",
            "bump",
            "dependency",
            "dependencies",
            "update deps",
        ],
        requires: Some(Requires::Ecosystem(Ecosystem::Python)),
        effects: &[
            "web/package-registry-pypi",
            "fs/edit-workspace",
            "shell/run-tests",
            "git/commit",
        ],
    },
    Rule {
        id: "issue",
        any_of: &["issue", "ticket"],
        requires: Some(Requires::RemoteHost("github.com")),
        effects: &["github/read-issue"],
    },
    Rule {
        id: "pr-read",
        any_of: &["review", "pull request", "pr", "prs", "pull requests"],
        requires: Some(Requires::RemoteHost("github.com")),
        effects: &["github/read-pull-request"],
    },
    Rule {
        id: "pr-open",
        any_of: &[
            "open a pr",
            "open a pull request",
            "create a pr",
            "create a pull request",
            "submit a pr",
            "submit a pull request",
            "send a pr",
            "push",
        ],
        requires: Some(Requires::RemoteHost("github.com")),
        effects: &["github/open-pr", "git/push-branch", "git/commit"],
    },
    Rule {
        id: "pr-comment",
        any_of: &["comment", "reply"],
        requires: Some(Requires::RemoteHost("github.com")),
        effects: &["github/comment"],
    },
    Rule {
        id: "merge",
        any_of: &["merge"],
        requires: Some(Requires::RemoteHost("github.com")),
        effects: &["github/merge-pr"],
    },
    Rule {
        id: "docs",
        any_of: &["docs", "documentation", "readme", "document", "changelog"],
        requires: None,
        effects: &["fs/edit-workspace", "git/commit"],
    },
    Rule {
        id: "research",
        any_of: &[
            "research",
            "investigate",
            "explore",
            "understand",
            "explain",
            "audit",
            "summarize",
            "summarise",
            "what does",
        ],
        requires: None,
        effects: &[],
    },
    Rule {
        id: "web-search",
        any_of: &["search the web", "look up online", "web search", "google"],
        requires: None,
        effects: &["web/search"],
    },
    // ── Beyond the repository ───────────────────────────────────────────────
    //
    // These rules propose READ effects only, and that asymmetry is the design.
    // A goal is evidence about what a person wants to LEARN; it is much weaker
    // evidence about what they are willing to have CHANGED. "the deploy is
    // broken" plausibly means read the logs and see what is running — it does
    // not mean roll something out, and a rule that inferred so would widen
    // authority from a guess.
    //
    // The mutating effects in these packs are reachable, but by being asked
    // for: `--effects kubernetes/apply-manifest`, or an escalation proposal
    // raised by the denial the read-only grant produces. Both put the decision
    // in front of a person, which is where a deploy belongs.
    Rule {
        id: "cloud-inspect",
        any_of: &[
            "aws",
            "cloud",
            "s3",
            "bucket",
            "ec2",
            "lambda",
            "cloudwatch",
            "cloudformation",
        ],
        requires: None,
        effects: &["aws/read-inventory", "aws/read-logs"],
    },
    Rule {
        id: "cluster-inspect",
        any_of: &[
            "kubernetes",
            "k8s",
            "kubectl",
            "cluster",
            "pod",
            "pods",
            "deployment",
            "helm",
        ],
        requires: None,
        effects: &["kubernetes/read-workloads", "kubernetes/read-logs"],
    },
    Rule {
        id: "database-inspect",
        any_of: &[
            "database",
            "sql",
            "postgres",
            "postgresql",
            "mysql",
            "sqlite",
            "schema",
            "migration",
            "query",
        ],
        requires: None,
        effects: &["database/read-schema", "database/read-rows"],
    },
    Rule {
        id: "chat-read",
        any_of: &["slack", "channel", "thread", "what did the team", "standup"],
        requires: None,
        effects: &["slack/read-channel"],
    },
];

/// Run every rule against the goal. Returns an empty proposal (no rules
/// fired, no effects) when nothing recognises the goal; the base effects
/// are added only when at least one rule fired.
pub fn apply(goal: &str, ctx: &RepoContext) -> Proposal {
    let words = tokenize(goal);
    let mut effects = BTreeSet::new();
    let mut fired = Vec::new();
    for rule in RULES {
        if !rule
            .any_of
            .iter()
            .any(|phrase| contains_phrase(&words, phrase))
        {
            continue;
        }
        if let Some(req) = rule.requires
            && !req.holds(ctx)
        {
            continue;
        }
        fired.push(rule.id.to_string());
        for e in rule.effects {
            effects.insert(parse(e));
        }
    }
    if !fired.is_empty() {
        for (e, req) in BASE_EFFECTS {
            if req.is_none_or(|r| r.holds(ctx)) {
                effects.insert(parse(e));
            }
        }
    }
    Proposal {
        proposer: "rules".to_string(),
        effects,
        rules_fired: fired,
    }
}

fn parse(s: &str) -> EffectId {
    s.parse().expect("RULES names only well-formed effect ids")
}

/// Lowercase alphanumeric words; punctuation splits.
fn tokenize(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

fn contains_phrase(words: &[String], phrase: &str) -> bool {
    let p = tokenize(phrase);
    if p.is_empty() || words.len() < p.len() {
        return false;
    }
    words.windows(p.len()).any(|w| w == p.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ctx(ci: bool, github: bool, cargo: bool) -> RepoContext {
        let mut c = RepoContext {
            root: PathBuf::from("/tmp/x"),
            ecosystems: BTreeSet::new(),
            ci: BTreeSet::new(),
            remotes: Vec::new(),
            has_git: true,
            mcp_servers: BTreeSet::new(),
            has_egress_policy: false,
            digest: "d".into(),
        };
        if ci {
            c.ci.insert(CiSystem::GithubActions);
        }
        if github {
            c.remotes.push(crate::repo_context::GitRemote {
                name: "origin".into(),
                host: "github.com".into(),
                owner_repo: Some("a/b".into()),
            });
        }
        if cargo {
            c.ecosystems.insert(Ecosystem::Cargo);
        }
        c
    }

    fn has(p: &Proposal, e: &str) -> bool {
        p.effects.contains(&e.parse().unwrap())
    }

    #[test]
    fn every_rule_names_valid_effects_in_the_builtin_catalog() {
        let catalog = portcullis::EffectCatalog::builtin().unwrap();
        for rule in RULES {
            for e in rule.effects {
                let id: EffectId = e.parse().unwrap();
                assert!(
                    catalog.get(&id).is_some(),
                    "rule {} names unknown {e}",
                    rule.id
                );
            }
        }
        for (e, _) in BASE_EFFECTS {
            assert!(catalog.get(&e.parse().unwrap()).is_some());
        }
    }

    #[test]
    fn fix_ci_with_actions_reads_ci_logs() {
        let p = apply("fix the failing CI build", &ctx(true, true, true));
        assert!(has(&p, "github/read-ci-logs"));
        assert!(has(&p, "fs/edit-workspace"));
        assert!(has(&p, "shell/run-tests"));
        assert!(has(&p, "fs/read-workspace"));
        assert!(has(&p, "git/read-history"));
        assert!(!has(&p, "github/open-pr"), "fix does not imply publishing");
        assert!(p.rules_fired.contains(&"ci-logs".to_string()));
    }

    #[test]
    fn context_requirements_gate_rules() {
        let p = apply("fix the failing CI build", &ctx(false, true, true));
        assert!(!has(&p, "github/read-ci-logs"), "no CI system, no CI logs");
        let p = apply("upgrade axum and fix the tests", &ctx(true, true, false));
        assert!(
            !has(&p, "web/package-registry-crates"),
            "no Cargo.toml, no crates.io"
        );
        let p = apply("upgrade axum and fix the tests", &ctx(true, true, true));
        assert!(has(&p, "web/package-registry-crates"));
    }

    #[test]
    fn unrecognised_goal_proposes_nothing() {
        let p = apply("hello there", &ctx(true, true, true));
        assert!(p.effects.is_empty());
        assert!(p.rules_fired.is_empty());
    }

    #[test]
    fn phrases_match_whole_words() {
        let p = apply("clarify the spec", &ctx(true, true, true));
        assert!(
            !has(&p, "github/read-ci-logs"),
            "'ci' inside 'clarify' is not CI"
        );
        let p = apply("push a branch and open a PR", &ctx(true, true, true));
        assert!(has(&p, "github/open-pr"));
        assert!(has(&p, "git/push-branch"));
    }

    // ── The rules beyond the repository ─────────────────────────────────────

    #[test]
    fn a_goal_about_the_cluster_proposes_reading_it() {
        let p = apply(
            "find out why the pods keep restarting",
            &ctx(true, true, true),
        );
        assert!(has(&p, "kubernetes/read-workloads"));
        assert!(has(&p, "kubernetes/read-logs"));
    }

    #[test]
    fn a_goal_about_the_database_proposes_reading_it() {
        let p = apply(
            "check the postgres schema for the users table",
            &ctx(true, true, true),
        );
        assert!(has(&p, "database/read-schema"));
        assert!(has(&p, "database/read-rows"));
    }

    #[test]
    fn a_goal_about_the_cloud_proposes_reading_it() {
        let p = apply(
            "look at the cloudwatch logs for the lambda",
            &ctx(true, true, true),
        );
        assert!(has(&p, "aws/read-inventory"));
        assert!(has(&p, "aws/read-logs"));
    }

    /// THE property of these four rules, and the reason they exist as reads
    /// only. A goal is evidence about what a person wants to LEARN and much
    /// weaker evidence about what they will let be CHANGED. No phrase in a goal
    /// may propose a deploy, a migration, a message to a team, or an IAM
    /// rewrite — those are reachable by being asked for, which puts the
    /// decision in front of a person.
    #[test]
    fn no_goal_phrase_proposes_a_mutation_beyond_the_repository() {
        let goals = [
            "the deploy is broken, roll it back",
            "delete the failing pods and redeploy",
            "run the migration and drop the old table",
            "tell the team in slack that the incident is over",
            "give the service permission to write to the bucket",
            "terminate the ec2 instances that are idle",
        ];
        let forbidden = [
            "kubernetes/apply-manifest",
            "kubernetes/exec-into-pod",
            "kubernetes/delete-workloads",
            "database/write-rows",
            "database/run-migration",
            "database/drop-data",
            "slack/post-message",
            "aws/write-object",
            "aws/delete-object",
            "aws/start-compute",
            "aws/mutate-iam",
            "aws/delete-resources",
        ];
        for goal in goals {
            let p = apply(goal, &ctx(true, true, true));
            for effect in forbidden {
                assert!(
                    !has(&p, effect),
                    "goal {goal:?} proposed {effect}: a stated goal must never widen \
                     authority beyond the repository on its own"
                );
            }
        }
    }

    /// Non-vacuity for the test above: those goals DO fire their rules, so the
    /// absence of mutating effects is a decision and not a failure to match.
    #[test]
    fn those_goals_do_fire_their_rules() {
        let p = apply(
            "delete the failing pods and redeploy",
            &ctx(true, true, true),
        );
        assert!(has(&p, "kubernetes/read-workloads"), "the rule fired");
        let p = apply(
            "run the migration and drop the old table",
            &ctx(true, true, true),
        );
        assert!(has(&p, "database/read-schema"), "the rule fired");
    }
}
