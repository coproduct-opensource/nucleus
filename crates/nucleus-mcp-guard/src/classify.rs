//! Map MCP tools to IFC roles.
//!
//! The lethal-trifecta decision ([`nucleus_ifc`]) is the proven engine; this
//! module is the (deliberately simple, fully overridable) *adapter* that decides,
//! for a given MCP tool, whether its **result** brings a class of data into the
//! agent's context (a [`ToolRole::Source`]) or its **call** is an outbound action
//! that could exfiltrate (a [`ToolRole::Sink`]).
//!
//! Defaults are conservative: an **unknown** tool's result is treated as untrusted
//! [`DeclaredInput::ToolResponse`] (taint), and only explicitly-recognised tools
//! are treated as egress sinks. Override any of this via [`Classifier::with_rule`]
//! or a loaded [`ClassifierConfig`] — see `README.md`.

use nucleus_ifc::DeclaredInput;
use serde::{Deserialize, Serialize};

/// What an MCP tool means for information flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ToolRole {
    /// The tool's RESULT introduces this data class into the agent's context.
    Source {
        /// The IFC input class the tool's output is treated as.
        input: DeclaredInput,
    },
    /// The tool CALL is an outbound action (an egress point). `public = true` when
    /// the destination is publicly visible (the tightest confidentiality ceiling).
    Sink {
        /// Whether the destination is publicly visible (vs. an authenticated peer).
        public: bool,
    },
    /// Local / irrelevant to exfiltration (e.g. a calculator).
    Neutral,
}

/// A single name-match rule. `contains` is matched case-insensitively as a
/// substring of the tool name; first matching rule wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Lowercase substring to match against the tool name.
    pub contains: String,
    /// The role to assign on a match.
    pub role: ToolRole,
}

impl Rule {
    fn new(contains: &str, role: ToolRole) -> Self {
        Self {
            contains: contains.to_string(),
            role,
        }
    }
}

/// Serializable classifier config (load from JSON to override defaults).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassifierConfig {
    /// Extra rules, evaluated BEFORE the built-in defaults (so they take priority).
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// If `true`, drop the built-in default ruleset entirely.
    #[serde(default)]
    pub replace_defaults: bool,
}

/// The ordered ruleset that turns a tool name into a [`ToolRole`].
#[derive(Debug, Clone)]
pub struct Classifier {
    rules: Vec<Rule>,
    /// Role for a tool that matches nothing (conservative: untrusted tool output).
    fallback: ToolRole,
}

impl Default for Classifier {
    fn default() -> Self {
        use DeclaredInput::*;
        let src = |i| ToolRole::Source { input: i };
        // Order matters — first match wins. Specific sinks + private sources are
        // listed before the broad web/http source patterns.
        let rules = vec![
            // --- neutral (local, no exfil relevance) ---
            Rule::new("calculator", ToolRole::Neutral),
            Rule::new("math", ToolRole::Neutral),
            // --- egress sinks (outbound actions) ---
            Rule::new("send_email", ToolRole::Sink { public: false }),
            Rule::new("sendmail", ToolRole::Sink { public: false }),
            Rule::new("smtp", ToolRole::Sink { public: false }),
            Rule::new("email", ToolRole::Sink { public: false }),
            Rule::new("http_post", ToolRole::Sink { public: false }),
            Rule::new("webhook", ToolRole::Sink { public: false }),
            Rule::new("upload", ToolRole::Sink { public: false }),
            Rule::new("slack", ToolRole::Sink { public: true }),
            Rule::new("discord", ToolRole::Sink { public: true }),
            Rule::new("telegram", ToolRole::Sink { public: true }),
            Rule::new("tweet", ToolRole::Sink { public: true }),
            Rule::new("publish", ToolRole::Sink { public: true }),
            Rule::new("post_message", ToolRole::Sink { public: true }),
            // --- private / sensitive sources ---
            Rule::new("secret", src(Secret)),
            Rule::new("credential", src(Secret)),
            Rule::new("api_key", src(Secret)),
            Rule::new("apikey", src(Secret)),
            Rule::new("password", src(Secret)),
            Rule::new("getenv", src(EnvVar)),
            Rule::new("env_var", src(EnvVar)),
            Rule::new("read_file", src(FileRead)),
            Rule::new("readfile", src(FileRead)),
            Rule::new("file_read", src(FileRead)),
            Rule::new("fs_read", src(FileRead)),
            Rule::new("open_file", src(FileRead)),
            Rule::new("query", src(DatabaseRow)),
            Rule::new("sql", src(DatabaseRow)),
            Rule::new("database", src(DatabaseRow)),
            Rule::new("recall", src(MemoryRead)),
            Rule::new("memory", src(MemoryRead)),
            // --- untrusted external content sources ---
            Rule::new("fetch", src(WebContent)),
            Rule::new("browse", src(WebContent)),
            Rule::new("scrape", src(WebContent)),
            Rule::new("crawl", src(WebContent)),
            Rule::new("read_url", src(WebContent)),
            Rule::new("web", src(WebContent)),
            Rule::new("http", src(HttpResponse)),
            Rule::new("request", src(HttpResponse)),
            Rule::new("api", src(HttpResponse)),
        ];
        Self {
            rules,
            // Unknown tool → its output is untrusted tool content. Fail safe.
            fallback: ToolRole::Source {
                input: DeclaredInput::ToolResponse,
            },
        }
    }
}

impl Classifier {
    /// Build a classifier from a config (overrides applied before defaults).
    pub fn from_config(cfg: &ClassifierConfig) -> Self {
        let mut c = if cfg.replace_defaults {
            Self {
                rules: Vec::new(),
                fallback: ToolRole::Source {
                    input: DeclaredInput::ToolResponse,
                },
            }
        } else {
            Self::default()
        };
        // Prepend overrides so they win over defaults.
        let mut rules = cfg.rules.clone();
        rules.append(&mut c.rules);
        c.rules = rules;
        c
    }

    /// Add a high-priority override rule (takes precedence over defaults).
    pub fn with_rule(mut self, contains: &str, role: ToolRole) -> Self {
        self.rules.insert(0, Rule::new(contains, role));
        self
    }

    /// Classify a tool by name (case-insensitive substring match, first wins).
    pub fn classify(&self, tool_name: &str) -> ToolRole {
        let name = tool_name.to_ascii_lowercase();
        for r in &self.rules {
            if name.contains(&r.contains.to_ascii_lowercase()) {
                return r.role;
            }
        }
        self.fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_classify_the_trifecta_corners() {
        let c = Classifier::default();
        assert_eq!(
            c.classify("read_file"),
            ToolRole::Source {
                input: DeclaredInput::FileRead
            }
        );
        assert_eq!(
            c.classify("fetch_url"),
            ToolRole::Source {
                input: DeclaredInput::WebContent
            }
        );
        assert_eq!(c.classify("send_email"), ToolRole::Sink { public: false });
        assert_eq!(c.classify("slack_post"), ToolRole::Sink { public: true });
    }

    #[test]
    fn unknown_tool_is_untrusted_tool_output() {
        let c = Classifier::default();
        assert_eq!(
            c.classify("some_random_plugin"),
            ToolRole::Source {
                input: DeclaredInput::ToolResponse
            }
        );
    }

    #[test]
    fn overrides_win_over_defaults() {
        // A site that exposes secrets via a tool literally named "read_file".
        let c = Classifier::default().with_rule(
            "read_file",
            ToolRole::Source {
                input: DeclaredInput::Secret,
            },
        );
        assert_eq!(
            c.classify("read_file"),
            ToolRole::Source {
                input: DeclaredInput::Secret
            }
        );
    }
}
