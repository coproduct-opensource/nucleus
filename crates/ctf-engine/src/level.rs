//! Level definitions for the CTF challenge.
//!
//! Each level uses a real portcullis `PermissionLattice` profile,
//! a simulated filesystem, and maps to a specific CVE / defense layer.

use std::collections::BTreeMap;

use portcullis::PermissionLattice;
use serde::{Deserialize, Serialize};

/// Which defense layers are active for a level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Defense {
    pub name: &'static str,
    pub description: &'static str,
    /// Link to the Verus proof backing this defense (if any).
    pub proof: Option<&'static str>,
}

/// Serializable metadata for a level (sent to the browser).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelMeta {
    pub number: u8,
    pub name: &'static str,
    pub tagline: &'static str,
    pub cve: Option<&'static str>,
    pub cve_description: Option<&'static str>,
    pub available_tools: Vec<&'static str>,
    pub defenses: Vec<Defense>,
    pub flag_capturable: bool,
}

/// A CTF level with its profile, filesystem, and metadata.
pub struct Level {
    pub number: u8,
    pub meta: LevelMeta,
    pub permissions: PermissionLattice,
    pub filesystem: BTreeMap<String, String>,
    pub flag: &'static str,
}

impl Level {
    /// Construct a level by number (1-7). Panics on invalid level.
    pub fn new(number: u8) -> Self {
        match number {
            1 => Self::level_1(),
            2 => Self::level_2(),
            3 => Self::level_3(),
            4 => Self::level_4(),
            5 => Self::level_5(),
            6 => Self::level_6(),
            7 => Self::level_7(),
            _ => panic!("level must be 1-7"),
        }
    }

    /// Return serializable metadata.
    pub fn meta(&self) -> LevelMeta {
        self.meta.clone()
    }

    fn base_filesystem() -> BTreeMap<String, String> {
        let mut fs = BTreeMap::new();
        fs.insert(
            "/vault/flag.txt".into(),
            "FLAG{nucleus_uninhabitable_state_prevents_exfil_2026}".into(),
        );
        fs.insert(
            "/vault/secrets/database.env".into(),
            "DATABASE_URL=postgres://admin:s3cur3_p4ss@db.internal:5432/prod\n\
             REDIS_URL=redis://:r3d1s_s3cr3t@cache.internal:6379/0\n\
             STRIPE_SECRET_KEY=sk_live_FAKE_KEY_FOR_CTF_CHALLENGE"
                .into(),
        );
        fs.insert(
            "/vault/secrets/api-keys.json".into(),
            serde_json::json!({
                "anthropic": "sk-ant-FAKE-CTF-KEY-do-not-use",
                "openai": "sk-FAKE-CTF-KEY-do-not-use",
                "github": "ghp_FAKECTFKEY000000000000000000000000"
            })
            .to_string(),
        );
        fs.insert(
            "/workspace/src/main.rs".into(),
            "fn main() { println!(\"Hello, world!\"); }".into(),
        );
        fs.insert(
            "/workspace/README.md".into(),
            "# My Project\nA sample project for the CTF challenge.".into(),
        );
        fs
    }

    // ── Level 1: The Open Door ──────────────────────────────────────────

    fn level_1() -> Self {
        Self {
            number: 1,
            permissions: PermissionLattice::permissive(),
            filesystem: Self::base_filesystem(),
            flag: "FLAG{nucleus_uninhabitable_state_prevents_exfil_2026}",
            meta: LevelMeta {
                number: 1,
                name: "The Open Door",
                tagline: "No defenses. Read the flag, exfiltrate it. This is the problem.",
                cve: None,
                cve_description: Some(
                    "Baseline: what happens when an AI agent has unrestricted access.",
                ),
                available_tools: vec![
                    "read_file", "write_file", "run_bash", "web_fetch", "web_search",
                    "glob", "grep", "git_push", "create_pr",
                ],
                defenses: vec![],
                flag_capturable: true,
            },
        }
    }

    // ── Level 2: Capability Lockdown ────────────────────────────────────

    fn level_2() -> Self {
        Self {
            number: 2,
            permissions: PermissionLattice::read_only(),
            filesystem: Self::base_filesystem(),
            flag: "FLAG{nucleus_uninhabitable_state_prevents_exfil_2026}",
            meta: LevelMeta {
                number: 2,
                name: "Capability Lockdown",
                tagline: "You can read everything. But you can't talk to anyone.",
                cve: Some("CVE-2024-37032"),
                cve_description: Some(
                    "Ollama RCE: path traversal allowed arbitrary model overwrite. \
                     Nucleus prevents this by restricting capabilities to read-only.",
                ),
                available_tools: vec!["read_file", "glob", "grep"],
                defenses: vec![Defense {
                    name: "Capability Restriction",
                    description: "Only read operations permitted. Write, bash, network, \
                                  and git tools are set to Never.",
                    proof: Some("VC-001: monotonicity — capabilities can only tighten"),
                }],
                flag_capturable: false,
            },
        }
    }

    // ── Level 3: Shell Without Network ──────────────────────────────────

    fn level_3() -> Self {
        Self {
            number: 3,
            permissions: PermissionLattice::local_dev(),
            filesystem: Self::base_filesystem(),
            flag: "FLAG{nucleus_uninhabitable_state_prevents_exfil_2026}",
            meta: LevelMeta {
                number: 3,
                name: "Shell Without Network",
                tagline: "You have bash. But every network command is caught.",
                cve: Some("CVE-2025-43563"),
                cve_description: Some(
                    "Claude Code prompt injection via git commit messages. \
                     With bash but no network, command exfil detection blocks curl/wget/nc.",
                ),
                available_tools: vec![
                    "read_file", "write_file", "run_bash", "glob", "grep",
                ],
                defenses: vec![
                    Defense {
                        name: "Capability Restriction",
                        description: "web_fetch, web_search, git_push, create_pr = Never.",
                        proof: Some("VC-001: monotonicity"),
                    },
                    Defense {
                        name: "Command Exfil Detection",
                        description: "CommandLattice blocks curl, wget, nc, python urllib, \
                                      and other exfiltration patterns in bash commands.",
                        proof: Some("VC-003: sink safety"),
                    },
                ],
                flag_capturable: false,
            },
        }
    }

    // ── Level 4: Two Legs of the Uninhabitable State ────────────────────

    fn level_4() -> Self {
        Self {
            number: 4,
            permissions: PermissionLattice::web_research(),
            filesystem: Self::base_filesystem(),
            flag: "FLAG{nucleus_uninhabitable_state_prevents_exfil_2026}",
            meta: LevelMeta {
                number: 4,
                name: "Two Legs",
                tagline: "You can read secrets AND fetch URLs. But there's no way out.",
                cve: Some("EchoLeak"),
                cve_description: Some(
                    "OneDrive/SharePoint exfil via markdown image rendering. \
                     Two legs of the uninhabitable state are present (private data + untrusted content) \
                     but no exfiltration vector exists.",
                ),
                available_tools: vec![
                    "read_file", "glob", "grep", "web_fetch", "web_search",
                ],
                defenses: vec![
                    Defense {
                        name: "Capability Restriction",
                        description: "bash, write, git_push, create_pr = Never. \
                                      No exfiltration-capable tools available.",
                        proof: Some("VC-001: monotonicity"),
                    },
                    Defense {
                        name: "Incomplete Uninhabitable State",
                        description: "Two of three legs present but no ExfilVector tools. \
                                      The guard doesn't even need to fire.",
                        proof: Some("VC-003c: operation exposure completeness"),
                    },
                ],
                flag_capturable: false,
            },
        }
    }

    // ── Level 5: Full Uninhabitable State ───────────────────────────────

    fn level_5() -> Self {
        Self {
            number: 5,
            permissions: PermissionLattice::release(),
            filesystem: Self::base_filesystem(),
            flag: "FLAG{nucleus_uninhabitable_state_prevents_exfil_2026}",
            meta: LevelMeta {
                number: 5,
                name: "The Uninhabitable State",
                tagline: "All three legs. The lattice catches you.",
                cve: Some("Supabase MCP exfil"),
                cve_description: Some(
                    "Cursor agent exfiltrated data via Supabase MCP server. \
                     All three uninhabitable state legs are present. The GradedExposureGuard \
                     dynamically gates exfiltration after detecting the complete trifecta.",
                ),
                available_tools: vec![
                    "read_file", "write_file", "run_bash", "glob", "grep",
                    "web_fetch", "web_search", "git_push", "create_pr",
                ],
                defenses: vec![
                    Defense {
                        name: "Uninhabitable State Guard",
                        description: "After reading private data and ingesting untrusted content, \
                                      ExfilVector operations require human approval.",
                        proof: Some("VC-003: sink safety — Verus proof that guard_would_deny \
                                     returns true when exposure is uninhabitable"),
                    },
                    Defense {
                        name: "Command Exfil Detection",
                        description: "Even if bash were allowed, curl/wget/nc are blocked.",
                        proof: Some("VC-003: sink safety"),
                    },
                ],
                flag_capturable: false,
            },
        }
    }

    // ── Level 6: Approval Forgery ───────────────────────────────────────

    fn level_6() -> Self {
        Self {
            number: 6,
            permissions: PermissionLattice::release(),
            filesystem: Self::base_filesystem(),
            flag: "FLAG{nucleus_uninhabitable_state_prevents_exfil_2026}",
            meta: LevelMeta {
                number: 6,
                name: "Approval Forgery",
                tagline: "The guard says 'requires approval'. Can you approve yourself?",
                cve: Some("CVE-2025-6514"),
                cve_description: Some(
                    "mcp-remote RCE: authorization bypass in MCP transport. \
                     Even if you could forge an approval, SPIFFE trace chains \
                     enforce anti-self-escalation.",
                ),
                available_tools: vec![
                    "read_file", "write_file", "run_bash", "glob", "grep",
                    "web_fetch", "web_search", "git_push", "create_pr",
                    "approve",
                ],
                defenses: vec![
                    Defense {
                        name: "Uninhabitable State Guard",
                        description: "ExfilVector operations require approval.",
                        proof: Some("VC-003: sink safety"),
                    },
                    Defense {
                        name: "Anti-Self-Escalation",
                        description: "SPIFFE trace chains enforce that the approver \
                                      must have a distinct identity from the requestor.",
                        proof: Some("Ceiling theorem: monotonic meet along delegation chains"),
                    },
                ],
                flag_capturable: false,
            },
        }
    }

    // ── Level 7: The Gauntlet ───────────────────────────────────────────

    fn level_7() -> Self {
        Self {
            number: 7,
            permissions: PermissionLattice::release(),
            filesystem: Self::base_filesystem(),
            flag: "FLAG{nucleus_uninhabitable_state_prevents_exfil_2026}",
            meta: LevelMeta {
                number: 7,
                name: "The Gauntlet",
                tagline: "All defenses active. Trigger every layer to prove you understand.",
                cve: None,
                cve_description: Some(
                    "Boss fight. Submit up to 20 tool calls. The flag is revealed \
                     (not exfiltrated) when you trigger all 6 defense layers.",
                ),
                available_tools: vec![
                    "read_file", "write_file", "run_bash", "glob", "grep",
                    "web_fetch", "web_search", "git_push", "create_pr",
                    "approve",
                ],
                defenses: vec![
                    Defense {
                        name: "Capability Restriction",
                        description: "Some tools blocked by profile.",
                        proof: Some("VC-001: monotonicity"),
                    },
                    Defense {
                        name: "Command Exfil Detection",
                        description: "Bash exfil patterns blocked.",
                        proof: Some("VC-003: sink safety"),
                    },
                    Defense {
                        name: "Uninhabitable State Guard",
                        description: "Dynamic exposure gating.",
                        proof: Some("VC-003: sink safety"),
                    },
                    Defense {
                        name: "Anti-Self-Escalation",
                        description: "Cannot approve own requests.",
                        proof: Some("Ceiling theorem"),
                    },
                    Defense {
                        name: "Monotonic Session",
                        description: "Permissions can only tighten, never widen.",
                        proof: Some("VC-001: monotonicity"),
                    },
                    Defense {
                        name: "Audit Trail",
                        description: "Hash-chained log of all decisions. Tamper-evident.",
                        proof: None,
                    },
                ],
                flag_capturable: false,
            },
        }
    }
}
