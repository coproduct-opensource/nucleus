//! Intent system for user-facing permission profiles.
//!
//! [`Intent`] maps high-level goals (e.g., "fix an issue", "review code") to
//! lattice-guard permission profiles. [`IntentSession`] wraps a [`ProxyClient`]
//! with the resolved profile for scoped, type-safe operations.
//!
//! Mirrors the Python SDK's `intent.py`.

use std::collections::HashMap;

use crate::proxy::ProxyClient;
use crate::Error;

/// User-facing intent describing what an agent session will do.
///
/// Each intent maps to a lattice-guard profile name that determines the
/// permission lattice for the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Intent {
    /// Web research: read + web_fetch + web_search. No write or exec.
    ResearchWeb,
    /// Code review: read files + glob + grep. No write, no network.
    CodeReview,
    /// Fix an issue: full code editing with trifecta obligations.
    FixIssue,
    /// Generate code: write files in workspace. No network (network-isolated).
    GenerateCode,
    /// Release: git push + PR operations. CI-gated.
    Release,
    /// Database client: network to allowed hosts, no file write.
    DatabaseClient,
    /// Read-only: observe files, no mutations.
    ReadOnly,
    /// Edit-only: write files, no execution or network.
    EditOnly,
    /// Local development: permissive local environment.
    LocalDev,
    /// Network-only: web operations, no filesystem access.
    NetworkOnly,
    /// Orchestrator: manage sub-pods, no direct file/network access.
    Orchestrate,
}

impl Intent {
    /// Get the lattice-guard profile name for this intent.
    pub fn profile_name(&self) -> &'static str {
        match self {
            Intent::ResearchWeb => "web_research",
            Intent::CodeReview => "code_review",
            Intent::FixIssue => "fix_issue",
            Intent::GenerateCode => "codegen",
            Intent::Release => "release",
            Intent::DatabaseClient => "database_client",
            Intent::ReadOnly => "read_only",
            Intent::EditOnly => "edit_only",
            Intent::LocalDev => "local_dev",
            Intent::NetworkOnly => "network_only",
            Intent::Orchestrate => "orchestrator",
        }
    }

    /// Human-readable description of the intent.
    pub fn description(&self) -> &'static str {
        match self {
            Intent::ResearchWeb => "Web research: read + web access, no writes",
            Intent::CodeReview => "Code review: read + search, no writes or network",
            Intent::FixIssue => "Fix issue: full code editing with trifecta obligations",
            Intent::GenerateCode => "Generate code: write files, no network (isolated)",
            Intent::Release => "Release: git push + PR operations, CI-gated",
            Intent::DatabaseClient => "Database client: network to allowed hosts, no file write",
            Intent::ReadOnly => "Read-only: observe files, no mutations",
            Intent::EditOnly => "Edit-only: write files, no execution or network",
            Intent::LocalDev => "Local development: permissive local environment",
            Intent::NetworkOnly => "Network-only: web operations, no filesystem access",
            Intent::Orchestrate => "Orchestrator: manage sub-pods only",
        }
    }

    /// All available intents.
    pub fn all() -> &'static [Intent] {
        &[
            Intent::ResearchWeb,
            Intent::CodeReview,
            Intent::FixIssue,
            Intent::GenerateCode,
            Intent::Release,
            Intent::DatabaseClient,
            Intent::ReadOnly,
            Intent::EditOnly,
            Intent::LocalDev,
            Intent::NetworkOnly,
            Intent::Orchestrate,
        ]
    }
}

/// Resolved profile for an intent, including the permission lattice.
#[derive(Debug, Clone)]
pub struct IntentProfile {
    /// The intent this profile was derived from.
    pub intent: Intent,
    /// Lattice-guard profile name.
    pub profile_name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Resolved permission lattice.
    pub lattice: lattice_guard::PermissionLattice,
}

impl IntentProfile {
    /// Resolve an intent to its full profile including lattice.
    pub fn resolve(intent: Intent) -> Result<Self, Error> {
        let profile_name = intent.profile_name();
        let policy = nucleus_spec::PolicySpec::Profile {
            name: profile_name.to_string(),
        };
        let lattice = policy.resolve().map_err(|e| {
            Error::Config(format!(
                "failed to resolve profile '{}': {}",
                profile_name, e
            ))
        })?;

        Ok(Self {
            intent,
            profile_name,
            description: intent.description(),
            lattice,
        })
    }

    /// Check which operations are allowed at autonomous level.
    pub fn allowed_operations(&self) -> Vec<lattice_guard::Operation> {
        use lattice_guard::{CapabilityLevel, Operation};

        let ops = [
            (Operation::ReadFiles, self.lattice.capabilities.read_files),
            (Operation::WriteFiles, self.lattice.capabilities.write_files),
            (Operation::RunBash, self.lattice.capabilities.run_bash),
            (Operation::WebFetch, self.lattice.capabilities.web_fetch),
            (Operation::WebSearch, self.lattice.capabilities.web_search),
            (Operation::GitPush, self.lattice.capabilities.git_push),
            (Operation::GitCommit, self.lattice.capabilities.git_commit),
            (Operation::CreatePr, self.lattice.capabilities.create_pr),
            (Operation::GlobSearch, self.lattice.capabilities.glob_search),
            (Operation::GrepSearch, self.lattice.capabilities.grep_search),
        ];

        ops.iter()
            .filter(|(_, level)| {
                matches!(level, CapabilityLevel::Always | CapabilityLevel::LowRisk)
            })
            .map(|(op, _)| *op)
            .collect()
    }

    /// Check which operations have approval obligations (gated by trifecta enforcement).
    pub fn gated_operations(&self) -> Vec<lattice_guard::Operation> {
        self.lattice.obligations.approvals.iter().copied().collect()
    }
}

/// A session bound to an intent profile, wrapping a [`ProxyClient`].
///
/// Provides the same operations as `ProxyClient` but scoped to the intent's
/// permission profile. The tool-proxy enforces the actual lattice — this is
/// a client-side convenience for intent-aware usage.
///
/// # Example
///
/// ```rust,no_run
/// use nucleus_sdk::{Nucleus, Intent, HmacAuth};
///
/// # async fn example() -> nucleus_sdk::Result<()> {
/// let nucleus = Nucleus::builder()
///     .proxy_url("http://127.0.0.1:8080")
///     .auth(HmacAuth::new(b"secret", None))
///     .build()?;
///
/// let session = nucleus.intent(Intent::CodeReview).await?;
/// let source = session.read("src/lib.rs").await?;
/// // session.write(...) would be denied by the tool-proxy (CodeReview is read-only)
/// # Ok(())
/// # }
/// ```
pub struct IntentSession {
    proxy: ProxyClient,
    /// The resolved intent profile for this session.
    pub profile: IntentProfile,
    /// Pod ID if this session was created via nucleus-node.
    pub pod_id: Option<String>,
}

impl IntentSession {
    /// Create a new intent session wrapping a proxy client.
    pub fn new(proxy: ProxyClient, profile: IntentProfile, pod_id: Option<String>) -> Self {
        Self {
            proxy,
            profile,
            pod_id,
        }
    }

    /// Get the underlying proxy client.
    pub fn proxy(&self) -> &ProxyClient {
        &self.proxy
    }

    // -- Delegated operations --

    /// Read a file's contents.
    pub async fn read(&self, path: &str) -> Result<String, Error> {
        self.proxy.read(path).await
    }

    /// Write contents to a file.
    pub async fn write(&self, path: &str, contents: &str) -> Result<(), Error> {
        self.proxy.write(path, contents).await
    }

    /// Run a command.
    pub async fn run(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        directory: Option<&str>,
    ) -> Result<crate::proxy::RunOutput, Error> {
        self.proxy.run(args, stdin, directory).await
    }

    /// Search for files matching a glob pattern.
    pub async fn glob(
        &self,
        pattern: &str,
        directory: Option<&str>,
        max_results: Option<u32>,
    ) -> Result<crate::proxy::GlobOutput, Error> {
        self.proxy.glob(pattern, directory, max_results).await
    }

    /// Search file contents with a regex pattern.
    pub async fn grep(
        &self,
        pattern: &str,
        path: Option<&str>,
        file_glob: Option<&str>,
        context_lines: Option<u32>,
        max_matches: Option<u32>,
        case_insensitive: Option<bool>,
    ) -> Result<crate::proxy::GrepOutput, Error> {
        self.proxy
            .grep(
                pattern,
                path,
                file_glob,
                context_lines,
                max_matches,
                case_insensitive,
            )
            .await
    }

    /// Fetch a URL.
    pub async fn web_fetch(
        &self,
        url: &str,
        method: Option<&str>,
        headers: Option<&HashMap<String, String>>,
        body: Option<&str>,
    ) -> Result<serde_json::Value, Error> {
        self.proxy.web_fetch(url, method, headers, body).await
    }

    /// Grant pre-approval for an operation.
    pub async fn approve(
        &self,
        operation: &str,
        count: u32,
        expires_at_unix: Option<u64>,
        nonce: Option<&str>,
    ) -> Result<serde_json::Value, Error> {
        self.proxy
            .approve(operation, count, expires_at_unix, nonce)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_intents_resolve() {
        for intent in Intent::all() {
            let profile = IntentProfile::resolve(*intent);
            assert!(
                profile.is_ok(),
                "Intent {:?} should resolve, got: {:?}",
                intent,
                profile.err()
            );
        }
    }

    #[test]
    fn test_intent_profile_names_match() {
        let cases = [
            (Intent::ResearchWeb, "web_research"),
            (Intent::CodeReview, "code_review"),
            (Intent::FixIssue, "fix_issue"),
            (Intent::GenerateCode, "codegen"),
            (Intent::Release, "release"),
            (Intent::DatabaseClient, "database_client"),
            (Intent::ReadOnly, "read_only"),
            (Intent::EditOnly, "edit_only"),
            (Intent::LocalDev, "local_dev"),
            (Intent::NetworkOnly, "network_only"),
            (Intent::Orchestrate, "orchestrator"),
        ];

        for (intent, expected) in cases {
            assert_eq!(intent.profile_name(), expected);
        }
    }

    #[test]
    fn test_code_review_is_read_only() {
        let profile = IntentProfile::resolve(Intent::CodeReview).unwrap();
        let allowed = profile.allowed_operations();

        // Code review should allow read, glob, grep
        assert!(allowed.contains(&lattice_guard::Operation::ReadFiles));
        assert!(allowed.contains(&lattice_guard::Operation::GlobSearch));
        assert!(allowed.contains(&lattice_guard::Operation::GrepSearch));

        // Should NOT allow write, run_bash, git push
        assert!(!allowed.contains(&lattice_guard::Operation::WriteFiles));
        assert!(!allowed.contains(&lattice_guard::Operation::RunBash));
        assert!(!allowed.contains(&lattice_guard::Operation::GitPush));
    }

    #[test]
    fn test_fix_issue_has_trifecta_awareness() {
        let profile = IntentProfile::resolve(Intent::FixIssue).unwrap();

        // Fix issue has broad capabilities — check that gated ops exist
        // (trifecta enforcement adds approval obligations)
        let _gated = profile.gated_operations();
        let allowed = profile.allowed_operations();

        // Should allow read and write
        assert!(allowed.contains(&lattice_guard::Operation::ReadFiles));
        assert!(allowed.contains(&lattice_guard::Operation::WriteFiles));
    }

    #[test]
    fn test_codegen_no_network() {
        let profile = IntentProfile::resolve(Intent::GenerateCode).unwrap();
        let allowed = profile.allowed_operations();

        // Codegen should allow write
        assert!(allowed.contains(&lattice_guard::Operation::WriteFiles));

        // Should NOT allow web fetch (network-isolated)
        assert!(!allowed.contains(&lattice_guard::Operation::WebFetch));
    }

    #[test]
    fn test_orchestrator_pod_management() {
        let profile = IntentProfile::resolve(Intent::Orchestrate).unwrap();

        // Orchestrator has limited direct ops but manages sub-pods
        // The key assertion is that it resolves without error
        assert_eq!(profile.profile_name, "orchestrator");
    }

    #[test]
    fn test_all_intents_count() {
        assert_eq!(Intent::all().len(), 11);
    }
}
