//! Takeaway builder: generates human-readable summaries for triggered defenses.

/// Build takeaway messages for each defense layer that was triggered.
pub fn build_takeaways(defenses: &[String]) -> Vec<String> {
    let mut takeaways = Vec::new();

    if defenses.iter().any(|d| d == "Capability Restriction") {
        takeaways.push(
            "Capability Restriction: The simplest defense is not granting capabilities \
             in the first place. Nucleus's permission lattice is monotonic (VC-001) — \
             capabilities can only tighten during a session, never widen. This alone \
             would have prevented CVE-2024-37032 (Ollama RCE via path traversal)."
                .into(),
        );
    }
    if defenses.iter().any(|d| d == "Command Exfil Detection") {
        takeaways.push(
            "Command Exfil Detection: Even with bash access, the CommandLattice performs \
             sink analysis on every command before execution. curl, wget, nc, python \
             urllib — all caught. This blocks the exact attack from CVE-2025-43563 \
             (Claude Code prompt injection via git commit messages)."
                .into(),
        );
    }
    if defenses.iter().any(|d| d == "Uninhabitable State Guard") {
        takeaways.push(
            "Uninhabitable State Guard: Data exfiltration requires three simultaneous \
             conditions: private data access + untrusted content + exfil vector. The \
             GradedExposureGuard tracks this trifecta in real-time and blocks when all \
             three legs are present. Proven correct by VC-003 — zero false negatives. \
             This would have stopped the Supabase MCP exfiltration."
                .into(),
        );
    }
    if defenses.iter().any(|d| d == "Anti-Self-Escalation") {
        takeaways.push(
            "Anti-Self-Escalation: SPIFFE workload identity ensures the approver is \
             cryptographically distinct from the requestor. The Ceiling Theorem proves \
             self-delegation is impossible in the principal lattice. This closes the \
             attack surface from CVE-2025-6514 (mcp-remote authorization bypass)."
                .into(),
        );
    }
    if defenses.iter().any(|d| d == "Monotonic Session") {
        takeaways.push(
            "Monotonic Session: Once a session's capabilities tighten, they can never \
             widen again. The lattice ordering (Never ≤ OnApproval ≤ Always) is enforced \
             by VC-001. No sequence of operations, no matter how clever, can escalate \
             back up."
                .into(),
        );
    }
    if defenses.iter().any(|d| d == "Audit Trail") {
        takeaways.push(
            "Audit Trail: Every operation decision is logged in a hash-chained, \
             tamper-evident audit log. Even if an attacker found a way past the other \
             5 layers, the audit trail makes the breach detectable and forensically \
             reconstructable."
                .into(),
        );
    }

    takeaways.push(
        "These 6 defense layers are production code from Nucleus — an open-source, \
         formally verified secure runtime for AI agents. 297 Verus SMT proofs. MIT \
         licensed. https://github.com/coproduct-opensource/nucleus"
            .into(),
    );

    takeaways
}
