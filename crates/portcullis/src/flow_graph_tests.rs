use super::*;
use portcullis_core::flow::FlowDenyReason;
use portcullis_core::*;

#[test]
fn empty_graph() {
    let g = FlowGraph::new();
    assert!(g.is_empty());
    assert!(g.get(0).is_none());
    assert!(g.get(1).is_none());
}

#[test]
fn sequential_ids() {
    let mut g = FlowGraph::new();
    let now = 1000;
    assert_eq!(
        g.insert_observation(NodeKind::UserPrompt, &[], now)
            .unwrap(),
        1
    );
    assert_eq!(
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap(),
        2
    );
    assert_eq!(
        g.insert_observation(NodeKind::WebContent, &[], now)
            .unwrap(),
        3
    );
    assert_eq!(g.len(), 3);
}

#[test]
fn observation_propagates_labels() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], now)
        .unwrap();
    let plan = g
        .insert_observation(NodeKind::ModelPlan, &[web, user], now)
        .unwrap();
    let n = g.get(plan).unwrap();
    assert_eq!(n.label.integrity, IntegLevel::Adversarial);
    assert_eq!(n.label.authority, AuthorityLevel::NoAuthority);
}

#[test]
fn action_denied_with_web_parent() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let r = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
    assert_eq!(
        r.verdict,
        FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
    );
}

#[test]
fn action_allowed_with_clean_parents() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], now)
        .unwrap();
    let file = g
        .insert_observation(NodeKind::FileRead, &[user], now)
        .unwrap();
    let r = g
        .insert_action(Operation::WriteFiles, &[file], now)
        .unwrap();
    assert_eq!(r.verdict, FlowVerdict::Allow);
}

#[test]
fn parent_not_found() {
    let mut g = FlowGraph::new();
    assert_eq!(
        g.insert_observation(NodeKind::FileRead, &[999], 1000),
        Err(FlowGraphError::ParentNotFound(999))
    );
}

#[test]
fn too_many_parents() {
    let mut g = FlowGraph::new();
    let parents: Vec<NodeId> = (1..=9).collect();
    assert_eq!(
        g.insert_observation(NodeKind::ModelPlan, &parents, 1000),
        Err(FlowGraphError::TooManyParents {
            provided: 9,
            max: 8
        })
    );
}

#[test]
fn ancestors_traversal() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let a = g
        .insert_observation(NodeKind::UserPrompt, &[], now)
        .unwrap();
    let b = g.insert_observation(NodeKind::FileRead, &[a], now).unwrap();
    let c = g
        .insert_observation(NodeKind::ModelPlan, &[b], now)
        .unwrap();
    let d = g.insert_action(Operation::WriteFiles, &[c], now).unwrap();
    assert_eq!(g.ancestors(d.node_id).ancestors.len(), 3);
}

#[test]
fn receipt_from_denied_action() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let r = g.insert_action(Operation::CreatePr, &[web], now).unwrap();
    assert!(matches!(r.verdict, FlowVerdict::Deny(_)));
    let receipt = g.build_receipt_for(r.node_id, now).unwrap();
    assert!(receipt.display_chain().contains("BLOCKED"));
}

#[test]
fn sentinel_parent_rejected() {
    let mut g = FlowGraph::new();
    assert_eq!(
        g.insert_observation(NodeKind::FileRead, &[0], 1000),
        Err(FlowGraphError::SentinelParent)
    );
}

#[test]
fn denied_action_cannot_be_parent() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    // This write is denied (web taint)
    let denied = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
    assert!(matches!(denied.verdict, FlowVerdict::Deny(_)));
    // Trying to reference the denied node as a parent should fail
    assert_eq!(
        g.insert_observation(NodeKind::FileRead, &[denied.node_id], now),
        Err(FlowGraphError::DeniedParent(denied.node_id))
    );
}

#[test]
fn sentinel_parent_rejected_in_action() {
    let mut g = FlowGraph::new();
    assert!(matches!(
        g.insert_action(Operation::WriteFiles, &[0], 1000),
        Err(FlowGraphError::SentinelParent)
    ));
}

// THE KEY TEST
#[test]
fn independent_branches_no_overtaint() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Task A: web content (adversarial)
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    // Task B: local file (trusted) — NO dependency on web
    let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    // Task B write: depends ONLY on file — ALLOWED
    let b = g
        .insert_action(Operation::WriteFiles, &[file], now)
        .unwrap();
    assert_eq!(
        b.verdict,
        FlowVerdict::Allow,
        "No web taint — should be allowed"
    );

    // Task A write: depends on web — DENIED
    let a = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
    assert!(
        matches!(a.verdict, FlowVerdict::Deny(_)),
        "Web taint — should be denied"
    );
}

/// #372: Same operation can be denied then allowed (denied set uses IDs, not ops)
#[test]
fn denied_then_allowed_same_operation() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Web content → write denied
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let denied = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
    assert!(matches!(denied.verdict, FlowVerdict::Deny(_)));

    // Clean source → same operation (WriteFiles) allowed
    let clean = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    let allowed = g
        .insert_action(Operation::WriteFiles, &[clean], now)
        .unwrap();
    assert!(
        matches!(allowed.verdict, FlowVerdict::Allow),
        "WriteFiles with clean parents should be allowed even after a prior denial"
    );
}

/// #370: ancestors() skips denied nodes
#[test]
fn ancestors_skip_denied_nodes() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let denied = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
    assert!(matches!(denied.verdict, FlowVerdict::Deny(_)));

    // The denied node's own ancestors should work (for its receipt)
    // but we can verify that if somehow reached, denied nodes are skipped
    let ancestry = g.ancestors(denied.node_id);
    // Should include web (the parent) but not the denied node itself
    for a in &ancestry.ancestors {
        assert_ne!(
            a.id, denied.node_id,
            "denied node should not appear in its own ancestors"
        );
    }
}

/// #368: FlowGraphError has Display
#[test]
fn error_display_messages() {
    let e = FlowGraphError::SentinelParent;
    assert!(e.to_string().contains("sentinel"));

    let e = FlowGraphError::DeniedParent(42);
    assert!(e.to_string().contains("42"));
    assert!(e.to_string().contains("denied"));

    let e = FlowGraphError::ParentNotFound(99);
    assert!(e.to_string().contains("99"));
}

// ── causal_label() tests (#653) ────────────────────────────────────

#[test]
fn causal_label_no_parents_is_clean() {
    let g = FlowGraph::new();
    let now = 1000;
    // No parents → base OutboundAction label (trusted, no taint)
    let label = g.causal_label(&[], now).unwrap();
    assert_eq!(label.integrity, portcullis_core::IntegLevel::Trusted);
}

#[test]
fn causal_label_from_web_is_tainted() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let label = g.causal_label(&[web], now).unwrap();
    assert_eq!(
        label.integrity,
        portcullis_core::IntegLevel::Adversarial,
        "causal label from web content should be adversarial"
    );
}

#[test]
fn causal_label_independent_branches_not_tainted() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Branch A: web content (adversarial)
    let _web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();

    // Branch B: local file read (trusted) — independent of web
    let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    // causal_label for an action depending ONLY on the file read
    let label = g.causal_label(&[file], now).unwrap();
    assert_eq!(
        label.integrity,
        portcullis_core::IntegLevel::Trusted,
        "action depending only on file read should NOT be tainted by unrelated web content"
    );
}

#[test]
fn causal_label_mixed_parents_takes_worst() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    // Action depending on BOTH web and file → takes the worst (adversarial)
    let label = g.causal_label(&[web, file], now).unwrap();
    assert_eq!(
        label.integrity,
        portcullis_core::IntegLevel::Adversarial,
        "mixed parents should propagate the worst label"
    );
}

#[test]
fn causal_label_matches_insert_action_label() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();

    // Query the causal label
    let queried = g.causal_label(&[web], now).unwrap();

    // Actually insert the action
    let decision = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
    let inserted = g.get(decision.node_id).unwrap().label;

    assert_eq!(
        queried, inserted,
        "causal_label query must match the label of an actually inserted action"
    );
}

#[test]
fn causal_label_invalid_parent_returns_error() {
    let g = FlowGraph::new();
    let result = g.causal_label(&[999], 1000);
    assert!(result.is_err());
}

// ── DeclassificationToken integration tests ──────────────────────

#[test]
fn apply_token_raises_integrity() {
    use portcullis_core::declassify::*;

    let mut g = FlowGraph::new();
    let now = 1000;

    // Insert web content (adversarial integrity)
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let web_label = g.get(web).unwrap().label;
    assert_eq!(
        web_label.integrity,
        portcullis_core::IntegLevel::Adversarial
    );

    // Create a token to raise integrity for this specific node
    let token = DeclassificationToken::new(
        web,
        DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: portcullis_core::IntegLevel::Adversarial,
                to: portcullis_core::IntegLevel::Untrusted,
            },
            justification: "Validated search results",
        },
        vec![Operation::WriteFiles, Operation::GitCommit],
        now + 3600,
        "Curated API output".to_string(),
    );

    let result = g.apply_token(&token, now);
    match result {
        TokenApplyResult::Applied {
            original_label,
            new_label,
        } => {
            assert_eq!(
                original_label.integrity,
                portcullis_core::IntegLevel::Adversarial
            );
            assert_eq!(new_label.integrity, portcullis_core::IntegLevel::Untrusted);
        }
        other => panic!("Expected Applied, got {other:?}"),
    }

    // Verify the node's label was actually modified in the graph
    assert_eq!(
        g.get(web).unwrap().label.integrity,
        portcullis_core::IntegLevel::Untrusted
    );
}

#[test]
fn apply_token_expired() {
    use portcullis_core::declassify::*;

    let mut g = FlowGraph::new();
    let now = 1000;
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();

    let token = DeclassificationToken::new(
        web,
        DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: portcullis_core::IntegLevel::Adversarial,
                to: portcullis_core::IntegLevel::Untrusted,
            },
            justification: "test",
        },
        vec![Operation::WriteFiles],
        999, // expired before now=1000
        "expired token".to_string(),
    );

    let result = g.apply_token(&token, now);
    assert!(matches!(result, TokenApplyResult::Expired { .. }));

    // Label should be unchanged
    assert_eq!(
        g.get(web).unwrap().label.integrity,
        portcullis_core::IntegLevel::Adversarial
    );
}

#[test]
fn apply_token_node_not_found() {
    use portcullis_core::declassify::*;

    let mut g = FlowGraph::new();
    let token = DeclassificationToken::new(
        999, // nonexistent
        DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: portcullis_core::IntegLevel::Adversarial,
                to: portcullis_core::IntegLevel::Untrusted,
            },
            justification: "test",
        },
        vec![],
        u64::MAX,
        "ghost node".to_string(),
    );

    assert!(matches!(
        g.apply_token(&token, 1000),
        TokenApplyResult::NodeNotFound
    ));
}

#[test]
fn apply_token_precondition_unmet() {
    use portcullis_core::declassify::*;

    let mut g = FlowGraph::new();
    let now = 1000;

    // FileRead has Trusted integrity — rule expects Adversarial
    let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    let token = DeclassificationToken::new(
        file,
        DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: portcullis_core::IntegLevel::Adversarial,
                to: portcullis_core::IntegLevel::Untrusted,
            },
            justification: "test",
        },
        vec![Operation::WriteFiles],
        u64::MAX,
        "wrong precondition".to_string(),
    );

    assert!(matches!(
        g.apply_token(&token, now),
        TokenApplyResult::PreconditionUnmet
    ));
}

// ── Artifact-granular quarantine tests (#639) ───────────────────

#[test]
fn quarantine_nonexistent_node_returns_false() {
    let mut g = FlowGraph::new();
    assert!(!g.quarantine(999));
}

#[test]
fn quarantine_and_check_direct() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    assert!(!g.is_quarantined(web));
    assert!(g.quarantine(web));
    assert!(g.is_quarantined(web));
}

#[test]
fn quarantine_idempotent() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    assert!(g.quarantine(web)); // first time: true (newly inserted)
    assert!(!g.quarantine(web)); // second time: false (already present)
    assert!(g.is_quarantined(web));
}

#[test]
fn quarantine_propagates_to_descendants() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Web content → model plan → action chain
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let plan = g
        .insert_observation(NodeKind::ModelPlan, &[web], now)
        .unwrap();
    let summary = g
        .insert_observation(NodeKind::Summarization, &[plan], now)
        .unwrap();

    // Quarantine the web content node
    g.quarantine(web);

    // All descendants should be quarantined via ancestry
    assert!(g.is_quarantined(plan), "child of quarantined node");
    assert!(g.is_quarantined(summary), "grandchild of quarantined node");
}

#[test]
fn quarantine_independent_branch_not_affected() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Branch A: web content (will be quarantined)
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let web_plan = g
        .insert_observation(NodeKind::ModelPlan, &[web], now)
        .unwrap();

    // Branch B: local file (independent, clean)
    let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    let file_plan = g
        .insert_observation(NodeKind::ModelPlan, &[file], now)
        .unwrap();

    // Quarantine web content
    g.quarantine(web);

    // Branch A is quarantined
    assert!(g.is_quarantined(web));
    assert!(g.is_quarantined(web_plan));

    // Branch B is NOT quarantined
    assert!(!g.is_quarantined(file), "independent file not quarantined");
    assert!(
        !g.is_quarantined(file_plan),
        "independent file plan not quarantined"
    );
}

#[test]
fn quarantined_ancestors_returns_specific_nodes() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let plan = g
        .insert_observation(NodeKind::ModelPlan, &[web], now)
        .unwrap();
    let summary = g
        .insert_observation(NodeKind::Summarization, &[plan], now)
        .unwrap();

    g.quarantine(web);

    let qa = g.quarantined_ancestors(summary);
    assert_eq!(
        qa,
        vec![web],
        "should identify the exact quarantined ancestor"
    );
}

#[test]
fn quarantined_ancestors_multiple() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web1 = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let web2 = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let merged = g
        .insert_observation(NodeKind::ModelPlan, &[web1, web2], now)
        .unwrap();

    g.quarantine(web1);
    g.quarantine(web2);

    let mut qa = g.quarantined_ancestors(merged);
    qa.sort();
    assert_eq!(qa, vec![web1, web2]);
}

#[test]
fn insert_action_inherits_quarantine_from_parent() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    g.quarantine(web);

    // Insert an action with the quarantined parent
    let decision = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();

    // The action node should be quarantined
    assert!(
        g.is_quarantined(decision.node_id),
        "action with quarantined parent should inherit quarantine"
    );
}

#[test]
fn insert_observation_inherits_quarantine_from_parent() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    g.quarantine(web);

    // Insert observation with quarantined parent
    let plan = g
        .insert_observation(NodeKind::ModelPlan, &[web], now)
        .unwrap();

    assert!(
        g.is_quarantined(plan),
        "observation with quarantined parent should inherit quarantine"
    );
}

#[test]
fn insert_action_clean_parents_not_quarantined() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    let decision = g
        .insert_action(Operation::WriteFiles, &[file], now)
        .unwrap();

    assert!(
        !g.is_quarantined(decision.node_id),
        "action with clean parents should not be quarantined"
    );
}

#[test]
fn release_quarantine_with_audit() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    g.quarantine(web);
    assert!(g.is_quarantined(web));

    let release = g
        .release_quarantine(
            web,
            "admin@example.com",
            "verified safe by human review",
            now,
        )
        .unwrap();
    assert_eq!(release.node_id, web);
    assert_eq!(release.released_by, "admin@example.com");
    assert_eq!(release.reason, "verified safe by human review");
    assert_eq!(release.released_at, now);
    assert!(!g.is_quarantined(web));

    // Double release returns NotQuarantined error
    assert_eq!(
        g.release_quarantine(web, "admin@example.com", "again", now),
        Err(QuarantineError::NotQuarantined(web))
    );
}

#[test]
fn release_quarantine_stops_propagation() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let plan = g
        .insert_observation(NodeKind::ModelPlan, &[web], now)
        .unwrap();

    g.quarantine(web);
    assert!(g.is_quarantined(plan));

    // Release the quarantine on web
    g.release_quarantine(web, "reviewer@example.com", "content verified", now)
        .unwrap();

    // plan should no longer be quarantined (the ancestor is released)
    assert!(
        !g.is_quarantined(plan),
        "after releasing ancestor quarantine, descendant should be clean"
    );
}

#[test]
fn release_quarantine_not_quarantined_fails() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    // Node exists but is not quarantined
    assert_eq!(
        g.release_quarantine(file, "admin@example.com", "not needed", now),
        Err(QuarantineError::NotQuarantined(file))
    );
}

#[test]
fn quarantine_releases_are_logged() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web1 = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let web2 = g
        .insert_observation(NodeKind::WebContent, &[], now + 1)
        .unwrap();

    g.quarantine(web1);
    g.quarantine(web2);

    assert!(g.quarantine_releases().is_empty());

    g.release_quarantine(web1, "alice@example.com", "reviewed content", now + 10)
        .unwrap();
    g.release_quarantine(web2, "bob@example.com", "false positive", now + 20)
        .unwrap();

    let releases = g.quarantine_releases();
    assert_eq!(releases.len(), 2);

    assert_eq!(releases[0].node_id, web1);
    assert_eq!(releases[0].released_by, "alice@example.com");
    assert_eq!(releases[0].reason, "reviewed content");
    assert_eq!(releases[0].released_at, now + 10);

    assert_eq!(releases[1].node_id, web2);
    assert_eq!(releases[1].released_by, "bob@example.com");
    assert_eq!(releases[1].reason, "false positive");
    assert_eq!(releases[1].released_at, now + 20);
}

#[test]
fn quarantine_error_display() {
    let err = QuarantineError::NotQuarantined(42);
    assert!(err.to_string().contains("not quarantined"));
    assert!(err.to_string().contains("42"));
}

#[test]
fn check_flow_with_quarantine_clean() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], now)
        .unwrap();
    let decision = g
        .insert_action(Operation::WriteFiles, &[user], now)
        .unwrap();

    let qv = g.check_flow_with_quarantine(decision.node_id, now).unwrap();
    assert_eq!(
        qv,
        QuarantineVerdict::Clean(FlowVerdict::Allow),
        "clean node should get Clean verdict"
    );
}

#[test]
fn check_flow_with_quarantine_blocked() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    g.quarantine(web);

    // Even though this action is also denied by IFC (web taint),
    // the quarantine verdict takes precedence
    let decision = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
    let qv = g.check_flow_with_quarantine(decision.node_id, now).unwrap();

    match qv {
        QuarantineVerdict::Quarantined {
            quarantined_ancestors,
            underlying_verdict,
        } => {
            // The action itself is quarantined (inherited from web parent)
            assert!(
                quarantined_ancestors.contains(&decision.node_id)
                    || quarantined_ancestors.contains(&web),
                "should identify quarantined ancestor(s)"
            );
            // The underlying IFC verdict should also be Deny
            assert!(
                matches!(underlying_verdict, FlowVerdict::Deny(_)),
                "underlying verdict should also be deny for web-tainted action"
            );
        }
        other => panic!("Expected Quarantined, got {other:?}"),
    }
}

/// THE KEY QUARANTINE TEST: malicious issue quarantined, unrelated code clean
#[test]
fn quarantine_scenario_malicious_issue_vs_clean_code() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Agent reads malicious GitHub issue (web content)
    let malicious_issue = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();

    // Agent produces a summary from the malicious issue
    let summary = g
        .insert_observation(NodeKind::Summarization, &[malicious_issue], now)
        .unwrap();

    // Agent also reads local code (independent branch)
    let local_code = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    // Agent edits code based ONLY on local code (no dependency on issue)
    let code_edit = g
        .insert_action(Operation::WriteFiles, &[local_code], now)
        .unwrap();

    // Quarantine the malicious issue
    g.quarantine(malicious_issue);

    // Summary (from malicious issue) is quarantined
    assert!(
        g.is_quarantined(summary),
        "summary derived from quarantined issue should be quarantined"
    );

    // Code edit (independent branch) is NOT quarantined
    assert!(
        !g.is_quarantined(code_edit.node_id),
        "code edit from clean local code should NOT be quarantined"
    );

    // Summary cannot reach GitPush (quarantine check)
    let summary_action = g
        .insert_action(Operation::GitPush, &[summary], now)
        .unwrap();
    let qv = g
        .check_flow_with_quarantine(summary_action.node_id, now)
        .unwrap();
    assert!(
        matches!(qv, QuarantineVerdict::Quarantined { .. }),
        "action from quarantined summary should be blocked"
    );

    // Code edit CAN reach GitPush (no quarantine)
    // (It may still be denied by IFC rules, but no quarantine)
    let code_push = g
        .insert_action(Operation::GitPush, &[local_code], now)
        .unwrap();
    let qv2 = g
        .check_flow_with_quarantine(code_push.node_id, now)
        .unwrap();
    assert!(
        matches!(qv2, QuarantineVerdict::Clean(_)),
        "action from clean code should not be quarantined"
    );
}

#[test]
fn error_display_quarantined_parent() {
    let e = FlowGraphError::QuarantinedParent(7);
    assert!(e.to_string().contains("7"));
    assert!(e.to_string().contains("quarantined"));
}

// ── Trusted ancestry check tests (#515) ────────────────────────

#[test]
fn trusted_ancestry_file_reads_only() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], now)
        .unwrap();
    let file = g
        .insert_observation(NodeKind::FileRead, &[user], now)
        .unwrap();
    let plan = g
        .insert_observation(NodeKind::ModelPlan, &[file], now)
        .unwrap();

    assert_eq!(
        g.check_trusted_ancestry(plan),
        Some(TrustAncestryResult::Trusted),
        "chain of user prompt → file read → model plan should be trusted"
    );
}

#[test]
fn trusted_ancestry_web_ancestor_untrusted() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let plan = g
        .insert_observation(NodeKind::ModelPlan, &[web], now)
        .unwrap();

    match g.check_trusted_ancestry(plan) {
        Some(TrustAncestryResult::Untrusted { tainted_ancestors }) => {
            // The web node (Adversarial integrity) should be flagged.
            // The plan node inherits Adversarial via propagation, so both are tainted.
            assert!(
                tainted_ancestors.contains(&web),
                "web content node should be in tainted ancestors"
            );
            assert!(
                tainted_ancestors.contains(&plan),
                "plan node (inherits Adversarial from web) should be tainted"
            );
        }
        other => panic!("Expected Untrusted, got {other:?}"),
    }
}

#[test]
fn trusted_ancestry_declassified_web_content_trusted() {
    use portcullis_core::declassify::*;

    let mut g = FlowGraph::new();
    let now = 1000;

    // Web content starts as Adversarial
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    assert_eq!(
        g.get(web).unwrap().label.integrity,
        portcullis_core::IntegLevel::Adversarial
    );

    // Declassify: raise integrity from Adversarial to Untrusted
    let token = DeclassificationToken::new(
        web,
        DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: portcullis_core::IntegLevel::Adversarial,
                to: portcullis_core::IntegLevel::Untrusted,
            },
            justification: "Operator reviewed search results",
        },
        vec![Operation::WriteFiles],
        now + 3600,
        "Curated search output".to_string(),
    );
    let result = g.apply_token(&token, now);
    assert!(matches!(result, TokenApplyResult::Applied { .. }));

    // Insert a plan node depending on the declassified web content
    let plan = g
        .insert_observation(NodeKind::ModelPlan, &[web], now)
        .unwrap();

    // The plan inherits Untrusted (from declassified web) — which is
    // >= Untrusted, so the ancestry check should pass.
    assert_eq!(
        g.check_trusted_ancestry(plan),
        Some(TrustAncestryResult::Trusted),
        "declassified web content (Untrusted) should pass trusted ancestry check"
    );
}

#[test]
fn trusted_ancestry_nonexistent_node_returns_none() {
    let g = FlowGraph::new();
    assert_eq!(g.check_trusted_ancestry(999), None);
}

#[test]
fn trusted_ancestry_root_node_no_parents() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // A file read with no parents — Trusted integrity
    let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    assert_eq!(
        g.check_trusted_ancestry(file),
        Some(TrustAncestryResult::Trusted),
    );

    // A web content with no parents — Adversarial integrity
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    match g.check_trusted_ancestry(web) {
        Some(TrustAncestryResult::Untrusted { tainted_ancestors }) => {
            assert_eq!(tainted_ancestors, vec![web]);
        }
        other => panic!("Expected Untrusted, got {other:?}"),
    }
}

#[test]
fn trusted_ancestry_independent_branch_not_affected() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Branch A: web content (adversarial)
    let _web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();

    // Branch B: clean file chain (independent)
    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], now)
        .unwrap();
    let file = g
        .insert_observation(NodeKind::FileRead, &[user], now)
        .unwrap();

    // Branch B should be trusted — web content in branch A is irrelevant
    assert_eq!(
        g.check_trusted_ancestry(file),
        Some(TrustAncestryResult::Trusted),
        "independent branch should not be tainted by unrelated web content"
    );
}

#[test]
fn trusted_ancestry_mixed_parents_one_tainted() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let merged = g
        .insert_observation(NodeKind::ModelPlan, &[file, web], now)
        .unwrap();

    match g.check_trusted_ancestry(merged) {
        Some(TrustAncestryResult::Untrusted { tainted_ancestors }) => {
            assert!(
                tainted_ancestors.contains(&web),
                "web ancestor should be in tainted list"
            );
        }
        other => panic!("Expected Untrusted, got {other:?}"),
    }
}

// ── apply_token_verified integration tests (#731) ───────────────

#[cfg(feature = "crypto")]
mod apply_token_verified_tests {
    use super::*;
    use portcullis_core::declassify::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn test_key() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn make_graph_with_web_node() -> (FlowGraph, u64) {
        let mut g = FlowGraph::new();
        let now = 1000;
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        assert_eq!(
            g.get(web).unwrap().label.integrity,
            portcullis_core::IntegLevel::Adversarial
        );
        (g, web)
    }

    fn make_token_for(node_id: u64) -> DeclassificationToken {
        DeclassificationToken::new(
            node_id,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: portcullis_core::IntegLevel::Adversarial,
                    to: portcullis_core::IntegLevel::Untrusted,
                },
                justification: "Validated search results",
            },
            vec![Operation::WriteFiles, Operation::GitCommit],
            2000, // valid_until
            "Curated API output".to_string(),
        )
    }

    #[test]
    fn apply_token_verified_signed_token_succeeds() {
        let key = test_key();
        let (mut g, web) = make_graph_with_web_node();
        let mut token = make_token_for(web);

        crate::token_sign::sign_token(&mut token, &key);
        assert!(token.is_signed());

        let pk = key.public_key().as_ref();
        let result = g.apply_token_verified(&token, &[pk], 1000);

        match result {
            TokenApplyResult::Applied {
                original_label,
                new_label,
            } => {
                assert_eq!(
                    original_label.integrity,
                    portcullis_core::IntegLevel::Adversarial
                );
                assert_eq!(new_label.integrity, portcullis_core::IntegLevel::Untrusted);
            }
            other => panic!("Expected Applied, got {other:?}"),
        }

        // Verify the graph node was actually modified
        assert_eq!(
            g.get(web).unwrap().label.integrity,
            portcullis_core::IntegLevel::Untrusted
        );
    }

    #[test]
    fn apply_token_verified_tampered_signature_rejected() {
        let key = test_key();
        let (mut g, web) = make_graph_with_web_node();
        let mut token = make_token_for(web);

        crate::token_sign::sign_token(&mut token, &key);

        // Tamper: change the target node ID after signing
        token.target_node_id = web; // keep same so node exists, but tamper justification
        token.justification = "malicious override".to_string();

        let pk = key.public_key().as_ref();
        let result = g.apply_token_verified(&token, &[pk], 1000);
        assert_eq!(result, TokenApplyResult::InvalidSignature);

        // Verify the graph node was NOT modified
        assert_eq!(
            g.get(web).unwrap().label.integrity,
            portcullis_core::IntegLevel::Adversarial
        );
    }

    #[test]
    fn apply_token_verified_unsigned_token_rejected() {
        let key = test_key();
        let (mut g, web) = make_graph_with_web_node();
        let token = make_token_for(web); // unsigned

        assert!(!token.is_signed());

        let pk = key.public_key().as_ref();
        let result = g.apply_token_verified(&token, &[pk], 1000);
        assert_eq!(result, TokenApplyResult::InvalidSignature);

        // Verify the graph node was NOT modified
        assert_eq!(
            g.get(web).unwrap().label.integrity,
            portcullis_core::IntegLevel::Adversarial
        );
    }

    #[test]
    fn apply_token_verified_wrong_key_rejected() {
        let sign_key = test_key();
        let wrong_key = test_key();
        let (mut g, web) = make_graph_with_web_node();
        let mut token = make_token_for(web);

        crate::token_sign::sign_token(&mut token, &sign_key);

        let wrong_pk = wrong_key.public_key().as_ref();
        let result = g.apply_token_verified(&token, &[wrong_pk], 1000);
        assert_eq!(result, TokenApplyResult::InvalidSignature);
    }

    #[test]
    fn apply_token_verified_with_key_rotation() {
        let old_key = test_key();
        let new_key = test_key();
        let (mut g, web) = make_graph_with_web_node();
        let mut token = make_token_for(web);

        // Sign with old key
        crate::token_sign::sign_token(&mut token, &old_key);

        // Verify with both keys (rotation scenario)
        let old_pk = old_key.public_key().as_ref();
        let new_pk = new_key.public_key().as_ref();
        let result = g.apply_token_verified(&token, &[new_pk, old_pk], 1000);

        assert!(
            matches!(result, TokenApplyResult::Applied { .. }),
            "Should accept token signed by rotated-out key: {result:?}"
        );
    }

    #[test]
    fn apply_token_verified_expired_after_sig_check() {
        let key = test_key();
        let (mut g, web) = make_graph_with_web_node();
        let mut token = make_token_for(web);
        token.valid_until = 500; // expired

        // Re-sign with the updated valid_until
        crate::token_sign::sign_token(&mut token, &key);

        let pk = key.public_key().as_ref();
        let result = g.apply_token_verified(&token, &[pk], 1000);

        // Signature is valid, but token is expired
        assert!(
            matches!(result, TokenApplyResult::Expired { .. }),
            "Expected Expired after valid signature, got {result:?}"
        );
    }
}

// ── Node compaction tests (#746) ───────────────────────────────

#[test]
fn node_count_tracks_vec_size() {
    let mut g = FlowGraph::new();
    let now = 1000;
    assert_eq!(g.node_count(), 1); // sentinel only
    g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    assert_eq!(g.node_count(), 2); // sentinel + 1 node
    g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    assert_eq!(g.node_count(), 3);
}

#[test]
fn compaction_caps_graph_at_max_nodes() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Fill the graph to MAX_GRAPH_NODES + some extra.
    // Each insert_observation adds one node.
    for _ in 0..(MAX_GRAPH_NODES + 100) {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // After compaction, the Vec size is MAX_GRAPH_NODES + 100 + 1 (sentinel),
    // but many old slots should be tombstoned.
    let live = g.len();
    // The most recent MAX_GRAPH_NODES/2 nodes are kept, plus any
    // that survived. Live count should be roughly MAX_GRAPH_NODES/2.
    assert!(
        live <= MAX_GRAPH_NODES / 2 + 200,
        "live nodes ({live}) should be bounded after compaction"
    );

    // Old nodes in the evicted range should be None.
    // The first non-sentinel node (index 1) should have been tombstoned.
    assert!(
        g.get(1).is_none(),
        "oldest node should be tombstoned after compaction"
    );
}

#[test]
fn compaction_preserves_denied_nodes() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Insert web content early so its ID is low (will be in eviction range).
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();

    // Denied action — this node should survive compaction.
    let denied = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
    assert!(matches!(denied.verdict, FlowVerdict::Deny(_)));
    let denied_id = denied.node_id;

    // Fill the graph past the limit.
    for _ in 0..(MAX_GRAPH_NODES + 100) {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // The denied node should still be present.
    assert!(
        g.get(denied_id).is_some(),
        "denied node (id={denied_id}) must survive compaction"
    );
}

#[test]
fn compaction_preserves_quarantined_nodes() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Insert and quarantine a node early.
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    g.quarantine(web);

    // Fill the graph past the limit.
    for _ in 0..(MAX_GRAPH_NODES + 100) {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // The quarantined node should still be present.
    assert!(
        g.get(web).is_some(),
        "quarantined node (id={web}) must survive compaction"
    );
    assert!(
        g.is_quarantined(web),
        "quarantined status must survive compaction"
    );
}

#[test]
fn compaction_preserves_recent_nodes() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Fill past the limit.
    let mut last_id = 0;
    for _ in 0..(MAX_GRAPH_NODES + 50) {
        last_id = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // The most recently inserted node should be accessible.
    assert!(
        g.get(last_id).is_some(),
        "most recent node must survive compaction"
    );

    // A node near the end (within the recent half) should also survive.
    let recent_id = last_id - 10;
    assert!(
        g.get(recent_id).is_some(),
        "recent node (id={recent_id}) should survive compaction"
    );
}

// ── Compaction laundering prevention tests (#782) ────────────────

#[test]
fn compaction_records_preserved_labels() {
    // Verify that when compaction tombstones a node, its label
    // is recorded in the compaction log.
    //
    // The web node is inserted close to the keep_from boundary so its
    // compaction record falls within the retained MAX_COMPACTION_LOG
    // entries after capping (#836).
    let mut g = FlowGraph::new();
    let now = 1000;

    // Fill most of the graph first.
    // keep_from will be count - MAX_GRAPH_NODES/2.
    // When count = MAX_GRAPH_NODES, keep_from = MAX_GRAPH_NODES/2 = 5000.
    // We want web node just below keep_from so it gets compacted but its
    // record is among the last MAX_COMPACTION_LOG entries.
    // Insert filler up to index ~(keep_from - 500).
    let filler_count = MAX_GRAPH_NODES / 2 - 500;
    for _ in 0..filler_count {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // Insert the tainted web content node.
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    let web_label = g.get(web).unwrap().label;

    // Fill past the compaction limit.
    for _ in 0..(MAX_GRAPH_NODES - filler_count) {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // The web node should be tombstoned.
    assert!(
        g.get(web).is_none(),
        "web node should be tombstoned after compaction"
    );

    // But its label should be preserved in the compaction log.
    let log = g.compaction_log();
    assert!(!log.is_empty(), "compaction log should not be empty");
    assert!(
        log.len() <= MAX_COMPACTION_LOG,
        "compaction log should be capped at {MAX_COMPACTION_LOG}"
    );

    let web_record = log.iter().find(|r| r.compacted_node_id == web);
    assert!(
        web_record.is_some(),
        "compaction log must contain a record for the tombstoned web node"
    );
    let record = web_record.unwrap();
    assert_eq!(
        record.preserved_label, web_label,
        "compaction record must preserve the node's original label (taint)"
    );
}

#[test]
fn ancestors_reports_tombstoned_nodes() {
    // Verify that ancestors() reports tombstoned ancestors instead
    // of silently skipping them.
    //
    // Strategy: insert a plan node early, fill to just before threshold,
    // then insert a bridge referencing plan. Trigger compaction so plan
    // is tombstoned but bridge survives. BFS from bridge hits plan
    // (tombstoned) on the first hop.
    let mut g = FlowGraph::new();
    let now = 1000;

    // Plan node at index 1 — will be compacted.
    let plan = g.insert_observation(NodeKind::ModelPlan, &[], now).unwrap();

    // Fill to MAX_GRAPH_NODES - 3.
    for _ in 0..(MAX_GRAPH_NODES - 3) {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // Bridge at index MAX_GRAPH_NODES - 1, referencing plan.
    let bridge = g
        .insert_observation(NodeKind::FileRead, &[plan], now)
        .unwrap();

    // Trigger compaction.
    g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    assert!(g.get(plan).is_none(), "plan node should be tombstoned");
    assert!(g.get(bridge).is_some(), "bridge node should survive");

    // Ancestors of bridge should report plan as tombstoned.
    let ancestry = g.ancestors(bridge);
    assert!(
        !ancestry.is_complete(),
        "ancestry should be incomplete after compaction"
    );
    assert!(
        ancestry.tombstoned_count() > 0,
        "should report tombstoned ancestors"
    );

    // The tombstoned records should include plan.
    let tombstoned_ids: Vec<_> = ancestry
        .tombstoned
        .iter()
        .map(|r| r.compacted_node_id)
        .collect();
    assert!(
        tombstoned_ids.contains(&plan),
        "tombstoned list should contain the compacted plan node"
    );
}

#[test]
fn receipt_marks_incomplete_chain_after_compaction() {
    // Verify that receipts built after compaction include
    // tombstoned ancestor info (#782).
    //
    // Strategy: insert a plan node early. Fill to just before the
    // compaction threshold, then insert a bridge node that references
    // the plan. Continue filling to trigger compaction. The plan node
    // is in the old half (compacted), while the bridge node is recent
    // enough to survive. When we build a receipt for an action
    // referencing bridge, the BFS finds bridge (live) then tries
    // bridge's parent (plan, tombstoned) and reports it.
    let mut g = FlowGraph::new();
    let now = 1000;

    // Insert a plan node early — this will be compacted.
    let plan = g.insert_observation(NodeKind::ModelPlan, &[], now).unwrap();

    // Fill to MAX_GRAPH_NODES - 3 (sentinel + plan + space for bridge).
    // After this, the Vec has MAX_GRAPH_NODES - 1 slots.
    for _ in 0..(MAX_GRAPH_NODES - 3) {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // Insert bridge referencing plan. This is at index MAX_GRAPH_NODES - 1.
    // The alloc_node call does maybe_compact first, but count is
    // MAX_GRAPH_NODES - 1, which is < MAX_GRAPH_NODES, so no compaction yet.
    let bridge = g
        .insert_observation(NodeKind::FileRead, &[plan], now)
        .unwrap();

    // Now Vec has MAX_GRAPH_NODES slots. Next insert triggers compaction.
    // keep_from = MAX_GRAPH_NODES + 1 - MAX_GRAPH_NODES/2
    //           = 1 + MAX_GRAPH_NODES/2 = 5001
    // So indices 1..5001 are compacted. plan (index 1) is compacted.
    // bridge (index MAX_GRAPH_NODES - 1 = 9999) survives.

    // Insert one more to trigger compaction.
    g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    // plan should be compacted, bridge should survive.
    assert!(g.get(plan).is_none(), "plan node should be compacted");
    assert!(g.get(bridge).is_some(), "bridge node should survive");

    // Insert action referencing bridge.
    let action = g
        .insert_action(Operation::WriteFiles, &[bridge], now)
        .unwrap();

    // Build receipt — bridge's parent (plan) is tombstoned, so
    // ancestry traversal should report it.
    let receipt = g.build_receipt_for(action.node_id, now).unwrap();
    assert!(
        !receipt.chain_complete(),
        "receipt should indicate chain is incomplete after compaction"
    );
    assert!(
        !receipt.tombstoned_ancestors().is_empty(),
        "receipt should contain tombstoned ancestor records"
    );

    // The display should mention compaction.
    let display = receipt.display_chain();
    assert!(
        display.contains("compacted"),
        "receipt display should mention compacted ancestors"
    );
}

#[test]
fn compaction_log_accessible() {
    // Verify the compaction_log() accessor works.
    let mut g = FlowGraph::new();
    let now = 1000;

    // Before compaction, log should be empty.
    assert!(g.compaction_log().is_empty());

    // Fill past the limit.
    for _ in 0..(MAX_GRAPH_NODES + 100) {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // After compaction, log should contain records.
    let log = g.compaction_log();
    assert!(
        !log.is_empty(),
        "compaction log should contain records after compaction"
    );

    // Each record should have a valid (non-zero) node ID.
    for record in log {
        assert!(
            record.compacted_node_id > 0,
            "compacted node ID should be non-zero"
        );
    }
}

#[test]
fn compaction_log_excludes_denied_and_quarantined() {
    // Denied and quarantined nodes are preserved by compaction,
    // so they should NOT appear in the compaction log.
    let mut g = FlowGraph::new();
    let now = 1000;

    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();
    g.quarantine(web);

    // Fill past the limit.
    for _ in 0..(MAX_GRAPH_NODES + 100) {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // The quarantined node should NOT be in the compaction log.
    let log = g.compaction_log();
    let quarantined_in_log = log.iter().any(|r| r.compacted_node_id == web);
    assert!(
        !quarantined_in_log,
        "quarantined nodes must not appear in compaction log (they are preserved)"
    );

    // But the quarantined node itself should still exist.
    assert!(
        g.get(web).is_some(),
        "quarantined node should survive compaction"
    );
}

#[test]
fn insert_action_populates_sink_class() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], now)
        .unwrap();
    let file = g
        .insert_observation(NodeKind::FileRead, &[user], now)
        .unwrap();

    let r = g.insert_action(Operation::GitPush, &[file], now).unwrap();
    let node = g.get(r.node_id).unwrap();
    assert_eq!(
        node.sink_class,
        Some(SinkClass::GitPush),
        "insert_action must populate sink_class from operation"
    );
}

#[test]
fn insert_action_sink_class_enables_sink_based_rules() {
    // Secret data flowing to GitPush (an exfil vector) must be denied.
    // This only works when sink_class is populated on the node.
    let mut g = FlowGraph::new();
    let now = 1000;
    let secret = g.insert_observation(NodeKind::Secret, &[], now).unwrap();

    let r = g.insert_action(Operation::GitPush, &[secret], now).unwrap();
    assert_eq!(
        r.verdict,
        FlowVerdict::Deny(FlowDenyReason::Exfiltration),
        "secret data to GitPush (exfil sink) must be denied"
    );
}

// ── EffectKind threading tests (#775) ────────────────────────────

#[test]
fn insert_action_with_effect_stores_effect_kind() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], now)
        .unwrap();
    let r = g
        .insert_action_with_effect(
            Operation::ReadFiles,
            &[user],
            now,
            Some(EffectKind::DeterministicFetch),
        )
        .unwrap();
    assert_eq!(r.verdict, FlowVerdict::Allow);
    let node = g.get(r.node_id).unwrap();
    assert_eq!(node.effect_kind, Some(EffectKind::DeterministicFetch));
}

#[test]
fn insert_action_without_effect_has_none() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], now)
        .unwrap();
    let r = g
        .insert_action(Operation::WriteFiles, &[user], now)
        .unwrap();
    let node = g.get(r.node_id).unwrap();
    assert_eq!(node.effect_kind, None);
}

// ── Field-level lineage tests (#711) ───────────────────────────────

#[test]
fn set_field_lineage_basic() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let db_read = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    let llm_call = g
        .insert_observation(NodeKind::ToolResponse, &[], now)
        .unwrap();

    // A node that combines both sources
    let output = g
        .insert_observation(NodeKind::ModelPlan, &[db_read, llm_call], now)
        .unwrap();

    // Annotate: price comes from DB (deterministic), summary from LLM (AI-derived)
    g.set_field_lineage(
        output,
        vec![
            FieldLineage {
                field_name: "price".to_string(),
                source_fields: vec![FieldRef {
                    node_id: db_read,
                    field_name: "raw_price".to_string(),
                }],
                effect_kind: EffectKind::DeterministicFetch,
                derivation: DerivationClass::Deterministic,
            },
            FieldLineage {
                field_name: "summary".to_string(),
                source_fields: vec![FieldRef {
                    node_id: llm_call,
                    field_name: "description".to_string(),
                }],
                effect_kind: EffectKind::LLMGenerate,
                derivation: DerivationClass::AIDerived,
            },
        ],
    )
    .unwrap();

    let lineage = g.get_field_lineage(output).unwrap();
    assert_eq!(lineage.len(), 2);
    assert_eq!(lineage[0].field_name, "price");
    assert_eq!(lineage[1].field_name, "summary");
}

#[test]
fn set_field_lineage_node_not_found() {
    let mut g = FlowGraph::new();
    let result = g.set_field_lineage(999, vec![]);
    assert_eq!(result, Err(FieldLineageError::NodeNotFound(999)));
}

#[test]
fn set_field_lineage_bad_source_ref() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let node = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    let result = g.set_field_lineage(
        node,
        vec![FieldLineage {
            field_name: "x".to_string(),
            source_fields: vec![FieldRef {
                node_id: 999,
                field_name: "y".to_string(),
            }],
            effect_kind: EffectKind::DeterministicFetch,
            derivation: DerivationClass::Deterministic,
        }],
    );
    assert!(matches!(
        result,
        Err(FieldLineageError::SourceNodeNotFound { .. })
    ));
}

#[test]
fn field_ancestry_traces_sources() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let source_a = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    let source_b = g
        .insert_observation(NodeKind::ToolResponse, &[], now)
        .unwrap();
    let output = g
        .insert_observation(NodeKind::ModelPlan, &[source_a, source_b], now)
        .unwrap();

    g.set_field_lineage(
        output,
        vec![FieldLineage {
            field_name: "result".to_string(),
            source_fields: vec![
                FieldRef {
                    node_id: source_a,
                    field_name: "val_a".to_string(),
                },
                FieldRef {
                    node_id: source_b,
                    field_name: "val_b".to_string(),
                },
            ],
            effect_kind: EffectKind::DeterministicFetch,
            derivation: DerivationClass::Mixed,
        }],
    )
    .unwrap();

    let ancestry = g.field_ancestry(output, "result");
    assert!(ancestry.contains(&source_a));
    assert!(ancestry.contains(&source_b));
    assert_eq!(ancestry.len(), 2);
}

#[test]
fn field_ancestry_transitive() {
    let mut g = FlowGraph::new();
    let now = 1000;

    let original = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    let intermediate = g
        .insert_observation(NodeKind::ModelPlan, &[original], now)
        .unwrap();
    let output = g
        .insert_observation(NodeKind::ModelPlan, &[intermediate], now)
        .unwrap();

    // intermediate.val derived from original.raw
    g.set_field_lineage(
        intermediate,
        vec![FieldLineage {
            field_name: "val".to_string(),
            source_fields: vec![FieldRef {
                node_id: original,
                field_name: "raw".to_string(),
            }],
            effect_kind: EffectKind::DeterministicFetch,
            derivation: DerivationClass::Deterministic,
        }],
    )
    .unwrap();

    // output.final_val derived from intermediate.val
    g.set_field_lineage(
        output,
        vec![FieldLineage {
            field_name: "final_val".to_string(),
            source_fields: vec![FieldRef {
                node_id: intermediate,
                field_name: "val".to_string(),
            }],
            effect_kind: EffectKind::DeterministicFetch,
            derivation: DerivationClass::Deterministic,
        }],
    )
    .unwrap();

    // Transitive: output.final_val should trace back to both intermediate and original
    let ancestry = g.field_ancestry(output, "final_val");
    assert!(ancestry.contains(&intermediate));
    assert!(ancestry.contains(&original));
}

#[test]
fn field_ancestry_unknown_field_returns_empty() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let node = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    assert!(g.field_ancestry(node, "nonexistent").is_empty());
}

#[test]
fn field_label_deterministic_vs_ai_derived() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // DB source: FileRead → deterministic, trusted
    let db = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    // LLM source: ToolResponse → untrusted
    let llm = g
        .insert_observation(NodeKind::ToolResponse, &[], now)
        .unwrap();

    // Combined node
    let output = g
        .insert_observation(NodeKind::ModelPlan, &[db, llm], now)
        .unwrap();

    g.set_field_lineage(
        output,
        vec![
            FieldLineage {
                field_name: "price".to_string(),
                source_fields: vec![FieldRef {
                    node_id: db,
                    field_name: "raw_price".to_string(),
                }],
                effect_kind: EffectKind::DeterministicFetch,
                derivation: DerivationClass::Deterministic,
            },
            FieldLineage {
                field_name: "summary".to_string(),
                source_fields: vec![FieldRef {
                    node_id: llm,
                    field_name: "text".to_string(),
                }],
                effect_kind: EffectKind::LLMGenerate,
                derivation: DerivationClass::AIDerived,
            },
        ],
    )
    .unwrap();

    // The node-level label is Mixed (joined from both sources)
    let node_label = g.get(output).unwrap().label;
    // The node-level derivation is AIDerived or Mixed depending on propagation,
    // but it's NOT Deterministic (because it includes LLM source)
    assert_ne!(node_label.derivation, DerivationClass::Deterministic);

    // Field-level: price is Deterministic, from the DB source only
    let price_label = g.field_label(output, "price").unwrap();
    assert_eq!(price_label.derivation, DerivationClass::Deterministic);
    // The price field should have the DB's integrity (Trusted)
    assert_eq!(price_label.integrity, IntegLevel::Trusted);

    // Field-level: summary is AIDerived, from the LLM source
    let summary_label = g.field_label(output, "summary").unwrap();
    assert_eq!(summary_label.derivation, DerivationClass::AIDerived);
}

#[test]
fn field_label_unknown_field_returns_none() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let node = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    assert!(g.field_label(node, "nonexistent").is_none());
}

#[test]
fn field_label_no_sources_uses_node_label() {
    let mut g = FlowGraph::new();
    let now = 1000;
    let node = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    g.set_field_lineage(
        node,
        vec![FieldLineage {
            field_name: "inline".to_string(),
            source_fields: vec![],
            effect_kind: EffectKind::DeterministicFetch,
            derivation: DerivationClass::Deterministic,
        }],
    )
    .unwrap();

    let label = g.field_label(node, "inline").unwrap();
    // Should use the node's own label with the field's derivation
    let node_label = g.get(node).unwrap().label;
    assert_eq!(label.integrity, node_label.integrity);
    assert_eq!(label.derivation, DerivationClass::Deterministic);
}

#[test]
fn field_label_join_of_multiple_sources() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Secret source
    let secret = g.insert_observation(NodeKind::EnvVar, &[], now).unwrap();
    // Public source
    let public = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();

    let output = g
        .insert_observation(NodeKind::ModelPlan, &[secret, public], now)
        .unwrap();

    g.set_field_lineage(
        output,
        vec![FieldLineage {
            field_name: "merged".to_string(),
            source_fields: vec![
                FieldRef {
                    node_id: secret,
                    field_name: "api_key".to_string(),
                },
                FieldRef {
                    node_id: public,
                    field_name: "data".to_string(),
                },
            ],
            effect_kind: EffectKind::LLMGenerate,
            derivation: DerivationClass::Mixed,
        }],
    )
    .unwrap();

    let label = g.field_label(output, "merged").unwrap();
    // Join of Secret + Public confidentiality = Secret
    assert_eq!(label.confidentiality, ConfLevel::Secret);
    // Join of Trusted + Adversarial integrity = Adversarial
    assert_eq!(label.integrity, IntegLevel::Adversarial);
    // Derivation is overridden to Mixed
    assert_eq!(label.derivation, DerivationClass::Mixed);
}

#[test]
fn field_label_monotonicity_field_leq_node() {
    // DPI monotonicity invariant: row_label >= any field label.
    // Since the node label is the join of ALL parents, and a field
    // label is the join of a SUBSET of source nodes, the field label
    // should be <= the node label in the lattice ordering.
    let mut g = FlowGraph::new();
    let now = 1000;

    let db = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    let web = g
        .insert_observation(NodeKind::WebContent, &[], now)
        .unwrap();

    let output = g
        .insert_observation(NodeKind::ModelPlan, &[db, web], now)
        .unwrap();

    g.set_field_lineage(
        output,
        vec![FieldLineage {
            field_name: "clean_field".to_string(),
            source_fields: vec![FieldRef {
                node_id: db,
                field_name: "val".to_string(),
            }],
            effect_kind: EffectKind::DeterministicFetch,
            derivation: DerivationClass::Deterministic,
        }],
    )
    .unwrap();

    let field_lbl = g.field_label(output, "clean_field").unwrap();
    let node_lbl = g.get(output).unwrap().label;

    // Field integrity should be >= node integrity (remember: lower is "worse"
    // for integrity, so field.integrity >= node.integrity means field is
    // at least as good as node)
    assert!(
        field_lbl.integrity >= node_lbl.integrity,
        "field integrity ({:?}) should be >= node integrity ({:?})",
        field_lbl.integrity,
        node_lbl.integrity,
    );
}

// ── Compaction leak prevention tests (#836) ────────────────────────

#[test]
fn compaction_caps_compaction_log() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Fill well past MAX_GRAPH_NODES so compaction fires repeatedly
    // and generates many compaction_log entries.
    // Each compaction tombstones ~MAX_GRAPH_NODES/2 nodes, each producing a log entry.
    // We need enough inserts to exceed MAX_COMPACTION_LOG entries.
    // After one compaction: ~5000 entries. After two: ~10000 entries total,
    // but capped to 1000 at end of each compaction.
    for _ in 0..(MAX_GRAPH_NODES * 3) {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    assert!(
        g.compaction_log().len() <= MAX_COMPACTION_LOG,
        "compaction_log ({}) should be capped at {MAX_COMPACTION_LOG}",
        g.compaction_log().len(),
    );
}

#[test]
fn compaction_caps_quarantine_releases() {
    let mut g = FlowGraph::new();
    let now = 1000;

    // Generate many quarantine releases.
    for i in 0..(MAX_QUARANTINE_RELEASES + 500) {
        let nid = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
        g.quarantine(nid);
        let _ = g.release_quarantine(nid, "admin", &format!("release-{i}"), now);
    }

    // Force compaction to trigger the cap.
    while g.nodes.len() < MAX_GRAPH_NODES {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }
    // One more to trigger compaction.
    g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

    assert!(
        g.quarantine_releases().len() <= MAX_QUARANTINE_RELEASES,
        "quarantine_releases ({}) should be capped at {MAX_QUARANTINE_RELEASES}",
        g.quarantine_releases().len(),
    );
}

#[test]
fn compaction_cleans_field_lineage_for_tombstoned_nodes() {
    use crate::flow_graph::{EffectKind, FieldLineage, FieldRef};
    use portcullis_core::DerivationClass;

    let mut g = FlowGraph::new();
    let now = 1000;

    // Insert a node early and give it field lineage.
    let early = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    g.set_field_lineage(
        early,
        vec![FieldLineage {
            field_name: "col_a".to_string(),
            source_fields: vec![FieldRef {
                node_id: early,
                field_name: "col_a".to_string(),
            }],
            effect_kind: EffectKind::DeterministicFetch,
            derivation: DerivationClass::Deterministic,
        }],
    )
    .unwrap();
    assert!(
        g.get_field_lineage(early).is_some(),
        "field lineage should exist before compaction"
    );

    // Fill past the compaction threshold so `early` is tombstoned.
    for _ in 0..(MAX_GRAPH_NODES + 100) {
        g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
    }

    // The early node should be tombstoned.
    assert!(g.get(early).is_none(), "early node should be tombstoned");

    // Its field lineage should have been cleaned up.
    assert!(
        g.get_field_lineage(early).is_none(),
        "field_lineage for tombstoned node should be removed during compaction"
    );
}
