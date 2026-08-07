//! Who a lockdown command is allowed to reach.
//!
//! Its own module because `main.rs` carries a line ratchet and anything added
//! must be paid for by something taken out -- and because the fail-open rule
//! below is the one place in this subsystem that deliberately inverts the
//! project's fail-closed default, which is easier to find here than buried
//! among request handlers.

use uuid::Uuid;

/// Forward broadcast lockdown commands to one watcher's stream, filtered.
///
/// Lives beside `reaches` rather than in the gRPC handler so the decision and
/// the rule it applies are read together. Every proxy used to receive every
/// command and filter locally, which put pod A's uuid and the operator's
/// free-text reason into every other pod's VM -- the same mistake as returning
/// a full pod list and refusing individually, since the information has already
/// crossed by the time the check runs.
pub(crate) fn spawn_filtered_forwarder(
    mut rx: tokio::sync::broadcast::Receiver<crate::proto::LockdownCommand>,
    tx: tokio::sync::mpsc::Sender<Result<crate::proto::LockdownCommand, tonic::Status>>,
    watcher: Option<Uuid>,
) {
    tokio::spawn(async move {
        while let Ok(cmd) = rx.recv().await {
            if !reaches(&cmd.scope, watcher) {
                continue;
            }
            if tx.send(Ok(cmd)).await.is_err() {
                break; // client disconnected
            }
        }
    });
}

/// Should a lockdown command scoped `scope` reach a watcher that is `watcher`?
///
/// # The direction of the doubt is deliberately opposite to the rest of this arc
///
/// Everything else here fails CLOSED: when the node cannot establish something,
/// it withholds. This fails OPEN, and on purpose. Lockdown is a *safety* control
/// — an operator halting a workload — so the cost of over-delivering is that a
/// pod learns another pod was locked down, while the cost of under-delivering is
/// that a pod the operator meant to stop keeps running. Those are not
/// comparable, and confidentiality does not get to win that trade.
///
/// So anything unresolvable is delivered: an unidentified watcher, an
/// unparseable id, a label selector, an unrecognised scope form. What this
/// removes is the case that is both resolvable and was leaking —
/// `pod:<uuid>` reaching pods that are not that uuid.
///
/// Label selectors are still broadcast. The node holds the PodSpecs and could
/// evaluate them properly — which would also fix the proxy applying label
/// lockdowns it cannot evaluate and so over-applies — but that is a behaviour
/// change to the lockdown semantics rather than to who hears about them, and it
/// belongs in its own change.
pub(crate) fn reaches(scope: &str, watcher: Option<Uuid>) -> bool {
    let Some(watcher) = watcher else {
        return true;
    };
    if scope.is_empty() || scope == "all" {
        return true;
    }
    match scope.strip_prefix("pod:") {
        Some(id) => match Uuid::parse_str(id) {
            Ok(target) => target == watcher,
            // Malformed scope: deliver. See above — a lockdown nobody can parse
            // must not become a lockdown nobody receives.
            Err(_) => true,
        },
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::reaches as lockdown_reaches;
    use uuid::Uuid;

    fn a() -> Uuid {
        Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap()
    }
    fn b() -> Uuid {
        Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap()
    }

    /// **The disclosure this closes.** A lockdown aimed at pod A no longer
    /// reaches pod B, so B's VM never receives A's uuid or the operator's
    /// free-text reason.
    #[test]
    fn a_pod_scoped_lockdown_does_not_reach_other_pods() {
        assert!(!lockdown_reaches(&format!("pod:{}", a()), Some(b())));
    }

    /// And it does still reach its target, or the control would be broken
    /// rather than narrowed.
    #[test]
    fn a_pod_scoped_lockdown_reaches_its_target() {
        assert!(lockdown_reaches(&format!("pod:{}", a()), Some(a())));
    }

    /// A node-wide lockdown reaches everyone. Nothing about scoping may weaken
    /// the operator's blunt instrument.
    #[test]
    fn an_all_scoped_lockdown_reaches_everyone() {
        assert!(lockdown_reaches("all", Some(b())));
        assert!(lockdown_reaches("", Some(b())));
    }

    /// **The fail-OPEN legs**, stated as tests because they are the deliberate
    /// exception to this arc's fail-closed rule. Under-delivering a lockdown
    /// leaves a pod running that an operator meant to stop; over-delivering only
    /// discloses that some pod was locked down. Those costs are not comparable.
    #[test]
    fn anything_unresolvable_is_still_delivered() {
        // No proved identity: cannot decide, so deliver.
        assert!(lockdown_reaches(&format!("pod:{}", a()), None));
        // Label selectors: the node could evaluate these but does not yet.
        assert!(lockdown_reaches("label:tier=prod", Some(b())));
        // Malformed target: a lockdown nobody can parse must not become a
        // lockdown nobody receives.
        assert!(lockdown_reaches("pod:not-a-uuid", Some(b())));
        // Unrecognised scope form.
        assert!(lockdown_reaches("something-new", Some(b())));
    }
}
