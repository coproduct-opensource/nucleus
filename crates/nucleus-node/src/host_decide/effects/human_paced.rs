//! Approvals at a human's pace (#3266), on a simulated clock.
//!
//! The v2.5.0 journey measured it: a held request waits two minutes, a pending
//! approval lived five, and the workload's retries minted a fresh id each time
//! the old one expired, so an operator who took minutes approved an id that was
//! gone. Here the clock is a parameter, so an operator who takes seven minutes
//! takes no time at all.
use super::*;
use portcullis::PermissionLattice;

const HOLD: u64 = 1_000_000;
const MINUTE: u64 = 60;
const SUBJECT: &str = "https://forge.invalid/org/repo.git/git-receive-pack";

fn operator() -> Operator {
    Operator::authenticate("spiffe://test/operator", "spiffe://test/operator").unwrap()
}

/// A pod whose policy asks the operator for every push.
fn gated() -> super::super::SharedPodPolicy {
    let mut policy = PermissionLattice::permissive();
    policy.obligations.insert(Operation::GitPush);
    super::super::test_policy(policy)
}

/// The workload sending the push's pack at `now`: what the host answers.
fn send(policy: &mut PodPolicy, digest: ArgsDigest, now: u64) -> Result<EffectPermit, String> {
    policy.authorize_effect(
        digest,
        Operation::GitPush,
        SUBJECT,
        now,
        crate::upstreams::CallCharge::free(),
        false,
    )
}

/// The id the host named when it held the request.
fn held_id(answer: Result<EffectPermit, String>) -> Uuid {
    let reason = answer.expect_err("the request was released without a grant");
    reason
        .strip_prefix("host approval required: ")
        .unwrap_or_else(|| panic!("not held for approval: {reason}"))
        .parse()
        .unwrap()
}

fn pending_at(policy: &mut PodPolicy, now: u64) -> Vec<ApprovalView> {
    policy
        .list_effect_approvals(operator(), now)
        .into_iter()
        .filter(|a| a.status == ApprovalStatus::Pending)
        .collect()
}

/// **The acceptance, at the host.** The push is held; the workload's request
/// times out and it sends the same push again at 2 and 4 minutes; the operator
/// lists the pod at 7 minutes and finds ONE pending approval, the id it was
/// first held under; grants it; and the next identical push, sent after the
/// grant by a workload that never saw it, is released, once. A replay is held
/// afresh under a new id.
///
/// A-19: the pre-#3266 timing (a pending approval living five minutes from
/// the hold, `ApprovalTiming::new(300, 300)` here) reds the listing — at seven
/// minutes the operator finds nothing to grant.
#[test]
fn a_grant_seven_minutes_after_the_hold_releases_the_next_identical_push_once() {
    let shared = gated();
    let mut policy = shared.lock().unwrap();
    let digest = ArgsDigest::new([42; 32]);
    let first = held_id(send(&mut policy, digest, HOLD));
    for resend in [2, 4] {
        assert_eq!(
            held_id(send(&mut policy, digest, HOLD + resend * MINUTE)),
            first,
            "a re-sent request churned its approval id"
        );
    }
    let pending = pending_at(&mut policy, HOLD + 7 * MINUTE);
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0].id, first);
    policy
        .settle_effect_approval(operator(), first, true, HOLD + 7 * MINUTE)
        .unwrap();
    let _released = send(&mut policy, digest, HOLD + 8 * MINUTE)
        .expect("the granted digest released the next identical push");
    let replay = held_id(send(&mut policy, digest, HOLD + 8 * MINUTE));
    assert_ne!(replay, first, "a spent grant released a replay");
    let listed = policy.list_effect_approvals(operator(), HOLD + 8 * MINUTE);
    let spent = listed.iter().find(|a| a.id == first).unwrap();
    assert_eq!(spent.status, ApprovalStatus::Spent);
}

/// **One pending entry per digest, kept alive by the workload asking.** Each
/// re-send refreshes the pending approval in place, so a workload that keeps
/// retrying keeps the operator's id valid past the TTL counted from the hold.
/// A different request is a different entry.
///
/// A-19: not refreshing in place (a pending entry expiring `pending_ttl` after
/// the hold, whatever the workload sends) reds the id at 50 minutes.
#[test]
fn a_resent_request_keeps_its_pending_id_alive() {
    let shared = gated();
    let mut policy = shared.lock().unwrap();
    let digest = ArgsDigest::new([43; 32]);
    let first = held_id(send(&mut policy, digest, HOLD));
    for resend in [25, 50, 75] {
        assert_eq!(
            held_id(send(&mut policy, digest, HOLD + resend * MINUTE)),
            first,
            "re-sent at {resend} minutes"
        );
    }
    let other = held_id(send(
        &mut policy,
        ArgsDigest::new([44; 32]),
        HOLD + 75 * MINUTE,
    ));
    assert_ne!(other, first, "two requests shared one approval");
    assert_eq!(pending_at(&mut policy, HOLD + 75 * MINUTE).len(), 2);
    // Once the workload stops asking, the entry expires a full TTL later.
    let ttl = ApprovalTiming::HUMAN.pending_ttl;
    let quiet = HOLD + 75 * MINUTE + ttl;
    assert!(
        pending_at(&mut policy, quiet - 1)
            .iter()
            .any(|a| a.id == first)
    );
    assert!(pending_at(&mut policy, quiet).iter().all(|a| a.id != first));
}

/// **A grant is valid from the grant, and only that long.** A grant made 25
/// minutes after the hold is spendable for its whole validity, however old
/// the hold; one second past it, the grant is gone and the push is held
/// afresh under a new id.
///
/// A-19: counting the grant's validity from the hold (leaving `expires_unix`
/// as the pending entry's) reds the release at 39 minutes.
#[test]
fn a_grant_lives_its_validity_from_the_grant_and_then_expires() {
    let validity = ApprovalTiming::HUMAN.grant_validity;
    for (spend_after, released) in [(14 * MINUTE, true), (validity, false)] {
        let shared = gated();
        let mut policy = shared.lock().unwrap();
        let digest = ArgsDigest::new([45; 32]);
        let first = held_id(send(&mut policy, digest, HOLD));
        let granted_at = HOLD + 25 * MINUTE;
        policy
            .settle_effect_approval(operator(), first, true, granted_at)
            .unwrap();
        let answer = send(&mut policy, digest, granted_at + spend_after);
        assert_eq!(answer.is_ok(), released, "{spend_after} s after the grant");
        if !released {
            assert_ne!(held_id(answer), first, "an expired grant was reused");
        }
    }
}

/// **A grant is bound to its digest.** Granted late for one push, it does not
/// release a different push sent after the grant, which is held under its own
/// id, and it stays granted for its own. (Bound to the category it was shown
/// as, too: `an_ordinary_grant_never_declassifies_a_session_tainted_since`.)
#[test]
fn a_grant_for_one_digest_releases_no_other() {
    let shared = gated();
    let mut policy = shared.lock().unwrap();
    let digest = ArgsDigest::new([46; 32]);
    let first = held_id(send(&mut policy, digest, HOLD));
    policy
        .settle_effect_approval(operator(), first, true, HOLD + 7 * MINUTE)
        .unwrap();
    let other = held_id(send(
        &mut policy,
        ArgsDigest::new([47; 32]),
        HOLD + 8 * MINUTE,
    ));
    assert_ne!(other, first, "another push found the grant");
    let _released = send(&mut policy, digest, HOLD + 8 * MINUTE).unwrap();
}

/// The operator's timing is bounded: neither may be zero or longer than a
/// day, and the flags with nothing given are the human-sized defaults.
#[test]
fn approval_timing_is_bounded_and_defaults_to_human_sized() {
    assert_eq!(
        ApprovalTimingArgs::HUMAN.timing(),
        Ok(ApprovalTiming::HUMAN)
    );
    assert_eq!(ApprovalTiming::HUMAN.pending_ttl, 30 * MINUTE);
    assert_eq!(ApprovalTiming::HUMAN.grant_validity, 15 * MINUTE);
    let day = ApprovalTiming::MAX_SECONDS;
    assert!(ApprovalTiming::new(1, day).is_ok());
    for (pending, grant) in [(0, 60), (60, 0), (day + 1, 60), (60, day + 1)] {
        assert!(
            ApprovalTiming::new(pending, grant).is_err(),
            "{pending} / {grant}"
        );
    }

    #[derive(clap::Parser)]
    struct Flags {
        #[command(flatten)]
        approvals: ApprovalTimingArgs,
    }
    use clap::Parser as _;
    let none = Flags::try_parse_from(["node"]).unwrap().approvals;
    assert_eq!(none.timing(), Ok(ApprovalTiming::HUMAN));
    let set = Flags::try_parse_from([
        "node",
        "--effect-approval-pending-ttl-secs",
        "3600",
        "--effect-approval-grant-validity-secs",
        "600",
    ])
    .unwrap()
    .approvals;
    assert_eq!(set.timing(), ApprovalTiming::new(3600, 600));
    let zero = Flags::try_parse_from(["node", "--effect-approval-grant-validity-secs", "0"])
        .unwrap()
        .approvals;
    assert!(zero.timing().is_err());
}
