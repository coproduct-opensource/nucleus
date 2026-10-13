//! #2963: an inline policy's validity window is re-stamped at admission, so a
//! window that spent itself while the spec queued does not mint a root the
//! parent-expired check then refuses.

use super::*;
use portcullis::TimeLattice;

/// A fixed instant, so the window arithmetic is tested against a clock that
/// does not move.
fn t0() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-09-20T03:53:17Z")
        .unwrap()
        .with_timezone(&Utc)
}

/// The measured failure, reproduced deterministically: a gate spec whose
/// lattice window was stamped when the spec was written, and which closed
/// while the pod waited for admission. The root minted from it is expired by
/// the time `mint_child` checks it, so on main this is refused with
/// `root mint refused: ... Parent permission has expired`. Admitted, the
/// window keeps its author's duration, measured from admission.
#[tokio::test]
async fn a_window_that_closed_in_the_queue_is_restamped_not_refused() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let mut stale = lattice(5);
    // Written 15 minutes ago with a 5-minute window (the spec's timeout is 10).
    let written = Utc::now() - Duration::minutes(15);
    stale.time = TimeLattice::between(written, written + Duration::minutes(5));
    assert!(
        stale.time.is_expired(),
        "precondition: the window is closed"
    );

    let before = Utc::now();
    let issued = auth
        .admit_kept(&by(MINTER), &spec_with(stale), Uuid::new_v4())
        .await
        .expect("a window spent in the queue must not refuse the bootstrap mint");

    let window = &issued.effective.time;
    assert!(
        window.valid_from >= before,
        "the window opens at admission, not when the spec was written: {window:?}"
    );
    assert_eq!(
        window.duration(),
        Duration::minutes(5),
        "the author's duration is kept"
    );
    assert!(!window.is_expired());
}

/// A named profile resolves at admission already; its window is left as
/// resolved (and still admits).
#[tokio::test]
async fn a_profile_policy_is_not_restamped() {
    let dir = tempfile::tempdir().unwrap();
    let auth = authority(dir.path(), args());
    let mut spec = spec_with(lattice(5));
    spec.spec.policy = PolicySpec::Profile {
        name: "default".into(),
    };
    let issued = auth
        .admit_kept(&by(MINTER), &spec, Uuid::new_v4())
        .await
        .expect("a profile admits");
    // `default` resolves to a one-hour window; re-stamping would have capped it
    // at the spec's 10-minute timeout.
    assert!(issued.effective.time.duration() > Duration::minutes(10));
}

#[test]
fn a_stale_window_moves_to_now_and_keeps_its_length() {
    let now = t0();
    let stale = TimeLattice::between(now - Duration::hours(2), now - Duration::hours(1));
    let w = restamp_window(&stale, now, now + Duration::hours(3)).unwrap();
    assert_eq!(w.valid_from, now);
    assert_eq!(w.valid_until, now + Duration::hours(1));
}

#[test]
fn a_restamped_window_never_outlives_the_certificate() {
    let now = t0();
    let long = TimeLattice::between(now - Duration::hours(1), now + Duration::hours(5));
    let w = restamp_window(&long, now, now + Duration::minutes(10)).unwrap();
    assert_eq!(w.valid_from, now);
    assert_eq!(w.valid_until, now + Duration::minutes(10));
}

#[test]
fn a_future_start_is_never_moved_earlier() {
    let now = t0();
    let pending = TimeLattice::between(now + Duration::minutes(5), now + Duration::minutes(20));
    let w = restamp_window(&pending, now, now + Duration::hours(1)).unwrap();
    assert_eq!(w, pending, "a window not yet open is the author's to keep");
}

#[test]
fn an_empty_window_is_refused_by_name() {
    let now = t0();
    for empty in [
        TimeLattice::between(now, now),
        TimeLattice::between(now, now - Duration::seconds(1)),
    ] {
        let err = restamp_window(&empty, now, now + Duration::hours(1)).unwrap_err();
        assert!(
            matches!(&err, ApiError::InvalidSpec(m) if m.contains("time window is empty")),
            "got {err:?}"
        );
    }
}

#[test]
fn a_window_opening_after_the_certificate_expires_is_refused_by_name() {
    let now = t0();
    let late = TimeLattice::between(now + Duration::hours(2), now + Duration::hours(3));
    let err = restamp_window(&late, now, now + Duration::hours(1)).unwrap_err();
    assert!(
        matches!(&err, ApiError::InvalidSpec(m) if m.contains("certificate expiry")),
        "got {err:?}"
    );
}
