//! Reserve, then refund (2026-10-31). A metered call reserves its ceiling from
//! the pod's balance before any upstream traffic, and settles down to what it
//! cost afterwards. Until then a call was refused only once the balance was
//! already zero: with the live zero tariff, a pod with one micro-USD left ran a
//! call that could cost its whole ceiling, and the ledger clamped the overshoot
//! away. Each test here failed on `3ee48704b`.
use super::*;
use rust_decimal::Decimal;

/// `request()`'s body is 15 bytes. At the live rates its ceiling is
/// 15 x 0.75 + 65,536 x 3.75 = 245,771.25, rounded up.
const CEILING: u64 = 245_772;

fn metered() -> RegistryEntry {
    upstream().with_metering(crate::metering::Metering::live_rates())
}

fn usd(micro: u64) -> Decimal {
    Decimal::from_i128_with_scale(i128::from(micro), 6)
}

fn consumed(context: &PerformContext<'_>) -> u64 {
    context
        .host_policy
        .lock()
        .unwrap()
        .budget()
        .snapshot()
        .unwrap()
        .core()
        .parent_consumed_units()
}

fn available(policy: &crate::host_decide::SharedPodPolicy) -> Decimal {
    policy.lock().unwrap().budget().available().unwrap()
}

/// The defect: a pod whose balance is below one call's ceiling is refused
/// before the upstream sees a byte, and nothing is spent.
#[tokio::test]
async fn a_pod_with_less_than_one_ceiling_left_is_refused_before_upstream_io() {
    let mut policy = PermissionLattice::permissive();
    // One cent: positive, and far below the 0.245772 USD ceiling.
    policy.budget.max_cost_usd = usd(10_000);
    let credentials = store();
    let identity = who();
    let upstreams = [metered()];
    let ledger = IdempotencyLedger::new();
    let context = ctx(&policy, &credentials, &upstreams, &ledger, &identity);
    let net = Upstream::default();
    let reply = handle_perform(&request(), &context, NOW, net.caller()).await;
    assert!(!reply.granted, "{}", reply.reason);
    assert!(reply.reason.contains("budget"), "{}", reply.reason);
    assert_eq!(net.count(), 0, "the upstream saw no request");
    assert_eq!(consumed(&context), 0, "a refused call spends nothing");
    // Exactly one ceiling fits.
    policy.budget.max_cost_usd = usd(CEILING);
    let context = ctx(&policy, &credentials, &upstreams, &ledger, &identity);
    assert!(
        handle_perform(&request(), &context, NOW, net.caller())
            .await
            .granted
    );
    assert_eq!(net.count(), 1);
}

/// While a call is in flight its ceiling is held; after it, the hold is
/// released down to the charge. A refused status (403) is charged nothing
/// beyond the tariff, so the balance returns to where it started.
#[tokio::test]
async fn a_call_holds_its_ceiling_in_flight_and_settles_down_to_its_charge() {
    let mut policy = PermissionLattice::permissive();
    policy.budget.max_cost_usd = Decimal::ONE;
    let credentials = store();
    let identity = who();
    let upstreams = [metered()];
    let ledger = IdempotencyLedger::new();
    let context = ctx(&policy, &credentials, &upstreams, &ledger, &identity);
    let host = context.host_policy;
    let during = std::sync::Mutex::new(None);
    let reply = handle_perform(&request(), &context, NOW, |_call| {
        *during.lock().unwrap() = Some(available(host));
        std::future::ready(Ok(UpstreamResponse {
            status: 403,
            body: b"{}".to_vec(),
        }))
    })
    .await;
    assert!(reply.granted, "{}", reply.reason);
    assert_eq!(
        during.lock().unwrap().unwrap(),
        Decimal::ONE - usd(CEILING),
        "the ceiling is reserved before the call"
    );
    assert_eq!(available(host), Decimal::ONE, "a refusal settles to zero");
    assert_eq!(consumed(&context), 0);
}

/// Two calls in flight at once cannot both reserve past the balance: the
/// second is refused before the upstream sees it, and the first's settlement
/// frees room for a third.
#[tokio::test]
async fn concurrent_calls_cannot_both_reserve_past_the_budget() {
    let mut policy = PermissionLattice::permissive();
    // One and a half ceilings.
    policy.budget.max_cost_usd = usd(CEILING + CEILING / 2);
    let credentials = store();
    let identity = who();
    let upstreams = [metered()];
    let ledger = IdempotencyLedger::new();
    let context = ctx(&policy, &credentials, &upstreams, &ledger, &identity);
    let calls = AtomicUsize::new(0);
    let release = tokio::sync::Notify::new();
    let refused_403 = || {
        std::future::ready(Ok(UpstreamResponse {
            status: 403,
            body: b"{}".to_vec(),
        }))
    };
    let first = with_key("first");
    let second = with_key("second");
    let (a, b) = tokio::join!(
        handle_perform(&first, &context, NOW, |_call| {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                release.notified().await;
                Ok(UpstreamResponse {
                    status: 403,
                    body: b"{}".to_vec(),
                })
            }
        }),
        async {
            // Runs once the first call is parked at the upstream, holding its ceiling.
            let reply = handle_perform(&second, &context, NOW, |_call| {
                calls.fetch_add(1, Ordering::SeqCst);
                refused_403()
            })
            .await;
            release.notify_one();
            reply
        }
    );
    assert!(a.granted, "{}", a.reason);
    assert!(!b.granted, "the second reservation does not fit");
    assert!(b.reason.contains("budget"), "{}", b.reason);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "only one call reached the upstream"
    );
    let third = handle_perform(&with_key("third"), &context, NOW, |_call| {
        calls.fetch_add(1, Ordering::SeqCst);
        refused_403()
    })
    .await;
    assert!(
        third.granted,
        "the first call's hold was released: {}",
        third.reason
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// The ledger is exactly what was charged, never clamped: here every call is
/// unread (the buffered path does not attest it read the body's end, and one
/// call fails at the transport), so each is charged its ceiling. The call that
/// would cross the line is refused instead of run and clamped.
#[tokio::test]
async fn the_ledger_is_the_sum_of_charges_and_the_crossing_call_is_refused() {
    let mut policy = PermissionLattice::permissive();
    // Room for two ceilings and a part of a third.
    policy.budget.max_cost_usd = usd(2 * CEILING + 100_000);
    let credentials = store();
    let identity = who();
    let upstreams = [metered()];
    let ledger = IdempotencyLedger::new();
    let context = ctx(&policy, &credentials, &upstreams, &ledger, &identity);
    let calls = AtomicUsize::new(0);
    let ok = |_call: UpstreamCall| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(UpstreamResponse {
            status: 200,
            body: br#"{"usage":{"in":10,"out":100}}"#.to_vec(),
        }))
    };
    let lost = |_call: UpstreamCall| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Err("connection lost after send".to_string()))
    };
    assert!(
        handle_perform(&with_key("a"), &context, NOW, ok)
            .await
            .granted
    );
    assert!(
        !handle_perform(&with_key("b"), &context, NOW, lost)
            .await
            .granted
    );
    assert_eq!(consumed(&context), 2 * CEILING);
    // 100,000 left: the next call's ceiling does not fit, so it never runs.
    let crossing = handle_perform(&with_key("c"), &context, NOW, lost).await;
    assert!(crossing.reason.contains("budget"), "{}", crossing.reason);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the crossing call sent nothing"
    );
    assert_eq!(consumed(&context), 2 * CEILING, "nothing was clamped away");
    let ledger = context
        .host_policy
        .lock()
        .unwrap()
        .budget()
        .snapshot()
        .unwrap();
    assert!(ledger.core().conserves());
}
