//! What the host's shadow decision service and its guest client say about
//! themselves (ADR 0014 S1, #2702).
//!
//! The flip criterion (ADR 0014 §10) is decided from these numbers, so each one
//! has ONE type here, written by the party that measured it and read back by
//! `cargo xtask host-decide-agreement` (ADR 0007 F-1: derived serialization, one
//! `Deserialize` per shape):
//!
//! * the node's teardown line for each pod ([`TEARDOWN_MESSAGE`]): its counts as
//!   numeric fields, the per-operation × outcome-pair counts ([`OutcomePair`]),
//!   the `Decide`s no guest ever reported on, and the host's service time
//!   ([`LatencyHistogram`]);
//! * the guest's console line ([`GuestTelemetry`], prefixed [`CONSOLE_PREFIX`]):
//!   its own tally, every [`HostUnavailable`] by kind, and the round trip it
//!   waited for each decision.
//!
//! Every reader here refuses a shape it does not know rather than read it as
//! zero (ADR 0007 A-2), and a percentile is the upper edge of its bucket, so a
//! rounding error can only ever make a latency look worse than it was.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The node's log message carrying one pod's final counts.
pub const TEARDOWN_MESSAGE: &str = "host-decide shadow tally at teardown";

/// The file in a pod's directory the node appends each disagreement to, and
/// its name in a live-boot bundle.
pub const DISAGREEMENT_LOG: &str = "host-decide-disagreements.jsonl";

/// What starts the guest's telemetry line on its console.
pub const CONSOLE_PREFIX: &str = "NUCLEUS-HOST-DECIDE-TELEMETRY";

/// Why a decision's shadow never reached a comparison. Typed, so a host that
/// cannot be dialled reads differently from one that answered nonsense. The
/// guest counts every one of these by kind; the host cannot, because it never
/// received the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostUnavailable {
    /// The channel could not be opened.
    Connect,
    /// The host did not answer within the guest's deadline.
    Timeout,
    /// The channel failed mid-exchange.
    Io,
    /// The host answered with a frame that is not the answer to the question.
    Protocol,
    /// The guest's queue was full; the question was dropped.
    Backlog,
    /// More kernel sessions than the guest opens channels for asked at once.
    TooManySessions,
    /// The guest's worker is gone.
    Stopped,
    /// The exact subject does not fit the protocol; comparing a prefix would be
    /// misleading.
    SubjectTooLong,
}

/// [`HostUnavailable`] counted by kind. One field per kind, so a new kind does
/// not compile until it is counted here, and a line naming a kind this build
/// does not know is refused (`deny_unknown_fields`, ADR 0007 E-1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnavailableByKind {
    /// [`HostUnavailable::Connect`].
    pub connect: u64,
    /// [`HostUnavailable::Timeout`].
    pub timeout: u64,
    /// [`HostUnavailable::Io`].
    pub io: u64,
    /// [`HostUnavailable::Protocol`].
    pub protocol: u64,
    /// [`HostUnavailable::Backlog`].
    pub backlog: u64,
    /// [`HostUnavailable::TooManySessions`].
    pub too_many_sessions: u64,
    /// [`HostUnavailable::Stopped`].
    pub stopped: u64,
    /// [`HostUnavailable::SubjectTooLong`].
    pub subject_too_long: u64,
}

impl UnavailableByKind {
    fn slot(&mut self, kind: HostUnavailable) -> &mut u64 {
        match kind {
            HostUnavailable::Connect => &mut self.connect,
            HostUnavailable::Timeout => &mut self.timeout,
            HostUnavailable::Io => &mut self.io,
            HostUnavailable::Protocol => &mut self.protocol,
            HostUnavailable::Backlog => &mut self.backlog,
            HostUnavailable::TooManySessions => &mut self.too_many_sessions,
            HostUnavailable::Stopped => &mut self.stopped,
            HostUnavailable::SubjectTooLong => &mut self.subject_too_long,
        }
    }

    /// Count one.
    pub fn count(&mut self, kind: HostUnavailable) {
        let slot = self.slot(kind);
        *slot = slot.saturating_add(1);
    }

    /// Every kind with its count, in declaration order.
    #[must_use]
    pub fn by_kind(&self) -> [(&'static str, u64); 8] {
        // Destructured with no `..`: a new field is a compile error here.
        let Self {
            connect,
            timeout,
            io,
            protocol,
            backlog,
            too_many_sessions,
            stopped,
            subject_too_long,
        } = *self;
        [
            ("connect", connect),
            ("timeout", timeout),
            ("io", io),
            ("protocol", protocol),
            ("backlog", backlog),
            ("too_many_sessions", too_many_sessions),
            ("stopped", stopped),
            ("subject_too_long", subject_too_long),
        ]
    }

    /// Every decision that was never compared.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.by_kind()
            .iter()
            .fold(0u64, |sum, (_, n)| sum.saturating_add(*n))
    }

    /// Add another count in.
    pub fn add(&mut self, other: &Self) {
        let Self {
            connect,
            timeout,
            io,
            protocol,
            backlog,
            too_many_sessions,
            stopped,
            subject_too_long,
        } = *other;
        for (kind, n) in [
            (HostUnavailable::Connect, connect),
            (HostUnavailable::Timeout, timeout),
            (HostUnavailable::Io, io),
            (HostUnavailable::Protocol, protocol),
            (HostUnavailable::Backlog, backlog),
            (HostUnavailable::TooManySessions, too_many_sessions),
            (HostUnavailable::Stopped, stopped),
            (HostUnavailable::SubjectTooLong, subject_too_long),
        ] {
            let slot = self.slot(kind);
            *slot = slot.saturating_add(n);
        }
    }
}

// ── latency ─────────────────────────────────────────────────────────────────

/// Buckets per power of two. Four gives each bucket at most a quarter of its
/// lower edge in width: a 0.5 ms budget is read to within 0.13 ms.
const SUB_BUCKETS: u64 = 4;

/// Bucket indices run 0..=251: the first four hold 0–3 µs exactly, then four
/// per power of two up to `u64::MAX`.
const BUCKETS: u16 = 252;

fn bucket_of(micros: u64) -> u16 {
    if micros < SUB_BUCKETS {
        // < 4, so it fits.
        return u16::try_from(micros).unwrap_or(BUCKETS - 1);
    }
    let exp = 63 - u64::from(micros.leading_zeros());
    let sub = (micros >> (exp - 2)) & (SUB_BUCKETS - 1);
    u16::try_from(SUB_BUCKETS * (exp - 1) + sub).unwrap_or(BUCKETS - 1)
}

/// The largest value bucket `index` holds. A percentile reports this, so it is
/// never below the measurement it stands for.
fn upper_edge(index: u16) -> u64 {
    let i = u64::from(index);
    if i < SUB_BUCKETS {
        return i;
    }
    let exp = i / SUB_BUCKETS + 1;
    let sub = i % SUB_BUCKETS;
    let width = 1u64 << (exp - 2);
    ((SUB_BUCKETS + sub) << (exp - 2)).saturating_add(width - 1)
}

/// A latency distribution in microseconds, in logarithmic buckets: bounded in
/// size whatever it counts, and mergeable across pods and runs, which a
/// per-pod percentile is not.
///
/// Serialized as `[[bucket, count], …]`, ascending, with no empty bucket.
/// Anything else is refused on reading rather than repaired.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<(u16, u64)>", into = "Vec<(u16, u64)>")]
pub struct LatencyHistogram {
    counts: BTreeMap<u16, u64>,
}

impl TryFrom<Vec<(u16, u64)>> for LatencyHistogram {
    type Error = String;

    fn try_from(raw: Vec<(u16, u64)>) -> Result<Self, Self::Error> {
        let mut counts = BTreeMap::new();
        let mut last = None;
        for (bucket, count) in raw {
            if bucket >= BUCKETS {
                return Err(format!(
                    "bucket {bucket} is past the last ({})",
                    BUCKETS - 1
                ));
            }
            if count == 0 {
                return Err(format!("bucket {bucket} is listed with no count"));
            }
            if last.is_some_and(|l| l >= bucket) {
                return Err(format!("bucket {bucket} is out of order"));
            }
            last = Some(bucket);
            counts.insert(bucket, count);
        }
        Ok(Self { counts })
    }
}

impl From<LatencyHistogram> for Vec<(u16, u64)> {
    fn from(h: LatencyHistogram) -> Self {
        h.counts.into_iter().collect()
    }
}

impl LatencyHistogram {
    /// Count one measurement.
    pub fn record(&mut self, elapsed: std::time::Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let slot = self.counts.entry(bucket_of(micros)).or_insert(0);
        *slot = slot.saturating_add(1);
    }

    /// How many measurements it holds.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.counts
            .values()
            .fold(0u64, |sum, n| sum.saturating_add(*n))
    }

    /// Add another distribution in.
    pub fn merge(&mut self, other: &Self) {
        for (bucket, n) in &other.counts {
            let slot = self.counts.entry(*bucket).or_insert(0);
            *slot = slot.saturating_add(*n);
        }
    }

    /// The `permille`-th percentile (500 is the median, 990 the 99th), as the
    /// upper edge of the bucket it falls in. `None` when nothing was measured:
    /// no measurement is not a latency of zero (ADR 0007 A-5).
    #[must_use]
    pub fn percentile_us(&self, permille: u16) -> Option<u64> {
        let total = u128::from(self.count());
        if total == 0 {
            return None;
        }
        let rank = (total * u128::from(permille.min(1000)))
            .div_ceil(1000)
            .max(1);
        let mut seen = 0u128;
        for (bucket, n) in &self.counts {
            seen += u128::from(*n);
            if seen >= rank {
                return Some(upper_edge(*bucket));
            }
        }
        self.counts.keys().next_back().map(|b| upper_edge(*b))
    }
}

// ── the node's teardown line ────────────────────────────────────────────────

/// How many decisions on one operation ended in one pair of outcomes, spelled
/// as the disagreement record spells them (`allowed`, `approval_required`,
/// `denied:<reason>`). A pair whose outcomes are equal is an agreement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomePair {
    /// The operation, as `portcullis::grant_usage::operation_name` spells it.
    pub operation: String,
    /// What the guest's kernel decided, and enforced.
    pub guest: String,
    /// What the host's kernel decided.
    pub host: String,
    /// How many decisions.
    pub count: u64,
}

impl OutcomePair {
    /// Whether the two outcomes agreed. The host's `Agreement::of` is equality
    /// of outcomes, and the spelling is injective, so this is the same fact.
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.guest == self.host
    }
}

/// One pod's final counts, as the node prints them at teardown. The node
/// writes `agree`, `disagree`, `faults` and `unreported` as numeric log fields,
/// and `pairs` and `service` as JSON text in the same line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTeardown {
    /// Compared decisions the two kernels agreed on.
    pub agree: u64,
    /// Compared decisions they did not.
    pub disagree: u64,
    /// Channels the host closed because the guest broke the protocol or the
    /// pod's policy was gone. A fault's decision was never compared.
    pub faults: u64,
    /// `Decide`s the host answered and no `Shadow` report ever followed:
    /// decided by the host, never compared.
    pub unreported: u64,
    /// The comparisons, by operation and outcome pair.
    pub pairs: Vec<OutcomePair>,
    /// From a `Decide` frame's arrival to the host's verdict written back.
    pub service: LatencyHistogram,
}

impl HostTeardown {
    /// Assemble a teardown from the line's fields. Refused when the counts and
    /// the pairs disagree: two spellings of one fact that differ mean the line
    /// cannot be trusted for either (ADR 0007 A-2).
    pub fn from_fields(
        agree: u64,
        disagree: u64,
        faults: u64,
        unreported: u64,
        pairs_json: &str,
        service_json: &str,
    ) -> Result<Self, String> {
        let pairs: Vec<OutcomePair> =
            serde_json::from_str(pairs_json).map_err(|e| format!("pairs: {e}"))?;
        let service: LatencyHistogram =
            serde_json::from_str(service_json).map_err(|e| format!("service: {e}"))?;
        let (mut paired_agree, mut paired_disagree) = (0u64, 0u64);
        for p in &pairs {
            if p.count == 0 {
                return Err(format!("a pair with no count: {p:?}"));
            }
            let slot = if p.agrees() {
                &mut paired_agree
            } else {
                &mut paired_disagree
            };
            *slot = slot.saturating_add(p.count);
        }
        if (paired_agree, paired_disagree) != (agree, disagree) {
            return Err(format!(
                "the pairs sum to agree {paired_agree}, disagree {paired_disagree}; the line says \
                 agree {agree}, disagree {disagree}"
            ));
        }
        Ok(Self {
            agree,
            disagree,
            faults,
            unreported,
            pairs,
            service,
        })
    }
}

// ── the guest's console line ────────────────────────────────────────────────

/// The guest's own view of its shadow traffic, printed on its console.
///
/// Built only by [`GuestTelemetry::new`] or read back by
/// [`GuestTelemetry::last_on_console`], each of which derives or checks the
/// printed percentiles against the histogram, so a line whose `p50` is not its
/// histogram's median is refused rather than believed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawGuestTelemetry")]
pub struct GuestTelemetry {
    agree: u64,
    disagree: u64,
    unavailable: UnavailableByKind,
    round_trip: LatencyHistogram,
    round_trip_p50_us: Option<u64>,
    round_trip_p99_us: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGuestTelemetry {
    agree: u64,
    disagree: u64,
    unavailable: UnavailableByKind,
    round_trip: LatencyHistogram,
    round_trip_p50_us: Option<u64>,
    round_trip_p99_us: Option<u64>,
}

impl TryFrom<RawGuestTelemetry> for GuestTelemetry {
    type Error = String;

    fn try_from(raw: RawGuestTelemetry) -> Result<Self, Self::Error> {
        let RawGuestTelemetry {
            agree,
            disagree,
            unavailable,
            round_trip,
            round_trip_p50_us,
            round_trip_p99_us,
        } = raw;
        let derived = Self::new(agree, disagree, unavailable, round_trip);
        if (derived.round_trip_p50_us, derived.round_trip_p99_us)
            != (round_trip_p50_us, round_trip_p99_us)
        {
            return Err(format!(
                "printed p50/p99 {round_trip_p50_us:?}/{round_trip_p99_us:?} are not the \
                 histogram's {:?}/{:?}",
                derived.round_trip_p50_us, derived.round_trip_p99_us
            ));
        }
        Ok(derived)
    }
}

impl GuestTelemetry {
    /// The telemetry for these counts, with its percentiles derived.
    #[must_use]
    pub fn new(
        agree: u64,
        disagree: u64,
        unavailable: UnavailableByKind,
        round_trip: LatencyHistogram,
    ) -> Self {
        Self {
            agree,
            disagree,
            unavailable,
            round_trip_p50_us: round_trip.percentile_us(500),
            round_trip_p99_us: round_trip.percentile_us(990),
            round_trip,
        }
    }

    /// Decisions the host compared and agreed on.
    #[must_use]
    pub fn agree(&self) -> u64 {
        self.agree
    }

    /// Decisions the host compared and did not agree on.
    #[must_use]
    pub fn disagree(&self) -> u64 {
        self.disagree
    }

    /// Decisions never compared, by why.
    #[must_use]
    pub fn unavailable(&self) -> &UnavailableByKind {
        &self.unavailable
    }

    /// Every `Decide` round trip the guest waited for.
    #[must_use]
    pub fn round_trip(&self) -> &LatencyHistogram {
        &self.round_trip
    }

    /// The line the guest prints: the prefix, a space, and the JSON.
    #[must_use]
    pub fn console_line(&self) -> String {
        // Serializing plain integers and a map of them cannot fail.
        let json = serde_json::to_string(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
        format!("{CONSOLE_PREFIX} {json}")
    }

    /// The last telemetry line on a console, or `None` when it printed none.
    /// A line that carries the prefix and does not parse fails the whole read:
    /// it is not "no telemetry" (ADR 0007 A-2).
    pub fn last_on_console(console: &str) -> Result<Option<Self>, String> {
        let marker = format!("{CONSOLE_PREFIX} ");
        let mut last = None;
        for (n, line) in console.lines().enumerate() {
            let Some(at) = line.find(&marker) else {
                continue;
            };
            let json = line[at + marker.len()..].trim_end();
            let parsed: Self =
                serde_json::from_str(json).map_err(|e| format!("console line {}: {e}", n + 1))?;
            last = Some(parsed);
        }
        Ok(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn us(n: u64) -> Duration {
        Duration::from_micros(n)
    }

    /// Every value lands in a bucket whose upper edge is at least the value
    /// and whose width is at most a quarter of it: a percentile can only
    /// overstate, and by a bounded amount.
    #[test]
    fn a_bucket_never_understates_and_is_narrow() {
        for v in (0..10_000u64).chain([1 << 20, (1 << 40) + 7, u64::MAX - 1, u64::MAX]) {
            let b = bucket_of(v);
            assert!(b < BUCKETS, "{v}");
            let upper = upper_edge(b);
            assert!(upper >= v, "{v} in bucket {b} with upper edge {upper}");
            assert!(upper - v <= v / 4, "{v}: bucket {b} too wide ({upper})");
            if b > 0 {
                assert!(upper_edge(b - 1) < v, "{v} belongs in an earlier bucket");
            }
        }
    }

    #[test]
    fn percentiles_are_upper_edges_and_none_when_empty() {
        let mut h = LatencyHistogram::default();
        assert_eq!(h.percentile_us(500), None);
        for v in [100, 100, 100, 100, 100, 100, 100, 100, 100, 4_000] {
            h.record(us(v));
        }
        assert_eq!(h.count(), 10);
        assert_eq!(h.percentile_us(500), Some(upper_edge(bucket_of(100))));
        assert!(h.percentile_us(500).is_some_and(|p| p >= 100));
        assert!(h.percentile_us(990).is_some_and(|p| p >= 4_000));
    }

    #[test]
    fn a_histogram_round_trips_and_refuses_malformed_buckets() {
        let mut h = LatencyHistogram::default();
        for v in [3, 900, 900, 70_000] {
            h.record(us(v));
        }
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(serde_json::from_str::<LatencyHistogram>(&json).unwrap(), h);
        for bad in [
            "[[5,0]]",
            "[[9,1],[5,1]]",
            "[[5,1],[5,1]]",
            "[[252,1]]",
            "{}",
        ] {
            assert!(
                serde_json::from_str::<LatencyHistogram>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn histograms_merge() {
        let (mut a, mut b) = (LatencyHistogram::default(), LatencyHistogram::default());
        a.record(us(10));
        b.record(us(10));
        b.record(us(5_000));
        a.merge(&b);
        assert_eq!(a.count(), 3);
        assert!(a.percentile_us(990).is_some_and(|p| p >= 5_000));
    }

    #[test]
    fn the_console_line_round_trips_and_the_last_one_wins() {
        let mut by_kind = UnavailableByKind::default();
        by_kind.count(HostUnavailable::Connect);
        by_kind.count(HostUnavailable::Timeout);
        by_kind.count(HostUnavailable::Timeout);
        let mut rt = LatencyHistogram::default();
        rt.record(us(250));
        let first = GuestTelemetry::new(
            0,
            0,
            UnavailableByKind::default(),
            LatencyHistogram::default(),
        );
        let last = GuestTelemetry::new(4, 1, by_kind, rt);
        let console = format!(
            "[    1.000000] guest-init up\n[    2.000000] {}\nnoise\n[    3.000000] {}\n",
            first.console_line(),
            last.console_line()
        );
        let read = GuestTelemetry::last_on_console(&console).unwrap().unwrap();
        assert_eq!(read, last);
        assert_eq!(read.unavailable().total(), 3);
        assert_eq!(read.unavailable().timeout, 2);
        assert_eq!(
            GuestTelemetry::last_on_console("no telemetry\n").unwrap(),
            None
        );
    }

    /// A-2: a printed percentile that is not the histogram's, an unknown kind,
    /// or a line that is not JSON is refused, never read as zero.
    #[test]
    fn a_malformed_console_line_is_refused() {
        let good = GuestTelemetry::new(1, 0, UnavailableByKind::default(), {
            let mut h = LatencyHistogram::default();
            h.record(us(300));
            h
        });
        let line = good.console_line();
        for bad in [
            line.replace("\"round_trip_p50_us\":", "\"round_trip_p50_us\":1,\"x\":"),
            line.replace("\"connect\":0", "\"connect\":0,\"lost\":1"),
            format!("{CONSOLE_PREFIX} not json"),
            line.replace(
                &format!("\"round_trip_p50_us\":{}", good.round_trip_p50_us.unwrap()),
                "\"round_trip_p50_us\":1",
            ),
        ] {
            assert!(GuestTelemetry::last_on_console(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_teardown_whose_pairs_disagree_with_its_counts_is_refused() {
        let pairs = r#"[{"operation":"read_files","guest":"allowed","host":"allowed","count":3},
                        {"operation":"web_fetch","guest":"allowed","host":"denied:flow_refused","count":1}]"#;
        let t = HostTeardown::from_fields(3, 1, 0, 2, pairs, "[[10,4]]").unwrap();
        assert_eq!(t.unreported, 2);
        assert_eq!(t.service.count(), 4);
        assert!(HostTeardown::from_fields(4, 1, 0, 0, pairs, "[]").is_err());
        assert!(HostTeardown::from_fields(3, 0, 0, 0, pairs, "[]").is_err());
        assert!(HostTeardown::from_fields(3, 1, 0, 0, pairs, "[[10,0]]").is_err());
        assert!(HostTeardown::from_fields(3, 1, 0, 0, "not json", "[]").is_err());
    }

    #[test]
    fn unavailable_counts_add_by_kind() {
        let mut a = UnavailableByKind::default();
        a.count(HostUnavailable::Backlog);
        let mut b = UnavailableByKind::default();
        b.count(HostUnavailable::Backlog);
        b.count(HostUnavailable::SubjectTooLong);
        a.add(&b);
        assert_eq!((a.backlog, a.subject_too_long, a.total()), (2, 1, 3));
    }
}
