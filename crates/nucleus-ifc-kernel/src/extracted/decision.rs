//! The proxy's decision channel (ADR 0014 §7, ADR 0015 §2): what an arriving
//! answer and a passed deadline mean, as the slice Charon→Aeneas translates to
//! Lean. `DecisionChannel.lean` is the meaning; `DecisionChannelExtracted.lean`
//! proves these functions compute its decisions.
//!
//! Found 2026-11-19 (ADR 0017 local rehearsal): the proxy poisoned its channel
//! on any missed deadline, so one answer 0.2 s late left a pod whose links and
//! egress never carried anything again. Lateness belongs to one request. The
//! channel stays usable as long as a late answer can never be read as the
//! answer to another request: it is dropped by number.

/// What to do with an answer that arrives carrying number `s`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disposition {
    /// `s` is the outstanding request: its verdict applies.
    Apply,
    /// `s` timed out earlier: the answer is owed and dropped.
    DropLate,
    /// `s` is neither: a broken peer. The channel is poisoned.
    Poison,
}

/// [`Disposition`] for an answer, given whether its number is the outstanding
/// request's and whether it is owed.
pub fn disposition(is_current: bool, is_owed: bool) -> Disposition {
    if is_current {
        Disposition::Apply
    } else if is_owed {
        Disposition::DropLate
    } else {
        Disposition::Poison
    }
}

/// What a passed deadline does to the channel. The request is refused either
/// way (fail closed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OnDeadline {
    /// Refuse; the node still owes this number's answer, which will be dropped.
    RefuseAndOwe,
    /// Refuse and poison: the node received a partial frame, or owes more
    /// answers than `cap` (it is not answering at all).
    RefuseAndPoison,
}

/// [`OnDeadline`], given whether the request's frame was fully written and how
/// many answers would be owed after this one.
pub fn on_deadline(frame_written: bool, owed_after: u32, cap: u32) -> OnDeadline {
    if !frame_written || owed_after > cap {
        OnDeadline::RefuseAndPoison
    } else {
        OnDeadline::RefuseAndOwe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_applies_only_to_its_own_request() {
        assert_eq!(disposition(true, false), Disposition::Apply);
        assert_eq!(disposition(true, true), Disposition::Apply);
        assert_eq!(disposition(false, true), Disposition::DropLate);
        assert_eq!(disposition(false, false), Disposition::Poison);
    }

    #[test]
    fn a_deadline_poisons_only_a_broken_peer() {
        assert_eq!(on_deadline(true, 1, 64), OnDeadline::RefuseAndOwe);
        assert_eq!(on_deadline(true, 64, 64), OnDeadline::RefuseAndOwe);
        assert_eq!(on_deadline(true, 65, 64), OnDeadline::RefuseAndPoison);
        assert_eq!(on_deadline(false, 1, 64), OnDeadline::RefuseAndPoison);
    }
}
