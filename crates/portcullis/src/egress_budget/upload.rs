//! Total reservations with incremental admission to the shared pace window.

use super::*;

/// A complete upload's total reservation. Dropping it retains the allocation.
/// Each admitted slice consumes part of this token without reserving volume again.
#[must_use = "an unsettled upload keeps its entire total reservation"]
#[derive(Debug)]
pub struct EgressUploadHold {
    id: ChildId,
    bytes: EgressBytes,
    epoch: u64,
    remaining: EgressBytes,
}

/// What a pace decision reads of an [`EgressUploadHold`]: a copy, so no
/// decision borrows the hold it is deciding about.
#[derive(Debug, Clone, Copy)]
struct UploadSlot {
    id: ChildId,
    bytes: EgressBytes,
    epoch: u64,
    remaining: EgressBytes,
}

impl EgressUploadHold {
    const fn slot(&self) -> UploadSlot {
        UploadSlot {
            id: self.id,
            bytes: self.bytes,
            epoch: self.epoch,
            remaining: self.remaining,
        }
    }
}

/// The next upload slice, or the time until another pace decision can help.
#[derive(Debug, PartialEq, Eq)]
pub enum UploadPace {
    /// At most the requested number of bytes may now be sent.
    Ready(EgressBytes),
    /// No bytes may be sent yet. Retry using a fresh clock after this delay.
    Wait {
        /// Seconds until the current fixed window expires.
        seconds: u64,
    },
    /// All reserved bytes have already received pace admission.
    Complete,
}

impl EgressLedger {
    /// Reserve the complete upload before starting I/O. This only reserves total
    /// volume; every outgoing slice must also pass [`Self::pace_upload`].
    pub fn reserve_upload(
        &mut self,
        bytes: EgressBytes,
    ) -> Result<EgressUploadHold, (EgressRefusal, EgressNovelty)> {
        if self.latch == Latch::Exhausted {
            return Err((self.exhausted(bytes), EgressNovelty::Repeat));
        }
        match self.allocate(bytes) {
            EgressDecision::Admitted(hold) => Ok(EgressUploadHold {
                id: hold.id,
                bytes: hold.bytes,
                epoch: hold.epoch,
                remaining: bytes,
            }),
            EgressDecision::Refused(reason, novelty) => Err((reason, novelty)),
        }
    }

    /// Admit up to `requested` bytes from an existing total reservation.
    /// Packet reservations and other uploads consume this same pace window.
    /// A later total-ceiling latch does not invalidate already reserved volume.
    /// Consume and return the reservation for every step, including waits.
    /// A refusal drops the handle and conservatively retains its allocation.
    pub fn pace_upload(
        &mut self,
        mut upload: EgressUploadHold,
        requested: EgressBytes,
        now_unix: u64,
    ) -> Result<(EgressUploadHold, UploadPace), EgressRefusal> {
        let (pace, window) = self.upload_step(upload.slot(), requested, now_unix)?;
        if let Some(window) = window {
            self.window = window;
        }
        if let UploadPace::Ready(bytes) = pace {
            upload.remaining -= bytes;
        }
        Ok((upload, pace))
    }

    /// What [`Self::pace_upload`] would admit now, without admitting it: for a
    /// caller that must ask several ledgers before any of them admits. The
    /// hold is taken and handed back by value, as every step takes it (C-4);
    /// a refusal drops it and retains its allocation, as [`Self::pace_upload`]
    /// does.
    pub fn upload_allowance(
        &self,
        upload: EgressUploadHold,
        requested: EgressBytes,
        now_unix: u64,
    ) -> Result<(EgressUploadHold, UploadPace), EgressRefusal> {
        let (pace, _) = self.upload_step(upload.slot(), requested, now_unix)?;
        Ok((upload, pace))
    }

    /// The one decision behind [`Self::pace_upload`] and
    /// [`Self::upload_allowance`]: the pace, and the window as admitting it
    /// would leave it (`None` when the window is untouched).
    fn upload_step(
        &self,
        upload: UploadSlot,
        requested: EgressBytes,
        now_unix: u64,
    ) -> Result<(UploadPace, Option<Window>), EgressRefusal> {
        if upload.epoch != self.epoch || self.core.allocation_of(upload.id) != Some(upload.bytes) {
            return Err(EgressRefusal::LedgerFault);
        }
        if upload.remaining == 0 {
            return Ok((UploadPace::Complete, None));
        }
        let bytes = requested.min(upload.remaining);
        let EgressPace::PerWindow {
            bytes: per_window,
            window_secs,
        } = self.ceiling.pace
        else {
            return Ok((UploadPace::Ready(bytes), None));
        };
        let len = u64::from(window_secs.get());
        let mut window = self.window.at(now_unix, len);
        let available = per_window.saturating_sub(window.counted);
        if available == 0 {
            let seconds = len.saturating_sub(now_unix.saturating_sub(window.started_at));
            return Ok((UploadPace::Wait { seconds }, Some(window)));
        }
        let bytes = bytes.min(available);
        window.counted = window.counted.saturating_add(bytes);
        Ok((UploadPace::Ready(bytes), Some(window)))
    }

    /// Settle the entire upload. Use `NotSent` only when no bytes were handed to
    /// transport; cancellation after handoff retains the full conservative charge.
    pub fn settle_upload(
        &mut self,
        upload: EgressUploadHold,
        outcome: EgressSettlement,
    ) -> Result<(), EgressSettleError> {
        self.settle(
            EgressHold {
                id: upload.id,
                bytes: upload.bytes,
                epoch: upload.epoch,
            },
            outcome,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger() -> EgressLedger {
        EgressLedger::new(EgressCeiling::new(
            1_000,
            EgressPace::PerWindow {
                bytes: 100,
                window_secs: NonZeroU32::new(2).unwrap(),
            },
        ))
    }

    #[test]
    fn upload_spans_windows_and_shares_pace_with_packets() {
        let mut ledger = ledger();
        let upload = ledger.reserve_upload(250).unwrap();
        let EgressDecision::Admitted(packet) = ledger.reserve(30, 10) else {
            panic!("packet fits");
        };
        ledger.settle(packet, EgressSettlement::Sent).unwrap();
        assert_eq!(ledger.counted(), 280);
        let (upload, pace) = ledger.pace_upload(upload, 250, 10).unwrap();
        assert_eq!(pace, UploadPace::Ready(70));
        let (upload, pace) = ledger.pace_upload(upload, 180, 11).unwrap();
        assert_eq!(pace, UploadPace::Wait { seconds: 1 });
        let (upload, pace) = ledger.pace_upload(upload, 180, 12).unwrap();
        assert_eq!(pace, UploadPace::Ready(100));
        assert!(matches!(
            ledger.reserve(1, 12),
            EgressDecision::Refused(EgressRefusal::RateExceeded { .. }, _)
        ));
        let (upload, pace) = ledger.pace_upload(upload, 180, 14).unwrap();
        assert_eq!(pace, UploadPace::Ready(80));
        let (upload, pace) = ledger.pace_upload(upload, 1, 14).unwrap();
        assert_eq!(pace, UploadPace::Complete);
        ledger
            .settle_upload(upload, EgressSettlement::Sent)
            .unwrap();
        assert_eq!(ledger.counted(), 280);
        assert!(ledger.core().conserves());
    }

    /// The allowance is what pacing would admit, and asking for it admits
    /// nothing: a caller can ask every ledger before any of them counts.
    #[test]
    fn an_upload_allowance_is_the_pace_and_admits_nothing() {
        let mut ledger = ledger();
        let mut upload = ledger.reserve_upload(250).unwrap();
        for _ in 0..3 {
            let (back, pace) = ledger.upload_allowance(upload, 250, 10).unwrap();
            assert_eq!(pace, UploadPace::Ready(100));
            upload = back;
        }
        let (upload, pace) = ledger.pace_upload(upload, 250, 10).unwrap();
        assert_eq!(pace, UploadPace::Ready(100), "the allowance was not spent");
        let (upload, pace) = ledger.upload_allowance(upload, 250, 11).unwrap();
        assert_eq!(pace, UploadPace::Wait { seconds: 1 });
        let (upload, pace) = ledger.upload_allowance(upload, 250, 12).unwrap();
        assert_eq!(pace, UploadPace::Ready(100), "a later window is fresh");
        ledger
            .settle_upload(upload, EgressSettlement::Sent)
            .unwrap();
    }

    #[test]
    fn total_refusal_does_not_interrupt_reserved_upload() {
        let mut ledger = ledger();
        let upload = ledger.reserve_upload(250).unwrap();
        assert!(matches!(
            ledger.reserve_upload(751),
            Err((EgressRefusal::CeilingExhausted { .. }, _))
        ));
        let (upload, pace) = ledger.pace_upload(upload, 50, 10).unwrap();
        assert_eq!(pace, UploadPace::Ready(50));
        ledger
            .settle_upload(upload, EgressSettlement::Sent)
            .unwrap();
        assert_eq!(ledger.counted(), 250);
    }

    #[test]
    fn concurrent_uploads_reserve_total_once_and_share_windows() {
        let mut ledger = ledger();
        let first = ledger.reserve_upload(200).unwrap();
        let second = ledger.reserve_upload(200).unwrap();
        assert_eq!(ledger.counted(), 400);
        let (first, pace) = ledger.pace_upload(first, 60, 10).unwrap();
        assert_eq!(pace, UploadPace::Ready(60));
        let (second, pace) = ledger.pace_upload(second, 60, 10).unwrap();
        assert_eq!(pace, UploadPace::Ready(40));
        let (first, pace) = ledger.pace_upload(first, 60, 10).unwrap();
        assert_eq!(pace, UploadPace::Wait { seconds: 2 });
        let (second, pace) = ledger.pace_upload(second, 60, 12).unwrap();
        assert_eq!(pace, UploadPace::Ready(60));
        ledger.settle_upload(first, EgressSettlement::Sent).unwrap();
        ledger
            .settle_upload(second, EgressSettlement::Sent)
            .unwrap();
        assert_eq!(ledger.counted(), 400);
        assert!(ledger.core().conserves());
    }

    #[test]
    fn unpaced_upload_is_still_limited_by_its_total_reservation() {
        let mut ledger = EgressLedger::new(EgressCeiling::new(1_000, EgressPace::Unpaced));
        let upload = ledger.reserve_upload(250).unwrap();
        let (upload, pace) = ledger.pace_upload(upload, 1_000, 10).unwrap();
        assert_eq!(pace, UploadPace::Ready(250));
        let (upload, pace) = ledger.pace_upload(upload, 1_000, 10).unwrap();
        assert_eq!(pace, UploadPace::Complete);
        ledger
            .settle_upload(upload, EgressSettlement::Sent)
            .unwrap();
        assert_eq!(ledger.counted(), 250);
    }

    #[test]
    fn unsent_refunds_total_but_not_pace_and_drop_retains_total() {
        let mut ledger = ledger();
        let upload = ledger.reserve_upload(250).unwrap();
        let (upload, pace) = ledger.pace_upload(upload, 100, 10).unwrap();
        assert_eq!(pace, UploadPace::Ready(100));
        ledger
            .settle_upload(upload, EgressSettlement::NotSent)
            .unwrap();
        assert_eq!(ledger.counted(), 0);
        assert!(matches!(
            ledger.reserve(1, 10),
            EgressDecision::Refused(EgressRefusal::RateExceeded { .. }, _)
        ));
        drop(ledger.reserve_upload(250).unwrap());
        assert_eq!(ledger.counted(), 250);
    }
}
