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
    pub fn pace_upload(
        &mut self,
        upload: &mut EgressUploadHold,
        requested: EgressBytes,
        now_unix: u64,
    ) -> Result<UploadPace, EgressRefusal> {
        if upload.epoch != self.epoch || self.core.allocation_of(upload.id) != Some(upload.bytes) {
            return Err(EgressRefusal::LedgerFault);
        }
        if upload.remaining == 0 {
            return Ok(UploadPace::Complete);
        }
        let mut bytes = requested.min(upload.remaining);
        if let EgressPace::PerWindow {
            bytes: per_window,
            window_secs,
        } = self.ceiling.pace
        {
            let len = u64::from(window_secs.get());
            self.refresh_window(now_unix, len);
            let available = per_window.saturating_sub(self.window.counted);
            if available == 0 {
                return Ok(UploadPace::Wait {
                    seconds: len.saturating_sub(now_unix.saturating_sub(self.window.started_at)),
                });
            }
            bytes = bytes.min(available);
            self.window.counted = self.window.counted.saturating_add(bytes);
        }
        upload.remaining -= bytes;
        Ok(UploadPace::Ready(bytes))
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
        let mut upload = ledger.reserve_upload(250).unwrap();
        let EgressDecision::Admitted(packet) = ledger.reserve(30, 10) else {
            panic!("packet fits");
        };
        ledger.settle(packet, EgressSettlement::Sent).unwrap();
        assert_eq!(ledger.counted(), 280);
        assert_eq!(
            ledger.pace_upload(&mut upload, 250, 10),
            Ok(UploadPace::Ready(70))
        );
        assert_eq!(
            ledger.pace_upload(&mut upload, 180, 11),
            Ok(UploadPace::Wait { seconds: 1 })
        );
        assert_eq!(
            ledger.pace_upload(&mut upload, 180, 12),
            Ok(UploadPace::Ready(100))
        );
        assert!(matches!(
            ledger.reserve(1, 12),
            EgressDecision::Refused(EgressRefusal::RateExceeded { .. }, _)
        ));
        assert_eq!(
            ledger.pace_upload(&mut upload, 180, 14),
            Ok(UploadPace::Ready(80))
        );
        assert_eq!(
            ledger.pace_upload(&mut upload, 1, 14),
            Ok(UploadPace::Complete)
        );
        ledger
            .settle_upload(upload, EgressSettlement::Sent)
            .unwrap();
        assert_eq!(ledger.counted(), 280);
        assert!(ledger.core().conserves());
    }

    #[test]
    fn total_refusal_does_not_interrupt_reserved_upload() {
        let mut ledger = ledger();
        let mut upload = ledger.reserve_upload(250).unwrap();
        assert!(matches!(
            ledger.reserve_upload(751),
            Err((EgressRefusal::CeilingExhausted { .. }, _))
        ));
        assert_eq!(
            ledger.pace_upload(&mut upload, 50, 10),
            Ok(UploadPace::Ready(50))
        );
        ledger
            .settle_upload(upload, EgressSettlement::Sent)
            .unwrap();
        assert_eq!(ledger.counted(), 250);
    }

    #[test]
    fn concurrent_uploads_reserve_total_once_and_share_windows() {
        let mut ledger = ledger();
        let mut first = ledger.reserve_upload(200).unwrap();
        let mut second = ledger.reserve_upload(200).unwrap();
        assert_eq!(ledger.counted(), 400);
        assert_eq!(
            ledger.pace_upload(&mut first, 60, 10),
            Ok(UploadPace::Ready(60))
        );
        assert_eq!(
            ledger.pace_upload(&mut second, 60, 10),
            Ok(UploadPace::Ready(40))
        );
        assert_eq!(
            ledger.pace_upload(&mut first, 60, 10),
            Ok(UploadPace::Wait { seconds: 2 })
        );
        assert_eq!(
            ledger.pace_upload(&mut second, 60, 12),
            Ok(UploadPace::Ready(60))
        );
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
        let mut upload = ledger.reserve_upload(250).unwrap();
        assert_eq!(
            ledger.pace_upload(&mut upload, 1_000, 10),
            Ok(UploadPace::Ready(250))
        );
        assert_eq!(
            ledger.pace_upload(&mut upload, 1_000, 10),
            Ok(UploadPace::Complete)
        );
        ledger
            .settle_upload(upload, EgressSettlement::Sent)
            .unwrap();
        assert_eq!(ledger.counted(), 250);
    }

    #[test]
    fn unsent_refunds_total_but_not_pace_and_drop_retains_total() {
        let mut ledger = ledger();
        let mut upload = ledger.reserve_upload(250).unwrap();
        assert_eq!(
            ledger.pace_upload(&mut upload, 100, 10),
            Ok(UploadPace::Ready(100))
        );
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
