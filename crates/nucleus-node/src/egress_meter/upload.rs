use super::*;
use portcullis::{EgressUploadHold, UploadPace};

impl EgressMeter {
    /// Reserve the full staged upload before credentials or upstream I/O.
    pub async fn reserve_upload(
        self: &Arc<Self>,
        bytes: u64,
    ) -> Result<UploadCharge, EgressRefusal> {
        let decision = match self.ledger.lock() {
            Ok(mut ledger) => ledger
                .as_mut()
                .ok_or((EgressRefusal::LedgerFault, EgressNovelty::Repeat))
                .and_then(|ledger| ledger.reserve_upload(bytes)),
            Err(_) => Err((EgressRefusal::LedgerFault, EgressNovelty::First)),
        };
        match decision {
            Ok(hold) => Ok(UploadCharge {
                meter: self.clone(),
                hold: Some(hold),
            }),
            Err((reason, novelty)) => {
                if novelty == EgressNovelty::First {
                    self.record(&reason).await;
                }
                Err(reason)
            }
        }
    }
}

/// Owned by the HTTP body: cancellation after handoff charges the whole upload.
pub struct UploadCharge {
    meter: Arc<EgressMeter>,
    hold: Option<EgressUploadHold>,
}

impl UploadCharge {
    pub fn pace(&mut self, bytes: u64, now: u64) -> Result<UploadPace, EgressRefusal> {
        let mut ledger = self
            .meter
            .ledger
            .lock()
            .map_err(|_| EgressRefusal::LedgerFault)?;
        let (hold, pace) = ledger
            .as_mut()
            .ok_or(EgressRefusal::LedgerFault)?
            .pace_upload(
                self.hold.take().ok_or(EgressRefusal::LedgerFault)?,
                bytes,
                now,
            )?;
        self.hold = Some(hold);
        Ok(pace)
    }

    pub fn not_sent(mut self) {
        self.settle(EgressSettlement::NotSent);
    }

    fn settle(&mut self, outcome: EgressSettlement) {
        if let Some(hold) = self.hold.take() {
            if let Ok(mut state) = self.meter.ledger.lock() {
                if let Some(ledger) = state.as_mut() {
                    if let Err(error) = ledger.settle_upload(hold, outcome) {
                        tracing::error!(pod = %self.meter.pod_id, "upload settle refused: {error}");
                    }
                }
            }
        }
    }
}

impl Drop for UploadCharge {
    fn drop(&mut self) {
        self.settle(EgressSettlement::Sent);
    }
}
