use super::*;
use portcullis::{EgressUploadHold, UploadPace};

impl EgressMeter {
    /// Reserve the full staged upload before credentials or upstream I/O, from
    /// every account on the pod's chain, all or nothing.
    pub async fn reserve_upload(
        self: &Arc<Self>,
        bytes: u64,
    ) -> Result<UploadCharge, EgressRefusal> {
        let mut holds = Vec::with_capacity(self.chain.accounts().len());
        for account in self.chain.accounts() {
            match account.reserve_upload(bytes).await {
                Ok(hold) => holds.push(hold),
                Err((reason, novelty)) => {
                    for (account, hold) in self.chain.accounts().iter().zip(holds) {
                        account.settle_upload(hold, EgressSettlement::NotSent);
                    }
                    if novelty == EgressNovelty::First {
                        self.record(&reason).await;
                    }
                    return Err(reason);
                }
            }
        }
        Ok(UploadCharge {
            meter: self.clone(),
            holds,
        })
    }
}

/// Owned by the HTTP body: cancellation after handoff charges the whole upload.
pub struct UploadCharge {
    meter: Arc<EgressMeter>,
    /// One hold per account on the meter's chain, in order. Empty once settled,
    /// or once a pace step failed (the allocation is then retained).
    holds: Vec<EgressUploadHold>,
}

impl UploadCharge {
    /// The next slice: the least every account on the chain admits
    /// (`EgressChain::pace_upload`).
    pub fn pace(&mut self, bytes: u64, now: u64) -> Result<UploadPace, EgressRefusal> {
        let holds = std::mem::take(&mut self.holds);
        let (holds, pace) = self.meter.chain.pace_upload(holds, bytes, now)?;
        self.holds = holds;
        Ok(pace)
    }

    pub fn not_sent(mut self) {
        self.settle(EgressSettlement::NotSent);
    }

    fn settle(&mut self, outcome: EgressSettlement) {
        for (account, hold) in self
            .meter
            .chain
            .accounts()
            .iter()
            .zip(std::mem::take(&mut self.holds))
        {
            account.settle_upload(hold, outcome);
        }
    }
}

impl Drop for UploadCharge {
    fn drop(&mut self) {
        self.settle(EgressSettlement::Sent);
    }
}
