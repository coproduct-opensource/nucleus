//! Wire types for operator review of action-bound host approvals.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalView {
    pub id: Uuid,
    pub operation: String,
    pub subject: String,
    pub effect_sha256: String,
    pub call_charge_micro_usd: u64,
    pub expires_unix: u64,
    pub status: ApprovalStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Granted,
    Refused,
    Spent,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Grant,
    Refuse,
}
