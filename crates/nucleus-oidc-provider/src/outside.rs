//! Outside issuers: a token from an issuer nucleus does not run, exchanged as
//! one configured SPIFFE ID.
//!
//! The binding (`crate::federation::OutsideIssuerBinding`) is operator
//! configuration; this module turns each into a running
//! `nucleus_federation::ExternalIssuerValidator` and answers, for a presented
//! token, "which binding, and does the token satisfy it?".
//!
//! # Dispatch is by exact `iss`, before any key work
//!
//! The token's payload is decoded WITHOUT verification only to read `iss`, and
//! only to choose which validator judges it. A token whose `iss` names no
//! binding goes to the SPIFFE path and is refused there unless it is a valid
//! JWT-SVID from the trust bundle. Nothing about the unverified payload is used
//! for anything else.
//!
//! # What a validated token becomes
//!
//! Exactly the binding's `spiffe_id` — not a name derived from the outside
//! `sub`. The outside issuer's namespace is not nucleus's; the operator states
//! the correspondence once, in the binding, and the token carries no say in it.
//! The outside `sub` and the token's hash go to the log, so which outside
//! workload obtained the identity is on record.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nucleus_federation::{
    ExternalIssuerConfig, ExternalIssuerValidator, InboundError, JwksSource, VerifyAlg,
};
use nucleus_lineage::CallSpiffeId;

use crate::federation::{FederationError, OutsideIssuerBinding, OutsideJwks};

/// One bound outside issuer, running.
pub struct OutsideIssuer {
    id: String,
    spiffe_id: CallSpiffeId,
    validator: ExternalIssuerValidator,
}

impl std::fmt::Debug for OutsideIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutsideIssuer")
            .field("id", &self.id)
            .field("issuer", &self.validator.issuer())
            .field("spiffe_id", &self.spiffe_id.as_str())
            .finish_non_exhaustive()
    }
}

/// A token that passed its binding.
#[derive(Debug)]
pub struct ExchangedOutsideToken {
    /// The binding's id, for the log.
    pub binding_id: String,
    /// The identity the token becomes.
    pub spiffe_id: CallSpiffeId,
    /// The outside token's `sub`, for the log only.
    pub outside_sub: String,
    /// The outside token's `exp`.
    pub exp: u64,
}

impl OutsideIssuer {
    /// The binding's id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Validate `token` at `now` against this binding.
    pub async fn validate(
        &self,
        token: &str,
        now: u64,
    ) -> Result<ExchangedOutsideToken, InboundError> {
        let caller = self.validator.validate(token, now).await?;
        Ok(ExchangedOutsideToken {
            binding_id: self.id.clone(),
            spiffe_id: self.spiffe_id.clone(),
            outside_sub: caller.sub,
            exp: caller.exp,
        })
    }
}

/// Every bound outside issuer, keyed by exact `iss`.
#[derive(Debug, Default)]
pub struct OutsideIssuers {
    by_issuer: BTreeMap<String, OutsideIssuer>,
}

impl OutsideIssuers {
    /// No outside issuers: every subject_token takes the SPIFFE path.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a validator for each binding. `op_issuer` is THIS OP's issuer
    /// URL, which every outside token must carry as its `aud`.
    ///
    /// # Errors
    /// A binding that `FederationRules::parse_toml` would refuse (the same
    /// check, not a copy of it), one that names this OP's own issuer, or one
    /// the validator refuses (issuer or JWKS URL not https / loopback http).
    pub fn build(
        bindings: &[OutsideIssuerBinding],
        op_issuer: &str,
    ) -> Result<Self, FederationError> {
        crate::federation::validate_outside_issuers(bindings)?;
        // A binding for the OP's own issuer would route the OP's own tokens
        // (and anything claiming to be one) to the outside path and turn them
        // into one fixed identity. Compared without a trailing slash, since
        // the two spellings are one issuer to a careless reader.
        let own = op_issuer.trim_end_matches('/');
        if let Some(b) = bindings
            .iter()
            .find(|b| b.issuer.trim_end_matches('/') == own)
        {
            return Err(FederationError::InvalidRule(format!(
                "outside_issuer {:?}: issuer is this OP's own issuer URL",
                b.id
            )));
        }
        let http = nucleus_federation::default_client()
            .map_err(|e| FederationError::Io(format!("building the outside-issuer client: {e}")))?;
        let mut by_issuer = BTreeMap::new();
        for b in bindings {
            let bad = |why: String| {
                FederationError::InvalidRule(format!("outside_issuer {:?}: {why}", b.id))
            };
            let algs: BTreeSet<VerifyAlg> = b
                .algs
                .iter()
                .map(|a| {
                    a.parse::<VerifyAlg>()
                        .map_err(|e| bad(format!("{a:?}: {e}")))
                })
                .collect::<Result<_, _>>()?;
            let jwks = match &b.jwks {
                OutsideJwks::Discovery => JwksSource::Discovery,
                OutsideJwks::Uri(u) => {
                    JwksSource::Uri(u.parse().map_err(|e| bad(format!("jwks uri {u:?}: {e}")))?)
                }
            };
            let spiffe_id = CallSpiffeId::parse(b.spiffe_id.as_str())
                .map_err(|e| bad(format!("spiffe_id: {e}")))?;
            let mut cfg = ExternalIssuerConfig::new(b.issuer.clone(), op_issuer, algs, jwks);
            cfg.max_lifetime = Duration::from_secs(b.max_lifetime_secs);
            cfg.leeway = Duration::from_secs(b.leeway_secs);
            cfg.required_claims = b.required_claims.clone();
            let validator =
                ExternalIssuerValidator::new(cfg, http.clone()).map_err(|e| bad(e.to_string()))?;
            // Unique by `validate_outside_issuers` above.
            by_issuer.insert(
                b.issuer.clone(),
                OutsideIssuer {
                    id: b.id.clone(),
                    spiffe_id,
                    validator,
                },
            );
        }
        Ok(Self { by_issuer })
    }

    /// How many issuers are bound — for `/healthz`.
    pub fn len(&self) -> usize {
        self.by_issuer.len()
    }

    /// True when no issuer is bound.
    pub fn is_empty(&self) -> bool {
        self.by_issuer.is_empty()
    }

    /// The binding a token's `iss` names, if any. Reads `iss` from the
    /// UNVERIFIED payload, to choose a validator and for nothing else.
    pub fn for_token(&self, token: &str) -> Option<&OutsideIssuer> {
        if self.by_issuer.is_empty() {
            return None;
        }
        let payload = token.split('.').nth(1)?;
        let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let iss = claims.get("iss")?.as_str()?;
        self.by_issuer.get(iss)
    }
}
