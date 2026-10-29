//! Operator-declared metering for an upstream: per-token prices and where the
//! upstream's own response reports usage and refusal reasons, as JSON pointers.
//! Nothing here knows any upstream's format or price; the registry names both.
//!
//! The flat call tariff is debited before the call (`CallCharge`). After a
//! successful response this prices the call from its reported usage, and the
//! caller debits any excess over the tariff. The ledger only grows, so the
//! tariff is a floor and an overestimate is not refunded: an operator who wants
//! each call charged at its price sets `call_charge_micro_usd = 0`.
//!
//! A call whose usage cannot be read is charged its ceiling, never zero: its
//! request's bytes (each input token is at least one byte, so this bounds the
//! input) and `ceiling_output_tokens`, at the upstream's rates. Until
//! 2026-10-29 it was charged the tariff alone, which with a zero tariff would
//! have made an unread call free.
use nucleus_spec::host_effect::outcome::{
    MAX_PROVIDER_MESSAGE, MAX_PROVIDER_STATUS, ProviderError, Settlement, Usage,
};
use serde::Deserialize;
use serde_json::Value;

/// The most response body the host keeps to read usage from. A larger metered
/// response is recorded as `usage_unreadable`, never priced at zero.
pub(crate) const CAPTURE_MAX: usize = 4 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MeteringFile {
    input_micro_usd_per_million_tokens: u64,
    output_micro_usd_per_million_tokens: u64,
    /// JSON pointers summed as billed input tokens; at least one must resolve.
    input_tokens: Vec<String>,
    /// JSON pointers summed as billed output tokens; absent ones count zero.
    output_tokens: Vec<String>,
    /// The most output (thinking included) one call can bill. Required: an
    /// unread call is charged up to it, so a missing ceiling would be a guess.
    ceiling_output_tokens: u64,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    error_status: Option<String>,
    #[serde(default)]
    error_message: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Metering {
    input_rate: u64,
    output_rate: u64,
    input_tokens: Vec<String>,
    output_tokens: Vec<String>,
    ceiling_output: u64,
    error_code: Option<String>,
    error_status: Option<String>,
    error_message: Option<String>,
}

fn pointer(upstream: &str, p: &str) -> Result<String, String> {
    if p.starts_with('/') && p.len() <= 256 && !p.chars().any(char::is_control) {
        Ok(p.to_owned())
    } else {
        Err(format!(
            "upstream {upstream:?}: metering pointer {p:?} must be a JSON pointer"
        ))
    }
}

impl Metering {
    pub(crate) fn from_file(upstream: &str, file: MeteringFile) -> Result<Self, String> {
        if file.input_tokens.is_empty()
            || file.input_tokens.len() > 8
            || file.output_tokens.len() > 8
        {
            return Err(format!(
                "upstream {upstream:?}: metering needs 1-8 input and 0-8 output pointers"
            ));
        }
        let all = |v: Vec<String>| {
            v.iter()
                .map(|p| pointer(upstream, p))
                .collect::<Result<Vec<_>, _>>()
        };
        let one = |v: Option<String>| v.map(|p| pointer(upstream, &p)).transpose();
        Ok(Self {
            input_rate: file.input_micro_usd_per_million_tokens,
            output_rate: file.output_micro_usd_per_million_tokens,
            input_tokens: all(file.input_tokens)?,
            output_tokens: all(file.output_tokens)?,
            ceiling_output: file.ceiling_output_tokens,
            error_code: one(file.error_code)?,
            error_status: one(file.error_status)?,
            error_message: one(file.error_message)?,
        })
    }

    /// Whether a refusal body is worth keeping: only if the operator named fields.
    pub(crate) fn reads_errors(&self) -> bool {
        self.error_code.is_some() || self.error_status.is_some() || self.error_message.is_some()
    }

    /// The response's JSON documents, last first: the whole body, or each
    /// server-sent-event `data:` line when the body is an event stream.
    fn documents(body: &[u8]) -> Vec<Value> {
        if let Ok(whole) = serde_json::from_slice::<Value>(body) {
            return vec![whole];
        }
        let text = String::from_utf8_lossy(body);
        let mut docs: Vec<Value> = text
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .filter_map(|d| serde_json::from_str(d.trim()).ok())
            .collect();
        docs.reverse();
        docs
    }

    fn count(doc: &Value, pointers: &[String]) -> (u64, bool) {
        let mut found = false;
        let mut total: u64 = 0;
        for p in pointers {
            if let Some(n) = doc.pointer(p).and_then(Value::as_u64) {
                found = true;
                total = total.saturating_add(n);
            }
        }
        (total, found)
    }

    fn price(&self, input: u64, output: u64) -> u64 {
        let micro = (u128::from(input) * u128::from(self.input_rate)
            + u128::from(output) * u128::from(self.output_rate))
        .div_ceil(1_000_000);
        u64::try_from(micro).unwrap_or(u64::MAX)
    }

    /// The most a call with a `request_bytes` body can cost: every input token
    /// is at least one byte, and output is at most `ceiling_output_tokens`.
    /// Never below the tariff, which was debited already.
    pub(crate) fn ceiling(&self, request_bytes: u64, tariff: u64) -> u64 {
        self.price(request_bytes, self.ceiling_output).max(tariff)
    }

    /// A call whose usage cannot be read, charged its ceiling.
    pub(crate) fn unreadable(&self, reason: &str, request_bytes: u64, tariff: u64) -> Settlement {
        Settlement::UsageUnreadable {
            tariff_micro_usd: tariff,
            reason: reason.into(),
            ceiling_micro_usd: self.ceiling(request_bytes, tariff),
        }
    }

    /// Settle a successful response observed in full (`complete`) within the
    /// capture (`!overflow`). Ceil-rounded so pricing never undercharges.
    pub(crate) fn settle(
        &self,
        body: &[u8],
        overflow: bool,
        complete: bool,
        tariff: u64,
        request_bytes: u64,
    ) -> Settlement {
        let unreadable = |reason: &str| self.unreadable(reason, request_bytes, tariff);
        if overflow {
            return unreadable("the response exceeded the host's metering capture");
        }
        if !complete {
            return unreadable("the response ended before the host observed all of it");
        }
        for doc in Self::documents(body) {
            let (input, found) = Self::count(&doc, &self.input_tokens);
            if !found {
                continue;
            }
            let (output, _) = Self::count(&doc, &self.output_tokens);
            let priced = self.price(input, output);
            return Settlement::Priced {
                usage: Usage {
                    input_tokens: input,
                    output_tokens: output,
                },
                priced_micro_usd: priced,
                tariff_micro_usd: tariff,
                top_up_micro_usd: priced.saturating_sub(tariff),
            };
        }
        unreadable("no response document carried the configured usage fields")
    }

    /// A refused response's reason from the operator-named fields, bounded.
    pub(crate) fn provider_error(&self, body: &[u8]) -> Option<ProviderError> {
        let doc = Self::documents(body).into_iter().next()?;
        let text = |p: &Option<String>, limit: usize| {
            p.as_ref()
                .and_then(|p| doc.pointer(p))
                .and_then(Value::as_str)
                .map(|s| bounded(s, limit))
        };
        let code = self
            .error_code
            .as_ref()
            .and_then(|p| doc.pointer(p))
            .and_then(Value::as_u64)
            .and_then(|c| u32::try_from(c).ok());
        let status = text(&self.error_status, MAX_PROVIDER_STATUS);
        let message = text(&self.error_message, MAX_PROVIDER_MESSAGE);
        (code.is_some() || status.is_some() || message.is_some()).then(|| ProviderError {
            code,
            status: status.unwrap_or_default(),
            message: message.unwrap_or_default(),
        })
    }
}

/// Truncate to `limit` bytes at a character boundary, without control characters.
fn bounded(s: &str, limit: usize) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if clean.len() <= limit {
        return clean;
    }
    let mut end = limit;
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    clean[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generic shape: usage under `/meta`, errors under `/error`. Prices are
    /// operator inputs for the test, not any vendor's rates.
    fn metering() -> Metering {
        Metering::from_file(
            "model",
            toml::from_str(
                r#"
                input_micro_usd_per_million_tokens = 300000
                output_micro_usd_per_million_tokens = 2500000
                input_tokens = ["/meta/in"]
                output_tokens = ["/meta/out", "/meta/thinking"]
                ceiling_output_tokens = 1000
                error_code = "/error/code"
                error_status = "/error/status"
                error_message = "/error/message"
                "#,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn prices_a_json_body_from_the_named_fields_rounding_up() {
        let body = br#"{"text":"...","meta":{"in":200000,"out":30000,"thinking":10000}}"#;
        // 200,000 x 0.3 + 40,000 x 2.5 = 60,000 + 100,000 micro-USD.
        assert_eq!(
            metering().settle(body, false, true, 100_000, 0),
            Settlement::Priced {
                usage: Usage {
                    input_tokens: 200_000,
                    output_tokens: 40_000
                },
                priced_micro_usd: 160_000,
                tariff_micro_usd: 100_000,
                top_up_micro_usd: 60_000,
            }
        );
        let tiny = br#"{"meta":{"in":1,"out":0}}"#;
        assert!(matches!(
            metering().settle(tiny, false, true, 0, 0),
            Settlement::Priced {
                priced_micro_usd: 1,
                ..
            }
        ));
    }

    #[test]
    fn reads_the_last_event_of_a_stream_and_never_refunds_below_the_tariff() {
        let body = b"data: {\"text\":\"a\"}\n\ndata: {\"text\":\"b\",\"meta\":{\"in\":1000,\"out\":100}}\n\n";
        match metering().settle(body, false, true, 100_000, 0) {
            Settlement::Priced {
                usage,
                priced_micro_usd,
                top_up_micro_usd,
                ..
            } => {
                assert_eq!((usage.input_tokens, usage.output_tokens), (1000, 100));
                assert_eq!(priced_micro_usd, 550);
                assert_eq!(top_up_micro_usd, 0, "the tariff is a floor");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unreadable_usage_is_said_not_priced_at_zero() {
        for (body, overflow, complete) in [
            (&br#"{"text":"no usage here"}"#[..], false, true),
            (&br#"{"meta":{"in":5}}"#[..], true, true),
            (&br#"{"meta":{"in":5}}"#[..], false, false),
            (&b"not json"[..], false, true),
        ] {
            // Charged its ceiling: 400 request bytes x 0.3 + 1,000 output x 2.5.
            assert!(matches!(
                metering().settle(body, overflow, complete, 7, 400),
                Settlement::UsageUnreadable {
                    tariff_micro_usd: 7,
                    ceiling_micro_usd: 2620,
                    ..
                }
            ));
        }
        // Never below the tariff already debited.
        assert_eq!(metering().ceiling(0, 5000), 5000);
    }

    /// With no tariff, a call is charged exactly its price: the whole price is the
    /// top-up (2026-10-29: the $0.10 floor charged 15-30x the priced cost).
    #[test]
    fn a_zero_tariff_charges_each_call_its_price() {
        let body = br#"{"meta":{"in":2670,"out":2}}"#;
        match metering().settle(body, false, true, 0, 9000) {
            Settlement::Priced { priced_micro_usd, top_up_micro_usd, tariff_micro_usd, .. } => {
                assert_eq!((priced_micro_usd, tariff_micro_usd, top_up_micro_usd), (806, 0, 806));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn keeps_only_the_named_bounded_refusal_fields() {
        let long = "x".repeat(2000);
        let body = format!(
            r#"{{"error":{{"code":403,"status":"PERMISSION_DENIED","message":"Spend cap reached. {long}","debug":"secret"}}}}"#
        );
        let error = metering().provider_error(body.as_bytes()).unwrap();
        assert_eq!(error.code, Some(403));
        assert_eq!(error.status, "PERMISSION_DENIED");
        assert!(
            error.message.starts_with("Spend cap reached.")
                && error.message.len() == MAX_PROVIDER_MESSAGE
        );
        assert!(
            !format!("{error:?}").contains("secret"),
            "unnamed fields are never kept"
        );
        assert!(metering().provider_error(b"<html>refused</html>").is_none());
    }

    #[test]
    fn malformed_metering_is_refused_at_load() {
        let bad = |s: &str| Metering::from_file("m", toml::from_str(s).unwrap()).is_err();
        assert!(bad(
            "input_micro_usd_per_million_tokens = 1\noutput_micro_usd_per_million_tokens = 1\ninput_tokens = []\noutput_tokens = []\nceiling_output_tokens = 1"
        ));
        assert!(bad(
            "input_micro_usd_per_million_tokens = 1\noutput_micro_usd_per_million_tokens = 1\ninput_tokens = [\"meta.in\"]\noutput_tokens = []\nceiling_output_tokens = 1"
        ));
        // No output ceiling: an unread call's charge would be a guess, so it does not load.
        assert!(toml::from_str::<MeteringFile>(
            "input_micro_usd_per_million_tokens = 1\noutput_micro_usd_per_million_tokens = 1\ninput_tokens = [\"/meta/in\"]\noutput_tokens = []"
        ).is_err());
    }
}
