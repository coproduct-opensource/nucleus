//! End-to-end demo: a 3-step pod workflow with full SPIFFE lineage.
//!
//! Steps:
//!   1. Bash: `echo` a fixture string (acts as "raw input").
//!   2. Write: persist a derived file from step 1's output.
//!   3. LLM call (mock by default; `--real-claude` for live mode):
//!      sends the file content to a relying party that verifies the
//!      JWT-SVID we mint at the boundary, then echoes a "response".
//!
//! For each step we mint a JWT-SVID via [`LocalIssuer`] and emit a
//! [`LineageEdge`] to a JSONL log. After the workflow finishes, the demo
//! prints the leaf SPIFFE ID; the operator can then run:
//!
//!     nucleus lineage <leaf-id> --log <path>
//!
//! to walk the full chain back to the pod root.
//!
//! Real-Claude mode requires:
//!   - `ANTHROPIC_API_KEY` (or a workload identity federation rule preconfigured).
//!   - The user accepts that the JWT-SVID signed by `LocalIssuer` will *not*
//!     be accepted by Anthropic without a registered federation issuer; in
//!     real mode the demo therefore falls back to the API key and merely
//!     records the SPIFFE ID locally.

use std::env;
use std::path::PathBuf;
use std::process::Command;

use jsonwebtoken::{decode, Algorithm, Validation};
use nucleus_lineage::{
    CallSpiffeId, EdgeKind, IdentityFetcher, JsonlSink, LineageEdge, LineageSink, LocalIssuer,
    SvidClaims,
};

const POD_TRUST_DOMAIN: &str = "demo.nucleus.local";
const POD_NAMESPACE: &str = "agents";
const POD_SA: &str = "lineage-demo";

const MOCK_LLM_AUDIENCE: &str = "https://mock-llm.local/api";
const REAL_CLAUDE_AUDIENCE: &str = "https://api.anthropic.com";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let real_claude = env::args().any(|a| a == "--real-claude");
    let log_path = env::args()
        .skip_while(|a| a != "--log")
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./nucleus-lineage.jsonl"));

    println!("=== nucleus-lineage three-step demo ===");
    println!("log:         {}", log_path.display());
    println!(
        "external:    {}",
        if real_claude {
            "real Claude API (--real-claude)"
        } else {
            "mock LLM (default)"
        }
    );
    println!();

    // ── Setup ──────────────────────────────────────────────────────────
    let sink = JsonlSink::open(&log_path)?;
    let issuer = LocalIssuer::random()?;
    let pod = CallSpiffeId::pod(POD_TRUST_DOMAIN, POD_NAMESPACE, POD_SA)?;

    sink.emit(LineageEdge::pod_admit(pod.clone()))?;
    println!("admitted pod: {}", pod);

    // ── Step 1: Bash ──────────────────────────────────────────────────
    let bash_input = "hello world from nucleus";
    let output = Command::new("bash")
        .arg("-c")
        .arg(format!("echo '{}' | tr a-z A-Z", bash_input))
        .output()?;
    if !output.status.success() {
        return Err(format!("bash exited with {:?}", output.status).into());
    }
    let bash_stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let bash_id = pod.derive_tool("Bash", Some(bash_stdout.as_bytes()))?;
    let bash_jwt = issuer.fetch_jwt_svid_with_kind(&bash_id, "tool/Bash", Some("tool_call"))?;
    sink.emit(
        LineageEdge::from_parent(
            bash_id.clone(),
            pod.clone(),
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        )
        .with_content_hash(bash_id.content_hash_hex().unwrap_or_default())
        .with_attr("cmd", "echo … | tr a-z A-Z")
        .with_attr("exit_code", output.status.code().unwrap_or(-1).to_string())
        .with_attr("jwt_jti", jti_from_jwt(&bash_jwt, &issuer)?),
    )?;
    println!("step 1 ✔ Bash → {} ({} bytes)", bash_id, bash_stdout.len());

    // ── Step 2: Write ─────────────────────────────────────────────────
    let tmp =
        std::env::temp_dir().join(format!("nucleus-lineage-demo-{}.txt", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, &bash_stdout)?;
    let written_bytes = std::fs::read(&tmp)?;
    let write_id = bash_id.derive_tool("Write", Some(&written_bytes))?;
    let _write_jwt = issuer.fetch_jwt_svid_with_kind(&write_id, "tool/Write", Some("tool_call"))?;
    sink.emit(
        LineageEdge::from_parent(
            write_id.clone(),
            bash_id.clone(),
            EdgeKind::ToolCall {
                tool: "Write".to_string(),
            },
        )
        .with_content_hash(write_id.content_hash_hex().unwrap_or_default())
        .with_attr("path", tmp.display().to_string())
        .with_attr("bytes", written_bytes.len().to_string()),
    )?;
    println!("step 2 ✔ Write → {} ({})", write_id, tmp.display());

    // ── Step 3: LLM call ──────────────────────────────────────────────
    // Mint a JWT-SVID for the prompt before calling out — this is the
    // boundary-attribution moment that closes the cross-system IFC gap.
    let prompt_bytes = std::fs::read(&tmp)?;
    let prompt_id = write_id.derive_llm("anthropic", "prompt", &prompt_bytes)?;
    let aud = if real_claude {
        REAL_CLAUDE_AUDIENCE
    } else {
        MOCK_LLM_AUDIENCE
    };
    let prompt_jwt = issuer.fetch_jwt_svid_with_kind(&prompt_id, aud, Some("llm_call"))?;
    sink.emit(
        LineageEdge::from_parent(
            prompt_id.clone(),
            write_id.clone(),
            EdgeKind::LlmCall {
                provider: "anthropic".to_string(),
                direction: "prompt".to_string(),
            },
        )
        .with_content_hash(prompt_id.content_hash_hex().unwrap_or_default())
        .with_attr("audience", aud.to_string())
        .with_attr("jwt_jti", jti_from_jwt(&prompt_jwt, &issuer)?),
    )?;
    println!("step 3a ✔ LLM prompt → {}", prompt_id);

    let response_bytes = if real_claude {
        call_real_claude(&prompt_bytes, &prompt_jwt)?
    } else {
        call_mock_llm(&prompt_bytes, &prompt_jwt, &issuer)?
    };
    let response_id = prompt_id.derive_llm("anthropic", "response", &response_bytes)?;
    sink.emit(
        LineageEdge::from_parent(
            response_id.clone(),
            prompt_id.clone(),
            EdgeKind::LlmCall {
                provider: "anthropic".to_string(),
                direction: "response".to_string(),
            },
        )
        .with_content_hash(response_id.content_hash_hex().unwrap_or_default())
        .with_attr("bytes", response_bytes.len().to_string()),
    )?;
    println!(
        "step 3b ✔ LLM response → {} ({} bytes)",
        response_id,
        response_bytes.len()
    );

    // ── Cleanup ────────────────────────────────────────────────────────
    let _ = std::fs::remove_file(&tmp);

    println!();
    println!("done. lineage log written to {}", log_path.display());
    println!("walk it with:");
    println!(
        "  nucleus lineage '{}' --log {}",
        response_id,
        log_path.display()
    );
    Ok(())
}

/// Mock LLM: receives the bytes + JWT, verifies the JWT against the issuer's
/// public key, and returns a synthesized "response". This is the same code
/// path a real relying party would follow — just with the issuer trust root
/// known a priori instead of fetched via OIDC discovery.
fn call_mock_llm(
    prompt: &[u8],
    jwt: &str,
    issuer: &LocalIssuer,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[MOCK_LLM_AUDIENCE]);
    validation.set_issuer(&[issuer.issuer()]);
    let decoded = decode::<SvidClaims>(jwt, &issuer.decoding_key(), &validation)?;
    println!(
        "    mock-llm: verified JWT, sub={}, jti={}, exp_in={}s",
        decoded.claims.sub,
        decoded.claims.jti,
        decoded.claims.exp.saturating_sub(decoded.claims.iat),
    );
    Ok(format!(
        "mock-llm received {} bytes from caller {}",
        prompt.len(),
        decoded.claims.sub
    )
    .into_bytes())
}

/// Real Claude API call. Uses ANTHROPIC_API_KEY for auth (since we don't
/// have a registered federation issuer in the Anthropic Console for our
/// demo SPIFFE trust domain). The SPIFFE ID and JWT are still minted and
/// recorded — they show what a real WIF call WOULD attribute, even though
/// the bearer token sent over the wire is the API key.
fn call_real_claude(prompt: &[u8], _jwt: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let api_key = env::var("ANTHROPIC_API_KEY")
        .map_err(|_| "ANTHROPIC_API_KEY must be set for --real-claude mode")?;
    let body = serde_json::json!({
        "model": "claude-sonnet-4-6",
        "max_tokens": 64,
        "messages": [{
            "role": "user",
            "content": String::from_utf8_lossy(prompt).into_owned(),
        }],
    });
    let resp = ureq::post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .send_json(&body)?;
    let body: serde_json::Value = resp.into_body().read_json()?;
    let text = body
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("(no text in response)")
        .to_string();
    Ok(text.into_bytes())
}

fn jti_from_jwt(jwt: &str, issuer: &LocalIssuer) -> Result<String, Box<dyn std::error::Error>> {
    // We accept either audience because this helper is called for tool-call
    // JWTs (audience tool/...) and llm-call JWTs (audience https://...).
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[issuer.issuer()]);
    validation.validate_aud = false;
    let decoded = decode::<SvidClaims>(jwt, &issuer.decoding_key(), &validation)?;
    Ok(decoded.claims.jti)
}
