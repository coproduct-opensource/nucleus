//! End-to-end demo: a 3-step pod workflow with full SPIFFE lineage and
//! cryptographically-signed edges.
//!
//! Steps:
//!   1. Bash: `tr` lowercases→uppercases a fixture string (acts as "raw
//!      input"). Uses `Command::new("tr").stdin(...)` — never `bash -c` with
//!      string interpolation; this is a security demo, no shell injection.
//!   2. Write: persist a derived file from step 1's output.
//!   3. LLM call (mock by default; `--real-llm` for live mode): sends
//!      the file content to a relying party. The mock LLM verifies the
//!      JWT-SVID by loading the issuer's JWKS from disk (cross-process
//!      verification, not a same-process self-loop).
//!
//! Every emitted [`LineageEdge`] is signed by [`LocalIssuer`] (which also
//! implements [`EdgeSigner`]) over canonical bytes that include the
//! parent edge's hash — i.e., a real hash chain. The operator can then run:
//!
//!     nucleus lineage <leaf-id> --log <path> --jwks <jwks-path> --require-signed
//!
//! to walk the chain with cryptographic verification.
//!
//! `--real-llm` mode honestly records `wire_auth=api_key` because we
//! don't have a registered federation issuer at the LLM provider for our
//! demo trust domain. The SPIFFE ID is recorded locally to show what a
//! real WIF call WOULD attribute. The real endpoint, token, and model are
//! supplied by the operator via the `LLM_API_URL`, `LLM_API_TOKEN`, and
//! `LLM_MODEL` environment variables — nucleus stays vendor-agnostic.

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use jsonwebtoken::{decode, Algorithm, Validation};
use nucleus_lineage::{
    canonical_edge_bytes, edge_content_hash, CallSpiffeId, EdgeKind, EdgeSigner, IdentityFetcher,
    JsonlSink, Jwks, LineageEdge, LineageSink, LocalIssuer, Proof, SvidClaims,
};

const POD_TRUST_DOMAIN: &str = "demo.nucleus.local";
const POD_NAMESPACE: &str = "agents";
const POD_SA: &str = "lineage-demo";

const MOCK_LLM_AUDIENCE: &str = "https://mock-llm.local/api";
const DEFAULT_LLM_AUDIENCE: &str = "https://api.example-llm.local";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let real_llm = env::args().any(|a| a == "--real-llm");
    let log_path = env::args()
        .skip_while(|a| a != "--log")
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./nucleus-lineage.jsonl"));
    let jwks_path = env::args()
        .skip_while(|a| a != "--jwks")
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./nucleus-lineage.jwks.json"));

    println!("=== nucleus-lineage three-step demo ===");
    println!("log:         {}", log_path.display());
    println!("jwks:        {}", jwks_path.display());
    println!(
        "external:    {}",
        if real_llm {
            "real LLM API (--real-llm; uses LLM_API_TOKEN for wire auth)"
        } else {
            "mock LLM (default; verifies JWT-SVID against on-disk JWKS)"
        }
    );
    println!();

    // ── Setup ──────────────────────────────────────────────────────────
    let sink = JsonlSink::open(&log_path)?;
    let issuer = LocalIssuer::random()?;
    let pod = CallSpiffeId::pod(POD_TRUST_DOMAIN, POD_NAMESPACE, POD_SA)?;

    // Publish the JWKS to disk so any verifier (mock LLM, `nucleus lineage`)
    // can load it WITHOUT touching the issuer struct directly. This is the
    // cross-process trust anchor — the audit's CRIT-4 / DEMO-2 fix.
    let jwks_bytes = serde_json::to_vec_pretty(&issuer.publish_jwks())?;
    std::fs::write(&jwks_path, &jwks_bytes)?;
    println!(
        "published JWKS ({} bytes) → {}",
        jwks_bytes.len(),
        jwks_path.display()
    );

    // Edge-emission helper that signs every edge over canonical bytes that
    // include the previous edge's hash (real chain).
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut emit_signed = |edge: LineageEdge| -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let bytes = canonical_edge_bytes(&edge, prev_hash.as_ref());
        let sig = issuer.sign(&bytes)?;
        let mut proof = Proof::new(issuer.kid().to_string(), issuer.alg().to_string(), sig);
        if let Some(h) = prev_hash {
            proof = proof.with_prev_hash(h);
        }
        let signed_edge = edge.with_proof(proof);
        let h = edge_content_hash(&signed_edge, prev_hash.as_ref());
        sink.emit(signed_edge)?;
        prev_hash = Some(h);
        Ok(h)
    };

    emit_signed(LineageEdge::pod_admit(pod.clone()))?;
    println!("admitted pod: {}", pod);

    // ── Step 1: Bash → tr (no shell interpolation) ────────────────────
    let bash_input = "hello world from nucleus";
    let mut tr = Command::new("tr")
        .args(["a-z", "A-Z"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    {
        use std::io::Write as _;
        tr.stdin
            .as_mut()
            .unwrap()
            .write_all(bash_input.as_bytes())?;
    }
    let output = tr.wait_with_output()?;
    if !output.status.success() {
        return Err(format!("tr exited with {:?}", output.status).into());
    }
    let bash_stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let bash_id = pod.derive_tool("Bash", Some(bash_stdout.as_bytes()))?;
    let bash_jwt = issuer.fetch_jwt_svid_with_kind(&bash_id, "tool/Bash", Some("tool_call"))?;
    emit_signed(
        LineageEdge::from_parent(
            bash_id.clone(),
            pod.clone(),
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        )
        .with_content_hash(bash_id.content_hash_hex().unwrap_or_default())
        .with_attr("cmd", "tr a-z A-Z")
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
    emit_signed(
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
    // Provider label + audience are operator-supplied so nucleus stays
    // vendor-agnostic (the orchestrator layer owns vendor specifics).
    let provider = env::var("LLM_PROVIDER").unwrap_or_else(|_| "example-llm".to_string());
    let real_llm_audience =
        env::var("LLM_API_URL").unwrap_or_else(|_| DEFAULT_LLM_AUDIENCE.to_string());
    let prompt_bytes = std::fs::read(&tmp)?;
    let prompt_id = write_id.derive_llm(&provider, "prompt", &prompt_bytes)?;
    let aud: &str = if real_llm {
        real_llm_audience.as_str()
    } else {
        MOCK_LLM_AUDIENCE
    };
    let prompt_jwt = issuer.fetch_jwt_svid_with_kind(&prompt_id, aud, Some("llm_call"))?;

    // Audit attrs: be honest about what's actually on the wire.
    let mut prompt_edge = LineageEdge::from_parent(
        prompt_id.clone(),
        write_id.clone(),
        EdgeKind::LlmCall {
            provider: provider.clone(),
            direction: "prompt".to_string(),
        },
    )
    .with_content_hash(prompt_id.content_hash_hex().unwrap_or_default());
    if real_llm {
        // The actual wire auth is the API key; the JWT-SVID is recorded but
        // NOT presented to the provider (no federation rule registered for
        // our demo trust domain). Audit reflects this.
        prompt_edge = prompt_edge
            .with_attr("wire_auth", "api_key")
            .with_attr("audience_intended", aud.to_string())
            .with_attr("recorded_subject", prompt_id.to_string())
            .with_attr("jwt_jti", jti_from_jwt(&prompt_jwt, &issuer)?);
    } else {
        prompt_edge = prompt_edge
            .with_attr("wire_auth", "jwt_svid")
            .with_attr("audience", aud.to_string())
            .with_attr("jwt_jti", jti_from_jwt(&prompt_jwt, &issuer)?);
    }
    emit_signed(prompt_edge)?;
    println!("step 3a ✔ LLM prompt → {}", prompt_id);

    let response_bytes = if real_llm {
        call_real_llm(&prompt_bytes)?
    } else {
        call_mock_llm_via_jwks(&prompt_bytes, &prompt_jwt, &jwks_path)?
    };
    let response_id = prompt_id.derive_llm(&provider, "response", &response_bytes)?;
    emit_signed(
        LineageEdge::from_parent(
            response_id.clone(),
            prompt_id.clone(),
            EdgeKind::LlmCall {
                provider: provider.clone(),
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
    println!("walk it WITH cryptographic verification:");
    println!(
        "  nucleus lineage '{}' --log {} --jwks {} --require-signed",
        response_id,
        log_path.display(),
        jwks_path.display(),
    );
    Ok(())
}

/// Mock LLM that loads the issuer's JWKS from disk (cross-process verification,
/// not a same-process self-loop). Same code path a real relying party would
/// follow — except OIDC-discovery is replaced by a local file read.
fn call_mock_llm_via_jwks(
    prompt: &[u8],
    jwt: &str,
    jwks_path: &PathBuf,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let jwks_bytes = std::fs::read(jwks_path)?;
    let jwks: Jwks = Jwks::parse(&jwks_bytes)?;

    // Decode header to find the kid, then look up the verifying key in the JWKS.
    let header = jsonwebtoken::decode_header(jwt)?;
    let kid = header.kid.ok_or("JWT missing kid")?;
    let vk = jwks.verifying_key(&kid)?;

    // Build a jsonwebtoken DecodingKey from the raw Ed25519 public key
    // bytes. `from_ed_components` takes a base64url-encoded 32-byte key.
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let decoding_key =
        jsonwebtoken::DecodingKey::from_ed_components(&URL_SAFE_NO_PAD.encode(vk.as_bytes()))?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[MOCK_LLM_AUDIENCE]);
    // Note: mock LLM doesn't pin issuer in this demo; a real RP would.
    validation.validate_aud = true;
    validation.required_spec_claims = std::collections::HashSet::new(); // simplifies demo
    validation.required_spec_claims.insert("aud".to_string());
    validation.required_spec_claims.insert("exp".to_string());
    let decoded = decode::<SvidClaims>(jwt, &decoding_key, &validation)?;
    println!(
        "    mock-llm: verified JWT against on-disk JWKS, kid={}, sub={}, exp_in={}s",
        kid,
        decoded.claims.sub,
        decoded.claims.exp.saturating_sub(decoded.claims.iat),
    );
    Ok(format!(
        "mock-llm received {} bytes from caller {}",
        prompt.len(),
        decoded.claims.sub
    )
    .into_bytes())
}

/// Real LLM API call. Uses `LLM_API_TOKEN` for auth — the JWT-SVID is
/// recorded in the audit log but NOT presented to the provider, since we
/// don't have a registered federation issuer for our demo SPIFFE trust
/// domain. The audit `prompt` edge for `--real-llm` records
/// `wire_auth=api_key` to be honest about what was actually on the wire.
///
/// The endpoint (`LLM_API_URL`), bearer token (`LLM_API_TOKEN`), and model
/// name (`LLM_MODEL`) are all operator-supplied — nucleus makes no vendor
/// assumptions. The response is read from either a `content[0].text` or a
/// `choices[0].message.content` shape, falling back to the raw JSON body.
fn call_real_llm(prompt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let api_key =
        env::var("LLM_API_TOKEN").map_err(|_| "LLM_API_TOKEN must be set for --real-llm mode")?;
    let url = env::var("LLM_API_URL").map_err(|_| "LLM_API_URL must be set for --real-llm mode")?;
    let model = env::var("LLM_MODEL").unwrap_or_else(|_| "default".to_string());
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 64,
        "messages": [{
            "role": "user",
            "content": String::from_utf8_lossy(prompt).into_owned(),
        }],
    });
    let resp = ureq::post(&url)
        .header("authorization", &format!("Bearer {api_key}"))
        .header("content-type", "application/json")
        .send_json(&body)?;
    let body: serde_json::Value = resp.into_body().read_json()?;
    let text = body
        .pointer("/content/0/text")
        .or_else(|| body.pointer("/choices/0/message/content"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| body.to_string());
    Ok(text.into_bytes())
}

fn jti_from_jwt(jwt: &str, issuer: &LocalIssuer) -> Result<String, Box<dyn std::error::Error>> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[issuer.issuer()]);
    validation.validate_aud = false;
    let decoded = decode::<SvidClaims>(jwt, &issuer.decoding_key(), &validation)?;
    Ok(decoded.claims.jti)
}
