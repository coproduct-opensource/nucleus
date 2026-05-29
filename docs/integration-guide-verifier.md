# Integration Guide — nucleus Verifier

**Audience:** developers wiring nucleus bundles + verifier-service into
a product.
**You'll have by the end:** a verify-bundle path in your backend OR
browser, a working badge widget your end users can click, and a clear
operational playbook for trust-anchor management.

This guide is the developer-facing complement to the
[threat model](./verifier-service-threat-model.md) and
[compliance posture](./compliance-posture.md). If you have a
compliance officer reading along, point them at those two docs;
they can sign off in 30 minutes.

---

## The three integration patterns

Most products fit one of these. Pick the one that matches your
threat model + UX needs, then jump to that section.

### A — Ship a bundle alongside your AI API response

You have a "build me X" API endpoint that today returns

```json
{ "summary": "...", "stats": {...} }
```

You want it to return

```json
{
  "summary": "...",
  "stats": {...},
  "_provenance": {
    "bundle_url": "https://your-cdn/bundles/abc...json",
    "bundle_hash_sha256_hex": "abc...",
    "verify_url": "https://verifier.coproduct.io/v1/bundles/abc.../verify"
  }
}
```

so any downstream consumer can verify before trusting. The bundle
itself doesn't need to be inline; serving it from your CDN +
shipping the hash is the canonical pattern.

→ jump to [Pattern A: backend production](#pattern-a-backend-production)

### B — Embed a verify badge in your UI

You return AI-generated content (an image, a summary, a code
diff) to a human user, and you want a "verified provenance" badge
they can click to confirm authenticity.

→ jump to [Pattern B: badge widget](#pattern-b-badge-widget)

### C — Verify in your backend before re-emission

You receive bundles from upstream and want to refuse them if they
fail verification, before passing the content on to your own
users.

→ jump to [Pattern C: backend verification](#pattern-c-backend-verification)

---

## Producing bundles

All three patterns assume you have access to bundles. Today you
get bundles by running agents through `nucleus-control-plane-server`:

```sh
# Start the server (in your infrastructure):
nucleus-control-plane-server \
  --bind 0.0.0.0:8080 \
  --log /data/nucleus-lineage.jsonl \
  --jwks-out /data/nucleus.jwks.json \
  --trust-domain prod.your-org.example \
  --namespace agents \
  --service-account summarizer \
  # In production set the SPIFFE flags so /v1/jobs requires a JWT-SVID:
  --spiffe-trust-jwks-path /etc/nucleus/oidc-trust.jwks.json \
  --spiffe-allowed-audience "https://control.your-org.example/api" \
  --spiffe-allowed-subject-prefix "spiffe://prod.your-org.example/ns/clients/sa/"
```

Submit a job (with a JWT-SVID minted by your `nucleus-oidc-provider`):

```sh
curl -sS -X POST https://control.your-org.example/v1/jobs \
  -H "Authorization: Bearer $JWT_SVID" \
  -H "Content-Type: application/json" \
  -d '{
    "input_ref": {"Inline": {"content": {"document": "..."}}},
    "task": "summarize",
    "destination": "InResponse",
    "policy_profile": "report-extraction",
    "agent_driver": {"name": "your-driver", "config": {}}
  }'
# → 202 with Location: /v1/jobs/{id}
```

Poll until `state == "Completed"`, then fetch:

```sh
curl -sS https://control.your-org.example/v1/jobs/$ID/bundle \
  -H "Authorization: Bearer $JWT_SVID" \
  -o bundle.json
```

That `bundle.json` is what every downstream pattern consumes.

---

## The trust anchor

Every verifier needs a **trust anchor**: the JWKS the producer
published out of band. **Do not use the JWKS embedded in the
bundle's envelope as the trust anchor** — it's producer-controlled
and a forger fabricating a whole bundle controls it.

Get the trust anchor once, at integration time, via:

- `GET https://control.your-org.example/.well-known/jwks.json`
  (from your control plane — operator-administered)
- OR via a file the operator hands you out of band
  (`chmod 400 /etc/nucleus/issuer.jwks.json`)
- OR via the verifier-service's discovery endpoint:
  `GET https://verifier.coproduct.io/.well-known/nucleus-verifier-configuration`

Pin the JWKS bytes. Rotate when the operator rotates keys (their
key-rotation cadence + your acceptance window are the operator's
responsibility to communicate).

The trust anchor JSON shape — re-used in every SDK below:

```json
{
  "trust_jwks": { "keys": [...] },
  "allow_empty": false,
  "trust_witness_pubkey_hex": null,
  "trusted_witnesses_hex": [],
  "cosignature_threshold": 0,
  "require_payload_binding": false
}
```

---

## Pattern A: backend production

Your API endpoint already produces some `{summary, stats}` JSON.
After you produce the AI output, you also have a bundle (e.g. by
running it through `nucleus-control-plane-server`). Two strategies:

### A.1 Inline (small bundles, tightly coupled clients)

```python
# Python (FastAPI) — ship bundle inline
from fastapi import FastAPI
from nucleus_verifier import verify_bundle, supported_envelope_schema_version
import hashlib, json

app = FastAPI()

# Loaded once at startup from your control plane's published JWKS.
TRUST_ANCHOR = json.dumps({
    "trust_jwks": json.load(open("/etc/nucleus/issuer.jwks.json")),
})

@app.post("/summarize")
async def summarize(req: SummarizeRequest):
    payload, bundle_json = await run_agent(req)   # your producer code

    # Cross-check before emission: bundle SHOULD verify against our anchor.
    try:
        verify_bundle(bundle_json, TRUST_ANCHOR)
    except RuntimeError as e:
        logger.error("bundle from agent does not self-verify: %s", e)
        raise HTTPException(500, "internal provenance failure")

    bundle_hash = hashlib.sha256(bundle_json.encode()).hexdigest()

    return {
        **payload,
        "_provenance": {
            "envelope_schema_version": supported_envelope_schema_version(),
            "bundle_inline_b64": base64.b64encode(bundle_json.encode()).decode(),
            "bundle_hash_sha256_hex": bundle_hash,
            "verify_url": f"https://verifier.coproduct.io/v1/bundles/{bundle_hash}/verify",
        },
    }
```

### A.2 Sidecar (recommended, scales to large bundles)

Upload the bundle to your own CDN; ship only the URL + hash.

```python
# Same setup, but offload the bundle to S3/R2:
bundle_hash = hashlib.sha256(bundle_json.encode()).hexdigest()
bundle_url = f"https://your-cdn/bundles/{bundle_hash}.json"
await s3.put_object(Bucket="your-bundles", Key=f"{bundle_hash}.json",
                    Body=bundle_json, ContentType="application/json")

return {
    **payload,
    "_provenance": {
        "bundle_url": bundle_url,
        "bundle_hash_sha256_hex": bundle_hash,
        "verify_url": f"https://verifier.coproduct.io/v1/bundles/{bundle_hash}/verify",
    },
}
```

End users / downstream services GET the bundle by hash, then
verify against your published trust JWKS — exactly the flow CT
log clients use against the SCT extension.

---

## Pattern B: badge widget

You return AI-generated content to a human user. Drop in a badge
they can click to confirm verification. The badge runs verification
**in their browser** via the wasm SDK — no trust in your servers
needed.

### Embed (one-time setup)

```html
<!-- index.html -->
<script type="module" async>
  import init, { verifyBundle } from "https://your-cdn/nucleus-verifier-wasm/index.js";
  await init();
  window.__nucleusVerify = verifyBundle;
</script>
```

(Or `npm install nucleus-verifier-wasm` if you have a bundler.)

### Badge component (React example)

```tsx
import { useEffect, useState } from "react";

const TRUST_ANCHOR = JSON.stringify({
  trust_jwks: await fetch("/static/issuer.jwks.json").then(r => r.json()),
});

function NucleusBadge({ bundleUrl, bundleHash }: { bundleUrl: string; bundleHash: string }) {
  const [state, setState] = useState<"loading" | "ok" | "fail" | "idle">("idle");
  const [report, setReport] = useState<any>(null);

  async function verify() {
    setState("loading");
    try {
      const bundle = await fetch(bundleUrl).then(r => r.text());
      const r = window.__nucleusVerify(bundle, TRUST_ANCHOR);
      setReport(r);
      setState("ok");
    } catch (e) {
      setReport({ error: String(e) });
      setState("fail");
    }
  }

  return (
    <button onClick={verify} className={`badge badge--${state}`}>
      {state === "idle" && "Click to verify provenance"}
      {state === "loading" && "verifying..."}
      {state === "ok" && `Verified ✓ (${report.edge_count} steps)`}
      {state === "fail" && `Failed: ${report.error.slice(0, 40)}`}
    </button>
  );
}
```

You can also link to `https://verifier.coproduct.io/v1/bundles/{hash}/verify`
as a fallback for clients without JS — that returns the stored
report from the hosted verifier. **But** the SDK-side check is
the cryptographic one; the hosted endpoint is convenience only,
not trust root.

### Optional: served badge image

For email / non-JS contexts, you can use a server-rendered SVG
badge whose `<image>` element points at the verifier-service:

```html
<a href="https://verifier.coproduct.io/v1/bundles/{hash}/verify"
   target="_blank" rel="noopener">
  <img src="https://verifier.coproduct.io/badge/{hash}.svg"
       alt="nucleus provenance verified" height="20" />
</a>
```

(The `/badge/{hash}.svg` endpoint is part of the v1.1 verifier
roadmap; track via task #91 metrics + future task for SVG badge.)

---

## Pattern C: backend verification

You receive bundles from upstream (a partner sends them, an
exchange aggregates them, …) and want to reject the ones that
don't verify before passing the content to your own users.

### Python

```python
from nucleus_verifier import verify_bundle
import json

UPSTREAM_TRUST = json.dumps({
    "trust_jwks": json.load(open("/etc/nucleus/upstream.jwks.json")),
    # Lock down to the upstream's specific witness:
    "trust_witness_pubkey_hex": "<32-byte hex of their witness pubkey>",
    "cosignature_threshold": 1,   # require at least 1 federated cosig
    "require_payload_binding": True,  # refuse v1 bundles
})

def accept_upstream(bundle_json: str) -> dict:
    try:
        report = verify_bundle(bundle_json, UPSTREAM_TRUST)
    except ValueError as e:
        # malformed JSON / hex / shape — log + reject as user error
        raise BadRequest(f"bundle is structurally invalid: {e}")
    except RuntimeError as e:
        # verification rejected — REFUSE the content
        log_security_event("upstream bundle failed verification", error=str(e))
        raise Forbidden(f"upstream bundle does not verify: {e}")

    if report["trust_mode"] != "out_of_band":
        raise Forbidden("upstream bundle is in self-check mode; refuse")
    if report["edge_count"] == 0:
        raise Forbidden("upstream bundle is empty; refuse")
    return report
```

### Node.js

```js
import { verifyBundle } from "@coproduct/verifier";
import fs from "node:fs";

const UPSTREAM_TRUST = JSON.stringify({
  trust_jwks: JSON.parse(fs.readFileSync("/etc/nucleus/upstream.jwks.json")),
  trust_witness_pubkey_hex: "<32-byte hex>",
  cosignature_threshold: 1,
  require_payload_binding: true,
});

export function acceptBundle(bundleJson) {
  try {
    const report = verifyBundle(bundleJson, UPSTREAM_TRUST);
    if (report.trust_mode !== "out_of_band") {
      throw new Error("self_check_only — refusing");
    }
    return report;
  } catch (e) {
    logSecurityEvent("upstream bundle failed", e.message);
    throw e;
  }
}
```

### shell (curl + the hosted verifier)

```sh
HASH=$(sha256sum bundle.json | cut -c1-64)
curl -sS -X POST https://verifier.coproduct.io/v1/verify \
  -H "Content-Type: application/json" \
  -d "$(jq -nc --slurpfile b bundle.json --slurpfile j /etc/nucleus/trust.jwks.json \
        '{bundle: $b[0], trust_jwks: $j[0]}')"
```

The hosted endpoint is for convenience + side-channel telemetry;
your production critical path should run the SDK locally.

---

## Operational playbook

### Key rotation

- The producer's JWKS rotates per their cadence (typically every
  24h for short-lived keys; every 90d for long-term anchors).
- Verifier-side: re-fetch `/.well-known/jwks.json` on every
  process start + every 1h. The JWKS is cheap to refetch.
- Old verifications signed under retired keys remain valid — keys
  stay in the JWKS until past every bundle they signed has
  expired.

### Monitoring

Operators should track:

| Metric | Source | Alert when |
|---|---|---|
| Verify failure rate | Your verify code logs | > 1% over 5 min |
| Bundle hash collisions (impossible, sentinel of bug) | Your producer | > 0 ever |
| JWKS fetch failure | Your bootstrap | any failure |
| `verifier.coproduct.io` SLO | Their status page | red |
| Hosted-verifier rate-limit 429s | Your callers | > 0/min sustained |

### Disaster recovery

If `verifier.coproduct.io` is down, your verification still
works via the SDK. The hosted endpoint only matters for the
hash-lookup convenience UX. Plan UX degradation, not outage —
your verify-or-refuse logic remains live.

### Versioning

Both SDKs export `supportedEnvelopeSchemaVersion()` /
`supported_envelope_schema_version()`. Pin to a specific schema
in your producer + verifier; reject bundles with newer schema
versions you haven't validated against.

---

## What this guide does NOT cover

- **C2PA / in-toto / SLSA export** — see the
  [eu-ai-act-article-50.md](./eu-ai-act-article-50.md) doc + the
  envelope crate's `interop` module.
- **Webhook delivery** of bundle-ready events — task #77 ships
  this on the control-plane-server.
- **SSE event stream** during a job — task #76 completes this.
- **Multi-region / sovereign-cloud** deployments — task #81 + #80
  iter-2.

## Questions

`security@coproduct.io` for security questions;
`https://github.com/coproduct-opensource/nucleus/issues` for bugs +
feature requests.
