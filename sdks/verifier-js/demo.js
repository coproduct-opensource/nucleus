// In-browser verifier demo. Everything runs in this tab: the WASM is the
// nucleus envelope verifier compiled from Rust, the bundle + trust anchor are
// REAL (generated and self-verified by
// `crates/nucleus-envelope/examples/emit_demo_bundle.rs`), and `verifyBundle`
// re-checks Merkle integrity + the witness cosignature against the anchor you
// pin. No network calls after load — open DevTools → Network → Offline and
// click Verify; it still works.
import init, {
  verifyBundle,
  sdkVersion,
  supportedEnvelopeSchemaVersion,
} from "./pkg/nucleus_verifier_wasm.js";

const $ = (id) => document.getElementById(id);
const bundleEl = $("bundle");
const anchorEl = $("anchor");
const result = $("result");
const note = $("tamper-note");

// Originals so "reset" restores the pristine, verifying fixtures.
let original = { bundle: "", anchor: "" };

function setNote(msg, kind) {
  note.textContent = msg || "";
  note.className = "note " + (kind || "");
}

function renderReport(report) {
  const rows = [
    ["ok", report.ok],
    ["trust_mode", report.trust_mode],
    ["trust_domain", report.trust_domain],
    ["edge_count", report.edge_count],
    ["merkle_verified", report.merkle_verified],
    ["cosignatures_verified", report.cosignatures_verified],
    ["matched_witness_pubkeys", (report.matched_witness_pubkeys_hex || []).join(", ") || "—"],
    ["head_edge_hash_hex", report.head_edge_hash_hex],
    ["kids", (report.kids || []).join(", ")],
    ["schema_version", report.schema_version],
  ];
  return rows.map(([k, v]) => "  " + k.padEnd(24) + String(v)).join("\n");
}

function doVerify() {
  result.className = "info";
  result.textContent = "verifying… (recomputed locally — no server)";
  try {
    const report = verifyBundle(bundleEl.value, anchorEl.value);
    result.className = "ok";
    result.textContent =
      "✓ VERIFIED — recomputed in your browser, nothing trusted but the anchor you pinned\n\n" +
      renderReport(report);
  } catch (e) {
    result.className = "fail";
    result.textContent =
      "✗ REJECTED — the local verifier refused it\n\n  reason: " + (e && e.message ? e.message : String(e));
  }
}

// --- Tamper helpers: mutate one real field, re-render the JSON so the user
// --- SEES the changed bytes, then they click Verify and watch it reject. ---
function flipBase64(s) {
  if (!s || s.length === 0) return s;
  const c = s[0];
  const repl = c === "A" ? "B" : "A";
  return repl + s.slice(1);
}

function mutateBundle(path, label) {
  let obj;
  try {
    obj = JSON.parse(bundleEl.value);
  } catch (_e) {
    setNote("bundle is not valid JSON — click reset", "fail");
    return;
  }
  const target = path(obj);
  if (!target) {
    setNote("this field is not present in the loaded bundle", "fail");
    return;
  }
  const ok = target.apply();
  if (!ok) {
    setNote("nothing to tamper at that field", "fail");
    return;
  }
  bundleEl.value = JSON.stringify(obj, null, 2);
  setNote("tampered: " + label + " — now click Verify", "fail");
}

function tamperEdgeSig() {
  mutateBundle(
    (o) => {
      const p = o.envelope && o.envelope.edges && o.envelope.edges[0] && o.envelope.edges[0].proof;
      if (!p || !p.sig) return null;
      return { apply: () => { p.sig = flipBase64(p.sig); return true; } };
    },
    "flipped the first byte of envelope.edges[0].proof.sig (Ed25519 edge signature)"
  );
}

function tamperWitnessSig() {
  mutateBundle(
    (o) => {
      const sth = o.envelope && o.envelope.merkle_anchor && o.envelope.merkle_anchor.sth;
      if (!sth || !sth.witness_sig) return null;
      return { apply: () => { sth.witness_sig = flipBase64(sth.witness_sig); return true; } };
    },
    "broke envelope.merkle_anchor.sth.witness_sig (the transparency-log witness cosignature)"
  );
}

function resetFixtures() {
  bundleEl.value = original.bundle;
  anchorEl.value = original.anchor;
  setNote("restored the original, untampered fixtures", "ok");
  result.className = "info";
  result.textContent = "ready — click Verify, or tamper first and watch it reject.";
}

async function loadFixtures(which) {
  const base = which === "basic" ? "bundle.basic.json" : "bundle.json";
  const anchorName = which === "basic" ? "trust-anchor.basic.json" : "trust-anchor.json";
  const [b, a] = await Promise.all([
    fetch(new URL("./demo-fixtures/" + base, import.meta.url)).then((r) => r.text()),
    fetch(new URL("./demo-fixtures/" + anchorName, import.meta.url)).then((r) => r.text()),
  ]);
  // Pretty-print so the structure (and later, the tampered byte) is legible.
  original.bundle = JSON.stringify(JSON.parse(b), null, 2);
  original.anchor = JSON.stringify(JSON.parse(a), null, 2);
  bundleEl.value = original.bundle;
  anchorEl.value = original.anchor;
}

async function boot() {
  try {
    // GitHub Pages does not reliably serve .wasm as application/wasm, which
    // breaks instantiateStreaming. Fetch the bytes and instantiate from an
    // ArrayBuffer so the MIME type is irrelevant.
    const wasmBytes = await fetch(
      new URL("./pkg/nucleus_verifier_wasm_bg.wasm", import.meta.url)
    ).then((r) => r.arrayBuffer());
    await init({ module_or_path: wasmBytes });
  } catch (e) {
    result.className = "fail";
    result.textContent = "verifier failed to load: " + (e && e.message ? e.message : String(e));
    return;
  }

  $("sdk-version").textContent = "v" + sdkVersion();
  $("schema-version").textContent = "envelope schema v" + supportedEnvelopeSchemaVersion();

  await loadFixtures("cosigned");
  setNote("", "");
  result.className = "info";
  result.textContent = "ready — click Verify, or tamper first and watch it reject.";

  $("verify-btn").addEventListener("click", doVerify);
  $("tamper-edge").addEventListener("click", tamperEdgeSig);
  $("tamper-witness").addEventListener("click", tamperWitnessSig);
  $("reset-btn").addEventListener("click", resetFixtures);
  $("fixture-select").addEventListener("change", async (ev) => {
    await loadFixtures(ev.target.value);
    setNote("loaded the " + ev.target.value + " fixture", "ok");
    result.className = "info";
    result.textContent = "ready — click Verify.";
  });
  $("verify-btn").disabled = false;
  for (const id of ["tamper-edge", "tamper-witness", "reset-btn"]) $(id).disabled = false;
}

boot();
