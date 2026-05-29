// quickstart wasm verifier — runs verification entirely in this tab.
// The wasm module is the same nucleus-envelope verifier the JS SDK
// ships on npm.

import init, {
  verifyBundle,
  sdkVersion,
} from "/static/wasm/nucleus_verifier_wasm.js";

const els = {
  status: document.getElementById("sdk-status"),
  dropzone: document.getElementById("bundle-drop"),
  fileInput: document.getElementById("bundle-file-input"),
  bundleTextarea: document.getElementById("bundle-textarea"),
  anchorTextarea: document.getElementById("anchor-textarea"),
  verifyBtn: document.getElementById("verify-btn"),
  clearBtn: document.getElementById("clear-btn"),
  resultSection: document.getElementById("result-section"),
  resultHeadline: document.getElementById("result-headline"),
  resultBody: document.getElementById("result-body"),
  badgeSection: document.getElementById("badge-section"),
  badgeSnippet: document.getElementById("badge-snippet"),
};

let bundleText = "";

// ── SDK boot ─────────────────────────────────────────────────────
try {
  await init("/static/wasm/nucleus_verifier_wasm_bg.wasm");
  els.status.textContent = `SDK ready — v${sdkVersion()}. The verifier runs in this tab.`;
  els.status.classList.remove("info");
  els.status.classList.add("ready");
  refreshVerifyEnabled();
} catch (err) {
  els.status.textContent = `SDK failed to load: ${err.message ?? err}`;
  els.status.classList.remove("info");
  els.status.classList.add("error");
}

// ── Drag-and-drop wiring ─────────────────────────────────────────
["dragenter", "dragover", "dragleave", "drop"].forEach((evt) =>
  els.dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    e.stopPropagation();
  }),
);
els.dropzone.addEventListener("dragenter", () =>
  els.dropzone.classList.add("dragover"),
);
els.dropzone.addEventListener("dragover", () =>
  els.dropzone.classList.add("dragover"),
);
els.dropzone.addEventListener("dragleave", () =>
  els.dropzone.classList.remove("dragover"),
);
els.dropzone.addEventListener("drop", async (e) => {
  els.dropzone.classList.remove("dragover");
  const file = e.dataTransfer?.files?.[0];
  if (file) await ingestFile(file);
});

els.dropzone.addEventListener("click", () => els.fileInput.click());
els.dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    els.fileInput.click();
  }
});
els.fileInput.addEventListener("change", async () => {
  const file = els.fileInput.files?.[0];
  if (file) await ingestFile(file);
});

async function ingestFile(file) {
  try {
    const text = await file.text();
    bundleText = text;
    els.bundleTextarea.value = text;
    els.dropzone.querySelector(".dropzone-default").innerHTML =
      `<strong>${file.name}</strong> loaded — ${file.size} bytes.`;
    refreshVerifyEnabled();
  } catch (err) {
    setError(`Could not read file: ${err.message ?? err}`);
  }
}

els.bundleTextarea.addEventListener("input", () => {
  bundleText = els.bundleTextarea.value;
  refreshVerifyEnabled();
});
els.anchorTextarea.addEventListener("input", refreshVerifyEnabled);

function refreshVerifyEnabled() {
  const hasBundle = bundleText.trim().length > 0;
  const hasAnchor = els.anchorTextarea.value.trim().length > 0;
  els.verifyBtn.disabled = !(hasBundle && hasAnchor);
}

// ── Verify ────────────────────────────────────────────────────────
els.verifyBtn.addEventListener("click", () => {
  els.resultSection.hidden = false;
  els.badgeSection.hidden = true;
  els.resultBody.className = "result-body";
  try {
    const report = verifyBundle(bundleText, els.anchorTextarea.value);
    setSuccess(report);
  } catch (err) {
    setError(err.message ?? String(err));
  }
});

els.clearBtn.addEventListener("click", () => {
  bundleText = "";
  els.bundleTextarea.value = "";
  els.anchorTextarea.value = "";
  els.fileInput.value = "";
  els.dropzone.querySelector(".dropzone-default").innerHTML =
    `drop <code>bundle.json</code> here<br /><span class="muted">or click to pick a file</span>`;
  els.resultSection.hidden = true;
  refreshVerifyEnabled();
});

function setSuccess(report) {
  els.resultHeadline.textContent = "VERIFIED";
  els.resultSection.classList.remove("result-fail");
  els.resultSection.classList.add("result-ok");
  els.resultBody.textContent = JSON.stringify(report, null, 2);

  // Compute a SHA-256 of the bundle bytes for the badge.
  crypto.subtle
    .digest("SHA-256", new TextEncoder().encode(bundleText))
    .then((hashBuf) => {
      const hashHex = [...new Uint8Array(hashBuf)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const snippet = `<!-- nucleus verify badge -->
<a href="https://verifier.coproduct.io/v1/bundles/${hashHex}/verify"
   target="_blank" rel="noopener">
  verified by nucleus &middot;
  ${report.edge_count} steps &middot;
  ${report.trust_domain}
</a>`;
      els.badgeSnippet.textContent = snippet;
      els.badgeSection.hidden = false;
    })
    .catch((err) => {
      // Badge is optional; failure here doesn't invalidate the verify.
      console.warn("badge hash failed", err);
    });

  els.resultSection.scrollIntoView({ behavior: "smooth" });
}

function setError(message) {
  els.resultSection.hidden = false;
  els.resultHeadline.textContent = "REJECTED";
  els.resultSection.classList.remove("result-ok");
  els.resultSection.classList.add("result-fail");
  els.resultBody.textContent = message;
  els.resultSection.scrollIntoView({ behavior: "smooth" });
}
