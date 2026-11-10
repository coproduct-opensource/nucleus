//! Browser presentation and disposable-worker protocol. All checking and UI
//! decisions are Rust; the JS interop is only wasm-bindgen module loading.
use serde_json::{Value, json};
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{Document, ErrorEvent, MessageEvent, Worker};

fn error(message: &str) -> JsValue {
    JsValue::from_str(message)
}
fn document() -> Result<Document, JsValue> {
    web_sys::window()
        .and_then(|w| w.document())
        .ok_or_else(|| error("document unavailable"))
}
fn text(id: &str, value: &str) {
    if let Ok(d) = document()
        && let Some(e) = d.get_element_by_id(id)
    {
        e.set_text_content(Some(value));
    }
}
fn show(id: &str, visible: bool) {
    if let Ok(d) = document()
        && let Some(e) = d.get_element_by_id(id)
    {
        if visible {
            let _ = e.remove_attribute("hidden");
        } else {
            let _ = e.set_attribute("hidden", "");
        }
    }
}
fn input(id: &str) -> Result<web_sys::HtmlInputElement, JsValue> {
    document()?
        .get_element_by_id(id)
        .ok_or_else(|| error("input missing"))?
        .dyn_into()
        .map_err(|_| error("input type differs"))
}
fn lock_inputs(locked: bool) {
    for id in ["certificate-file", "expected-origin", "expected-rp"] {
        if let Ok(input) = input(id) {
            input.set_disabled(locked);
        }
    }
}
mod assets;
use assets::{blob, fetch};
struct Assets {
    module: String,
    wasm: String,
    base: Vec<u8>,
}
struct Active {
    started: f64,
    worker: Worker,
    loader: String,
    timer: i32,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _error: Closure<dyn FnMut(ErrorEvent)>,
    _timeout: Closure<dyn FnMut()>,
}
fn clock() -> Result<f64, JsValue> {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .ok_or_else(|| error("monotonic checking clock unavailable"))
}
fn clear_result() {
    show("result", false);
    show("refusal", false);
    text("raw-report", "");
}
#[derive(Default)]
struct App {
    assets: Option<Assets>,
    certificate: Option<Vec<u8>>,
    active: Option<Active>,
}
fn finish(app: &Rc<RefCell<App>>, result: Result<Value, String>) {
    if let Some(active) = app.borrow_mut().active.take() {
        active.worker.set_onmessage(None);
        active.worker.set_onerror(None);
        active.worker.terminate();
        if let Some(window) = web_sys::window() {
            window.clear_timeout_with_handle(active.timer);
        }
        let _ = web_sys::Url::revoke_object_url(&active.loader);
    }
    lock_inputs(false);
    if let Ok(d) = document()
        && let Some(button) = d.get_element_by_id("verify")
    {
        let _ = button.remove_attribute("disabled");
    }
    match result {
        Ok(report) => {
            text("status", "Verified offline");
            text(
                "status-detail",
                "The exact signed packet and mathematical contract passed independent checking. This report grants no access or execution rights.",
            );
            text("subject", report["subject_sha256"].as_str().unwrap_or(""));
            text(
                "verified-origin",
                report["checked_origin"].as_str().unwrap_or(""),
            );
            text(
                "raw-report",
                &serde_json::to_string_pretty(&report).unwrap_or_default(),
            );
            show("result", true);
            show("refusal", false);
        }
        Err(message) => {
            text("status", "Not verified");
            text(
                "status-detail",
                "The certificate was refused. No application was changed by this verifier.",
            );
            text(
                "refusal-detail",
                &message.chars().take(2000).collect::<String>(),
            );
            show("refusal", true);
            show("result", false);
        }
    }
}
fn begin(app: &Rc<RefCell<App>>) -> Result<(), JsValue> {
    if app.borrow().active.is_some() {
        return Err(error("A verification is already running."));
    }
    let state = app.borrow();
    let assets = state
        .assets
        .as_ref()
        .ok_or_else(|| error("Verification resources are not ready."))?;
    let bytes = state
        .certificate
        .as_ref()
        .ok_or_else(|| error("Choose a certificate first."))?;
    let origin = input("expected-origin")?.value();
    let rp = input("expected-rp")?.value();
    if origin.is_empty() || rp.is_empty() {
        return Err(error("Expected origin and relying-party ID are required."));
    }
    let module = serde_json::to_string(&assets.module).map_err(|_| error("module URL"))?;
    let wasm = serde_json::to_string(&assets.wasm).map_err(|_| error("Wasm URL"))?;
    // Platform loader glue only; no authorization, checking or UI logic in JS.
    let loader = blob(
        format!("import init from {module};await init({{module_or_path:{wasm}}});").as_bytes(),
        "text/javascript",
    )?;
    let options = web_sys::WorkerOptions::new();
    options.set_type(web_sys::WorkerType::Module);
    let started = clock()?;
    let worker = Worker::new_with_options(&loader, &options)?;
    let payload = js_sys::Array::new();
    payload.push(&js_sys::Uint8Array::from(assets.base.as_slice()));
    payload.push(&js_sys::Uint8Array::from(bytes.as_slice()));
    payload.push(&JsValue::from_str(&origin));
    payload.push(&JsValue::from_str(&rp));
    drop(state);
    let app_message = app.clone();
    let worker_message = worker.clone();
    let message = Closure::wrap(Box::new(move |event: MessageEvent| {
        let expired = app_message
            .borrow()
            .active
            .as_ref()
            .is_none_or(|a| match clock() {
                Ok(now) => now - a.started >= 10_000.0,
                Err(_) => true,
            });
        if expired {
            finish(
                &app_message,
                Err("The checking deadline expired before the result was received.".into()),
            );
            return;
        }
        let parsed = event
            .data()
            .as_string()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        match parsed.as_ref().and_then(|v| v["status"].as_str()) {
            Some("ready") => {
                if worker_message.post_message(&payload).is_err() {
                    finish(
                        &app_message,
                        Err("Could not send certificate to the isolated checker.".into()),
                    );
                }
            }
            Some("verified") => {
                if let Some(value) = parsed {
                    finish(&app_message, Ok(value["report"].clone()));
                }
            }
            Some("refused") => finish(
                &app_message,
                Err(parsed
                    .as_ref()
                    .and_then(|v| v["reason"].as_str())
                    .unwrap_or("Certificate refused")
                    .into()),
            ),
            _ => finish(&app_message, Err("Malformed checker response.".into())),
        }
    }) as Box<dyn FnMut(MessageEvent)>);
    let app_error = app.clone();
    let failed = Closure::wrap(Box::new(move |event: ErrorEvent| {
        event.prevent_default();
        finish(
            &app_error,
            Err("The isolated checker trapped or stopped. Its instance was discarded.".into()),
        );
    }) as Box<dyn FnMut(ErrorEvent)>);
    let app_timeout = app.clone();
    let timeout = Closure::wrap(Box::new(move || {
        finish(
            &app_timeout,
            Err("The 10-second checking deadline was exceeded. The worker was terminated.".into()),
        )
    }) as Box<dyn FnMut()>);
    worker.set_onmessage(Some(message.as_ref().unchecked_ref()));
    worker.set_onerror(Some(failed.as_ref().unchecked_ref()));
    let timer = web_sys::window()
        .ok_or_else(|| error("window unavailable"))?
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            timeout.as_ref().unchecked_ref(),
            10_000,
        )?;
    app.borrow_mut().active = Some(Active {
        started,
        worker,
        loader,
        timer,
        _message: message,
        _error: failed,
        _timeout: timeout,
    });
    lock_inputs(true);
    if let Some(button) = document()?.get_element_by_id("verify") {
        button.set_attribute("disabled", "")?;
    }
    clear_result();
    text("status", "Checking locally…");
    text(
        "status-detail",
        "A fresh worker is checking the signed subject and every proof declaration. No network is needed.",
    );
    Ok(())
}
fn attach(app: &Rc<RefCell<App>>) -> Result<(), JsValue> {
    let file = input("certificate-file")?;
    let file_source = file.clone();
    let file_app = app.clone();
    let changed = Closure::wrap(Box::new(move |_event: web_sys::Event| {
        if file_app.borrow().active.is_some() {
            return;
        }
        file_app.borrow_mut().certificate = None;
        clear_result();
        text("certificate-name", "");
        let Some(file) = file_source.files().and_then(|f| f.get(0)) else {
            text("status", "Choose a certificate");
            text("status-detail", "No certificate is selected or verified.");
            return;
        };
        if file.size() > crate::MAX_PACKET_BYTES as f64 {
            finish(&file_app, Err("Certificate exceeds 16 MiB.".into()));
            return;
        }
        file_source.set_disabled(true);
        text("status", "Reading certificate…");
        if let Ok(d) = document()
            && let Some(button) = d.get_element_by_id("verify")
        {
            let _ = button.set_attribute("disabled", "");
        }
        let file_app = file_app.clone();
        spawn_local(async move {
            match JsFuture::from(file.array_buffer()).await {
                Ok(bytes) => {
                    let bytes = js_sys::Uint8Array::new(&bytes).to_vec();
                    file_app.borrow_mut().certificate = Some(bytes);
                    if let Ok(file) = input("certificate-file") {
                        file.set_disabled(false);
                    }
                    if file_app.borrow().assets.is_some()
                        && let Ok(d) = document()
                        && let Some(button) = d.get_element_by_id("verify")
                    {
                        let _ = button.remove_attribute("disabled");
                    }
                    text("certificate-name", &file.name());
                    text(
                        "status",
                        if file_app.borrow().assets.is_some() {
                            "Ready for offline checking"
                        } else {
                            "Loading verification resources…"
                        },
                    );
                    text(
                        "status-detail",
                        "Certificate loaded. Choose Verify certificate to check it locally.",
                    );
                }
                Err(_) => finish(
                    &file_app,
                    Err("Could not read that certificate file.".into()),
                ),
            }
        });
    }) as Box<dyn FnMut(web_sys::Event)>);
    file.add_event_listener_with_callback("change", changed.as_ref().unchecked_ref())?;
    changed.forget();
    if file.files().is_some_and(|files| files.length() > 0) {
        file.dispatch_event(&web_sys::Event::new("change")?)?;
    }
    for id in ["expected-origin", "expected-rp"] {
        let context_app = app.clone();
        let changed = Closure::wrap(Box::new(move |_event: web_sys::Event| {
            if context_app.borrow().active.is_some() {
                return;
            }
            clear_result();
            if context_app.borrow().assets.is_some() {
                text("status", "Ready for offline checking");
                text(
                    "status-detail",
                    "Expected identity changed. Verify the selected certificate again.",
                );
            }
        }) as Box<dyn FnMut(web_sys::Event)>);
        input(id)?.add_event_listener_with_callback("input", changed.as_ref().unchecked_ref())?;
        changed.forget();
    }
    let click_app = app.clone();
    let clicked = Closure::wrap(Box::new(move |_event: web_sys::Event| {
        if let Err(e) = begin(&click_app) {
            finish(
                &click_app,
                Err(e
                    .as_string()
                    .unwrap_or_else(|| "Could not start verification.".into())),
            );
        }
    }) as Box<dyn FnMut(web_sys::Event)>);
    document()?
        .get_element_by_id("verify")
        .ok_or_else(|| error("verify button missing"))?
        .add_event_listener_with_callback("click", clicked.as_ref().unchecked_ref())?;
    clicked.forget();
    Ok(())
}
async fn mount() -> Result<(), JsValue> {
    let app = Rc::new(RefCell::new(App::default()));
    attach(&app)?;
    let module = fetch("/proof/assets/nucleus_studio_proof.js", 2 * 1024 * 1024).await?;
    let wasm = fetch(
        "/proof/assets/nucleus_studio_proof_bg.wasm",
        16 * 1024 * 1024,
    )
    .await?;
    let base = fetch("/proof/assets/base.ndjson.gz", 8 * 1024 * 1024).await?;
    app.borrow_mut().assets = Some(Assets {
        module: blob(&module, "text/javascript")?,
        wasm: blob(&wasm, "application/wasm")?,
        base,
    });
    if let Some(button) = document()?.get_element_by_id("verify") {
        button.remove_attribute("disabled")?;
    }
    text("status", "Ready for offline checking");
    text(
        "status-detail",
        "The checking code and semantic base are loaded. Choose a certificate; the check runs entirely on this device.",
    );
    let source = document()?
        .body()
        .and_then(|b| b.get_attribute("data-certificate-url"));
    if let Some(source) = source {
        if !crate::page::valid_certificate_path(&source) {
            return Err(error("Certificate disclosure URL refused."));
        }
        let bytes = fetch(&source, crate::MAX_PACKET_BYTES).await?;
        app.borrow_mut().certificate = Some(bytes);
        text("certificate-name", "Shared certificate");
        begin(&app)?;
    }
    Ok(())
}
fn worker() -> Result<(), JsValue> {
    let scope: web_sys::DedicatedWorkerGlobalScope = js_sys::global().dyn_into()?;
    let reply = scope.clone();
    let message = Closure::wrap(Box::new(move |event: MessageEvent| {
        let args = js_sys::Array::from(&event.data());
        let result = (|| -> Result<Value, String> {
            if args.length() != 4 {
                return Err("checker input shape differs".into());
            }
            let base: js_sys::Uint8Array =
                args.get(0).dyn_into().map_err(|_| "base bytes required")?;
            let envelope: js_sys::Uint8Array = args
                .get(1)
                .dyn_into()
                .map_err(|_| "certificate bytes required")?;
            if base.length() > 8 * 1024 * 1024 || envelope.length() > crate::MAX_PACKET_BYTES as u32
            {
                return Err("checker byte budget exceeded".into());
            }
            let origin = args.get(2).as_string().ok_or("expected origin required")?;
            let rp = args.get(3).as_string().ok_or("expected RP required")?;
            let checked = crate::envelope::verify_bytes(
                &base.to_vec(),
                &envelope.to_vec(),
                crate::envelope::Context {
                    origin: &origin,
                    rp_id: &rp,
                },
            )?;
            serde_json::to_value(checked).map_err(|e| format!("report: {e}"))
        })();
        let value = match result {
            Ok(report) => json!({"status":"verified","report":report}),
            Err(reason) => json!({"status":"refused","reason":reason}),
        };
        if let Ok(value) = serde_json::to_string(&value) {
            let _ = reply.post_message(&JsValue::from_str(&value));
        }
    }) as Box<dyn FnMut(MessageEvent)>);
    scope.set_onmessage(Some(message.as_ref().unchecked_ref()));
    message.forget();
    scope.post_message(&JsValue::from_str("{\"status\":\"ready\"}"))
}
#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    if web_sys::window().is_some() {
        if document()?.get_element_by_id("proof-verifier").is_some() {
            spawn_local(async {
                if let Err(e) = mount().await {
                    text("status", "Could not load verifier");
                    text(
                        "status-detail",
                        &e.as_string().unwrap_or_else(|| {
                            "Verification assets unavailable. Reload when connected.".into()
                        }),
                    );
                }
            });
        }
        Ok(())
    } else {
        worker()
    }
}
