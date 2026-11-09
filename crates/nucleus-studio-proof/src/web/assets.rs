use super::error;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
pub(super) async fn fetch(url: &str, limit: usize) -> Result<Vec<u8>, JsValue> {
    let options = web_sys::RequestInit::new();
    options.set_credentials(web_sys::RequestCredentials::Omit);
    options.set_redirect(web_sys::RequestRedirect::Error);
    let request = web_sys::Request::new_with_str_and_init(url, &options)?;
    let window = web_sys::window().ok_or_else(|| error("window unavailable"))?;
    let response: web_sys::Response = JsFuture::from(window.fetch_with_request(&request))
        .await?
        .dyn_into()?;
    if !response.ok() {
        return Err(error("A verification resource is unavailable."));
    }
    let reader: web_sys::ReadableStreamDefaultReader = response
        .body()
        .ok_or_else(|| error("Verification resource body missing."))?
        .get_reader()
        .dyn_into()?;
    let mut bytes = Vec::new();
    loop {
        let item = JsFuture::from(reader.read()).await?;
        match js_sys::Reflect::get(&item, &JsValue::from_str("done"))?.as_bool() {
            Some(true) => break,
            Some(false) => {}
            None => return Err(error("Verification resource stream differs.")),
        }
        let chunk: js_sys::Uint8Array =
            js_sys::Reflect::get(&item, &JsValue::from_str("value"))?.dyn_into()?;
        if bytes
            .len()
            .checked_add(chunk.length() as usize)
            .is_none_or(|length| length > limit)
        {
            let _ = reader.cancel();
            return Err(error(
                "Verification resource exceeds its decoded byte budget.",
            ));
        }
        bytes.extend_from_slice(&chunk.to_vec());
    }
    Ok(bytes)
}
pub(super) fn blob(bytes: &[u8], kind: &str) -> Result<String, JsValue> {
    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type(kind);
    web_sys::Url::create_object_url_with_blob(
        &web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &options)?,
    )
}
