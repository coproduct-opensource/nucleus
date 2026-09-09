//! The two APIs the manager drives, behind traits so the reconciler is testable without either.
//!
//! Two properties are load-bearing here and are tested:
//!
//! * **No response body ever reaches a log.** A registration response carries a runner
//!   credential and a machine configuration carries the whole worker environment; an error that
//!   quotes the body puts either into the manager's log, which is the one place they must not be.
//!   [`Error`] can only be built from a status code and a path with its query removed.
//! * **A conditional GET that answers 304 is free.** The forge does not count it against the rate
//!   limit, which is what lets the manager poll every few seconds; the cached body is returned in
//!   its place.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Job, Machine, Runner};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// A status the caller did not expect. Carries no body, on purpose.
    Status {
        method: &'static str,
        path: String,
        code: u16,
    },
    /// The request never got an answer.
    Unreachable { path: String, cause: String },
    /// An answer that did not parse, or that lacked a field the caller needs.
    Malformed { path: String, field: &'static str },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // 422 on a machines route is one thing in practice and it is not obvious from the
            // number: the organization is at its machine cap, so the replacement an update needs
            // cannot be created. The body would say so, but a body may carry a credential and is
            // never printed — so the hint is derived from the status and the path instead.
            Error::Status { method, path, code } if *code == 422 && path.contains("/machines") => {
                write!(
                    f,
                    "{method} {path}: HTTP 422 (usually: the organization is at its machine limit, \
                     so the replacement this update needs cannot be created)"
                )
            }
            Error::Status { method, path, code } => write!(f, "{method} {path}: HTTP {code}"),
            Error::Unreachable { path, cause } => write!(f, "{path}: unreachable: {cause}"),
            Error::Malformed { path, field } => write!(f, "{path}: no {field} in the answer"),
        }
    }
}

impl Error {
    /// The substrate refused because the organization is at its machine cap. This is the live
    /// path REFUTING the declared budget: a deployment that passed its startup check is asking
    /// for a machine the substrate will not give it, so the declaration is wrong, whatever it
    /// says. Recognised by status and path — the body would say so plainly but may carry a
    /// credential and is never read.
    pub fn is_at_capacity(&self) -> bool {
        matches!(self, Error::Status { code: 422, path, .. } if path.contains("/machines"))
    }
}

impl std::error::Error for Error {}

/// A path with its query string removed: a query can name a run or a runner, and those end up in
/// log lines that are read by people who are not the tenant.
fn bare(path: &str) -> String {
    path.split('?').next().unwrap_or(path).to_string()
}

pub struct Response {
    pub status: u16,
    pub etag: Option<String>,
    pub body: String,
}

/// One HTTP call. The only thing a test has to fake to exercise the client, cache included.
pub trait Transport: Send + Sync {
    fn call(
        &self,
        method: &'static str,
        url: &str,
        token: &str,
        if_none_match: Option<&str>,
        body: Option<&str>,
    ) -> Result<Response, String>;
}

pub struct Ureq {
    agent: ureq::Agent,
}

impl Default for Ureq {
    fn default() -> Self {
        Self {
            // A 4xx must arrive as a response, not as a transport error: the manager decides what
            // a status means (a 304 is a hit, a 404 on a delete is success) and never reads the
            // body it would otherwise have to unwrap to find out.
            agent: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into(),
        }
    }
}

impl Transport for Ureq {
    fn call(
        &self,
        method: &'static str,
        url: &str,
        token: &str,
        if_none_match: Option<&str>,
        body: Option<&str>,
    ) -> Result<Response, String> {
        let mut response = match method {
            "GET" => {
                let mut request = self
                    .agent
                    .get(url)
                    .header("Authorization", &format!("Bearer {token}"))
                    .header("Accept", "application/json")
                    .header("User-Agent", "nucleus-fly-runner-manager");
                if let Some(etag) = if_none_match {
                    request = request.header("If-None-Match", etag);
                }
                request.call()
            }
            "DELETE" => self
                .agent
                .delete(url)
                .header("Authorization", &format!("Bearer {token}"))
                .header("Accept", "application/json")
                .header("User-Agent", "nucleus-fly-runner-manager")
                .call(),
            _ => self
                .agent
                .post(url)
                .header("Authorization", &format!("Bearer {token}"))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("User-Agent", "nucleus-fly-runner-manager")
                .send(body.unwrap_or("")),
        }
        .map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = response.body_mut().read_to_string().unwrap_or_default();
        Ok(Response { status, etag, body })
    }
}

/// A JSON client over one base URL and one token, with the conditional-request cache.
pub struct Client<T: Transport> {
    transport: T,
    base: String,
    token: String,
    cache: Mutex<BTreeMap<String, (String, String)>>,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T, base: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            transport,
            base: base.into(),
            token: token.into(),
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    fn send(
        &self,
        method: &'static str,
        path: &str,
        body: Option<&Value>,
        conditional: bool,
    ) -> Result<Value, Error> {
        let url = format!("{}{path}", self.base);
        let rendered = body.map(|b| b.to_string());
        let cached = if conditional {
            self.cache
                .lock()
                .ok()
                .and_then(|c| c.get(&url).map(|(etag, body)| (etag.clone(), body.clone())))
        } else {
            None
        };
        let response = self
            .transport
            .call(
                method,
                &url,
                &self.token,
                cached.as_ref().map(|(etag, _)| etag.as_str()),
                rendered.as_deref(),
            )
            .map_err(|cause| Error::Unreachable {
                path: bare(path),
                cause,
            })?;
        if response.status == 304 {
            if let Some((_, body)) = cached {
                return Ok(serde_json::from_str(&body).unwrap_or(Value::Null));
            }
        }
        if !(200..300).contains(&response.status) {
            return Err(Error::Status {
                method,
                path: bare(path),
                code: response.status,
            });
        }
        if conditional
            && let Some(etag) = response.etag
            && let Ok(mut cache) = self.cache.lock()
        {
            cache.insert(url, (etag, response.body.clone()));
        }
        if response.body.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&response.body).map_err(|_| Error::Malformed {
            path: bare(path),
            field: "JSON",
        })
    }
}

// ── The forge: queued work, runner registrations ────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Run {
    pub id: u64,
    #[serde(default)]
    pub created_at: String,
}

pub struct Registration {
    pub id: u64,
    pub encoded: String,
}

pub trait Forge {
    /// Runs that are queued or in progress, newest first, at most `limit` of them.
    fn active_runs(&self, limit: usize) -> Result<Vec<Run>, Error>;
    fn jobs(&self, run: u64) -> Result<Vec<Job>, Error>;
    fn runners(&self) -> Result<Vec<Runner>, Error>;
    /// One job's runner registration: the forge removes it the moment its single job completes.
    fn register(&self, label: &str, name: &str) -> Result<Registration, Error>;
    fn remove_runner(&self, id: u64) -> Result<(), Error>;
}

pub struct ForgeApi<T: Transport> {
    client: Client<T>,
    repo: String,
}

impl<T: Transport> ForgeApi<T> {
    pub fn new(transport: T, base: &str, token: &str, repo: &str) -> Self {
        Self {
            client: Client::new(transport, base.to_string(), token.to_string()),
            repo: repo.to_string(),
        }
    }

    fn path(&self, tail: &str) -> String {
        format!("/repos/{}/{tail}", self.repo)
    }
}

impl<T: Transport> Forge for ForgeApi<T> {
    fn active_runs(&self, limit: usize) -> Result<Vec<Run>, Error> {
        let mut runs: Vec<Run> = Vec::new();
        for status in ["queued", "in_progress"] {
            let path = self.path(&format!("actions/runs?status={status}&per_page={limit}"));
            let page = self.client.send("GET", &path, None, true)?;
            let listed: Vec<Run> =
                serde_json::from_value(page.get("workflow_runs").cloned().unwrap_or(json!([])))
                    .map_err(|_| Error::Malformed {
                        path: bare(&path),
                        field: "workflow_runs",
                    })?;
            runs.extend(listed);
        }
        runs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        runs.truncate(limit);
        Ok(runs)
    }

    fn jobs(&self, run: u64) -> Result<Vec<Job>, Error> {
        let path = self.path(&format!(
            "actions/runs/{run}/jobs?filter=latest&per_page=100"
        ));
        let page = self.client.send("GET", &path, None, true)?;
        serde_json::from_value(page.get("jobs").cloned().unwrap_or(json!([]))).map_err(|_| {
            Error::Malformed {
                path: bare(&path),
                field: "jobs",
            }
        })
    }

    fn runners(&self) -> Result<Vec<Runner>, Error> {
        let path = self.path("actions/runners?per_page=100");
        let page = self.client.send("GET", &path, None, true)?;
        serde_json::from_value(page.get("runners").cloned().unwrap_or(json!([]))).map_err(|_| {
            Error::Malformed {
                path: bare(&path),
                field: "runners",
            }
        })
    }

    fn register(&self, label: &str, name: &str) -> Result<Registration, Error> {
        let path = self.path("actions/runners/generate-jitconfig");
        let body = json!({
            "name": name,
            "runner_group_id": 1,
            "labels": ["self-hosted", "Linux", "X64", label],
            "work_folder": "_work",
        });
        let answer = self.client.send("POST", &path, Some(&body), false)?;
        let id = answer
            .pointer("/runner/id")
            .and_then(Value::as_u64)
            .ok_or(Error::Malformed {
                path: bare(&path),
                field: "runner id",
            })?;
        let encoded = answer
            .get("encoded_jit_config")
            .and_then(Value::as_str)
            .ok_or(Error::Malformed {
                path: bare(&path),
                field: "registration",
            })?
            .to_string();
        Ok(Registration { id, encoded })
    }

    fn remove_runner(&self, id: u64) -> Result<(), Error> {
        let path = self.path(&format!("actions/runners/{id}"));
        match self.client.send("DELETE", &path, None, false) {
            Ok(_) => Ok(()),
            // Already gone is the outcome asked for.
            Err(Error::Status { code: 404, .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

// ── The substrate: the machines that run the jobs ───────────────────────────────────────────

pub trait Substrate {
    fn machines(&self) -> Result<Vec<Machine>, Error>;
    /// Created stopped (`skip_launch`), so the caller decides when the first boot happens.
    fn create(&self, name: &str, region: &str, config: &Value) -> Result<Machine, Error>;
    fn update(&self, id: &str, config: &Value) -> Result<(), Error>;
    /// Block until the machine reaches `state`. An update rewrites the machine — the events read
    /// `launch pending`, `launch created`, `update stopped` — and a start issued before it has
    /// settled is answered 412, which is how the first live jobs were lost.
    fn wait_for(&self, id: &str, state: &str, timeout_s: u64) -> Result<(), Error>;
    fn start(&self, id: &str) -> Result<(), Error>;
    fn destroy(&self, id: &str) -> Result<(), Error>;
}

pub struct MachinesApi<T: Transport> {
    client: Client<T>,
    app: String,
}

impl<T: Transport> MachinesApi<T> {
    pub fn new(transport: T, base: &str, token: &str, app: &str) -> Self {
        Self {
            client: Client::new(transport, base.to_string(), token.to_string()),
            app: app.to_string(),
        }
    }

    fn path(&self, tail: &str) -> String {
        format!("/apps/{}/{tail}", self.app)
    }
}

impl<T: Transport> Substrate for MachinesApi<T> {
    fn machines(&self) -> Result<Vec<Machine>, Error> {
        let path = self.path("machines");
        let answer = self.client.send("GET", &path, None, false)?;
        serde_json::from_value(answer).map_err(|_| Error::Malformed {
            path: bare(&path),
            field: "machines",
        })
    }

    fn create(&self, name: &str, region: &str, config: &Value) -> Result<Machine, Error> {
        let path = self.path("machines");
        let body = json!({
            "name": name, "region": region, "skip_launch": true, "config": config,
        });
        let answer = self.client.send("POST", &path, Some(&body), false)?;
        serde_json::from_value(answer).map_err(|_| Error::Malformed {
            path: bare(&path),
            field: "machine",
        })
    }

    fn update(&self, id: &str, config: &Value) -> Result<(), Error> {
        let path = self.path(&format!("machines/{id}"));
        self.client
            .send("POST", &path, Some(&json!({"config": config})), false)
            .map(|_| ())
    }

    fn wait_for(&self, id: &str, state: &str, timeout_s: u64) -> Result<(), Error> {
        let path = self.path(&format!(
            "machines/{id}/wait?state={state}&timeout={timeout_s}"
        ));
        self.client.send("GET", &path, None, false).map(|_| ())
    }

    fn start(&self, id: &str) -> Result<(), Error> {
        let path = self.path(&format!("machines/{id}/start"));
        self.client.send("POST", &path, None, false).map(|_| ())
    }

    fn destroy(&self, id: &str) -> Result<(), Error> {
        let path = self.path(&format!("machines/{id}?force=true"));
        match self.client.send("DELETE", &path, None, false) {
            Ok(_) => Ok(()),
            Err(Error::Status { code: 404, .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Scripted {
        answers: Vec<Response>,
        calls: AtomicUsize,
        seen_conditional: Mutex<Vec<Option<String>>>,
    }

    impl Transport for Scripted {
        fn call(
            &self,
            _method: &'static str,
            _url: &str,
            _token: &str,
            if_none_match: Option<&str>,
            _body: Option<&str>,
        ) -> Result<Response, String> {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen_conditional
                .lock()
                .unwrap()
                .push(if_none_match.map(str::to_string));
            let answer = &self.answers[index.min(self.answers.len() - 1)];
            Ok(Response {
                status: answer.status,
                etag: answer.etag.clone(),
                body: answer.body.clone(),
            })
        }
    }

    fn scripted(answers: Vec<Response>) -> Client<Scripted> {
        Client::new(
            Scripted {
                answers,
                calls: AtomicUsize::new(0),
                seen_conditional: Mutex::new(Vec::new()),
            },
            "https://example.invalid",
            "token",
        )
    }

    #[test]
    fn a_304_reuses_the_cached_body_and_asks_with_the_etag_it_was_given() {
        let client = scripted(vec![
            Response {
                status: 200,
                etag: Some("\"v1\"".into()),
                body: r#"{"runners":[{"id":1,"name":"a","status":"online","busy":false}]}"#.into(),
            },
            Response {
                status: 304,
                etag: None,
                body: String::new(),
            },
        ]);
        let first = client.send("GET", "/x", None, true).unwrap();
        let second = client.send("GET", "/x", None, true).unwrap();
        assert_eq!(first, second);
        assert_eq!(second["runners"][0]["id"], 1);
        let asked = client.transport.seen_conditional.lock().unwrap().clone();
        assert_eq!(asked, vec![None, Some("\"v1\"".to_string())]);
    }

    #[test]
    fn a_304_without_anything_cached_is_a_status_not_a_silent_empty_answer() {
        // The alternative — returning null — reads as "no queued jobs" and stalls the pool.
        let client = scripted(vec![Response {
            status: 304,
            etag: None,
            body: String::new(),
        }]);
        assert_eq!(
            client.send("GET", "/x", None, true),
            Err(Error::Status {
                method: "GET",
                path: "/x".into(),
                code: 304
            })
        );
    }

    #[test]
    fn an_error_carries_a_status_and_a_bare_path_and_never_the_body() {
        let client = scripted(vec![Response {
            status: 422,
            etag: None,
            body: r#"{"encoded_jit_config":"SUPER-SECRET-CREDENTIAL"}"#.into(),
        }]);
        let error = client
            .send(
                "POST",
                "/repos/o/r/actions/runners/9?token=abc",
                None,
                false,
            )
            .unwrap_err();
        let rendered = format!("{error}");
        assert!(!rendered.contains("SUPER-SECRET-CREDENTIAL"), "{rendered}");
        assert!(!rendered.contains("abc"), "{rendered}");
        assert_eq!(rendered, "POST /repos/o/r/actions/runners/9: HTTP 422");
    }

    #[test]
    fn a_registration_is_read_from_the_answer_and_a_missing_one_is_not_a_launch() {
        let forge = ForgeApi::new(
            Scripted {
                answers: vec![Response {
                    status: 200,
                    etag: None,
                    body: r#"{"runner":{"id":42},"encoded_jit_config":"BLOB"}"#.into(),
                }],
                calls: AtomicUsize::new(0),
                seen_conditional: Mutex::new(Vec::new()),
            },
            "https://example.invalid",
            "token",
            "o/r",
        );
        let registration = forge.register("p", "p-0-1").unwrap();
        assert_eq!(registration.id, 42);
        assert_eq!(registration.encoded, "BLOB");

        let empty = ForgeApi::new(
            Scripted {
                answers: vec![Response {
                    status: 200,
                    etag: None,
                    body: r#"{"runner":{}}"#.into(),
                }],
                calls: AtomicUsize::new(0),
                seen_conditional: Mutex::new(Vec::new()),
            },
            "https://example.invalid",
            "token",
            "o/r",
        );
        assert!(matches!(
            empty.register("p", "p-0-1"),
            Err(Error::Malformed { .. })
        ));
    }
}
