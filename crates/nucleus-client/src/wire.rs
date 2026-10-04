//! The tool-proxy's file and command wire format, declared once.
//!
//! # Why this module exists
//!
//! Each client of the tool-proxy used to declare these bodies itself, and nothing
//! compared the copies with the server's. Measured 2026-09-29 by a containment
//! test run through `nucleus shell`:
//!
//! * `nucleus-mcp` sent `/v1/run` a `{"command": "<string>"}` body. The proxy has
//!   required `{"args": [...]}` since the array form replaced shell strings, so
//!   every `run` through the MCP bridge was rejected with a 422 before any
//!   decision was made. The agent's shell tool did not work at all in
//!   `nucleus shell` or enforced `nucleus run`.
//! * `nucleus-sdk` read `exit_code` from the reply. The proxy sends `status`, so
//!   every SDK caller saw an exit code of -1. Its own test mocked the reply with
//!   `"exit_code": 0` and so passed, restating the defect instead of catching it.
//!
//! Two declarations of one fact, and a parity test would only have converted the
//! next drift into a failure (ADR 0007 G). One declaration, used by the server
//! and by every client, makes the drift unwritable: the proxy deserializes the
//! same type the clients serialize.

use serde::{Deserialize, Serialize};

/// `POST /v1/read`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadRequest {
    /// Path to read, relative to the sandbox root.
    pub path: String,
}

/// Reply to `POST /v1/read`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResponse {
    /// The file's contents.
    pub contents: String,
}

/// `POST /v1/write`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    /// Path to write, relative to the sandbox root.
    pub path: String,
    /// The contents to write.
    pub contents: String,
}

/// Reply to `POST /v1/write`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResponse {
    /// Whether the write happened.
    pub ok: bool,
}

/// `POST /v1/run`, in the array form.
///
/// The array form prevents shell injection: the proxy executes the program
/// directly, each element one argument, with no shell interpreting the line. A
/// client holding a command STRING splits it into words first and gets no
/// pipes, redirections or `&&` -- that is the point, not a limitation to route
/// around.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequest {
    /// Program and arguments, e.g. `["ls", "-la", "/tmp"]`.
    pub args: Vec<String>,
    /// Input to pass to the command's stdin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    /// Working directory, relative to the sandbox root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    /// Requested timeout in seconds; the proxy clamps it to the policy limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

impl RunRequest {
    /// A request for `args` with no stdin, directory or timeout.
    #[must_use]
    pub fn new(args: Vec<String>) -> Self {
        Self {
            args,
            stdin: None,
            directory: None,
            timeout_seconds: None,
        }
    }
}

/// Reply to `POST /v1/run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    /// Exit status; -1 when the process was killed by a signal.
    pub status: i32,
    /// Whether the command exited successfully.
    pub success: bool,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_request_is_the_array_form() {
        let v = serde_json::to_value(RunRequest::new(vec!["ls".into(), "-la".into()])).unwrap();
        assert_eq!(v, serde_json::json!({ "args": ["ls", "-la"] }));
    }

    /// The shape `nucleus-mcp` used to send. The proxy must refuse it, not read
    /// it as an empty command.
    #[test]
    fn the_retired_string_form_does_not_parse() {
        let old = serde_json::json!({ "command": "ls -la" });
        assert!(serde_json::from_value::<RunRequest>(old).is_err());
    }

    #[test]
    fn a_run_reply_carries_status_not_exit_code() {
        let v = serde_json::to_value(RunResponse {
            status: 3,
            success: false,
            stdout: String::new(),
            stderr: String::new(),
        })
        .unwrap();
        assert_eq!(v["status"], 3);
        assert!(v.get("exit_code").is_none());
    }
}
