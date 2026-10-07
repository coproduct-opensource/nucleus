use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    process::{Child, Command},
    task::JoinHandle,
};

pub(crate) async fn command(path: PathBuf, args: &[OsString]) -> Result<Vec<u8>> {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new(&path).args(args).kill_on_drop(true).output(),
    )
    .await??;
    ensure!(
        output.status.success(),
        "{} failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

#[derive(Clone)]
struct Fixture {
    nonce: String,
    token: String,
    calls: Arc<AtomicUsize>,
}

async fn echo(State(f): State<Fixture>, headers: HeaderMap, body: String) -> (StatusCode, String) {
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(f.token.as_str())
        || body != f.nonce
    {
        return (StatusCode::BAD_REQUEST, "fixture request mismatch".into());
    }
    f.calls.fetch_add(1, Ordering::SeqCst);
    (StatusCode::OK, body)
}

pub(crate) struct Node {
    pub state: PathBuf,
    pub upstream: String,
    pub url: String,
    pub client: reqwest::Client,
    pub calls: Arc<AtomicUsize>,
    child: Child,
    server: JoinHandle<std::io::Result<()>>,
    /// Everything needed to start the SAME node again: one state dir, one jail base, one port.
    launch: Launch,
    /// Which life of the node this is: 0 for the first, +1 per [`Node::restart`].
    life: usize,
    _directory: tempfile::TempDir,
}

/// The node's command line and environment, kept so a restart is the same node in a new life.
struct Launch {
    node_bin: PathBuf,
    extra: Vec<String>,
    env: Vec<(&'static str, String)>,
    state: PathBuf,
    address: std::net::SocketAddr,
    registry: PathBuf,
    jail_base: PathBuf,
}

impl Launch {
    fn spawn(&self, log_path: &Path) -> Result<Child> {
        let log = std::fs::File::create(log_path)?;
        let mut command = Command::new(&self.node_bin);
        command.env_clear().env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        );
        for (key, value) in &self.env {
            command.env(key, value);
        }
        Ok(command
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--listen")
            .arg(self.address.to_string())
            .arg("--driver")
            .arg("firecracker")
            .arg("--firecracker-path")
            .arg("/usr/local/bin/firecracker")
            .arg("--jailer-path")
            .arg("/usr/local/bin/jailer")
            .arg("--broker-enforcing")
            .arg("--upstreams")
            .arg(&self.registry)
            .arg("--jailer-chroot-base")
            .arg(&self.jail_base)
            .args(&self.extra)
            .stdout(log.try_clone()?)
            .stderr(log)
            .kill_on_drop(true)
            .spawn()?)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Node {
    pub fn diagnostics(&self) -> String {
        let mut text = match self.log() {
            Ok(s) => s,
            Err(e) => format!("could not read fixture node log: {e}"),
        };
        if let Ok(pods) = std::fs::read_dir(self.state.join("pods")) {
            for pod in pods.flatten() {
                for name in [
                    "firecracker.log",
                    nucleus_spec::host_effect::LOG_FILE,
                    nucleus_spec::host_effect::outcome::LOG_FILE,
                ] {
                    if let Ok(log) = std::fs::read_to_string(pod.path().join(name)) {
                        text.push_str(&format!("\n{name}:\n{log}"));
                    }
                }
            }
        }
        text.push_str(&format!(
            "\nAuthenticated fixture calls: {}\n",
            self.calls.load(Ordering::SeqCst)
        ));
        text
    }
    pub async fn start(bins: &Path, nonce: &str) -> Result<Self> {
        Self::start_with(&bins.join("nucleus-node"), nonce, &[]).await
    }

    /// The running node's process id, for measuring what actually executes.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// The fixture node log, as written so far.
    pub fn log(&self) -> std::io::Result<String> {
        std::fs::read_to_string(self.log_path())
    }

    /// Start `node_bin` (e.g. the installed `/usr/local/bin/nucleus-node`),
    /// with `extra` arguments appended after the fixture's own.
    pub async fn start_with(node_bin: &Path, nonce: &str, extra: &[String]) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("he")
            .tempdir_in("/var/tmp")?;
        let state = directory.path().join("state");
        std::fs::create_dir(&state)?;
        let ca =
            nucleus_identity::SelfSignedCa::load_or_create("nucleus.local", &state.join("ca"))?;
        let identity = directory.path().join("identity");
        crate::provision::mint_cli_identity(&ca, "nucleus.local", &identity).await?;
        let client = crate::provision::mtls_client_from_identity_dir(&identity)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let upstream = format!("http://{}", listener.local_addr()?);
        let token = uuid::Uuid::new_v4().to_string();
        let calls = Arc::new(AtomicUsize::new(0));
        let fixture = Fixture {
            nonce: nonce.into(),
            token: format!("Bearer {token}"),
            calls: calls.clone(),
        };
        let registry = directory.path().join("upstreams.toml");
        let charge = super::CALL_CHARGE;
        std::fs::write(
            &registry,
            format!(
                "[[upstream]]\nname = 'receipt-fixture'\nbase_url = '{upstream}'\nheader = 'authorization'\nvalue_prefix = 'Bearer '\ncall_charge_micro_usd = {charge}\n[upstream.credential.env]\nvar = 'NUCLEUS_RECEIPT_FIXTURE_TOKEN'\n"
            ),
        )?;
        let reserved = TcpListener::bind("127.0.0.1:0").await?;
        let address = reserved.local_addr()?;
        drop(reserved); // A collision fails node startup rather than selecting another service.
        let launch = Launch {
            node_bin: node_bin.to_path_buf(),
            extra: extra.to_vec(),
            env: vec![
                ("RUST_LOG", "info".into()),
                ("NUCLEUS_RECEIPT_FIXTURE_TOKEN", token),
                (
                    "NUCLEUS_NODE_PROXY_AUTH_SECRET",
                    uuid::Uuid::new_v4().to_string(),
                ),
                (
                    "NUCLEUS_NODE_PROXY_APPROVAL_SECRET",
                    uuid::Uuid::new_v4().to_string(),
                ),
            ],
            state: state.clone(),
            address,
            registry,
            jail_base: directory.path().join("j"),
        };
        let log_path = directory.path().join("node.log");
        let child = launch.spawn(&log_path)?;
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/echo", post(echo)).with_state(fixture),
            )
            .await
        });
        let mut node = Self {
            state,
            upstream,
            url: format!("https://{address}"),
            client,
            calls,
            child,
            server,
            launch,
            life: 0,
            _directory: directory,
        };
        node.ready().await?;
        Ok(node)
    }

    /// Wait for `/v1/health`, or fail with the node's log if it exits or never answers.
    async fn ready(&mut self) -> Result<()> {
        let node = self;
        let ready = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                ensure!(
                    node.child.try_wait()?.is_none(),
                    "fixture node exited before readiness"
                );
                if let Ok(r) = node
                    .client
                    .get(format!("{}/v1/health", node.url))
                    .send()
                    .await
                {
                    if r.status().is_success() {
                        return Ok::<_, anyhow::Error>(());
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("fixture node readiness timed out")
        .and_then(|r| r);
        if let Err(e) = ready {
            let log = node.log()?;
            node.stop().await?;
            return Err(e.context(log));
        }
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.server.abort();
        self.child.kill().await.context("stopping fixture node")?;
        Ok(())
    }

    /// The jailer's chroot base this node (in every life) places pods under.
    pub fn jail_base(&self) -> &Path {
        &self.launch.jail_base
    }

    /// Send `signal` (a `kill -s` name: `TERM`, `KILL`) to the node and wait for it to exit.
    pub async fn signal(
        &mut self,
        signal: &str,
        within: Duration,
    ) -> Result<std::process::ExitStatus> {
        let pid = self.child.id().context("the node has already exited")?;
        command(
            PathBuf::from("/bin/kill"),
            &["-s".into(), signal.into(), pid.to_string().into()],
        )
        .await?;
        tokio::time::timeout(within, self.child.wait())
            .await
            .with_context(|| format!("the node did not exit within {within:?} of SIG{signal}"))?
            .context("waiting for the node")
    }

    /// Start the same node again, on the same state directory, jail base and port.
    pub async fn restart(&mut self) -> Result<()> {
        ensure!(
            self.child.try_wait()?.is_some(),
            "restart needs the previous life to have exited"
        );
        self.life += 1;
        let log_path = self.log_path();
        self.child = self.launch.spawn(&log_path)?;
        self.ready().await
    }

    fn log_path(&self) -> PathBuf {
        match self.life {
            0 => self._directory.path().join("node.log"),
            n => self._directory.path().join(format!("node.{n}.log")),
        }
    }
}
