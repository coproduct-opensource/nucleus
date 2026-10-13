//! `container_broker`'s tests (#2906). Each was driven red on the defect it
//! names; the PR body records how.

use super::*;

fn spec(inner: &str) -> PodSpec {
    serde_json::from_str(&format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{inner}}}"#
    ))
    .expect("test spec parses")
}

fn upstream_spec() -> nucleus_spec::CredentialedEgressSpec {
    nucleus_spec::CredentialedEgressSpec {
        name: "model-api".into(),
        upstream: "https://upstream.invalid/v1".into(),
        credential_env: "LLM_API_TOKEN".into(),
        header: "authorization".into(),
        value_prefix: "Bearer ".into(),
        effects: nucleus_spec::EffectTable::unclassified(),
    }
}

/// The container's tool-proxy and the node name ONE socket: the host binds the
/// pod directory's copy, and the container sees it through the bind mount.
#[test]
fn the_host_and_the_container_name_the_same_socket() {
    let pod_dir = Path::new("/var/lib/nucleus/pods/abc");
    let host = crate::guest_socket::listener_path(
        &host_socket_base(pod_dir),
        nucleus_ifc_kernel::VsockListener::CredentialBroker,
    );
    let inside = container_socket_path();
    assert_eq!(
        host.strip_prefix(pod_dir).expect("under the pod directory"),
        inside
            .strip_prefix("/data/pod")
            .expect("under the pod directory's mount"),
    );
    assert!(inside.starts_with(CONTAINER_BROKER_DIR));
    // Its own directory, which `prepare_socket` makes 0700: never the pod
    // directory itself, which the proxy must write.
    assert_ne!(host.parent(), Some(pod_dir));
}

/// Only the task runner survives on a container spec; every credential key is
/// named in the refusal.
#[test]
fn only_the_task_runner_is_admitted() {
    assert!(refuse_spec_credentials(&spec("{}")).is_ok());
    assert!(refuse_spec_credentials(&spec(r#"{"credentials":{"env":{}}}"#)).is_ok());
    assert!(
        refuse_spec_credentials(&spec(
            r#"{"credentials":{"env":{"NUCLEUS_TASK_CMD":"run"}}}"#
        ))
        .is_ok()
    );
    let Err(PostureRefused::ContainerCredentials { keys }) = refuse_spec_credentials(&spec(
        r#"{"credentials":{"env":{"LLM_API_TOKEN":"test-token-123","NUCLEUS_TASK_CMD":"run"}}}"#,
    )) else {
        panic!("a credential value on a container pod must be refused");
    };
    assert_eq!(keys, "LLM_API_TOKEN");
}

/// An image whose release predates the socket is refused by name for a pod
/// that needs it, and only for such a pod. Every published release lacks it
/// (the row is unreleased), so the published 2.7.0 image is the red case.
#[test]
fn an_image_without_the_socket_is_refused_for_credentialed_egress_alone() {
    let mut needs = spec("{}");
    needs.spec.credentialed_egress = vec![upstream_spec()];
    let refusal = admit_image("ghcr.io/x/nucleus-tool-proxy:2.7.0", Some("2.7.0"), &needs)
        .expect_err("2.7.0 has no container broker socket")
        .to_string();
    for needle in [
        "ContainerBrokerSocket",
        "#2906",
        "2.7.0",
        "credentialed_egress",
    ] {
        assert!(
            refusal.contains(needle),
            "{needle:?} missing from: {refusal}"
        );
    }
    // Cannot tell: launched, and an old proxy refuses at startup by name.
    assert!(admit_image("img", None, &needs).is_ok());
    assert!(admit_image("img", Some("main"), &needs).is_ok());
    // A pod with no upstream never needs the socket.
    assert!(admit_image("img", Some("2.7.0"), &spec("{}")).is_ok());
}

/// #2906's pin, the successor to `only_the_container_driver_injects_credential_values`
/// (removed in #3184): **no driver puts a credential value in a workload's
/// environment.** Checked against the functions that build what each driver
/// delivers, not against source text:
///
/// - the container driver's environment (`container_env`), mediated and
///   unmediated, for a spec that carries a credential — the defect: on main
///   both copied `credentials.env` into the container verbatim;
/// - the spec a Firecracker guest is served under enforcement
///   (`cred_split::guest_spec_yaml`), which carries the names and no value.
///
/// The local and Apple VZ drivers never read `credentials.env` at all, so
/// there is no function of theirs to call; `spec_posture::admit` is where a
/// container spec carrying a value is refused before any of this runs.
#[cfg(feature = "local-driver")]
#[tokio::test]
async fn no_driver_injects_credential_values() {
    const VALUE: &str = "test-token-123";
    let dir = tempfile::tempdir().expect("tempdir");
    let state = crate::pod_api::handler_tests::state(&dir);
    let carrying = spec(&format!(
        r#"{{"credentials":{{"env":{{"LLM_API_TOKEN":"{VALUE}","NUCLEUS_TASK_CMD":"run"}}}}}}"#
    ));
    let id = Uuid::new_v4();

    for mediation in [
        crate::container_mediation::ContainerMediation::ToolProxy,
        crate::container_mediation::ContainerMediation::Unmediated,
    ] {
        let mut state = state.clone();
        state.container_mediation = mediation;
        let env =
            crate::container_env::container_env(&state, &carrying, id, "", None, None).await;
        assert!(
            !env.iter().any(|e| e.contains(VALUE)),
            "{mediation:?}: a credential value reached the container's environment"
        );
        // Non-vacuity: the unmediated node still runs the orchestrator's task
        // runner, which is a command, not a credential.
        assert_eq!(
            env.iter().any(|e| e == "NUCLEUS_TASK_CMD=run"),
            !mediation.runs_tool_proxy(),
            "{mediation:?}"
        );
    }

    let (served, withheld) =
        crate::cred_split::guest_spec_yaml(&carrying, true).expect("serialises");
    assert!(withheld.is_some());
    assert!(served.contains("LLM_API_TOKEN") && !served.contains(VALUE));
}

#[cfg(feature = "local-driver")]
mod live {
    //! The broker a container pod is given, served for real: a Unix socket, the
    //! kernel's peer credentials, the shared decider, a real HTTP call to an
    //! upstream the node holds the credential for.

    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "test-token-123";

    struct Pod {
        _dir: tempfile::TempDir,
        state: crate::NodeState,
        spec: PodSpec,
        id: Uuid,
        pod_dir: PathBuf,
    }

    /// A container node with one upstream in its registry, whose credential is
    /// in the node's environment under `var`.
    fn node(upstream: &MockServer, var: &str) -> (tempfile::TempDir, crate::NodeState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = dir.path().join("upstreams.toml");
        std::fs::write(
            &registry,
            format!(
                "[[upstream]]\nname = \"model-api\"\nbase_url = \"{}/v1\"\nheader = \
                 \"authorization\"\nvalue_prefix = \"Bearer \"\ncall_charge_micro_usd = 0\n\
                 credential.env.var = \"{var}\"\n",
                upstream.uri()
            ),
        )
        .expect("registry");
        let mut state = crate::pod_api::handler_tests::state(&dir);
        let args = <crate::Args as clap::Parser>::parse_from([
            "nucleus-node",
            "--state-dir",
            dir.path().to_str().expect("utf-8"),
            "--driver",
            "container",
            "--proxy-auth-secret",
            "a",
            "--proxy-approval-secret",
            "b",
            "--upstreams",
            registry.to_str().expect("utf-8"),
        ]);
        state.authority = std::sync::Arc::new(
            crate::pod_authority::PodAuthority::from_args(&args).expect("authority"),
        );
        state.identity_manager = Some(
            crate::identity::IdentityManager::new(
                "nucleus.local",
                std::time::Duration::from_secs(3600),
            )
            .expect("identity manager"),
        );
        (dir, state)
    }

    /// A pod spec under a permissive policy, holding the node's one upstream
    /// when `declare`.
    fn pod_spec(state: &crate::NodeState, declare: bool) -> PodSpec {
        let mut spec = spec("{}");
        spec.spec.policy = nucleus_spec::PolicySpec::Inline {
            lattice: Box::new(portcullis::PermissionLattice::permissive()),
        };
        if declare {
            spec.spec.credentialed_egress = state
                .authority
                .upstream_registry()
                .expect("registry loaded")
                .entries()
                .to_vec();
        }
        spec
    }

    /// [`node`], and one admitted pod on it.
    async fn pod(upstream: &MockServer, var: &str, declare: bool) -> Pod {
        let (dir, state) = node(upstream, var);
        let spec = pod_spec(&state, declare);
        let id = Uuid::new_v4();
        let root = crate::pod_authority::Admission {
            caller_spiffe_id: state.authority.root_minter().to_string(),
            caller_pod: None,
            header_cert: None,
        };
        state
            .authority
            .admit_kept(&root, &spec, id)
            .await
            .expect("the root minter admits the pod");
        let pod_dir = dir.path().join("pods").join(id.to_string());
        std::fs::create_dir_all(&pod_dir).expect("pod dir");
        Pod {
            _dir: dir,
            state,
            spec,
            id,
            pod_dir,
        }
    }

    fn set(var: &str) {
        // SAFETY: edition 2024 makes env mutation unsafe -- it races any
        // concurrent reader. Each test here owns its variable's name.
        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 H-1: test-only process-global mutation"
        )]
        unsafe {
            std::env::set_var(var, TOKEN)
        };
    }

    fn secret_of(env: &[String]) -> String {
        env.iter()
            .find_map(|e| e.strip_prefix("NUCLEUS_TOOL_PROXY_BROKER_SECRET="))
            .expect("the proxy is told its capability")
            .to_string()
    }

    fn host_socket(pod_dir: &Path) -> PathBuf {
        crate::guest_socket::listener_path(
            &host_socket_base(pod_dir),
            nucleus_ifc_kernel::VsockListener::CredentialBroker,
        )
    }

    /// One signed perform frame, as the container's tool-proxy would send it.
    fn perform_frame(secret: &str, target: &str) -> String {
        let payload = serde_json::json!({
            "operation": "WebFetch",
            "target": target,
            "justification": "routine",
            "idempotency_key": Uuid::new_v4().to_string(),
            "path": "/complete",
            "body": b"{\"prompt\":\"hi\"}".to_vec(),
        })
        .to_string();
        nucleus_cred_protocol::frame::sign(secret.as_bytes(), &payload)
    }

    /// Ask the broker over its socket from this process.
    async fn perform(socket: &Path, secret: &str, target: &str) -> String {
        crate::broker_transport::request_over_socket(socket, &perform_frame(secret, target))
            .await
            .expect("the broker answers")
    }

    /// **The property.** A container pod's proxy reaches its admitted upstream
    /// through the host, the upstream receives the credential, and the
    /// credential is in nothing the container is given: not its environment,
    /// not the reply. Red on main: no broker was served for a container pod
    /// (`prepare` did not exist; `decide_rollout` had no container transport in
    /// use), and the value was in the container's environment instead.
    #[tokio::test]
    async fn a_container_pod_reaches_its_upstream_through_the_host() {
        let var = "NUCLEUS_TEST_CONTAINER_BROKER_LIVE";
        set(var);
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/complete"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
            .expect(1)
            .mount(&upstream)
            .await;
        let pod = pod(&upstream, var, true).await;
        let prepared = prepare(&pod.state, &pod.spec, &pod.pod_dir, pod.id)
            .await
            .expect("prepares")
            .expect("a pod with an upstream is served");
        let env = prepared.env().to_vec();
        assert!(
            !env.iter().any(|e| e.contains(TOKEN)),
            "the credential reached the container: {env:?}"
        );
        assert!(env.contains(&format!(
            "NUCLEUS_TOOL_PROXY_BROKER_SOCKET={}",
            container_socket_path().display()
        )));
        let secret = secret_of(&env);
        // This test process plays the container's init.
        let listener = prepared.arm(std::process::id()).expect("armed in time");
        let socket = host_socket(&pod.pod_dir);
        assert_eq!(listener.socket_path(), socket);

        let reply = perform(&socket, &secret, "model-api").await;
        assert!(reply.contains("\"granted\":true"), "reply: {reply}");
        assert!(reply.contains("\"status\":200"), "reply: {reply}");
        assert!(
            !reply.contains(TOKEN),
            "the credential crossed the socket: {reply}"
        );
        upstream.verify().await;
        listener.shutdown().await;
    }

    /// An upstream the pod was not admitted is refused, and nothing is called.
    /// Deliberately coarse on the wire ("not permitted", as for every policy
    /// refusal, so a guest cannot enumerate the node's registry); the pod's own
    /// `/v1/egress/{name}` names the upstream before it ever asks the host.
    #[tokio::test]
    async fn an_undeclared_upstream_is_refused() {
        let var = "NUCLEUS_TEST_CONTAINER_BROKER_UNDECLARED";
        set(var);
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&upstream)
            .await;
        let pod = pod(&upstream, var, true).await;
        let prepared = prepare(&pod.state, &pod.spec, &pod.pod_dir, pod.id)
            .await
            .expect("prepares")
            .expect("served");
        let secret = secret_of(prepared.env());
        let listener = prepared.arm(std::process::id()).expect("armed in time");
        let reply = perform(&host_socket(&pod.pod_dir), &secret, "other-api").await;
        assert!(reply.contains("\"granted\":false"), "reply: {reply}");
        upstream.verify().await;
        listener.shutdown().await;
    }

    /// **A peer that is not the container's init is refused by the kernel's
    /// account of it**, with a valid capability and an admitted upstream: the
    /// workload, a `docker exec`, any host process. Red with the peer check
    /// removed from `serve_broker`: the call is made.
    #[tokio::test]
    async fn a_peer_other_than_the_containers_init_is_refused() {
        let var = "NUCLEUS_TEST_CONTAINER_BROKER_PEER";
        set(var);
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&upstream)
            .await;
        let pod = pod(&upstream, var, true).await;
        let prepared = prepare(&pod.state, &pod.spec, &pod.pod_dir, pod.id)
            .await
            .expect("prepares")
            .expect("served");
        let secret = secret_of(prepared.env());
        // Armed with some other process: this test process is now "the workload".
        let listener = prepared
            .arm(std::process::id().wrapping_add(1).max(2))
            .expect("armed in time");
        let reply = perform(&host_socket(&pod.pod_dir), &secret, "model-api").await;
        assert!(reply.contains("\"granted\":false"), "reply: {reply}");
        upstream.verify().await;
        listener.shutdown().await;
    }

    /// **Torn down with the pod.** The listener is the container pod's, and its
    /// teardown removes the socket from the pod directory, so nothing can ask
    /// on behalf of a pod that is gone. Red with the shutdown removed from
    /// `ContainerPod::teardown`.
    #[tokio::test]
    async fn the_socket_is_torn_down_with_the_pod() {
        let var = "NUCLEUS_TEST_CONTAINER_BROKER_TEARDOWN";
        set(var);
        let upstream = MockServer::start().await;
        let pod = pod(&upstream, var, true).await;
        let prepared = prepare(&pod.state, &pod.spec, &pod.pod_dir, pod.id)
            .await
            .expect("prepares")
            .expect("served");
        let listener = prepared.arm(std::process::id()).expect("armed in time");
        let socket = host_socket(&pod.pod_dir);
        assert!(socket.exists(), "served while the pod runs");

        let docker = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&docker)
            .await;
        let container = crate::ContainerPod {
            launch_intent: None,
            container_id: "c".into(),
            docker: bollard::Docker::connect_with_http(
                &docker.uri(),
                2,
                bollard::API_DEFAULT_VERSION,
            )
            .expect("docker client"),
            signed_proxy: tokio::sync::Mutex::new(None),
            broker: tokio::sync::Mutex::new(Some(listener)),
            permit: tokio::sync::Mutex::new(None),
            cached_exit: tokio::sync::Mutex::new(Some(crate::PodState::Exited { code: Some(0) })),
        };
        container
            .teardown(crate::Stop::AlreadyExited)
            .await
            .expect("teardown");
        assert!(!socket.exists(), "the broker socket outlived its pod");
        assert!(tokio::net::UnixStream::connect(&socket).await.is_err());
    }

    /// No upstream, no socket: a pod that could ask for nothing gets nothing in
    /// its pod directory. And an unmediated container, which has no proxy to
    /// ask, gets none either.
    #[tokio::test]
    async fn a_pod_with_nothing_to_reach_gets_no_socket() {
        let var = "NUCLEUS_TEST_CONTAINER_BROKER_NONE";
        set(var);
        let upstream = MockServer::start().await;
        let bare = pod(&upstream, var, false).await;
        assert!(
            prepare(&bare.state, &bare.spec, &bare.pod_dir, bare.id)
                .await
                .expect("prepares")
                .is_none()
        );
        let declared = pod(&upstream, var, true).await;
        let mut unmediated = declared.state.clone();
        unmediated.container_mediation = crate::container_mediation::ContainerMediation::Unmediated;
        assert!(
            prepare(&unmediated, &declared.spec, &declared.pod_dir, declared.id)
                .await
                .expect("prepares")
                .is_none()
        );
        assert!(!host_socket(&bare.pod_dir).exists());
        assert!(!host_socket(&declared.pod_dir).exists());
    }

    /// Async: the broker this test talks to is served on the same runtime, and
    /// a blocking wait here would stop it answering the very call being made.
    async fn docker_cli(args: &[&str]) -> std::process::Output {
        tokio::process::Command::new("docker")
            .args(args)
            .output()
            .await
            .expect("the docker CLI runs")
    }

    /// **End to end, on a real container runtime.** A container pod created
    /// through `create_pod_internal` with credentialed egress: the orchestrator
    /// calls `/v1/egress/model-api/complete` on the pod's proxy address, the
    /// in-container tool-proxy asks the host over the bind-mounted socket, and
    /// the host makes the call with the credential from its own environment.
    /// Then the credential is looked for everywhere the container can see:
    /// `docker inspect`, `/proc/1/environ` inside it, the `pod.yaml` it mounts.
    /// A second process in the same container (`docker exec`, same uid as the
    /// proxy, holding the proxy's own capability read from `/proc/1/environ`)
    /// is refused by its pid. Cancelling the pod removes the socket.
    ///
    /// Needs a Docker daemon, a node with the host's pid namespace, and a
    /// tool-proxy image built from this tree whose proxy runs as root (so it can
    /// write the root-owned pod directory and drop its workload) and that has
    /// `nc` with `-U`:
    ///
    /// ```text
    /// cargo build -p nucleus-tool-proxy -p nucleus-egress-http
    /// printf 'FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*\nCOPY nucleus-tool-proxy nucleus-egress-http /usr/local/bin/\n' > target/debug/Dockerfile
    /// docker build -t nucleus-tool-proxy:e2e target/debug
    /// cargo test -p nucleus-node --features local-driver --no-run
    /// sudo NUCLEUS_TEST_TOOL_PROXY_IMAGE=nucleus-tool-proxy:e2e target/debug/deps/nucleus_node-<hash> \
    ///     --ignored --exact container_broker::tests::live::a_real_container_reaches_its_upstream_without_the_credential
    /// ```
    #[tokio::test]
    #[ignore = "needs a Docker daemon and NUCLEUS_TEST_TOOL_PROXY_IMAGE built from this tree"]
    async fn a_real_container_reaches_its_upstream_without_the_credential() {
        let image = std::env::var("NUCLEUS_TEST_TOOL_PROXY_IMAGE")
            .expect("NUCLEUS_TEST_TOOL_PROXY_IMAGE names a tool-proxy image built from this tree");
        let var = "NUCLEUS_TEST_CONTAINER_BROKER_E2E";
        set(var);
        // On a host address the NODE reaches; the container never does.
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/complete"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"answer\":42}"))
            .expect(1)
            .mount(&upstream)
            .await;

        let (_dir, mut state) = node(&upstream, var);
        state.driver = crate::driver::DriverKind::Container;
        state.container_image = image;
        state.docker = Some(std::sync::Arc::new(
            bollard::Docker::connect_with_local_defaults().expect("a Docker daemon"),
        ));
        let mut spec = pod_spec(&state, true);
        let work = state.host_roots.workspace_root().join("e2e");
        std::fs::create_dir_all(&work).expect("workspace");
        spec.spec.work_dir = work;
        let root = crate::pod_authority::Admission {
            caller_spiffe_id: state.authority.root_minter().to_string(),
            caller_pod: None,
            header_cert: None,
        };
        let created = crate::create_pod_internal(&state, spec, None, None, root).await;
        let (id, proxy) = created.unwrap_or_else(|error| {
            // The container is gone by now; its log is what it said before it went.
            let logs: Vec<String> = std::fs::read_dir(state.state_dir.join("pods"))
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|pod| std::fs::read_to_string(pod.path().join("pod.log")).ok())
                .collect();
            panic!(
                "the container pod did not launch: {error:?}\n{}",
                logs.join("\n")
            );
        });
        let proxy = proxy.expect("a mediated pod has a proxy address");
        let handle = state.pods.lock().await.get(&id).cloned().expect("pod");
        let crate::DriverState::Container(container) = &handle.driver_state else {
            panic!("a container pod");
        };
        let cid = container.container_id.clone();
        let pod_dir = crate::lifecycle::pod_dir(&state.state_dir, id);

        // The orchestrator's call, through the pod's own mediation.
        let reply = reqwest::Client::new()
            .post(format!("{proxy}/v1/egress/model-api/complete"))
            .header("content-type", "application/json")
            .body("{\"prompt\":\"hi\"}")
            .send()
            .await
            .expect("the proxy answers");
        let status = reply.status();
        let body = reply.text().await.expect("body");
        assert!(status.is_success(), "{status}: {body}");
        assert!(body.contains("42"), "{body}");
        assert!(!body.contains(TOKEN));
        upstream.verify().await;

        // Nowhere the container can look.
        let inspect = docker_cli(&["inspect", &cid]).await;
        let inspect = String::from_utf8_lossy(&inspect.stdout);
        assert!(
            inspect.contains("NUCLEUS_TOOL_PROXY_BROKER_SOCKET"),
            "{inspect}"
        );
        assert!(
            !inspect.contains(TOKEN),
            "docker inspect shows the credential"
        );
        let environ = docker_cli(&["exec", &cid, "cat", "/proc/1/environ"]).await;
        assert!(environ.status.success());
        let environ = String::from_utf8_lossy(&environ.stdout).replace('\0', "\n");
        assert!(
            !environ.contains(TOKEN),
            "the proxy's environment holds the credential"
        );
        let pod_yaml = std::fs::read_to_string(pod_dir.join("pod.yaml")).expect("pod.yaml");
        assert!(!pod_yaml.contains(TOKEN));

        // A second process in the same container, holding the proxy's own
        // capability: refused by its pid, and nothing is called.
        let secret = environ
            .lines()
            .find_map(|l| l.strip_prefix("NUCLEUS_TOOL_PROXY_BROKER_SECRET="))
            .expect("the proxy holds its capability")
            .to_string();
        let socket = container_socket_path();
        let script = format!(
            "printf '%s\\n' '{}' | nc -U -q 2 {}",
            perform_frame(&secret, "model-api").replace('\'', "'\\''"),
            socket.display()
        );
        let exec = docker_cli(&["exec", &cid, "sh", "-c", &script]).await;
        let answer = String::from_utf8_lossy(&exec.stdout);
        assert!(
            answer.contains("\"granted\":false"),
            "a second process in the container was served: {answer} / {}",
            String::from_utf8_lossy(&exec.stderr)
        );
        upstream.verify().await;

        // Torn down with the pod.
        let host = host_socket(&pod_dir);
        assert!(host.exists());
        handle.cancel().await.expect("cancel");
        assert!(!host.exists(), "the broker socket outlived its pod");
        eprintln!(
            "e2e: container {cid} reached its upstream through the host ({status}, {body}); \
             credential absent from docker inspect, /proc/1/environ and pod.yaml; \
             docker exec peer answered {}; socket removed on cancel",
            answer.trim()
        );
    }
}
