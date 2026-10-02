//! Whether a container pod is mediated, and by which binary — decided by the node (#3133).
//!
//! The container driver used to read both facts from the pod spec's labels:
//! `nucleus.io/proxy-mode` chose whether the tool-proxy ran at all (absent meant it did not), and
//! `nucleus.io/container-image` replaced the image the mediating `nucleus-tool-proxy` came from.
//! A spec author could therefore ask for no reference monitor, or for one they supplied.
//!
//! Both are now node configuration: [`ContainerMediation`] from `--container-mediation`, and the
//! image from `--container-image`. A spec that still sets either label is refused by name at create
//! (`spec_posture::admit`), so its author learns the label no longer means anything.
//! [`launch`] is the one place the container's image and entrypoint are decided.

/// How the container driver runs every pod on this node. Chosen by the operator, never by a spec.
///
/// Two named variants rather than a `bool` (ADR 0007 A-7), matched exhaustively (E-2), and no `Default` impl (B-1): the CLI
/// default is spelled out on the flag, and it is the mediated one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ContainerMediation {
    /// The node image's `nucleus-tool-proxy` is the container's entrypoint, so the kernel, the
    /// IFC monitor, the audit trail and the proxy's startup refusals all run. The default.
    ToolProxy,
    /// The image's own entrypoint (or the orchestrator's `NUCLEUS_TASK_CMD`) runs with **no
    /// reference monitor**. An explicit operator opt-in for a node whose containers are trusted
    /// by construction; the node logs it at startup. A spec cannot select it.
    Unmediated,
}

impl ContainerMediation {
    /// Whether the node's tool-proxy runs in the container.
    pub(crate) fn runs_tool_proxy(self) -> bool {
        match self {
            Self::ToolProxy => true,
            Self::Unmediated => false,
        }
    }
}

/// The binary that mediates a container pod, inside the node's image.
pub(crate) const TOOL_PROXY_BINARY: &str = "nucleus-tool-proxy";

/// What the container is created from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerLaunch {
    /// Always the node's `--container-image`.
    pub(crate) image: String,
    /// `None` keeps the image's own.
    pub(crate) entrypoint: Option<Vec<String>>,
    /// `None` keeps the image's own.
    pub(crate) cmd: Option<Vec<String>>,
}

/// The container's image and command for a pod, from node configuration and the env the node
/// built. Nothing here reads the spec: its only influence is `NUCLEUS_TASK_CMD`, which reaches
/// `env` through admitted `credentials.env` and is used only on an unmediated node.
pub(crate) fn launch(
    mediation: ContainerMediation,
    node_image: &str,
    env: &[String],
) -> ContainerLaunch {
    let image = node_image.to_string();
    match mediation {
        // Override entrypoint + cmd so the node controls the full command regardless of the
        // image's ENTRYPOINT/CMD (an image whose ENTRYPOINT is already the proxy would otherwise
        // start it twice).
        ContainerMediation::ToolProxy => ContainerLaunch {
            image,
            entrypoint: Some(vec![TOOL_PROXY_BINARY.to_string()]),
            cmd: Some(
                [
                    "--spec",
                    "/data/pod/pod.yaml",
                    "--listen",
                    "0.0.0.0:0",
                    "--announce-path",
                    "/data/pod/proxy.addr",
                ]
                .map(str::to_string)
                .to_vec(),
            ),
        },
        ContainerMediation::Unmediated => {
            // Direct task execution. The runner — and any credential bootstrap it needs — is the
            // orchestrator's, via the generic NUCLEUS_TASK_CMD, keeping nucleus vendor-agnostic;
            // nucleus only wraps it in its task_start/task_complete artifact markers. With no
            // task, or no runner, the image's own entrypoint runs with NUCLEUS_TASK in its env.
            let has_task = env.iter().any(|e| e.starts_with("NUCLEUS_TASK="));
            let runner = env.iter().find_map(|e| e.strip_prefix("NUCLEUS_TASK_CMD="));
            match runner.filter(|_| has_task) {
                Some(runner) => ContainerLaunch {
                    image,
                    entrypoint: Some(vec!["/bin/bash".to_string(), "-c".to_string()]),
                    cmd: Some(vec![format!(
                        "echo \"NUCLEUS_ARTIFACT type=task_start\" && \
                         {runner} 2>&1 && \
                         echo \"NUCLEUS_ARTIFACT type=task_complete\""
                    )]),
                },
                None => ContainerLaunch {
                    image,
                    entrypoint: None,
                    cmd: None,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #3133: a node started with no mediation flag mediates its container pods, with the proxy
    /// from the node's own image. On main the mode came from a spec label whose absence meant
    /// unmediated. Driven red by setting the flag's default to `unmediated`.
    #[test]
    fn the_default_container_pod_is_mediated_by_the_node_chosen_binary() {
        use clap::Parser;
        let args = crate::Args::try_parse_from([
            "nucleus-node",
            "--proxy-auth-secret=test",
            "--proxy-approval-secret=test",
            "--driver=container",
        ])
        .expect("minimal container node");
        assert_eq!(args.container_mediation, ContainerMediation::ToolProxy);

        let task = [
            "NUCLEUS_TASK=t".to_string(),
            "NUCLEUS_TASK_CMD=run".to_string(),
        ];
        let plan = launch(args.container_mediation, &args.container_image, &task);
        assert_eq!(plan.image, args.container_image);
        assert_eq!(plan.entrypoint, Some(vec![TOOL_PROXY_BINARY.to_string()]));
        assert!(
            !plan.cmd.iter().flatten().any(|a| a.contains("run")),
            "a mediated pod's command is the node's, never the spec's runner: {:?}",
            plan.cmd
        );
    }

    /// The node operator can choose a different image; the plan still mediates with it.
    #[test]
    fn the_operator_chooses_the_mediating_image() {
        use clap::Parser;
        let args = crate::Args::try_parse_from([
            "nucleus-node",
            "--proxy-auth-secret=test",
            "--proxy-approval-secret=test",
            "--container-image=registry.local/mediator@sha256:00",
        ])
        .expect("args");
        let plan = launch(args.container_mediation, &args.container_image, &[]);
        assert_eq!(plan.image, "registry.local/mediator@sha256:00");
        assert_eq!(plan.entrypoint, Some(vec![TOOL_PROXY_BINARY.to_string()]));
    }

    /// Unmediated is reachable only by naming it on the node; with it, the orchestrator's runner
    /// runs, and with no runner the image's own entrypoint does.
    #[test]
    fn unmediated_is_an_explicit_node_opt_in() {
        use clap::Parser;
        let args = crate::Args::try_parse_from([
            "nucleus-node",
            "--proxy-auth-secret=test",
            "--proxy-approval-secret=test",
            "--container-mediation=unmediated",
        ])
        .expect("args");
        assert_eq!(args.container_mediation, ContainerMediation::Unmediated);
        assert!(!args.container_mediation.runs_tool_proxy());

        let task = [
            "NUCLEUS_TASK=t".to_string(),
            "NUCLEUS_TASK_CMD=run".to_string(),
        ];
        let plan = launch(ContainerMediation::Unmediated, "img", &task);
        assert_eq!(
            plan.entrypoint.as_deref(),
            Some(&["/bin/bash".to_string(), "-c".to_string()][..])
        );
        assert!(plan.cmd.expect("cmd")[0].contains("run 2>&1"));

        let plain = launch(ContainerMediation::Unmediated, "img", &[]);
        assert_eq!((plain.entrypoint, plain.cmd), (None, None));
    }
}
