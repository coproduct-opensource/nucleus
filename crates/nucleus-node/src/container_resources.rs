//! Verify Docker's stored resource limits, device requests and selected network
//! mode before starting the workload. A successful create alone does not attest
//! to any of them.
use crate::{
    ApiError,
    pod_resources::{CONTAINER_PIDS_MAX, PodSize},
};

pub(crate) async fn verify(
    docker: &bollard::Docker,
    id: &str,
    size: PodSize,
    network_mode: &str,
) -> Result<(), ApiError> {
    let info = docker
        .inspect_container(
            id,
            None::<bollard::query_parameters::InspectContainerOptions>,
        )
        .await
        .map_err(|e| ApiError::Driver(format!("inspect accepted container limits: {e}")))?;
    let config = info
        .host_config
        .ok_or_else(|| ApiError::Driver("Docker omitted accepted resource configuration".into()))?;
    check(&config, size)?;
    check_devices(&config, size)?;
    check_network(&config, network_mode)
}

/// The capability a device request names. The runtime picks whichever device
/// driver it has that offers it; the node names no driver.
const ACCELERATOR_CAPABILITY: &str = "gpu";

/// What an admitted size sends the runtime: its limits, and its device requests.
/// Built here, beside the check that the runtime retained each of them.
///
/// An absent spec field is the node's default, never unlimited. Swap equal to
/// memory means none beyond it.
pub(crate) fn host_limits(size: PodSize) -> bollard::models::HostConfig {
    let memory = i64::try_from(size.memory_bytes()).unwrap_or(i64::MAX);
    bollard::models::HostConfig {
        memory: Some(memory),
        memory_swap: Some(memory),
        nano_cpus: Some(i64::from(size.vcpus()) * 1_000_000_000),
        pids_limit: Some(CONTAINER_PIDS_MAX),
        device_requests: device_requests(size),
        ..Default::default()
    }
}

/// The device requests for an admitted size: one request for the admitted
/// count, or none at all. `None`, not an empty request, when the pod asked for
/// nothing, so a pod is given no device it did not name.
pub(crate) fn device_requests(size: PodSize) -> Option<Vec<bollard::models::DeviceRequest>> {
    let count = size.accelerators();
    (count > 0).then(|| {
        vec![bollard::models::DeviceRequest {
            count: Some(i64::from(count)),
            capabilities: Some(vec![vec![ACCELERATOR_CAPABILITY.to_owned()]]),
            ..Default::default()
        }]
    })
}

/// The runtime retained exactly the device requests the node sent: the admitted
/// count under the accelerator capability, by count and not by device id, or
/// none. A request the node did not send is refused as firmly as one it sent
/// and the runtime dropped.
fn check_devices(config: &bollard::models::HostConfig, size: PodSize) -> Result<(), ApiError> {
    let asked = i64::from(size.accelerators());
    let observed = config.device_requests.as_deref().unwrap_or_default();
    let retained = match observed {
        [] => asked == 0,
        [one] => {
            asked > 0
                && one.count == Some(asked)
                && one.device_ids.as_deref().unwrap_or_default().is_empty()
                && one.capabilities.as_deref()
                    == Some(&[vec![ACCELERATOR_CAPABILITY.to_owned()]][..])
        }
        [_, _, ..] => false,
    };
    if retained {
        Ok(())
    } else {
        Err(ApiError::Driver(format!(
            "Docker did not retain required device requests: requested {asked} accelerator(s), accepted {observed:?}; workload was not started"
        )))
    }
}

fn check_network(config: &bollard::models::HostConfig, expected: &str) -> Result<(), ApiError> {
    if config.network_mode.as_deref() != Some(expected) {
        return Err(ApiError::Driver(format!(
            "Docker did not retain required network mode: requested {expected:?}, accepted {:?}; workload was not started",
            config.network_mode,
        )));
    }
    Ok(())
}

fn check(config: &bollard::models::HostConfig, size: PodSize) -> Result<(), ApiError> {
    let memory = i64::try_from(size.memory_bytes())
        .map_err(|_| ApiError::InvalidSpec("container memory is unrepresentable".into()))?;
    for (name, observed, expected) in [
        ("memory", config.memory, memory),
        ("memory_swap", config.memory_swap, memory),
        (
            "nano_cpus",
            config.nano_cpus,
            i64::from(size.vcpus()) * 1_000_000_000,
        ),
        ("pids_limit", config.pids_limit, CONTAINER_PIDS_MAX),
    ] {
        if observed != Some(expected) {
            return Err(ApiError::Driver(format!(
                "Docker did not retain required {name}: requested {expected}, accepted {observed:?}; check daemon resource-controller support"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_network_mode_must_be_retained() {
        for selected in ["none", "bridge", "project-network"] {
            let config = bollard::models::HostConfig {
                network_mode: Some(selected.into()),
                ..Default::default()
            };
            check_network(&config, selected).unwrap();
        }
        for accepted in [None, Some(""), Some("bridge"), Some("host")] {
            let config = bollard::models::HostConfig {
                network_mode: accepted.map(str::to_owned),
                ..Default::default()
            };
            let error = check_network(&config, "none").unwrap_err().to_string();
            assert!(error.contains("network mode") && error.contains("not started"));
        }
    }

    fn sized(resources: &str) -> PodSize {
        let spec = serde_json::from_str(&format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{{"resources":{resources},"policy":{{"type":"profile","name":"default"}}}}}}"#
        ))
        .unwrap();
        PodSize::of(&spec)
    }

    fn retaining(
        requests: Option<Vec<bollard::models::DeviceRequest>>,
    ) -> bollard::models::HostConfig {
        bollard::models::HostConfig {
            device_requests: requests,
            ..Default::default()
        }
    }

    #[test]
    fn a_pod_that_asked_for_no_accelerator_sends_no_device_request() {
        let none = sized("{}");
        assert_eq!(device_requests(none), None);
        check_devices(&retaining(None), none).unwrap();
        check_devices(&retaining(Some(vec![])), none).unwrap();
        // A device the node did not ask for is not a harmless extra.
        let error = check_devices(
            &retaining(device_requests(sized(r#"{"accelerators":1}"#))),
            none,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("device requests") && error.contains("not started"));
    }

    #[test]
    fn the_admitted_accelerator_count_must_be_retained_exactly() {
        let two = sized(r#"{"accelerators":2}"#);
        let sent = device_requests(two).unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].count, Some(2));
        check_devices(&retaining(Some(sent.clone())), two).unwrap();

        let dropped = [None, Some(vec![])];
        let mut fewer = sent.clone();
        fewer[0].count = Some(1);
        let mut all = sent.clone();
        all[0].count = Some(-1);
        let mut by_id = sent.clone();
        by_id[0].device_ids = Some(vec!["0".into()]);
        let mut other_capability = sent.clone();
        other_capability[0].capabilities = Some(vec![vec!["compute".into()]]);
        let mut no_capability = sent.clone();
        no_capability[0].capabilities = None;
        let mut twice = sent.clone();
        twice.extend(sent);
        for accepted in dropped.into_iter().chain(
            [fewer, all, by_id, other_capability, no_capability, twice]
                .into_iter()
                .map(Some),
        ) {
            let error = check_devices(&retaining(accepted.clone()), two)
                .expect_err(&format!("{accepted:?} is not what was asked for"))
                .to_string();
            assert!(error.contains("requested 2 accelerator(s)"), "{error}");
        }
    }

    /// What the node sends is what the node then requires the runtime to have kept.
    #[test]
    fn what_is_sent_for_a_size_passes_the_check_for_that_size_alone() {
        let asking = sized(r#"{"accelerators":1,"cpu_cores":2,"memory_mib":1024}"#);
        let plain = sized(r#"{"cpu_cores":2,"memory_mib":1024}"#);
        for size in [asking, plain] {
            let sent = host_limits(size);
            check(&sent, size).unwrap();
            check_devices(&sent, size).unwrap();
        }
        assert!(check_devices(&host_limits(asking), plain).is_err());
        assert!(check_devices(&host_limits(plain), asking).is_err());
        assert!(check(&host_limits(sized("{}")), asking).is_err());
    }

    #[test]
    fn a_zero_accelerator_count_cannot_be_written() {
        let refused = serde_json::from_str::<nucleus_spec::PodSpec>(
            r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"resources":{"accelerators":0},"policy":{"type":"profile","name":"default"}}}"#,
        );
        assert!(refused.is_err());
    }

    #[test]
    fn accepted_limits_match_the_admitted_size() {
        let spec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"}}}"#).unwrap();
        let size = PodSize::of(&spec);
        let config = bollard::models::HostConfig {
            memory: Some(536870912),
            memory_swap: Some(536870912),
            nano_cpus: Some(1_000_000_000),
            pids_limit: Some(CONTAINER_PIDS_MAX),
            ..Default::default()
        };
        check(&config, size).unwrap();
        for name in ["memory", "memory_swap", "nano_cpus", "pids_limit"] {
            let mut changed = config.clone();
            match name {
                "memory" => changed.memory = Some(0),
                "memory_swap" => changed.memory_swap = Some(-1),
                "nano_cpus" => changed.nano_cpus = None,
                "pids_limit" => changed.pids_limit = None,
                _ => unreachable!(),
            }
            assert!(
                check(&changed, size)
                    .unwrap_err()
                    .to_string()
                    .contains(name)
            );
        }
    }

    /// The device request against a real container runtime with a real accelerator.
    ///
    /// Run on a host whose runtime can attach one (`docker info` lists a runtime offering the
    /// `gpu` capability), as a user who can reach the Docker socket:
    ///
    /// ```text
    /// docker pull ubuntu:24.04
    /// cargo test -p nucleus-node -- --ignored \
    ///     a_real_container_is_given_the_accelerator_it_asked_for_and_no_other
    /// ```
    ///
    /// It names no device and no device vendor. A container given an accelerator has device
    /// nodes in `/dev` that a container given none lacks, and that difference is the assertion.
    #[tokio::test]
    #[ignore = "needs a container runtime with an accelerator; see the doc comment"]
    async fn a_real_container_is_given_the_accelerator_it_asked_for_and_no_other() {
        use bollard::query_parameters::{
            CreateContainerOptions, LogsOptions, RemoveContainerOptions, StartContainerOptions,
            WaitContainerOptions,
        };
        use tokio_stream::StreamExt;

        let docker = bollard::Docker::connect_with_local_defaults().expect("docker socket");
        let image = std::env::var("NUCLEUS_ACCELERATOR_E2E_IMAGE")
            .unwrap_or_else(|_| "ubuntu:24.04".to_owned());
        let asking = sized(r#"{"accelerators":1}"#);
        let plain = sized("{}");

        let mut dev = Vec::new();
        for (name, size) in [("asking", asking), ("plain", plain)] {
            let body = bollard::models::ContainerCreateBody {
                image: Some(image.clone()),
                cmd: Some(vec!["ls".into(), "-1".into(), "/dev".into()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("none".into()),
                    ..host_limits(size)
                }),
                ..Default::default()
            };
            let id = docker
                .create_container(None::<CreateContainerOptions>, body)
                .await
                .unwrap_or_else(|e| panic!("create the {name} container: {e}"))
                .id;

            // What the node does before it starts a workload, and its control: the same
            // container checked against the other size is refused.
            verify(&docker, &id, size, "none")
                .await
                .unwrap_or_else(|e| panic!("the runtime retained the {name} request: {e}"));
            let other = if size == asking { plain } else { asking };
            let refused = verify(&docker, &id, other, "none")
                .await
                .expect_err("a container checked against a size it was not created with");
            assert!(refused.to_string().contains("device requests"), "{refused}");

            docker
                .start_container(&id, None::<StartContainerOptions>)
                .await
                .unwrap_or_else(|e| panic!("start the {name} container: {e}"));
            let mut waiting = docker.wait_container(&id, None::<WaitContainerOptions>);
            while let Some(exit) = waiting.next().await {
                assert_eq!(exit.expect("wait").status_code, 0, "{name}: ls /dev failed");
            }
            let mut logs = docker.logs(
                &id,
                Some(LogsOptions {
                    stdout: true,
                    ..Default::default()
                }),
            );
            let mut out = Vec::new();
            while let Some(chunk) = logs.next().await {
                out.extend_from_slice(&chunk.expect("log chunk").into_bytes());
            }
            docker
                .remove_container(
                    &id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await
                .expect("remove");
            let nodes: std::collections::BTreeSet<String> = String::from_utf8(out)
                .expect("utf-8")
                .lines()
                .map(str::to_owned)
                .collect();
            assert!(!nodes.is_empty(), "{name}: /dev listed nothing");
            dev.push(nodes);
        }
        let (with, without) = (&dev[0], &dev[1]);
        let gained: Vec<_> = with.difference(without).collect();
        let lost: Vec<_> = without.difference(with).collect();
        println!("device nodes only the asking container has: {gained:?}");
        assert!(lost.is_empty(), "asking for a device removed {lost:?}");
        assert!(
            !gained.is_empty(),
            "the asking container has no device node the plain one lacks: the request was \
             retained and attached nothing"
        );
    }
}
