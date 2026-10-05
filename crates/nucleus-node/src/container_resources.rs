//! Docker can accept a create while rewriting unsupported resource limits.
//! Check its stored configuration before starting the workload.
use crate::{
    ApiError,
    pod_resources::{CONTAINER_PIDS_MAX, PodSize},
};

pub(crate) async fn verify(
    docker: &bollard::Docker,
    id: &str,
    size: PodSize,
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
    check(&config, size)
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
    fn accepted_limits_match_the_admitted_size() {
        let spec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#).unwrap();
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
}
