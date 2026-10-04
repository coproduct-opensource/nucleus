//! Admission and CLI refusals for production VMM confinement.
use nucleus_spec::SeccompSpec;

/// A jailer uid that cannot represent root. Declared beside the jail user it is part of, which
/// `nucleus-hostctl seed` hands a written-through disk to (#3152).
pub(crate) use nucleus_microvm_host::jail_user::NonRootUid;

pub(crate) fn parse_jailer_enabled(value: &str) -> Result<bool, String> {
    let enabled = value.parse::<bool>().map_err(|e| e.to_string())?;
    if !enabled && !cfg!(feature = "local-driver") {
        return Err("JailerRequired: production builds require --firecracker-jailer=true".into());
    }
    Ok(enabled)
}

pub(crate) fn admit_seccomp(seccomp: Option<&SeccompSpec>) -> Result<(), &'static str> {
    if cfg!(feature = "local-driver") {
        return Ok(());
    }
    match seccomp {
        Some(SeccompSpec::Disabled) => {
            Err("SeccompDisabled: production builds require the default filter")
        }
        Some(SeccompSpec::Custom { .. }) => {
            Err("SeccompUnpinned: custom filters require hash-pinned admission")
        }
        None | Some(SeccompSpec::Default) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_rejects_unsafe_values() {
        use clap::Parser;
        let err = crate::Args::try_parse_from([
            "nucleus-node",
            "--proxy-auth-secret=test",
            "--proxy-approval-secret=test",
            "--jailer-uid=0",
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("JailerRootUid"), "{err}");
        let result = crate::Args::try_parse_from([
            "nucleus-node",
            "--proxy-auth-secret=test",
            "--proxy-approval-secret=test",
            "--firecracker-jailer=false",
        ]);
        if cfg!(feature = "local-driver") {
            assert!(!result.unwrap().firecracker_jailer);
        } else {
            let err = result.unwrap_err().to_string();
            assert!(err.contains("JailerRequired"), "{err}");
        }
    }

    #[test]
    fn root_uid_is_unrepresentable() {
        assert_eq!(
            NonRootUid::new(0).unwrap_err(),
            "JailerRootUid: jailer uid must not be zero"
        );
        assert!("0".parse::<NonRootUid>().is_err());
        assert_eq!("123".parse::<NonRootUid>().unwrap().get(), 123);
    }

    #[test]
    fn production_confinement_refusals() {
        assert!(admit_seccomp(None).is_ok());
        assert!(admit_seccomp(Some(&SeccompSpec::Default)).is_ok());
        assert_eq!(parse_jailer_enabled("true"), Ok(true));
        for (spec, error) in [
            (SeccompSpec::Disabled, "SeccompDisabled"),
            (
                SeccompSpec::Custom {
                    filter_path: "/tmp/allow-all.bpf".into(),
                },
                "SeccompUnpinned",
            ),
        ] {
            let result = admit_seccomp(Some(&spec));
            if cfg!(feature = "local-driver") {
                assert!(result.is_ok());
            } else {
                assert!(result.unwrap_err().starts_with(error));
            }
        }
        let disabled = parse_jailer_enabled("false");
        if cfg!(feature = "local-driver") {
            assert_eq!(disabled, Ok(false));
        } else {
            assert!(disabled.unwrap_err().starts_with("JailerRequired"));
        }
    }
}
