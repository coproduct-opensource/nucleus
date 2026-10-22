//! Prepared in the parent; applied only in the trusted pre-exec hook.
//! The mapping retains exactly one outer uid/gid. No workload may choose maps.
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Prepared {
    bytes: [u8; 32],
    length: usize,
    outer: u32,
    loopback: bool,
    inner: u32,
}

impl Prepared {
    pub(super) fn parameters(&self) -> (u32, u32, bool) {
        (self.outer, self.inner, self.loopback)
    }

    pub(super) fn new(outer: u32, inner: u32, loopback: bool) -> Self {
        // Decimal u32 + space + decimal u32 + " 1\n" fits this fixed buffer.
        // Formatting happens in the parent, never after fork.
        let line = format!("{inner} {outer} 1\n");
        let mut bytes = [0; 32];
        bytes[..line.len()].copy_from_slice(line.as_bytes());
        Self {
            bytes,
            length: line.len(),
            outer,
            loopback,
            inner,
        }
    }

    /// Prepare one bounded mapping exchange. Spawn must follow within five
    /// seconds; a stale, failed or reused command refuses before exec.
    pub(super) fn prepare(self) -> io::Result<ChildMapping> {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        let (mut parent, child) = std::os::unix::net::UnixStream::pair()?;
        let timeout = Some(std::time::Duration::from_secs(5));
        parent.set_read_timeout(timeout)?;
        parent.set_write_timeout(timeout)?;
        child.set_read_timeout(timeout)?;
        child.set_write_timeout(timeout)?;
        let parent_pid = std::process::id();
        std::thread::Builder::new()
            .name("workload-id-map".into())
            .spawn(move || {
                let mut request = [0; 20];
                let result = (|| -> io::Result<()> {
                    parent.read_exact(&mut request)?;
                    let pid = u32::from_ne_bytes(request[..4].try_into().expect("fixed PID field"));
                    // Pin this task's proc directory before inspecting it.
                    // A timed-out child may exit; subsequent accesses must fail
                    // on that task, never resolve a reused numeric PID.
                    let directory = std::fs::File::open(format!("/proc/{pid}"))?;
                    let root = format!("/proc/self/fd/{}", directory.as_raw_fd());
                    let status = std::fs::read_to_string(format!("{root}/status"))?;
                    if !status
                        .lines()
                        .find_map(|line| line.strip_prefix("Groups:"))
                        .is_some_and(|groups| groups.trim().is_empty())
                    {
                        return Err(io::Error::from_raw_os_error(libc::EACCES));
                    }
                    // The endpoint is private to this command's trusted pre-exec
                    // hook. The pinned directory prevents PID reuse from
                    // redirecting writes; check parentage and every outer id.
                    let outer = self.outer;
                    for (field, expected, count) in [
                        ("PPid:", parent_pid.to_string(), 1),
                        ("Uid:", outer.to_string(), 4),
                        ("Gid:", outer.to_string(), 4),
                    ] {
                        let values = status
                            .lines()
                            .find_map(|line| line.strip_prefix(field))
                            .ok_or_else(|| io::Error::from_raw_os_error(libc::EACCES))?;
                        let values: Vec<_> = values.split_whitespace().collect();
                        if values.len() != count || values.iter().any(|value| *value != expected) {
                            return Err(io::Error::from_raw_os_error(libc::EACCES));
                        }
                    }
                    let mapping = &self.bytes[..self.length];
                    std::fs::write(format!("{root}/uid_map"), mapping)?;
                    std::fs::write(format!("{root}/setgroups"), b"deny\n")?;
                    std::fs::write(format!("{root}/gid_map"), mapping)?;
                    Ok(())
                })();
                // Refusal is explicit, including partial map setup. The child
                // never continues to workload code without the success byte.
                let mut ack = [0; 17];
                ack[..16].copy_from_slice(&request[4..]);
                ack[16] = u8::from(result.is_ok());
                let _ = parent.write_all(&ack);
            })?;
        Ok(ChildMapping {
            socket: child,
            prepared: self,
        })
    }

    /// # Safety
    /// The fresh namespaces and exact uid/gid mappings must already exist.
    unsafe fn finish(&self) -> io::Result<()> {
        unsafe {
            if libc::geteuid() != self.inner || libc::getegid() != self.inner {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            if self.loopback {
                loopback_up()?;
            }
            // Linux unshare grants capabilities in the NEW user namespace.
            // Prevent uid 0's exec fixups before clearing all capability sets.
            const NOROOT_LOCKED: libc::c_ulong = 1 | 2;
            if libc::prctl(libc::PR_SET_SECUREBITS, NOROOT_LOCKED, 0, 0, 0) != 0
                || libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL,
                    0,
                    0,
                    0,
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            struct Data {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let header = Header {
                version: 0x2008_0522,
                pid: 0,
            };
            let data = [
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
            ];
            if libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct ChildMapping {
    socket: std::os::unix::net::UnixStream,
    prepared: Prepared,
}

impl ChildMapping {
    /// # Safety
    /// Call only in the trusted child hook after std's outer uid/gid drop.
    pub(super) unsafe fn apply(&self) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        // SAFETY: raw checked syscalls over parent-prepared buffers only.
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                || libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut request = [0u8; 20];
            request[..4].copy_from_slice(&libc::getpid().to_ne_bytes());
            // Fresh per-fork correlation prevents a delayed acknowledgement
            // from an earlier failed spawn authorizing a reused command.
            if libc::syscall(libc::SYS_getrandom, request[4..].as_mut_ptr(), 16, 0) != 16 {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            if libc::write(
                self.socket.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
            ) != 20
            {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let mut ack = [0u8; 17];
            if libc::read(self.socket.as_raw_fd(), ack.as_mut_ptr().cast(), ack.len()) != 17
                || ack[16] != 1
                || ack[..16] != request[4..]
            {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            if libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            self.prepared.finish()
        }
    }
}

unsafe fn loopback_up() -> io::Result<()> {
    // SAFETY: a fresh namespace's fixed "lo" interface, initialized ifreq,
    // and a socket used only for these two ioctls and then closed.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut request: libc::ifreq = std::mem::zeroed();
        request.ifr_name[0] = b'l' as libc::c_char;
        request.ifr_name[1] = b'o' as libc::c_char;
        let mut result = libc::ioctl(fd, libc::SIOCGIFFLAGS, &raw mut request);
        if result == 0 {
            request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            result = libc::ioctl(fd, libc::SIOCSIFFLAGS, &raw const request);
        }
        let failure = if result != 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        let closed = libc::close(fd);
        if let Some(error) = failure {
            return Err(error);
        }
        if closed != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_namespace_probe() {
        let Ok(encoded) = std::env::var("NUCLEUS_NAMESPACE_TEST_UID") else {
            return;
        };
        let inner: u32 = encoded.parse().expect("expected inner uid");
        // SAFETY: read-only identity/prctl observations in the test child.
        assert_eq!(unsafe { libc::geteuid() }, inner);
        assert_eq!(unsafe { libc::getegid() }, inner);
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } & 3,
            3
        );
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
            let value = status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .expect("capability observation");
            assert_eq!(u64::from_str_radix(value.trim(), 16).unwrap(), 0);
        }
        let groups = status
            .lines()
            .find_map(|line| line.strip_prefix("Groups:"))
            .expect("groups observation");
        assert!(groups.trim().is_empty());
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _client = std::net::TcpStream::connect_timeout(
            &listener.local_addr().unwrap(),
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        let _peer = listener.accept().unwrap();
        let routes = std::fs::read_to_string("/proc/net/route").unwrap();
        assert!(
            routes
                .lines()
                .skip(1)
                .all(|line| line.split_whitespace().next() == Some("lo"))
        );
        println!(
            "\nNAMESPACE={}",
            std::fs::read_link("/proc/self/ns/net").unwrap().display()
        );
    }

    #[test]
    #[ignore = "requires a root Linux verification container with user namespaces enabled"]
    fn parent_mapping_keeps_child_nondumpable_before_exec() -> Result<(), Box<dyn std::error::Error>>
    {
        probe_setup()
    }

    #[test]
    #[ignore = "requires a root Linux verification container with user namespaces enabled"]
    fn mapping_refuses_a_different_outer_identity() -> io::Result<()> {
        use std::os::unix::process::CommandExt;
        // SAFETY: read-only test prerequisite.
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let mapping = Prepared::new(65533, 0, true).prepare()?;
        let mut command = std::process::Command::new("/usr/bin/true");
        command.uid(65534).gid(65534);
        // SAFETY: production hook after std's identity drop.
        unsafe {
            command.pre_exec(move || mapping.apply());
        }
        let error = command.spawn().expect_err("mismatched child must not exec");
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        Ok(())
    }

    #[test]
    #[ignore = "requires a root Linux verification container with user namespaces enabled"]
    fn stale_acknowledgement_cannot_start_child() -> io::Result<()> {
        use std::io::{Read, Write};
        use std::os::unix::process::CommandExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let (mut parent, child) = std::os::unix::net::UnixStream::pair()?;
        parent.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        child.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let peer = std::thread::spawn(move || -> io::Result<()> {
            let mut request = [0; 20];
            parent.read_exact(&mut request)?;
            let mut ack = [0; 17];
            ack[..16].copy_from_slice(&request[4..]);
            ack[0] ^= 1;
            ack[16] = 1;
            parent.write_all(&ack)
        });
        // 65534 is also the kernel's usual unmapped-ID observation: checking
        // just the observed uid cannot substitute for acknowledgement binding.
        let mapping = ChildMapping {
            socket: child,
            prepared: Prepared::new(65534, 65534, true),
        };
        let mut command = std::process::Command::new("/usr/bin/true");
        command.uid(65534).gid(65534);
        // SAFETY: production hook after std's identity drop.
        unsafe {
            command.pre_exec(move || mapping.apply());
        }
        let result = command.spawn();
        peer.join().expect("test acknowledgement peer")?;
        let error = match result {
            Err(error) => error,
            Ok(mut child) => {
                child.wait()?;
                panic!("stale acknowledgement must not exec");
            }
        };
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        Ok(())
    }

    fn probe_setup() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::{
            fs::{DirBuilderExt, PermissionsExt},
            process::CommandExt,
        };
        // SAFETY: read-only identity observation; no unsupported backend is
        // silently counted as a positive setup witness.
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "root verification backend required"
        );
        let original = std::fs::read_link("/proc/self/ns/net")?;
        for inner in [0, 1000] {
            // Use Linux's shared temporary directory, not an inherited TMPDIR
            // that may be a root-only build mount.
            let directory = std::path::Path::new("/tmp").join(format!(
                "nucleus-trusted-namespace-{}-{inner}",
                std::process::id()
            ));
            std::fs::DirBuilder::new().mode(0o755).create(&directory)?;
            // DirBuilder's mode is filtered by the verification runner's umask.
            // The dropped child must be able to traverse this test-only directory.
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
            struct Cleanup(std::path::PathBuf);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = std::fs::remove_dir_all(&self.0);
                }
            }
            let _cleanup = Cleanup(directory.clone());
            let binary = directory.join("probe");
            std::fs::copy(std::env::current_exe()?, &binary)?;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))?;
            let baseline = std::process::Command::new(&binary)
                .arg("--list")
                .uid(65534)
                .gid(65534)
                .current_dir("/")
                .output()
                .map_err(|error| io::Error::new(error.kind(), format!("baseline exec: {error}")))?;
            assert!(
                baseline.status.success(),
                "unprivileged baseline exec failed"
            );
            let prepared = Prepared::new(65534, inner, true);
            let mut command = std::process::Command::new(&binary);
            let module = module_path!()
                .split_once("::")
                .expect("nested test module")
                .1;
            command
                .args([
                    "--exact",
                    &format!("{module}::child_namespace_probe"),
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_clear()
                .env("NUCLEUS_NAMESPACE_TEST_UID", inner.to_string())
                .uid(65534)
                .gid(65534)
                .current_dir("/");
            let mapping = prepared.prepare()?;
            // SAFETY: production mapping hook, after std's outer identity drop.
            unsafe {
                command.pre_exec(move || mapping.apply());
            }
            let output = command.output();
            let output = output.map_err(|error| {
                io::Error::new(error.kind(), format!("spawn inner uid {inner}: {error}"))
            })?;
            assert!(
                output.status.success(),
                "probe failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout)?;
            let observed = stdout
                .lines()
                .find_map(|line| line.strip_prefix("NAMESPACE="))
                .expect("observed private namespace");
            assert_ne!(observed, original.to_str().expect("namespace link"));
        }
        Ok(())
    }

    #[test]
    fn maps_exactly_one_outer_identity() {
        for (outer, inner) in [(65534, 0), (65534, 1000), (u32::MAX - 1, u32::MAX - 1)] {
            let prepared = Prepared::new(outer, inner, true);
            assert_eq!(
                &prepared.bytes[..prepared.length],
                format!("{inner} {outer} 1\n").as_bytes()
            );
        }
    }
}
