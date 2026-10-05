//! Ordinary UDP uploads/downloads against the production namespace queue.
//! Run ignored tests on a disposable Linux host with CAP_SYS_ADMIN,
//! CAP_NET_ADMIN, writable /proc/sys, iproute2, iptables and ip6tables.
use super::*;
use portcullis::{EgressCeiling, EgressPace};
use std::sync::atomic::{AtomicU8, Ordering};

struct Network(NetPlan);
static NEXT: AtomicU8 = AtomicU8::new(0);

impl Drop for Network {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["link", "del", &self.0.host_veth])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", &self.0.netns])
            .status();
    }
}

async fn ip(args: &[&str]) {
    let out = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

impl Network {
    async fn new() -> Self {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .try_init();
        let id = uuid::Uuid::new_v4();
        let mut plan = crate::net::NetworkAllocator::new()
            .allocate(id, crate::net::netns_name(id))
            .unwrap();
        let index = NEXT.fetch_add(1, Ordering::SeqCst);
        plan.host_ip = std::net::Ipv4Addr::new(198, 18, index, 1);
        plan.peer_ip = std::net::Ipv4Addr::new(198, 18, index, 2);
        let net = Self(plan);
        let p = &net.0;
        ip(&["netns", "add", &p.netns]).await;
        ip(&[
            "netns",
            "exec",
            &p.netns,
            "sysctl",
            "-w",
            "net.ipv6.conf.all.disable_ipv6=1",
        ])
        .await;
        ip(&[
            "link",
            "add",
            &p.host_veth,
            "type",
            "veth",
            "peer",
            "name",
            &p.peer_veth,
            "netns",
            &p.netns,
        ])
        .await;
        ip(&[
            "addr",
            "add",
            &format!("{}/30", p.host_ip),
            "dev",
            &p.host_veth,
        ])
        .await;
        ip(&["link", "set", &p.host_veth, "up"]).await;
        ip(&[
            "-n",
            &p.netns,
            "addr",
            "add",
            &format!("{}/30", p.peer_ip),
            "dev",
            &p.peer_veth,
        ])
        .await;
        ip(&["-n", &p.netns, "link", "set", &p.peer_veth, "up"]).await;
        net
    }

    fn send(
        &self,
        address: std::net::SocketAddr,
        bytes: usize,
        download: bool,
    ) -> tokio::process::Child {
        tokio::process::Command::new("ip")
            .args(["netns", "exec", &self.0.netns])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "egress_link::linux_tests::namespace_udp_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("NUCLEUS_PACKET_FIXTURE_ADDR", address.to_string())
            .env("NUCLEUS_PACKET_FIXTURE_BYTES", bytes.to_string())
            .env(
                "NUCLEUS_PACKET_FIXTURE_DOWNLOAD",
                if download { "1" } else { "0" },
            )
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }
}

#[test]
#[ignore = "subprocess fixture for the ordinary namespace tests"]
fn namespace_udp_fixture() {
    let address = std::env::var("NUCLEUS_PACKET_FIXTURE_ADDR").unwrap();
    let bytes: usize = std::env::var("NUCLEUS_PACKET_FIXTURE_BYTES")
        .unwrap()
        .parse()
        .unwrap();
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.send_to(&vec![b'x'; bytes], address).unwrap();
    if std::env::var("NUCLEUS_PACKET_FIXTURE_DOWNLOAD").unwrap() == "1" {
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut response = [0; 4096];
        assert_eq!(socket.recv(&mut response).unwrap(), 4096);
        assert!(response.iter().all(|b| *b == b'd'));
    }
}

#[test]
#[ignore = "subprocess fixture for the ordinary TCP upload"]
fn namespace_tcp_fixture() {
    use std::io::Write;
    let address = std::env::var("NUCLEUS_PACKET_FIXTURE_ADDR").unwrap();
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream.write_all(&vec![b't'; 128 * 1024]).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
}

fn meter(dir: &std::path::Path, max: u64, pace: EgressPace) -> Arc<EgressMeter> {
    EgressMeter::new(
        EgressCeiling::new(max, pace),
        dir.into(),
        "live-packets".into(),
    )
}

async fn receive(socket: &tokio::net::UdpSocket) -> (usize, std::net::SocketAddr) {
    let mut body = [0; 2048];
    tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut body))
        .await
        .unwrap()
        .unwrap()
}

async fn absent(socket: &tokio::net::UdpSocket) {
    let mut body = [0; 2048];
    assert!(
        tokio::time::timeout(Duration::from_millis(250), socket.recv_from(&mut body))
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires isolated privileged Linux networking"]
async fn ordinary_upload_download_and_shared_total_use_kernel_admission() {
    let net = Network::new().await;
    let dir = tempfile::tempdir().unwrap();
    let meter = meter(dir.path(), 200, EgressPace::Unpaced);
    let mut monitor = LinkMonitor::start(&net.0, meter.clone()).await.unwrap();
    let sink = tokio::net::UdpSocket::bind((net.0.host_ip, 0))
        .await
        .unwrap();
    meter.admit(100, crate::now_unix()).await.unwrap().sent();
    let mut child = net.send(sink.local_addr().unwrap(), 15, true);
    let (len, from) = receive(&sink).await;
    assert_eq!(len, 15);
    sink.send_to(&[b'd'; 4096], from).await.unwrap();
    assert!(child.wait().await.unwrap().success());
    assert_eq!(
        meter.counted(),
        143,
        "100 broker bytes + 43 IP/UDP bytes; download is free"
    );
    let mut child = net.send(sink.local_addr().unwrap(), 100, false);
    assert!(child.wait().await.unwrap().success());
    absent(&sink).await;
    assert_eq!(meter.counted(), 143, "oversized packet was never admitted");
    monitor.shutdown().await.unwrap();
    // The queue rule persists without a receiver and continues dropping.
    let mut child = net.send(sink.local_addr().unwrap(), 1, false);
    assert!(child.wait().await.unwrap().success());
    absent(&sink).await;
    println!("ordinary upload/download: 43 IP bytes + 100 broker bytes; total never exceeded 200");
}

#[tokio::test]
#[ignore = "requires isolated privileged Linux networking"]
async fn ordinary_paced_uploads_resume_after_the_window() {
    let net = Network::new().await;
    let dir = tempfile::tempdir().unwrap();
    let meter = meter(
        dir.path(),
        1000,
        EgressPace::PerWindow {
            bytes: 78,
            window_secs: 2.try_into().unwrap(),
        },
    );
    let mut monitor = LinkMonitor::start(&net.0, meter.clone()).await.unwrap();
    let sink = tokio::net::UdpSocket::bind((net.0.host_ip, 0))
        .await
        .unwrap();
    for expected in [true, false] {
        let mut child = net.send(sink.local_addr().unwrap(), 50, false);
        assert!(child.wait().await.unwrap().success());
        if expected {
            assert_eq!(receive(&sink).await.0, 50);
        } else {
            absent(&sink).await;
        }
    }
    assert_eq!(meter.counted(), 78);
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let mut child = net.send(sink.local_addr().unwrap(), 50, false);
    assert!(child.wait().await.unwrap().success());
    assert_eq!(receive(&sink).await.0, 50);
    assert_eq!(meter.counted(), 156);
    monitor.shutdown().await.unwrap();
    println!(
        "ordinary paced uploads: first accepted, next window-excess dropped, later upload accepted"
    );
}

#[tokio::test]
#[ignore = "requires isolated privileged Linux networking"]
async fn ordinary_tcp_upload_larger_than_one_window_completes() {
    use tokio::io::AsyncReadExt;
    let net = Network::new().await;
    let dir = tempfile::tempdir().unwrap();
    let meter = meter(
        dir.path(),
        512 * 1024,
        EgressPace::PerWindow {
            bytes: 32 * 1024,
            window_secs: 1.try_into().unwrap(),
        },
    );
    let mut monitor = LinkMonitor::start(&net.0, meter.clone()).await.unwrap();
    let sink = tokio::net::TcpListener::bind((net.0.host_ip, 0))
        .await
        .unwrap();
    let start = tokio::time::Instant::now();
    let mut child = tokio::process::Command::new("ip")
        .args(["netns", "exec", &net.0.netns])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "egress_link::linux_tests::namespace_tcp_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env(
            "NUCLEUS_PACKET_FIXTURE_ADDR",
            sink.local_addr().unwrap().to_string(),
        )
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let body = tokio::time::timeout(Duration::from_secs(30), async {
        let (stream, _) = sink.accept().await.unwrap();
        let mut body = Vec::new();
        stream
            .take(128 * 1024 + 1)
            .read_to_end(&mut body)
            .await
            .unwrap();
        body
    })
    .await
    .unwrap();
    assert!(child.wait().await.unwrap().success());
    assert_eq!(body, vec![b't'; 128 * 1024]);
    assert!(
        start.elapsed() >= Duration::from_secs(2),
        "upload must span multiple pace windows"
    );
    assert!(meter.counted() >= 128 * 1024);
    assert!(meter.counted() <= 512 * 1024);
    monitor.shutdown().await.unwrap();
    println!(
        "ordinary TCP upload completed: {} payload bytes, {} charged IP bytes, {:?}",
        body.len(),
        meter.counted(),
        start.elapsed()
    );
}
