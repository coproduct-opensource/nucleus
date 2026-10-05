//! Minimal NFQUEUE netlink transport. Only packet metadata is copied; packet
//! bytes stay in the kernel. Constants come from Linux's UAPI through libc.
//! Socket ownership provides close-on-exec and drops the binding on failure.

use netlink_sys::{Socket, SocketAddr};
use std::{collections::VecDeque, io, time::Duration};
use tokio::io::unix::AsyncFd;

use super::PacketQueue;
use crate::egress_meter::EgressCharge;

const QUEUE: u16 = 0; // Each pod has its own network namespace.
const HEADER: usize = 16;
const CAPACITY: usize = 1024;

/// Not Clone: the kernel packet gets one verdict, consumed by value (C-4).
pub(super) struct Packet {
    id: u32,
    bytes: u64,
}

pub(super) struct Queue {
    socket: AsyncFd<Socket>,
    sequence: u32,
    pending: VecDeque<Packet>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn attribute(typ: i32, payload: &[u8]) -> Vec<u8> {
    let size = 4 + payload.len();
    let mut bytes = Vec::with_capacity(size.next_multiple_of(4));
    bytes.extend_from_slice(&(size as u16).to_ne_bytes());
    bytes.extend_from_slice(&(typ as u16).to_ne_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(size.next_multiple_of(4), 0);
    bytes
}

fn message(typ: i32, sequence: u32, ack: bool, attrs: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + 4 + attrs.len());
    bytes.extend_from_slice(&((HEADER + 4 + attrs.len()) as u32).to_ne_bytes());
    bytes.extend_from_slice(&(((libc::NFNL_SUBSYS_QUEUE << 8) | typ) as u16).to_ne_bytes());
    let flags = libc::NLM_F_REQUEST | if ack { libc::NLM_F_ACK } else { 0 };
    bytes.extend_from_slice(&(flags as u16).to_ne_bytes());
    bytes.extend_from_slice(&sequence.to_ne_bytes());
    bytes.extend_from_slice(&0u32.to_ne_bytes());
    bytes.extend_from_slice(&[libc::AF_UNSPEC as u8, libc::NFNETLINK_V0 as u8]);
    bytes.extend_from_slice(&QUEUE.to_be_bytes());
    bytes.extend_from_slice(attrs);
    bytes
}

fn attributes(mut bytes: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid("short netlink attribute"));
        }
        let len = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        let typ = u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff;
        if len < 4 || len > bytes.len() {
            return Err(invalid("invalid netlink attribute size"));
        }
        result.push((typ, &bytes[4..len]));
        let aligned = len.next_multiple_of(4);
        bytes = if len == bytes.len() {
            &[] // Linux may omit alignment padding after the final attribute.
        } else {
            bytes
                .get(aligned..)
                .ok_or_else(|| invalid("missing netlink attribute padding"))?
        };
    }
    Ok(result)
}

fn packet(bytes: &[u8]) -> io::Result<Packet> {
    if bytes.len() < 4
        || bytes[1] != 0
        || bytes[2..4] != QUEUE.to_be_bytes()
        || ![libc::AF_INET as u8, libc::AF_INET6 as u8].contains(&bytes[0])
    {
        return Err(invalid("unexpected queue packet header"));
    }
    let mut id = None;
    let mut length = None;
    for (typ, value) in attributes(&bytes[4..])? {
        match i32::from(typ) {
            libc::NFQA_PACKET_HDR => {
                if value.len() != 7 || value[6] != libc::NF_INET_POST_ROUTING as u8 || id.is_some()
                {
                    return Err(invalid("unexpected packet hook or header"));
                }
                id = Some(u32::from_be_bytes(
                    value[..4].try_into().map_err(io::Error::other)?,
                ));
            }
            libc::NFQA_CAP_LEN => {
                if length.is_some() {
                    return Err(invalid("duplicate packet length"));
                }
                length = Some(u32::from_be_bytes(
                    value.try_into().map_err(io::Error::other)?,
                ));
            }
            // Other metadata does not affect the kernel-reported length.
            _ => {}
        }
    }
    // Copy range is one byte. Every IP packet is longer, so CAP_LEN must exist.
    let bytes = length
        .filter(|n| *n >= 20)
        .ok_or_else(|| invalid("missing original IP length"))?;
    Ok(Packet {
        id: id.ok_or_else(|| invalid("missing packet id"))?,
        bytes: u64::from(bytes),
    })
}

impl Queue {
    pub async fn open(namespace: &str) -> io::Result<Self> {
        let namespace =
            std::fs::File::open(std::path::Path::new("/var/run/netns").join(namespace))?;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        // Never setns on a Tokio or blocking-pool thread: it could later run
        // unrelated work. This dedicated OS thread terminates after socket creation.
        std::thread::Builder::new()
            .name("pod-netqueue".into())
            .spawn(move || {
                let opened: io::Result<Socket> = (|| {
                    nix::sched::setns(&namespace, nix::sched::CloneFlags::CLONE_NEWNET)
                        .map_err(io::Error::from)?;
                    let mut socket = Socket::new(libc::NETLINK_NETFILTER as isize)?;
                    socket.bind_auto()?;
                    socket.connect(&SocketAddr::new(0, 0))?;
                    socket.set_non_blocking(true)?;
                    Ok(socket)
                })();
                let _ = sender.send(opened);
            })?;
        let socket = receiver.await.map_err(io::Error::other)??;
        let mut queue = Self {
            socket: AsyncFd::new(socket)?,
            sequence: 0,
            pending: VecDeque::new(),
        };
        queue
            .configure(attribute(
                libc::NFQA_CFG_CMD,
                &[libc::NFQNL_CFG_CMD_BIND as u8, 0, 0, 0],
            ))
            .await?;
        let mut params = 1u32.to_be_bytes().to_vec();
        params.push(libc::NFQNL_COPY_PACKET as u8);
        let mut attrs = attribute(libc::NFQA_CFG_PARAMS, &params);
        attrs.extend(attribute(
            libc::NFQA_CFG_QUEUE_MAXLEN,
            &(CAPACITY as u32).to_be_bytes(),
        ));
        // No fail-open, no GSO super-packets: the kernel segments before admission.
        attrs.extend(attribute(
            libc::NFQA_CFG_MASK,
            &((libc::NFQA_CFG_F_FAIL_OPEN | libc::NFQA_CFG_F_GSO) as u32).to_be_bytes(),
        ));
        attrs.extend(attribute(libc::NFQA_CFG_FLAGS, &0u32.to_be_bytes()));
        queue.configure(attrs).await?;
        Ok(queue)
    }

    async fn send(&self, bytes: &[u8]) -> io::Result<()> {
        loop {
            let mut ready = self.socket.writable().await?;
            match ready.try_io(|socket| socket.get_ref().send(bytes, 0)) {
                Ok(Ok(n)) if n == bytes.len() => return Ok(()),
                Ok(Ok(_)) => return Err(invalid("short netlink send")),
                Ok(Err(err)) => return Err(err),
                Err(_) => {}
            }
        }
    }

    async fn receive(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut ready = self.socket.readable().await?;
            match ready.try_io(|socket| {
                let mut bytes = Vec::with_capacity(8192);
                let (len, from) = socket.get_ref().recv_from(&mut bytes, libc::MSG_TRUNC)?;
                if len > bytes.len() || from.port_number() != 0 {
                    return Err(invalid("truncated or non-kernel netlink message"));
                }
                Ok(bytes)
            }) {
                Ok(result) => return result,
                Err(_) => {}
            }
        }
    }

    fn parse(&mut self, mut bytes: &[u8], expected_ack: Option<u32>) -> io::Result<bool> {
        let mut acknowledged = false;
        while !bytes.is_empty() {
            if bytes.len() < HEADER {
                return Err(invalid("short netlink header"));
            }
            let len = u32::from_ne_bytes(bytes[..4].try_into().map_err(io::Error::other)?) as usize;
            if len < HEADER || len > bytes.len() {
                return Err(invalid("invalid netlink message size"));
            }
            let typ = u16::from_ne_bytes(bytes[4..6].try_into().map_err(io::Error::other)?);
            let seq = u32::from_ne_bytes(bytes[8..12].try_into().map_err(io::Error::other)?);
            let body = &bytes[HEADER..len];
            match i32::from(typ) {
                libc::NLMSG_ERROR => {
                    let errno = i32::from_ne_bytes(
                        body.get(..4)
                            .ok_or_else(|| invalid("short ACK"))?
                            .try_into()
                            .map_err(io::Error::other)?,
                    );
                    if errno != 0 {
                        return Err(io::Error::from_raw_os_error(
                            errno
                                .checked_neg()
                                .ok_or_else(|| invalid("invalid ACK errno"))?,
                        ));
                    }
                    if Some(seq) != expected_ack {
                        return Err(invalid("unexpected netlink ACK"));
                    }
                    acknowledged = true;
                }
                n if n == (libc::NFNL_SUBSYS_QUEUE << 8) | libc::NFQNL_MSG_PACKET => {
                    if self.pending.len() == CAPACITY {
                        return Err(invalid("packet metadata queue full"));
                    }
                    self.pending.push_back(packet(body)?);
                }
                _ => return Err(invalid("unexpected netlink message")),
            }
            bytes = if len == bytes.len() {
                &[]
            } else {
                bytes
                    .get(len.next_multiple_of(4)..)
                    .ok_or_else(|| invalid("missing netlink padding"))?
            };
        }
        Ok(acknowledged)
    }

    async fn configure(&mut self, attrs: Vec<u8>) -> io::Result<()> {
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;
        tokio::time::timeout(Duration::from_secs(5), async {
            self.send(&message(libc::NFQNL_MSG_CONFIG, sequence, true, &attrs))
                .await?;
            loop {
                let bytes = self.receive().await?;
                if self.parse(&bytes, Some(sequence))? {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(io::Error::other)?
    }

    async fn verdict(&self, packet: Packet, verdict: u32) -> io::Result<()> {
        let mut payload = verdict.to_be_bytes().to_vec();
        payload.extend(packet.id.to_be_bytes());
        self.send(&message(
            libc::NFQNL_MSG_VERDICT,
            0,
            false,
            &attribute(libc::NFQA_VERDICT_HDR, &payload),
        ))
        .await
    }
}

#[tonic::async_trait]
impl PacketQueue for Queue {
    type Packet = Packet;
    fn bytes(packet: &Packet) -> u64 {
        packet.bytes
    }
    async fn next(&mut self) -> io::Result<Packet> {
        loop {
            if let Some(packet) = self.pending.pop_front() {
                return Ok(packet);
            }
            let bytes = self.receive().await?;
            self.parse(&bytes, None)?;
        }
    }
    async fn accept(&mut self, packet: Packet, charge: EgressCharge<'_>) -> io::Result<()> {
        let result = self.verdict(packet, libc::NF_ACCEPT as u32).await;
        // An attempted verdict may have reached the kernel. Never refund it.
        charge.sent();
        result
    }
    async fn reject(&mut self, packet: Packet) -> io::Result<()> {
        self.verdict(packet, libc::NF_DROP as u32).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_packet_metadata_can_end_without_alignment_padding() {
        let mut bytes = vec![libc::AF_INET as u8, 0, 0, 0];
        let mut header = 37u32.to_be_bytes().to_vec();
        header.extend([8, 0, libc::NF_INET_POST_ROUTING as u8]);
        bytes.extend(attribute(libc::NFQA_PACKET_HDR, &header));
        bytes.extend(attribute(libc::NFQA_CAP_LEN, &43u32.to_be_bytes()));
        let mut payload = attribute(libc::NFQA_PAYLOAD, &[0x45]);
        payload.truncate(5); // The kernel's final one-byte copy has no padding.
        bytes.extend(payload);
        let decoded = packet(&bytes).unwrap();
        assert_eq!(decoded.id, 37);
        assert_eq!(decoded.bytes, 43);
    }
}
