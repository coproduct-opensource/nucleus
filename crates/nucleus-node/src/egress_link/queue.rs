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

fn byte(value: i32) -> io::Result<u8> {
    u8::try_from(value).map_err(io::Error::other)
}

fn attribute(typ: i32, payload: &[u8]) -> io::Result<Vec<u8>> {
    let size = payload
        .len()
        .checked_add(4)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(|| invalid("netlink attribute exceeds its length field"))?;
    let typ = u16::try_from(typ).map_err(io::Error::other)?;
    let aligned = usize::from(size).next_multiple_of(4);
    let mut bytes = Vec::with_capacity(aligned);
    bytes.extend_from_slice(&size.to_ne_bytes());
    bytes.extend_from_slice(&typ.to_ne_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(aligned, 0);
    Ok(bytes)
}

fn message(typ: i32, sequence: u32, ack: bool, attrs: &[u8]) -> io::Result<Vec<u8>> {
    let size = (HEADER + 4)
        .checked_add(attrs.len())
        .ok_or_else(|| invalid("netlink message length overflows"))?;
    let wire_size = u32::try_from(size).map_err(io::Error::other)?;
    let typ = (u16::from(byte(libc::NFNL_SUBSYS_QUEUE)?) << 8) | u16::from(byte(typ)?);
    let flags = u16::try_from(libc::NLM_F_REQUEST | if ack { libc::NLM_F_ACK } else { 0 })
        .map_err(io::Error::other)?;
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&wire_size.to_ne_bytes());
    bytes.extend_from_slice(&typ.to_ne_bytes());
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&sequence.to_ne_bytes());
    bytes.extend_from_slice(&0u32.to_ne_bytes());
    bytes.extend_from_slice(&[byte(libc::AF_UNSPEC)?, byte(libc::NFNETLINK_V0)?]);
    bytes.extend_from_slice(&QUEUE.to_be_bytes());
    bytes.extend_from_slice(attrs);
    Ok(bytes)
}

fn attributes(mut bytes: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid("short netlink attribute"));
        }
        let len = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
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
        || ![libc::AF_INET, libc::AF_INET6].contains(&i32::from(bytes[0]))
    {
        return Err(invalid("unexpected queue packet header"));
    }
    let mut id = None;
    let mut length = None;
    for (typ, value) in attributes(&bytes[4..])? {
        match i32::from(typ) {
            libc::NFQA_PACKET_HDR => {
                if value.len() != 7
                    || i32::from(value[6]) != libc::NF_INET_POST_ROUTING
                    || id.is_some()
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
                    let mut socket = Socket::new(
                        isize::try_from(libc::NETLINK_NETFILTER).map_err(io::Error::other)?,
                    )?;
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
                &[byte(libc::NFQNL_CFG_CMD_BIND)?, 0, 0, 0],
            )?)
            .await?;
        let mut params = 1u32.to_be_bytes().to_vec();
        params.push(byte(libc::NFQNL_COPY_PACKET)?);
        let mut attrs = attribute(libc::NFQA_CFG_PARAMS, &params)?;
        attrs.extend(attribute(
            libc::NFQA_CFG_QUEUE_MAXLEN,
            &u32::try_from(CAPACITY)
                .map_err(io::Error::other)?
                .to_be_bytes(),
        )?);
        // No fail-open, no GSO super-packets: the kernel segments before admission.
        attrs.extend(attribute(
            libc::NFQA_CFG_MASK,
            &u32::try_from(libc::NFQA_CFG_F_FAIL_OPEN | libc::NFQA_CFG_F_GSO)
                .map_err(io::Error::other)?
                .to_be_bytes(),
        )?);
        attrs.extend(attribute(libc::NFQA_CFG_FLAGS, &0u32.to_be_bytes())?);
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
            if let Ok(result) = ready.try_io(|socket| {
                let mut bytes = Vec::with_capacity(8192);
                let (len, from) = socket.get_ref().recv_from(&mut bytes, libc::MSG_TRUNC)?;
                if len > bytes.len() || from.port_number() != 0 {
                    return Err(invalid("truncated or non-kernel netlink message"));
                }
                Ok(bytes)
            }) {
                return result;
            }
        }
    }

    fn parse(&mut self, mut bytes: &[u8], expected_ack: Option<u32>) -> io::Result<bool> {
        let mut acknowledged = false;
        while !bytes.is_empty() {
            if bytes.len() < HEADER {
                return Err(invalid("short netlink header"));
            }
            let len = usize::try_from(u32::from_ne_bytes(
                bytes[..4].try_into().map_err(io::Error::other)?,
            ))
            .map_err(io::Error::other)?;
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
            self.send(&message(libc::NFQNL_MSG_CONFIG, sequence, true, &attrs)?)
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
            &attribute(libc::NFQA_VERDICT_HDR, &payload)?,
        )?)
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
        let result = self
            .verdict(
                packet,
                u32::try_from(libc::NF_ACCEPT).map_err(io::Error::other)?,
            )
            .await;
        // An attempted verdict may have reached the kernel. Never refund it.
        charge.sent();
        result
    }
    async fn reject(&mut self, packet: Packet) -> io::Result<()> {
        self.verdict(
            packet,
            u32::try_from(libc::NF_DROP).map_err(io::Error::other)?,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_preserves_wire_fields_and_refuses_unrepresentable_inputs() {
        let attrs = attribute(libc::NFQA_CFG_FLAGS, &[1, 2, 3]).unwrap();
        assert_eq!(attributes(&attrs).unwrap()[0].1, &[1, 2, 3]);
        let encoded = message(libc::NFQNL_MSG_CONFIG, 37, true, &attrs).unwrap();
        assert_eq!(encoded.len(), HEADER + 4 + attrs.len());
        assert_eq!(u32::from_ne_bytes(encoded[..4].try_into().unwrap()), 28);
        assert_eq!(u32::from_ne_bytes(encoded[8..12].try_into().unwrap()), 37);
        assert_eq!(&encoded[HEADER + 4..], attrs);
        assert!(attribute(-1, &[]).is_err());
        assert!(attribute(65536, &[]).is_err());
        assert!(attribute(1, &vec![0; 65532]).is_err());
        assert!(message(-1, 0, false, &[]).is_err());
        assert!(message(256, 0, false, &[]).is_err());
    }

    #[test]
    fn kernel_packet_metadata_can_end_without_alignment_padding() {
        let mut bytes = vec![byte(libc::AF_INET).unwrap(), 0, 0, 0];
        let mut header = 37u32.to_be_bytes().to_vec();
        header.extend([8, 0, byte(libc::NF_INET_POST_ROUTING).unwrap()]);
        bytes.extend(attribute(libc::NFQA_PACKET_HDR, &header).unwrap());
        bytes.extend(attribute(libc::NFQA_CAP_LEN, &43u32.to_be_bytes()).unwrap());
        let mut payload = attribute(libc::NFQA_PAYLOAD, &[0x45]).unwrap();
        payload.truncate(5); // The kernel's final one-byte copy has no padding.
        bytes.extend(payload);
        let decoded = packet(&bytes).unwrap();
        assert_eq!(decoded.id, 37);
        assert_eq!(decoded.bytes, 43);
    }
}
