//! tun -> userspace TCP/IP bridge.
//!
//! Android hands us a file descriptor for the VPN interface. This module pumps
//! IP packets between that descriptor and a smoltcp stack, learns new TCP flows
//! from the SYN packets the app emits, dials the destination directly, and
//! relays payloads through [`crate::flow::Flow`] for dissection.
//!
//! Read-only by construction: the bridge has no API to rewrite a payload. Bytes
//! the app sends are the bytes that leave; bytes the remote sends are the bytes
//! the app receives.

use crate::dissect;
use crate::events::{emit, hex_preview, now_ms, AppProtocol, Direction, FlowEvent};
use crate::flow::{Flow, FlowKey};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::storage::PacketMetadata;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A TCP flow observed on the tun device.
#[derive(Debug, Clone, Copy)]
pub struct SynTuple {
    pub client: SocketAddr,
    pub remote: SocketAddr,
}

pub struct TunConfig {
    /// Interface address the tun side sees, e.g. 10.233.0.1/24.
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub mtu: usize,
    /// Resolver address handed to the app; UDP:53 here is relayed upstream.
    pub dns_listen: Ipv4Addr,
    /// Where relayed DNS queries are actually sent.
    pub dns_upstream: SocketAddr,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::new(10, 233, 0, 1),
            prefix: 24,
            mtu: 1500,
            dns_listen: Ipv4Addr::new(10, 233, 0, 2),
            dns_upstream: SocketAddr::from(([1, 1, 1, 1], 53)),
        }
    }
}

/// Run the bridge until `shutdown` is set. Returns on the first fatal error.
pub fn run(fd: RawFd, cfg: TunConfig, shutdown: Arc<AtomicBool>) -> io::Result<()> {
    let syns: Arc<Mutex<Vec<SynTuple>>> = Arc::new(Mutex::new(Vec::new()));
    let mut device = TunDevice::new(fd, cfg.mtu, syns.clone());

    let mut config = IfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = 0x5eed_1234_abcd_ef01;
    let mut iface = Interface::new(config, &mut device, Instant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(ipv4(IpAddr::V4(cfg.address))), cfg.prefix));
    });
    // The app addresses packets to the real remote (say 203.0.113.10), not to
    // us. AnyIP plus a default route whose gateway is our own interface address
    // is smoltcp's transparent-proxy setup: those packets are treated as local,
    // so they reach the listening socket that answers them. Without this the
    // stack would drop them and RST the app.
    iface.set_any_ip(true);
    if iface
        .routes_mut()
        .add_default_ipv4_route(ipv4(IpAddr::V4(cfg.address)))
        .is_err()
    {
        return Err(io::Error::other("route table full"));
    }

    let mut sockets = SocketSet::new(Vec::new());
    let mut flows: HashMap<SocketHandle, FlowState> = HashMap::new();

    // DNS: Android sends queries to the resolver we advertise, as plain UDP to
    // the tun address. Terminate them here and relay upstream, because the
    // userspace stack has no UDP forwarding of its own.
    let dns_handle = {
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0u8; 4 * 1024]),
            udp::PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0u8; 4 * 1024]),
        );
        let endpoint = IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(ipv4(IpAddr::V4(cfg.dns_listen)))),
            port: 53,
        };
        socket.bind(endpoint).map_err(|err| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("cannot bind DNS relay on {}: {err}", cfg.dns_listen),
            )
        })?;
        sockets.add(socket)
    };
    let (dns_tx, dns_rx) = mpsc::channel::<(Vec<u8>, IpEndpoint)>();
    let dns_upstream = cfg.dns_upstream;

    while !shutdown.load(Ordering::Relaxed) {
        // Pull packet heads off the tun before polling, so a SYN's listener
        // exists by the time the stack processes that same SYN. The bytes stay
        // queued in the device and are still delivered to the stack.
        device.prefill(64);
        let learned = {
            let mut guard = syns.lock().unwrap();
            std::mem::take(&mut *guard)
        };
        for tuple in learned {
            if flows.len() >= MAX_FLOWS {
                break;
            }
            // Answer as the destination: bind a listener to the exact address
            // and port the app dialled, then complete the handshake on its
            // behalf. AnyIP makes the SYN reach us.
            let local = IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(ipv4(tuple.remote.ip()))),
                port: tuple.remote.port(),
            };
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
                tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
            );
            if socket.listen(local).is_err() {
                continue;
            }
            let handle = sockets.add(socket);
            flows.insert(handle, FlowState::new());
        }

        let _ = iface.poll(Instant::now(), &mut device, &mut sockets);

        // Relay established sockets.
        let mut retire = Vec::new();
        for (handle, state) in flows.iter_mut() {
            let socket = sockets.get_mut::<tcp::Socket>(*handle);

            if state.key.is_none() {
                match socket.state() {
                    tcp::State::Established => {
                        let (Some(local), Some(remote)) =
                            (socket.local_endpoint(), socket.remote_endpoint())
                        else {
                            continue;
                        };
                        let (Some(client), Some(target)) =
                            (to_socket_addr(remote), to_socket_addr(local))
                        else {
                            socket.abort();
                            retire.push(*handle);
                            continue;
                        };
                        let key = FlowKey::new(client, target);
                        state.key = Some(key.clone());
                        state.flow = Some(Flow::new(key));
                        let (tx, rx) = mpsc::channel();
                        thread::spawn(move || {
                            let _ =
                                tx.send(TcpStream::connect_timeout(&target, Duration::from_secs(8)));
                        });
                        state.pending = Some(rx);
                    }
                    tcp::State::Closed => retire.push(*handle),
                    // An unclaimed listener must not hold a slot forever.
                    _ if state.created.elapsed() > Duration::from_secs(10) => {
                        retire.push(*handle)
                    }
                    _ => {}
                }
                continue;
            }

            if let Some(rx) = &state.pending {
                match rx.try_recv() {
                    Ok(Ok(stream)) => {
                        let _ = stream.set_nonblocking(true);
                        let _ = stream.set_nodelay(true);
                        state.upstream = Some(stream);
                        state.pending = None;
                    }
                    Ok(Err(_)) | Err(TryRecvError::Disconnected) => {
                        socket.abort();
                        state.pending = None;
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }

            let Some(upstream) = state.upstream.as_mut() else {
                continue;
            };

            // remote -> app
            let mut chunk = vec![0u8; 16 * 1024];
            loop {
                match upstream.read(&mut chunk) {
                    Ok(0) => {
                        // Half-close: the FIN must reach the stack before the
                        // socket is dropped, so retire on Closed, not here.
                        socket.close();
                        break;
                    }
                    Ok(n) => {
                        if let Some(flow) = state.flow.as_mut() {
                            flow.on_chunk(Direction::Server, &chunk[..n]);
                        }
                        if socket.can_send() && socket.send_slice(&chunk[..n]).is_err() {
                            break;
                        }
                        if n < chunk.len() {
                            break;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        socket.abort();
                        retire.push(*handle);
                        break;
                    }
                }
            }

            // app -> remote
            while socket.can_recv() {
                let mut payload = Vec::new();
                let _ = socket.recv(|buf| {
                    payload.extend_from_slice(buf);
                    (buf.len(), ())
                });
                if payload.is_empty() {
                    break;
                }
                if let Some(flow) = state.flow.as_mut() {
                    flow.on_chunk(Direction::Client, &payload);
                }
                if upstream.write_all(&payload).is_err() {
                    socket.abort();
                    retire.push(*handle);
                    break;
                }
            }

            if socket.state() == tcp::State::Closed {
                retire.push(*handle);
            }
        }

        for handle in retire {
            flows.remove(&handle);
            sockets.remove(handle);
        }

        // DNS queries: label them, then relay without blocking the poll loop.
        {
            let socket = sockets.get_mut::<udp::Socket>(dns_handle);
            let mut buf = vec![0u8; 2048];
            while let Ok((n, meta)) = socket.recv_slice(&mut buf) {
                let query = buf[..n].to_vec();
                emit_dns_query(&query, meta.endpoint);
                let tx = dns_tx.clone();
                let client = meta.endpoint;
                thread::spawn(move || {
                    if let Some(answer) = forward_dns(&query, dns_upstream) {
                        let _ = tx.send((answer, client));
                    }
                });
            }
            while let Ok((answer, client)) = dns_rx.try_recv() {
                let _ = socket.send_slice(&answer, client);
            }
        }

        thread::sleep(Duration::from_millis(2));
    }

    Ok(())
}

struct FlowState {
    /// Set once the handshake completes and both endpoints are known.
    key: Option<FlowKey>,
    flow: Option<Flow>,
    upstream: Option<TcpStream>,
    pending: Option<Receiver<io::Result<TcpStream>>>,
    created: std::time::Instant,
}

impl FlowState {
    fn new() -> Self {
        Self {
            key: None,
            flow: None,
            upstream: None,
            pending: None,
            created: std::time::Instant::now(),
        }
    }
}

/// Upper bound on simultaneously tracked connections (claimed listeners plus
/// established relays), so a burst of SYNs cannot exhaust memory.
const MAX_FLOWS: usize = 256;

fn to_socket_addr(endpoint: IpEndpoint) -> Option<SocketAddr> {
    // IPv6 is not enabled in this build, so `IpAddress` has a single variant.
    match endpoint.addr {
        IpAddress::Ipv4(addr) => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                addr.0[0], addr.0[1], addr.0[2], addr.0[3],
            )),
            endpoint.port,
        )),
    }
}

/// Report a DNS question so the overlay shows names, not just addresses.
fn emit_dns_query(query: &[u8], from: IpEndpoint) {
    let Some(question) = dissect::dns_question(query) else {
        return;
    };
    emit(FlowEvent {
        ts_ms: now_ms(),
        host: question.name.clone(),
        port: 53,
        direction: Direction::Client,
        protocol: AppProtocol::Dns,
        op: "query".into(),
        summary: format!("DNS {} {}", question.name, question.qtype),
        detail: Some(serde_json::json!({
            "name": question.name,
            "qtype": question.qtype,
            "id": question.id,
        })),
        raw_hex: hex_preview(query, 128),
        bytes: query.len(),
        flow: format!("{from}>dns"),
    });
}

/// One blocking round trip per query, bounded by a timeout so a dead resolver
/// cannot wedge anything.
fn forward_dns(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    socket.send_to(query, upstream).ok()?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

fn ipv4(addr: IpAddr) -> Ipv4Address {    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Ipv4Address::new(o[0], o[1], o[2], o[3])
        }
        IpAddr::V6(_) => Ipv4Address::new(0, 0, 0, 0),
    }
}

struct TunDevice {
    fd: RawFd,
    mtu: usize,
    syns: Arc<Mutex<Vec<SynTuple>>>,
    /// Packets read ahead so their SYNs can be classified before polling.
    pending: VecDeque<Vec<u8>>,
}

impl TunDevice {
    fn new(fd: RawFd, mtu: usize, syns: Arc<Mutex<Vec<SynTuple>>>) -> Self {
        // Non-blocking reads keep the poll loop responsive.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        Self {
            fd,
            mtu,
            syns,
            pending: VecDeque::new(),
        }
    }

    /// Read up to `budget` packets into the pending queue, recording SYNs.
    fn prefill(&mut self, budget: usize) {
        for _ in 0..budget {
            match self.read_packet() {
                Some(packet) => self.pending.push_back(packet),
                None => break,
            }
        }
    }

    fn read_packet(&mut self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; self.mtu + 64];
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        if let Some(tuple) = parse_syn(&buf) {
            if let Ok(mut guard) = self.syns.lock() {
                if guard.len() < 1024 {
                    guard.push(tuple);
                }
            }
        }
        Some(buf)
    }
}

struct TunRx {
    bytes: Vec<u8>,
}

impl RxToken for TunRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut bytes = self.bytes;
        f(&mut bytes)
    }
}

struct TunTx {
    fd: RawFd,
    buf: Vec<u8>,
}

impl TxToken for TunTx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = self.buf;
        buf.resize(len, 0);
        let out = f(&mut buf);
        let mut written = 0;
        let mut stalls = 0;
        while written < len {
            let n = unsafe {
                libc::write(
                    self.fd,
                    buf[written..].as_ptr() as *const libc::c_void,
                    len - written,
                )
            };
            if n > 0 {
                written += n as usize;
                stalls = 0;
                continue;
            }
            // The tun fd is non-blocking, so a full queue reports EAGAIN. Drop
            // the packet only after a bounded wait, rather than at the first
            // sign of backpressure.
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock if stalls < 50 => {
                    stalls += 1;
                    thread::sleep(Duration::from_millis(1));
                }
                _ => break,
            }
        }
        out
    }
}

impl Device for TunDevice {
    type RxToken<'a> = TunRx where Self: 'a;
    type TxToken<'a> = TunTx where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let bytes = match self.pending.pop_front() {
            Some(packet) => packet,
            None => self.read_packet()?,
        };
        Some((
            TunRx { bytes },
            TunTx {
                fd: self.fd,
                buf: Vec::with_capacity(self.mtu),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTx {
            fd: self.fd,
            buf: Vec::with_capacity(self.mtu),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// Spot an outbound TCP SYN so the stack can be given a socket to match it.
fn parse_syn(packet: &[u8]) -> Option<SynTuple> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 20 {
        return None;
    }
    if packet[9] != 6 {
        return None; // TCP only
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let tcp = &packet[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    let is_syn = flags & 0x02 != 0;
    let is_ack = flags & 0x10 != 0;
    if !is_syn || is_ack {
        return None;
    }
    Some(SynTuple {
        client: SocketAddr::new(IpAddr::V4(src_ip), src_port),
        remote: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::set_sink;
    use std::net::TcpListener;

    fn ipv4_tcp_syn(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        // 20-byte IPv4 header (total length 40, protocol 6) + 20-byte TCP header.
        let mut p = vec![0x45, 0x00, 0x00, 0x28, 0, 1, 0, 0, 64, 6, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1]); // sequence number
        p.extend_from_slice(&[0, 0, 0, 0]); // acknowledgement number
        p.push(0x50); // data offset 5 words, no options
        p.push(flags); // flags
        p.extend_from_slice(&[0xff, 0xff]); // window
        p.extend_from_slice(&[0, 0]); // checksum
        p.extend_from_slice(&[0, 0]); // urgent pointer
        p
    }

    #[test]
    fn learns_outbound_syn_only() {
        let syn = ipv4_tcp_syn([10, 233, 0, 2], [1, 1, 1, 1], 40000, 443, 0x02);
        let tuple = parse_syn(&syn).expect("SYN should be learned");
        assert_eq!(tuple.remote.to_string(), "1.1.1.1:443");
        assert_eq!(tuple.client.port(), 40000);

        let synack = ipv4_tcp_syn([1, 1, 1, 1], [10, 233, 0, 2], 443, 40000, 0x12);
        assert!(parse_syn(&synack).is_none(), "SYN-ACK is inbound, not a new flow");

        let ack = ipv4_tcp_syn([10, 233, 0, 2], [1, 1, 1, 1], 40000, 443, 0x10);
        assert!(parse_syn(&ack).is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_syn(&[]).is_none());
        assert!(parse_syn(&[0x60, 0, 0, 0]).is_none(), "IPv6 is out of scope");
        assert!(parse_syn(&[0x45, 0, 0, 0]).is_none());
    }

    // ---- integration: the tun bridge over a datagram socket pair -------------

    const APP_IP: [u8; 4] = [10, 233, 0, 2];
    const APP_PORT: u16 = 40000;
    const ISN: u32 = 1000;

    fn internet_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut chunks = data.chunks_exact(2);
        for c in &mut chunks {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += (last as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Build a checksum-correct IPv4/TCP segment, since the stack verifies them.
    fn tcp_segment(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + 20 + payload.len();
        let mut tcp = Vec::with_capacity(20 + payload.len());
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&ack.to_be_bytes());
        tcp.push(0x50);
        tcp.push(flags);
        tcp.extend_from_slice(&8192u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0]); // checksum placeholder
        tcp.extend_from_slice(&[0, 0]); // urgent pointer
        tcp.extend_from_slice(payload);

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src);
        pseudo.extend_from_slice(&dst);
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        pseudo.extend_from_slice(&tcp);
        let tcp_sum = internet_checksum(&pseudo);
        tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());

        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&(total_len as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        let ip_sum = internet_checksum(&ip);
        ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        ip.extend_from_slice(&tcp);
        ip
    }

    struct Segment {
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: Vec<u8>,
    }

    fn parse_segment(packet: &[u8]) -> Option<Segment> {
        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        let tcp = packet.get(ihl..)?;
        let data_offset = ((tcp[12] >> 4) as usize) * 4;
        Some(Segment {
            sport: u16::from_be_bytes([tcp[0], tcp[1]]),
            dport: u16::from_be_bytes([tcp[2], tcp[3]]),
            seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
            ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
            flags: tcp[13],
            payload: tcp.get(data_offset..)?.to_vec(),
        })
    }

    fn datagram_pair() -> (RawFd, RawFd) {
        let mut fds = [0 as RawFd; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed");
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fds[1],
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        (fds[0], fds[1])
    }

    fn send_fd(fd: RawFd, packet: &[u8]) {
        let n = unsafe {
            libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len())
        };
        assert_eq!(n as usize, packet.len(), "short write on tun fd");
    }

    fn recv_fd(fd: RawFd) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }

    /// Wait for a segment matching `pred`, ignoring unrelated traffic.
    fn expect_segment(fd: RawFd, pred: impl Fn(&Segment) -> bool) -> Segment {
        for _ in 0..40 {
            if let Some(packet) = recv_fd(fd) {
                if let Some(seg) = parse_segment(&packet) {
                    if pred(&seg) {
                        return seg;
                    }
                }
            }
        }
        panic!("expected segment never arrived");
    }

    #[test]
    fn answers_app_syn_and_relays_both_directions() {
        // The real destination the bridge will dial on the app's behalf.
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let origin_thread = thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut buf = [0u8; 512];
            let n = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong").unwrap();
            request
        });

        let (tun_fd, app_fd) = datagram_pair();
        let shutdown = Arc::new(AtomicBool::new(false));
        let cfg = TunConfig::default();
        let flag = shutdown.clone();
        let bridge = thread::spawn(move || {
            let _ = run(tun_fd, cfg, flag);
            unsafe { libc::close(tun_fd) };
        });

        // 1. The app opens a connection: SYN from the app to the destination.
        let dst = [127, 0, 0, 1];
        send_fd(
            app_fd,
            &tcp_segment(APP_IP, dst, APP_PORT, origin_port, ISN, 0, 0x02, &[]),
        );

        // 2. The bridge must answer as the destination did, not stay silent.
        let synack = expect_segment(app_fd, |s| s.flags & 0x12 == 0x12 && s.sport == origin_port);
        assert_eq!(synack.dport, APP_PORT);
        assert_eq!(synack.ack, ISN + 1);
        let server_isn = synack.seq;

        // 3. Complete the handshake.
        send_fd(
            app_fd,
            &tcp_segment(APP_IP, dst, APP_PORT, origin_port, ISN + 1, server_isn + 1, 0x10, &[]),
        );

        // 4. Send a request; it must reach the real origin over loopback.
        let request = b"GET /relay HTTP/1.1\r\nHost: tun.test\r\n\r\n";
        send_fd(
            app_fd,
            &tcp_segment(
                APP_IP,
                dst,
                APP_PORT,
                origin_port,
                ISN + 1,
                server_isn + 1,
                0x18,
                request,
            ),
        );

        let seen = origin_thread.join().unwrap();
        assert!(
            seen.starts_with("GET /relay HTTP/1.1"),
            "origin received {seen:?}"
        );

        // 5. The response must come back through the bridge as app-bound bytes.
        let mut body = Vec::new();
        for _ in 0..40 {
            let Some(packet) = recv_fd(app_fd) else { break };
            let Some(seg) = parse_segment(&packet) else { continue };
            if seg.sport == origin_port && !seg.payload.is_empty() {
                body.extend_from_slice(&seg.payload);
                if body.windows(4).any(|w| w == b"pong") {
                    break;
                }
            }
        }
        assert!(
            body.windows(4).any(|w| w == b"pong"),
            "expected the origin body to be relayed, got {:?}",
            String::from_utf8_lossy(&body)
        );

        shutdown.store(true, Ordering::SeqCst);
        bridge.join().unwrap();
        unsafe { libc::close(app_fd) };
    }

    #[test]
    fn relays_dns_queries_and_reports_the_name() {
        let _guard = crate::events::lock_test_sink();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let bucket = seen.clone();
        set_sink(Some(Arc::new(move |ev: FlowEvent| {
            bucket.lock().unwrap().push(ev);
        })));

        // Stand-in resolver that flips the query into a response.
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let resolver = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = upstream.recv_from(&mut buf).unwrap();
            let mut answer = buf[..n].to_vec();
            answer[2] |= 0x80; // QR = response
            answer.push(0xc0);
            answer.push(0x0c); // name pointer to offset 12
            answer.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
            answer.extend_from_slice(&[0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
            answer[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
            upstream.send_to(&answer, from).unwrap();
        });

        let (tun_fd, app_fd) = datagram_pair();
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut cfg = TunConfig::default();
        cfg.dns_upstream = upstream_addr;
        let flag = shutdown.clone();
        let bridge = thread::spawn(move || {
            let err = run(tun_fd, cfg, flag);
            unsafe { libc::close(tun_fd) };
            err
        });

        // Query clientbp.ggpolarbear.com A, from the app to the resolver we advertise.
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in ["clientbp", "ggpolarbear", "com"] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);

        let dns_ip = [10, 233, 0, 2];
        send_fd(
            app_fd,
            &udp_datagram(dns_ip, dns_ip, 5353, 53, &query),
        );

        let reply = expect_udp(app_fd, |sport| sport == 53);
        assert_eq!(reply[0..2], query[0..2], "transaction id must match");
        assert_eq!(reply[2] & 0x80, 0x80, "expected a DNS response");

        resolver.join().unwrap();
        shutdown.store(true, Ordering::SeqCst);
        bridge.join().unwrap().unwrap();
        unsafe { libc::close(app_fd) };
        set_sink(None);

        let events = seen.lock().unwrap();
        let dns = events
            .iter()
            .find(|e| e.protocol == AppProtocol::Dns)
            .expect("a DNS event should be emitted");
        assert_eq!(dns.host, "clientbp.ggpolarbear.com");
        assert_eq!(dns.summary, "DNS clientbp.ggpolarbear.com A");
    }

    fn udp_datagram(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut udp = Vec::with_capacity(udp_len);
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum placeholder
        udp.extend_from_slice(payload);

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src);
        pseudo.extend_from_slice(&dst);
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pseudo.extend_from_slice(&udp);
        let sum = internet_checksum(&pseudo);
        udp[6..8].copy_from_slice(&sum.to_be_bytes());

        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 2, 0x40, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        let ip_sum = internet_checksum(&ip);
        ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        ip.extend_from_slice(&udp);
        ip
    }

    /// Wait for a UDP payload whose source port matches `pred`.
    fn expect_udp(fd: RawFd, pred: impl Fn(u16) -> bool) -> Vec<u8> {
        for _ in 0..40 {
            let Some(packet) = recv_fd(fd) else { continue };
            if packet.get(9) != Some(&17) {
                continue;
            }
            let ihl = ((packet[0] & 0x0f) as usize) * 4;
            let udp = &packet[ihl..];
            let sport = u16::from_be_bytes([udp[0], udp[1]]);
            if pred(sport) {
                return udp[8..].to_vec();
            }
        }
        panic!("expected UDP datagram never arrived");
    }
}
