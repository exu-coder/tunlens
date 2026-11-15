//! Minimal SOCKS5 server: the single, explicit capture point of the pipeline.
//!
//! The VPN routes selected apps into the tun device; the tun bridge hands every
//! accepted connection to this listener as a plain SOCKS5 CONNECT. Observing at
//! one choke point keeps the dissection honest: what we record is exactly the
//! byte stream the app asked the network to carry.

use crate::events::Direction;
use crate::flow::{Flow, FlowKey};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CHUNK: usize = 16 * 1024;

static CONNECTIONS: AtomicU64 = AtomicU64::new(0);

pub fn connection_count() -> u64 {
    CONNECTIONS.load(Ordering::Relaxed)
}

/// Serve SOCKS5 on `listen` until `shutdown` is set.
pub fn serve(listen: SocketAddr, shutdown: Arc<AtomicBool>) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    serve_listener(listener, shutdown)
}

pub fn serve_listener(listener: TcpListener, shutdown: Arc<AtomicBool>) -> io::Result<()> {
    listener.set_nonblocking(true)?;

    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                let shutdown = shutdown.clone();
                thread::spawn(move || {
                    if let Err(err) = handle(stream, peer, shutdown) {
                        if err.kind() != io::ErrorKind::UnexpectedEof {
                            eprintln!("[socks5] {peer} closed: {err}");
                        }
                    }
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Run the server on an already-bound listener (keeps the port stable for tests
/// and lets the caller fail fast on a clash).
pub fn spawn(listener: TcpListener, shutdown: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Err(err) = serve_listener(listener, shutdown) {
            eprintln!("[socks5] serve failed: {err}");
        }
    })
}

fn handle(mut stream: TcpStream, peer: SocketAddr, shutdown: Arc<AtomicBool>) -> io::Result<()> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_nodelay(true)?;

    let target = handshake(&mut stream)?;
    stream.set_read_timeout(None)?;

    let upstream = match TcpStream::connect(target) {
        Ok(up) => {
            reply(&mut stream, 0x00)?;
            up
        }
        Err(err) => {
            let code = match err.kind() {
                io::ErrorKind::ConnectionRefused => 0x05,
                io::ErrorKind::TimedOut => 0x06,
                _ => 0x01,
            };
            let _ = reply(&mut stream, code);
            return Err(err);
        }
    };
    upstream.set_nodelay(true)?;

    let remote = upstream.peer_addr().unwrap_or(target);
    let key = FlowKey::new(peer, remote);
    let flow = Arc::new(Mutex::new(Flow::new(key)));
    eprintln!("[socks5] {} -> {}", peer, target);

    let flow_client = flow.clone();
    let flow_server = flow.clone();
    let shutdown_client = shutdown.clone();

    let up_write = upstream.try_clone()?;
    let down_read = upstream;
    let client_read = stream.try_clone()?;
    let client_write = stream;

    let a = thread::spawn(move || {
        pump(client_read, up_write, Direction::Client, flow_client, shutdown_client)
    });
    let b = thread::spawn(move || {
        pump(down_read, client_write, Direction::Server, flow_server, shutdown)
    });

    let _ = a.join();
    let _ = b.join();
    Ok(())
}

fn pump(
    mut from: TcpStream,
    mut to: TcpStream,
    direction: Direction,
    flow: Arc<Mutex<Flow>>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let n = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        flow.lock().unwrap().on_chunk(direction, &buf[..n]);
        if let Err(err) = to.write_all(&buf[..n]) {
            return Err(err);
        }
    }
    let _ = to.shutdown(Shutdown::Write);
    Ok(())
}

/// Reads the greeting and CONNECT request, returning the dial target.
fn handshake(stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(bad("unsupported socks version"));
    }
    let methods = head[1] as usize;
    let mut offered = vec![0u8; methods];
    stream.read_exact(&mut offered)?;
    if !offered.contains(&0x00) {
        let _ = stream.write_all(&[0x05, 0xff]);
        return Err(bad("client requires authentication"));
    }
    stream.write_all(&[0x05, 0x00])?;

    let mut req = [0u8; 4];
    stream.read_exact(&mut req)?;
    if req[0] != 0x05 || req[1] != 0x01 {
        let _ = reply(stream, 0x07);
        return Err(bad("only CONNECT is supported"));
    }

    let host = match req[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets)?;
            IpAddr::V4(Ipv4Addr::from(octets)).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets)?;
            IpAddr::from(octets).to_string()
        }
        _ => {
            let _ = reply(stream, 0x08);
            return Err(bad("unsupported address type"));
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);

    resolve(&host, port)
}

fn resolve(host: &str, port: u16) -> io::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut candidates: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    candidates.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
    candidates
        .into_iter()
        .next()
        .ok_or_else(|| bad(&format!("no address for {host}")))
}

fn reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    stream.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
}

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{set_sink, FlowEvent};
    use std::sync::mpsc;

    #[test]
    fn relays_and_emits_events() {
        let _guard = crate::events::lock_test_sink();
        // Stand-in remote server.
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_addr = origin.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut s, _)) = origin.accept() {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });

        let (tx, rx) = mpsc::channel::<FlowEvent>();
        set_sink(Some(Arc::new(move |ev: FlowEvent| {
            let _ = tx.send(ev);
        })));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = spawn(listener, shutdown.clone());
        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut hello = [0u8; 2];
        client.read_exact(&mut hello).unwrap();
        assert_eq!(hello, [0x05, 0x00]);

        let port = origin_addr.port().to_be_bytes();
        let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        request.extend_from_slice(&port);
        client.write_all(&request).unwrap();

        let mut reply_buf = [0u8; 10];
        client.read_exact(&mut reply_buf).unwrap();
        assert_eq!(reply_buf[1], 0x00, "CONNECT should succeed");

        client
            .write_all(b"GET /ping HTTP/1.1\r\nHost: clientbp.ggpolarbear.com\r\n\r\n")
            .unwrap();
        let mut response = [0u8; 64];
        let n = client.read(&mut response).unwrap();
        assert!(n > 0, "relay must return the origin response");

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();

        let mut seen = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            seen.push(ev);
        }
        set_sink(None);

        assert!(
            seen.iter().any(|e| e.direction == Direction::Client
                && e.summary.starts_with("GET ")
                && e.summary.contains("/ping")),
            "expected a client-side HTTP event, got {:?}",
            seen.iter().map(|e| e.summary.clone()).collect::<Vec<_>>()
        );
        assert!(
            seen.iter().any(|e| e.direction == Direction::Server),
            "expected a server-side event"
        );
    }
}
