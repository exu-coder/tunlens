//! `tunlens` CLI — the host-side harness for the same engine Android uses.
//!
//! Two subcommands:
//!   * `socks`   run the SOCKS5 capture point and print JSON events
//!   * `dissect` classify a captured payload from a file or hex string
//!
//! The CLI exists so the dissector can be exercised without a phone, a VPN
//! permission prompt, or root.

use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tunlens::events::{set_sink, FlowEvent};
use tunlens::{dissect, socks5};

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());

    let code = match command.as_str() {
        "socks" => cmd_socks(args),
        "dissect" => cmd_dissect(args),
        "version" => {
            println!("{} {}", tunlens::ENGINE_NAME, tunlens::ENGINE_VERSION);
            0
        }
        _ => {
            eprintln!(
                "tunlens {}\n\nusage:\n  tunlens socks [--listen 127.0.0.1:1080]\n  tunlens dissect <file|hex:...>\n  tunlens version",
                tunlens::ENGINE_VERSION
            );
            2
        }
    };
    std::process::exit(code);
}

fn cmd_socks(mut args: impl Iterator<Item = String>) -> i32 {
    let mut listen: SocketAddr = "127.0.0.1:1080".parse().expect("valid default");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" | "-l" => {
                let Some(value) = args.next() else {
                    eprintln!("--listen needs an address");
                    return 2;
                };
                match value.parse() {
                    Ok(addr) => listen = addr,
                    Err(err) => {
                        eprintln!("bad address {value}: {err}");
                        return 2;
                    }
                }
            }
            other => {
                eprintln!("unknown argument {other}");
                return 2;
            }
        }
    }

    set_sink(Some(Arc::new(|event: FlowEvent| {
        match serde_json::to_string(&event) {
            Ok(line) => println!("{line}"),
            Err(err) => eprintln!("event encode failed: {err}"),
        }
    })));

    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = shutdown.clone();
    let _ = ctrlc_stub(signal);

    eprintln!("[tunlens] SOCKS5 capture on {listen} — point a client at it");
    match socks5::serve(listen, shutdown) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("[tunlens] failed: {err}");
            1
        }
    }
}

fn ctrlc_stub(shutdown: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // Without a signal crate: stop after a Ctrl-C by watching stdin EOF.
        let mut sink = io::stdin();
        let mut buf = [0u8; 64];
        loop {
            match sink.read(&mut buf) {
                Ok(0) => {
                    shutdown.store(true, Ordering::SeqCst);
                    eprintln!("[tunlens] stdin closed, shutting down");
                    return;
                }
                Ok(_) => {}
                Err(_) => {
                    shutdown.store(true, Ordering::SeqCst);
                    return;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
    })
}

fn cmd_dissect(mut args: impl Iterator<Item = String>) -> i32 {
    let Some(source) = args.next() else {
        eprintln!("usage: tunlens dissect <file|hex:...>");
        return 2;
    };
    let bytes = if let Some(hex) = source.strip_prefix("hex:") {
        match decode_hex(hex) {
            Some(bytes) => bytes,
            None => {
                eprintln!("invalid hex payload");
                return 2;
            }
        }
    } else {
        match std::fs::read(&source) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("cannot read {source}: {err}");
                return 1;
            }
        }
    };

    let result = dissect::dissect(&bytes);
    let detail = result.detail.clone().unwrap_or(serde_json::Value::Null);
    let output = serde_json::json!({
        "protocol": result.protocol,
        "op": result.op,
        "summary": result.summary,
        "sni": result.sni,
        "alpn": result.alpn,
        "detail": detail,
        "bytes": bytes.len(),
    });
    match serde_json::to_string_pretty(&output) {
        Ok(text) => println!("{text}"),
        Err(err) => {
            eprintln!("encode failed: {err}");
            return 1;
        }
    }
    0
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.as_bytes().chunks(2) {
        let text = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(text, 16).ok()?);
    }
    Some(out)
}
