//! Per-flow state: accumulates the first bytes of each direction, classifies
//! them once, then degrades to bounded preview events.

use crate::dissect::{dissect, Dissected};
use crate::events::{emit, hex_preview, now_ms, AppProtocol, Direction, FlowEvent};
use crate::{MAX_EVENTS_PER_FLOW, PREVIEW_BYTES};
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub client: SocketAddr,
    pub remote: SocketAddr,
}

impl FlowKey {
    pub fn new(client: SocketAddr, remote: SocketAddr) -> Self {
        Self { client, remote }
    }

    pub fn label(&self) -> String {
        format!("{}>{}", self.client, self.remote)
    }
}

#[derive(Debug)]
pub struct Flow {
    key: FlowKey,
    client: SideState,
    server: SideState,
    events: usize,
    remote_host: String,
    sni: Option<String>,
}

#[derive(Debug, Default)]
struct SideState {
    /// Classification has already been reported for this direction.
    classified: bool,
    /// Bytes retained for classification, capped at PREVIEW_BYTES.
    head: Vec<u8>,
}

impl Flow {
    pub fn new(key: FlowKey) -> Self {
        let remote_host = key.remote.ip().to_string();
        Self {
            key,
            client: SideState::default(),
            server: SideState::default(),
            events: 0,
            remote_host,
            sni: None,
        }
    }

    pub fn key(&self) -> &FlowKey {
        &self.key
    }

    /// SNI learned from the client hello, when the flow is TLS.
    pub fn sni(&self) -> Option<String> {
        self.sni.clone()
    }

    pub fn remote_host(&self) -> &str {
        &self.remote_host
    }

    pub fn on_chunk(&mut self, direction: Direction, chunk: &[u8]) {
        if chunk.is_empty() || self.events >= MAX_EVENTS_PER_FLOW {
            return;
        }

        let side = match direction {
            Direction::Client => &mut self.client,
            Direction::Server => &mut self.server,
        };

        let first = !side.classified;
        if first {
            let room = PREVIEW_BYTES.saturating_sub(side.head.len());
            side.head.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }

        // Only look at the head; do not re-scan a partial buffer forever.
        let observed: &[u8] = if first { &side.head } else { chunk };
        let parsed: Dissected = dissect(observed);

        let interesting = first || parsed.protocol != AppProtocol::Unknown;
        if !interesting {
            return;
        }
        if first {
            side.classified = true;
        }

        if let Some(host) = parsed.sni.clone() {
            self.remote_host = host.clone();
            self.sni = Some(host);
        }

        self.events += 1;
        emit(FlowEvent {
            ts_ms: now_ms(),
            host: self.remote_host.clone(),
            port: self.key.remote.port(),
            direction,
            protocol: parsed.protocol,
            op: parsed.op.clone(),
            summary: parsed.summary.clone(),
            detail: parsed.detail.clone(),
            raw_hex: hex_preview(observed, 512),
            bytes: chunk.len(),
            flow: self.key.label(),
        });
    }
}

#[derive(Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn entry(&mut self, key: FlowKey) -> &mut Flow {
        self.flows.entry(key.clone()).or_insert_with(|| Flow::new(key))
    }

    pub fn remove(&mut self, key: &FlowKey) {
        self.flows.remove(key);
    }

    pub fn retention_cap(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::set_sink;
    use std::sync::{Arc, Mutex};

    #[test]
    fn classifies_once_and_counts_events() {
        let _guard = crate::events::lock_test_sink();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let bucket = seen.clone();
        set_sink(Some(Arc::new(move |ev: FlowEvent| {
            bucket.lock().unwrap().push((ev.direction, ev.protocol, ev.summary));
        })));

        let key = FlowKey::new(
            "10.233.0.1:51234".parse().unwrap(),
            "203.0.113.10:443".parse().unwrap(),
        );
        let mut table = FlowTable::new();
        let flow = table.entry(key.clone());
        flow.on_chunk(Direction::Client, &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]);
        flow.on_chunk(Direction::Client, b"more bytes");
        flow.on_chunk(Direction::Server, b"HTTP/1.1 200 OK\r\n");

        set_sink(None);
        let events = seen.lock().unwrap();
        assert_eq!(events.len(), 2, "one event per direction, not per chunk");
        assert_eq!(events[1].0, Direction::Server);
    }

    #[test]
    fn event_budget_is_bounded() {
        let _guard = crate::events::lock_test_sink();
        let counter = Arc::new(Mutex::new(0usize));
        let c = counter.clone();
        set_sink(Some(Arc::new(move |_ev: FlowEvent| {
            *c.lock().unwrap() += 1;
        })));
        let key = FlowKey::new("10.0.0.1:1".parse().unwrap(), "10.0.0.2:80".parse().unwrap());
        let mut table = FlowTable::new();
        let flow = table.entry(key);
        for i in 0..500 {
            let body = format!("{{\"n\":{i}}}");
            flow.on_chunk(Direction::Client, body.as_bytes());
        }
        set_sink(None);
        assert!(*counter.lock().unwrap() <= MAX_EVENTS_PER_FLOW);
    }
}
