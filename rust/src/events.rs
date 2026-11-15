//! Event model and the global sink that hands events to Kotlin or the CLI.

use serde::Serialize;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// App -> remote. The request side.
    Client,
    /// Remote -> app. The response side.
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AppProtocol {
    Tls,
    Http,
    Json,
    Dns,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowEvent {
    pub ts_ms: u64,
    pub host: String,
    pub port: u16,
    pub direction: Direction,
    pub protocol: AppProtocol,
    /// Short verb-like label, e.g. `client_hello`, `request`, `json_document`.
    pub op: String,
    /// One-line human summary for the overlay list.
    pub summary: String,
    /// Structured detail when the payload was understood.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    /// Hex preview of the observed bytes, truncated to `PREVIEW_BYTES`.
    pub raw_hex: String,
    /// True size of the chunk this event describes.
    pub bytes: usize,
    pub flow: String,
}

pub type Sink = Arc<dyn Fn(FlowEvent) + Send + Sync>;

static SINK: OnceLock<Mutex<Option<Sink>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<Sink>> {
    SINK.get_or_init(|| Mutex::new(None))
}

/// Install the process-wide event sink. `None` detaches it.
pub fn set_sink(sink: Option<Sink>) {
    if let Ok(mut guard) = slot().lock() {
        *guard = sink;
    }
}

pub fn emit(event: FlowEvent) {
    let sink = slot().lock().ok().and_then(|g| g.clone());
    if let Some(sink) = sink {
        sink(event);
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The sink is process-global, so tests that install one must not overlap:
/// otherwise one test's events arrive in another's channel. Tests take this
/// guard before touching the sink; it is recovered if a test panicked while
/// holding it.
#[cfg(test)]
pub(crate) static TEST_SINK_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn lock_test_sink() -> std::sync::MutexGuard<'static, ()> {
    TEST_SINK_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Uppercase hex with a truncation marker and the omitted byte count.
pub fn hex_preview(bytes: &[u8], max: usize) -> String {
    let shown = bytes.len().min(max);
    let mut out = String::with_capacity(shown * 2 + 16);
    for b in &bytes[..shown] {
        out.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > shown {
        out.push_str(&format!("..(+{}b)", bytes.len() - shown));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_preview_truncates() {
        assert_eq!(hex_preview(&[0xde, 0xad], 4), "dead");
        assert_eq!(hex_preview(&[0xde, 0xad, 0xbe], 2), "dead..(+1b)");
    }

    #[test]
    fn sink_receives_events() {
        let _guard = lock_test_sink();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let bucket = seen.clone();
        set_sink(Some(Arc::new(move |ev: FlowEvent| {
            bucket.lock().unwrap().push(ev.summary);
        })));
        emit(FlowEvent {
            ts_ms: 0,
            host: "clientbp.ggpolarbear.com".into(),
            port: 443,
            direction: Direction::Client,
            protocol: AppProtocol::Tls,
            op: "client_hello".into(),
            summary: "tls clientbp.ggpolarbear.com".into(),
            detail: None,
            raw_hex: String::new(),
            bytes: 0,
            flow: "test".into(),
        });
        set_sink(None);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}
