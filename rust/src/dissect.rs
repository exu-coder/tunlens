//! Payload dissection for the protocols a SOCKS5/TCP flow actually carries.
//!
//! Everything is parsed from the bytes we observed. Nothing is guessed from a
//! port number, and an unparsable payload is reported as `unknown` rather than
//! being coerced into a protocol.

use crate::events::AppProtocol;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct Dissected {
    pub protocol: AppProtocol,
    pub op: String,
    pub summary: String,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub http_method: Option<String>,
    pub http_host: Option<String>,
    pub http_path: Option<String>,
    pub detail: Option<Value>,
}

impl Default for AppProtocol {
    fn default() -> Self {
        AppProtocol::Unknown
    }
}

/// Classify a buffered payload. `payload` should start at a message boundary:
/// the first bytes of the flow, or the start of a new chunk.
pub fn dissect(payload: &[u8]) -> Dissected {
    if payload.is_empty() {
        return Dissected {
            protocol: AppProtocol::Unknown,
            op: "empty".into(),
            summary: "empty payload".into(),
            ..Default::default()
        };
    }

    if let Some(hello) = tls_client_hello(payload) {
        let sni = hello.0;
        let alpn = hello.1;
        let label = match (sni.as_deref(), alpn.first().map(String::as_str)) {
            (Some(host), Some(alpn)) => format!("TLS {host} ({alpn})"),
            (Some(host), None) => format!("TLS {host}"),
            (None, Some(alpn)) => format!("TLS (no SNI, {alpn})"),
            (None, None) => "TLS ClientHello (no SNI)".to_string(),
        };
        let detail = serde_json::json!({
            "sni": sni,
            "alpn": alpn,
            "record_bytes": payload.len(),
        });
        return Dissected {
            protocol: AppProtocol::Tls,
            op: "client_hello".into(),
            summary: label,
            sni,
            alpn,
            detail: Some(detail),
            ..Default::default()
        };
    }

    if let Some(http) = http_request(payload) {
        let host = http.host.clone().unwrap_or_else(|| "?".into());
        let summary = format!("{} {}{}", http.method, host, http.path);
        let detail = serde_json::json!({
            "method": http.method,
            "host": http.host,
            "path": http.path,
            "version": http.version,
        });
        return Dissected {
            protocol: AppProtocol::Http,
            op: "request".into(),
            summary,
            http_method: Some(http.method),
            http_host: http.host,
            http_path: Some(http.path),
            detail: Some(detail),
            ..Default::default()
        };
    }

    if let Some(value) = json_document(payload) {
        let kind = match &value {
            Value::Object(map) => format!("json object ({} keys)", map.len()),
            Value::Array(items) => format!("json array ({} items)", items.len()),
            other => format!("json {}", json_type(other)),
        };
        return Dissected {
            protocol: AppProtocol::Json,
            op: "json_document".into(),
            summary: kind,
            detail: Some(truncate_json(value, 32)),
            ..Default::default()
        };
    }

    if let Some(response) = http_response(payload) {
        return Dissected {
            protocol: AppProtocol::Http,
            op: "response".into(),
            summary: format!("HTTP {} {}", response.status, response.reason),
            detail: Some(serde_json::json!({
                "status": response.status,
                "reason": response.reason,
                "version": response.version,
            })),
            ..Default::default()
        };
    }

    // Any other TLS record: server hello, certificate, application data. The
    // body is encrypted (or, for handshakes, not worth decoding here), but the
    // record boundary itself is honest metadata.
    if let Some(record) = tls_record(payload) {
        return Dissected {
            protocol: AppProtocol::Tls,
            op: "tls_record".into(),
            summary: format!("TLS {} ({} B record)", record.kind, record.len),
            detail: Some(serde_json::json!({
                "record_type": record.kind,
                "record_bytes": record.len,
            })),
            ..Default::default()
        };
    }

    Dissected {
        protocol: AppProtocol::Unknown,
        op: "bytes".into(),
        summary: format!("{} bytes", payload.len()),
        ..Default::default()
    }
}

struct TlsRecord {
    kind: &'static str,
    len: usize,
}

struct HttpResponse {
    version: String,
    status: u16,
    reason: String,
}

fn http_response(payload: &[u8]) -> Option<HttpResponse> {
    if !payload.starts_with(b"HTTP/") {
        return None;
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let status = response.parse(payload).ok()?;
    if status.is_partial() && response.code.is_none() {
        return None;
    }
    Some(HttpResponse {
        version: format!("1.{}", response.version.unwrap_or(1)),
        status: response.code?,
        reason: response.reason.unwrap_or("").to_string(),
    })
}

/// Classify a TLS record by its header. Rejects impossible lengths so random
/// bytes cannot masquerade as TLS.
fn tls_record(payload: &[u8]) -> Option<TlsRecord> {
    if payload.len() < 6 || payload[1] != 0x03 {
        return None;
    }
    let len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if len == 0 || len > 16384 + 2048 {
        return None;
    }
    let kind = match payload[0] {
        0x14 => "change_cipher_spec",
        0x15 => "alert",
        0x16 => match payload[5] {
            0x02 => "server_hello",
            0x04 => "new_session_ticket",
            0x0b => "certificate",
            0x0e => "server_hello_done",
            _ => "handshake",
        },
        0x17 => "application_data",
        _ => return None,
    };
    Some(TlsRecord { kind, len })
}

/// A decoded DNS question, as carried in a plaintext query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// Dotted name without the trailing dot.
    pub name: String,
    /// Record type as text: `A`, `AAAA`, `HTTPS`, `TXT`, or `TYPE<n>`.
    pub qtype: String,
    pub id: u16,
}

/// Parse the question section of a DNS query. Returns `None` for responses or
/// malformed packets; compression pointers are rejected (a question never needs
/// them, so their presence means this is not a query we understand).
pub fn dns_question(payload: &[u8]) -> Option<DnsQuestion> {
    if payload.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = flags & 0x8000 != 0;
    let questions = u16::from_be_bytes([payload[4], payload[5]]);
    if is_response || questions == 0 {
        return None;
    }

    let mut cursor = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *payload.get(cursor)? as usize;
        cursor += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression pointer: not a question
        }
        let label = payload.get(cursor..cursor + len)?;
        cursor += len;
        labels.push(String::from_utf8(label.to_vec()).ok()?);
        if labels.len() > 64 {
            return None;
        }
    }
    if labels.is_empty() {
        return None; // root query, not interesting
    }
    let qtype_raw = u16::from_be_bytes([*payload.get(cursor)?, *payload.get(cursor + 1)?]);

    Some(DnsQuestion {
        name: labels.join("."),
        qtype: qtype_name(qtype_raw),
        id,
    })
}

fn qtype_name(value: u16) -> String {
    match value {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        43 => "DS".into(),
        46 => "RRSIG".into(),
        48 => "DNSKEY".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

fn json_type(value: &Value) -> &'static str {    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Keep the detail payload bounded; the raw hex is the authoritative record.
fn truncate_json(value: Value, max_items: usize) -> Value {
    match value {
        Value::Object(map) => {
            let kept: serde_json::Map<String, Value> = map
                .into_iter()
                .take(max_items)
                .map(|(k, v)| (k, truncate_json(v, max_items)))
                .collect();
            Value::Object(kept)
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().take(max_items).map(|v| truncate_json(v, max_items)).collect())
        }
        Value::String(s) if s.len() > 512 => Value::String(format!("{}…", &s[..512])),
        other => other,
    }
}

fn json_document(payload: &[u8]) -> Option<Value> {
    let first = payload.iter().find(|b| !b.is_ascii_whitespace())?;
    if *first != b'{' && *first != b'[' {
        return None;
    }
    let end = payload
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .unwrap_or(payload.len() - 1);
    let slice = &payload[..=end];
    let text = std::str::from_utf8(slice).ok()?;
    serde_json::from_str::<Value>(text).ok()
}

struct HttpRequest {
    method: String,
    host: Option<String>,
    path: String,
    version: String,
}

fn http_request(payload: &[u8]) -> Option<HttpRequest> {
    // Quick reject: a request line starts with a known method token.
    const METHODS: [&[u8]; 9] = [
        b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ",
    ];
    if !METHODS.iter().any(|m| payload.starts_with(m)) {
        return None;
    }

    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut request = httparse::Request::new(&mut headers);
    let status = request.parse(payload).ok()?;
    if status.is_partial() && request.path.is_none() {
        return None;
    }

    let method = request.method?.to_string();
    let path = request.path?.to_string();
    // httparse reports 0 for HTTP/1.0 and 1 for HTTP/1.1.
    let version = format!("1.{}", request.version.unwrap_or(1));
    let host = request
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|v| v.split(':').next().unwrap_or(v).to_string());

    Some(HttpRequest { method, host, path, version })
}

/// Returns `(sni, alpn)` if `payload` begins with a TLS ClientHello record.
///
/// Hand-rolled on purpose: the record is length-prefixed and every field is
/// bounds-checked, so a truncated or hostile capture cannot panic the engine.
fn tls_client_hello(payload: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    // ContentType handshake(22), version major 3.
    if payload.len() < 6 || payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let body = payload.get(5..5 + record_len)?;
    if body.first() != Some(&0x01) {
        return None; // not a ClientHello
    }
    let hello_len = u24(body.get(1..4)?);
    let hello = body.get(4..4 + hello_len)?;

    let mut cursor = Cursor::new(hello);
    let _legacy_version = cursor.take(2)?;
    let _random = cursor.take(32)?;
    let session_id_len = cursor.u8()? as usize;
    cursor.take(session_id_len)?;
    let cipher_len = cursor.u16()? as usize;
    cursor.take(cipher_len)?;
    let compression_len = cursor.u8()? as usize;
    cursor.take(compression_len)?;

    let extensions_len = cursor.u16()? as usize;
    let extensions = cursor.take(extensions_len)?;

    let mut sni = None;
    let mut alpn = Vec::new();
    let mut ext = Cursor::new(extensions);
    while ext.remaining() >= 4 {
        let ext_type = ext.u16()?;
        let ext_len = ext.u16()? as usize;
        let data = ext.take(ext_len)?;
        match ext_type {
            0x0000 => {
                // server_name: ServerNameList
                let mut list = Cursor::new(data);
                let _list_len = list.u16()?;
                while list.remaining() > 3 {
                    let name_type = list.u8()?;
                    let name_len = list.u16()? as usize;
                    let name = list.take(name_len)?;
                    if name_type == 0 && sni.is_none() {
                        sni = std::str::from_utf8(name).ok().map(|s| s.to_string());
                    }
                }
            }
            0x0010 => {
                // ALPN: ProtocolNameList
                let mut list = Cursor::new(data);
                let _list_len = list.u16()?;
                while list.remaining() > 1 {
                    let name_len = list.u8()? as usize;
                    let name = list.take(name_len)?;
                    if let Ok(text) = std::str::from_utf8(name) {
                        alpn.push(text.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    Some((sni, alpn))
}

fn u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal but structurally valid ClientHello carrying SNI + ALPN.
    fn client_hello(sni: &str, alpn: &[&str]) -> Vec<u8> {
        let mut ext = Vec::new();

        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
        sni_data.push(0);
        sni_data.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(sni.as_bytes());
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_data);

        let mut alpn_inner = Vec::new();
        for p in alpn {
            alpn_inner.push(p.len() as u8);
            alpn_inner.extend_from_slice(p.as_bytes());
        }
        let mut alpn_data = Vec::new();
        alpn_data.extend_from_slice(&(alpn_inner.len() as u16).to_be_bytes());
        alpn_data.extend_from_slice(&alpn_inner);
        ext.extend_from_slice(&0x0010u16.to_be_bytes());
        ext.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&alpn_data);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session id
        hello.extend_from_slice(&2u16.to_be_bytes()); // cipher suites
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1); // compression
        hello.push(0);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&((hello.len() + 4) as u16).to_be_bytes());
        record.push(0x01); // client_hello
        record.extend_from_slice(&[(hello.len() >> 16) as u8, (hello.len() >> 8) as u8, hello.len() as u8]);
        record.extend_from_slice(&hello);
        record
    }

    #[test]
    fn extracts_sni_and_alpn() {
        let payload = client_hello("clientbp.ggpolarbear.com", &["h2", "http/1.1"]);
        let d = dissect(&payload);
        assert_eq!(d.protocol, AppProtocol::Tls);
        assert_eq!(d.sni.as_deref(), Some("clientbp.ggpolarbear.com"));
        assert_eq!(d.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert!(d.summary.contains("clientbp.ggpolarbear.com"));
    }

    #[test]
    fn truncated_tls_does_not_panic() {
        let payload = client_hello("clientbp.ggpolarbear.com", &["h2"]);
        for cut in 0..payload.len() {
            let _ = dissect(&payload[..cut]);
        }
    }

    #[test]
    fn parses_http_request() {
        let payload = b"POST /v1/login HTTP/1.1\r\nHost: loginbp.ggpolarbear.com:8443\r\nContent-Length: 2\r\n\r\n{}";
        let d = dissect(payload);
        assert_eq!(d.protocol, AppProtocol::Http);
        assert_eq!(d.http_method.as_deref(), Some("POST"));
        assert_eq!(d.http_host.as_deref(), Some("loginbp.ggpolarbear.com"));
        assert_eq!(d.http_path.as_deref(), Some("/v1/login"));
    }

    #[test]
    fn parses_http_response() {
        let payload = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let d = dissect(payload);
        assert_eq!(d.protocol, AppProtocol::Http);
        assert_eq!(d.op, "response");
        assert_eq!(d.summary, "HTTP 404 Not Found");
    }

    #[test]
    fn parses_dns_question() {
        // Standard query, ID 0x1234, one question: clientbp.ggpolarbear.com IN A.
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 1, 0, 0, 0, 0];
        for label in ["clientbp", "ggpolarbear", "com"] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);

        let q = dns_question(&query).expect("query should parse");
        assert_eq!(q.name, "clientbp.ggpolarbear.com");
        assert_eq!(q.qtype, "A");
        assert_eq!(q.id, 0x1234);

        // A response (QR bit set) is not a query.
        let mut response = query.clone();
        response[2] |= 0x80;
        assert!(dns_question(&response).is_none());
        // Truncation and pure garbage must not panic.
        for cut in 0..query.len() {
            let _ = dns_question(&query[..cut]);
        }
        assert!(dns_question(&[0xff; 40]).is_none());
    }

    #[test]
    fn parses_json_document() {        let d = dissect(br#"  {"code":0,"items":[1,2,3]}  "#);
        assert_eq!(d.protocol, AppProtocol::Json);
        assert!(d.summary.contains("2 keys"));
    }

    #[test]
    fn random_bytes_are_unknown() {
        let d = dissect(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]);
        assert_eq!(d.protocol, AppProtocol::Unknown);
        assert_eq!(d.op, "bytes");
    }

    #[test]
    fn labels_tls_records_by_type() {        let server_hello = [0x16, 0x03, 0x03, 0x00, 0x40, 0x02, 0, 0];
        let d = dissect(&server_hello);
        assert_eq!(d.protocol, AppProtocol::Tls);
        assert!(d.summary.contains("server_hello"), "{}", d.summary);

        let app_data = [0x17, 0x03, 0x03, 0x10, 0x00, 0xff, 0xee, 0xdd];
        let d = dissect(&app_data);
        assert!(d.summary.contains("application_data"), "{}", d.summary);

        // A record header claiming an impossible length must not be trusted.
        let bogus = [0x17, 0x03, 0x03, 0xff, 0xff, 0x00, 0x00];
        assert_eq!(dissect(&bogus).protocol, AppProtocol::Unknown);
    }
}
