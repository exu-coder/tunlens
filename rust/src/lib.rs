//! tunlens — a read-only traffic observer for apps you own.
//!
//! Pipeline: Android `VpnService` tun fd -> userspace TCP/IP (smoltcp) ->
//! local SOCKS5 bridge -> per-flow dissection -> JSON events.
//!
//! Deliberate difference from the app this was reconstructed from: nothing here
//! can rewrite or re-inject a packet. There is no `set_key`, no `edit_and_send`,
//! and no cross-app log scraping. Flows are observed, recorded and exported.

pub mod dissect;
pub mod events;
pub mod flow;
pub mod jni_bridge;
pub mod socks5;
pub mod tun;

pub const ENGINE_NAME: &str = "tunlens";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Largest preview retained per direction, in bytes.
pub const PREVIEW_BYTES: usize = 4096;

/// Hard cap on events emitted per flow, so a bulk transfer cannot flood the UI.
pub const MAX_EVENTS_PER_FLOW: usize = 64;
