# tunlens

A read-only traffic observer for Android apps **you own**: a `VpnService` sends
selected apps' traffic into a userspace TCP/IP stack written in Rust, which
dials the real destination, dissects what crosses it, and emits JSON events.
Nothing is modified, blocked, throttled or re-sent.

It is a clean rebuild of the *engineering* in an Android packet-capture app,
minus the parts that made that app a cheat. See [Boundaries](#boundaries).

```
selected app
     │  (framework routes only these packages into the tun)
     ▼
VpnService  ──fd──►  Rust engine
                       ├── smoltcp (userspace IPv4/TCP + UDP:53)
                       ├── SYN ─► listener bound to the real destination
                       ├── dial destination, splice bytes
                       ├── dissect: TLS ClientHello/records, HTTP req/resp, DNS, JSON
                       └── JSON events ──JNI──► Kotlin UI / overlay
```

## Layout

| Path | What it is |
|---|---|
| `rust/src/tun.rs` | tun fd → smoltcp bridge, SYN learning, upstream splice, DNS relay |
| `rust/src/socks5.rs` | optional local SOCKS5 capture point (host/CLI use) |
| `rust/src/dissect.rs` | TLS ClientHello (SNI/ALPN), TLS record labels, HTTP request/response, DNS question, JSON |
| `rust/src/flow.rs` | per-flow state, one classification per direction, bounded event budget |
| `rust/src/events.rs` | event schema + process-wide sink |
| `rust/src/jni_bridge.rs` | `dev.tunlens.NativeBridge` JNI surface |
| `rust/src/bin/cli.rs` | `tunlens socks` / `tunlens dissect` |
| `android/` | Kotlin shell: `VpnService`, app picker, overlay, event bus |
| `docs/provenance.md` | what the original app was, and what was left out |

## Build and test the engine

The engine builds against the host's Android-target std; tests run natively.

```sh
cd rust
cargo build
cargo test            # 17 tests, incl. tun-bridge and SOCKS5 integration
cargo run -- version
cargo run -- dissect hex:474554202f70696e6720485454502f312e310d0a486f73743a20636c69656e7462702e6767706f6c6172626561722e636f6d0d0a0d0a
cargo run -- socks --listen 127.0.0.1:1080     # JSON events on stdout
```

`rust/.cargo/config.toml` is host-specific and git-ignored: on this Termux machine
it points the linker at Termux's clang because there is no NDK. The committed
template is `rust/.cargo/config.toml.example`. Build from inside `rust/`, since
cargo reads `.cargo/config.toml` from the working directory, not from the
manifest's.

## Build the APK

```sh
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.2.12479018
cargo install cargo-ndk            # once
android/build-native.sh            # libtunlens.so -> app/src/main/jniLibs/<abi>/
cd android && ./gradlew assembleDebug
```

`build-native.sh` temporarily moves `rust/.cargo/config.toml` aside so only the
NDK sysroot is used. Neither the NDK, Gradle nor `kotlinc` exists on this
machine, so the APK has not been produced here — the Kotlin is written against
framework APIs only (no AndroidX), but it needs a machine with the NDK to build.

### Runtime setup

1. Open tunlens, **Choose apps**, tick the apps you own.
2. **Start capture** → the system VPN consent dialog appears.
3. Optional: **Overlay** (needs the "display over other apps" permission).

Only ticked packages are captured. The allow-list is never empty: the service
refuses to start without a selection, so this tool cannot silently capture
everything. tunlens always excludes itself from the VPN so its own upstream
sockets cannot loop back into the tun.

## Event schema

```json
{
  "ts_ms": 1763215541123,
  "host": "clientbp.ggpolarbear.com",
  "port": 443,
  "direction": "client",
  "protocol": "tls",
  "op": "client_hello",
  "summary": "TLS clientbp.ggpolarbear.com (h2)",
  "detail": { "sni": "clientbp.ggpolarbear.com", "alpn": ["h2"], "record_bytes": 517 },
  "raw_hex": "1603010201...",
  "bytes": 517,
  "flow": "10.233.0.2:41234>203.0.113.10:443"
}
```

`protocol` is one of `tls`, `http`, `json`, `dns`, `unknown`. A payload is only
labelled when it actually parses; unparsable bytes stay `unknown` rather than
being guessed from the port. At most 64 events are emitted per flow, and the hex
preview is capped, so a large download cannot flood the UI.

The example above uses the original app's real API host, which is also what the
test fixtures use (`clientbp.ggpolarbear.com`, `loginbp.ggpolarbear.com`). Those
names are inert strings: every test dials `127.0.0.1`, so no query is ever
resolved and nothing is sent to that host. Addresses in fixtures are from the
documentation range (`203.0.113.0/24`) because tunlens does not resolve or pin
the real server's IP.

## What is missing (deliberately or pending)

* **No decryption of TLS/QUIC bodies.** Only metadata that is visible on the
  wire (SNI, ALPN, record types, plaintext HTTP and DNS). Adding a user-installed
  CA / MITM would be a separate, explicit feature.
* **IPv4 only.** No IPv6 address is added to the tun, so apps fall back to IPv4.
* **TCP plus DNS.** Other UDP (QUIC, games) is not forwarded; it is dropped and
  not reported.
* **No pcap/HAR export yet.** The event stream is JSON; a writer is easy to add.
* **Single upstream resolver** (`1.1.1.1:53` by default, `TunConfig::dns_upstream`).

## Boundaries

The original app this was reconstructed from also (a) scraped Free Fire's AES
key and IV out of its logcat through a Shizuku shell service and (b) re-injected
edited packets into a live session. Both are absent here, by design:

| Original | tunlens |
|---|---|
| `setKey` from another app's logs | no key injection; you see only what crosses *your* device's tun |
| `editAndSendDetailed` | no write path — the bridge has no API to alter a payload |
| Shizuku cross-app log reading | not used; no `QUERY_ALL_PACKAGES`, no shell service |
| signature gate in native code | none |
| rewrites the game's login URL to `127.0.0.1:8080` and re-issues requests to `clientbp.ggpolarbear.com` | no URL rewriting; dials exactly what the captured app dialled |

Use it on apps you own or are authorised to test. Capturing other people's
traffic, or using it to tamper with a game or another service, is out of scope.

Details of the original artifact, its endpoints, and the omission list are in
[`docs/provenance.md`](docs/provenance.md).

## Verified

* `cargo test`: 17 passing, including an integration test that drives the real
  tun bridge over a datagram socket pair (SYN → SYN-ACK from the destination,
  handshake, request relayed to a loopback origin, response relayed back) and a
  DNS test with a stand-in resolver.
* End-to-end SOCKS5 run against local HTTP and TLS origins: `GET` request
  dissected as `clientbp.ggpolarbear.com`, real `openssl` ClientHello reported as
  `TLS loginbp.ggpolarbear.com (h2)`, server records labelled (`server_hello`,
  `application_data`).
* `libtunlens.so` exports all nine `Java_dev_tunlens_NativeBridge_*` symbols.
