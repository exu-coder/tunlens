# Provenance

What this code was reconstructed from, and what was deliberately left out.

## Source artifact

| | |
|---|---|
| Original app | "H4RDIXx packets" |
| Package | `com.h4xdevxgen.ffpacket` |
| Version | 1.2.31-test |
| APK sha256 | `501c822215948eced7bb73b070fb428c795f7e3776db15c21f3d7f54a9d42870` |
| Signature | v2-only, single signer, cert `c8947473…` |
| Extracted libraries | `libffpacket.so` (2,087 exports, 19 JNI `NativeBridge` methods), `libhev-socks5-tunnel.so` |
| Analysis | REA (artifact inventory, ELF notes/exports, native disassembly) + jadx 1.5.6 for the 1,528 Java sources |

The original is a packet capture **and injection** tool for Garena Free Fire. Its
own network endpoints are just the game's API:

| Purpose | Endpoint |
|---|---|
| Login/ping | `https://loginbp.ggpolarbear.com/ping` |
| All other proxied calls | `https://clientbp.ggpolarbear.com/<path>?<query>` |
| Local MITM proxy | `http://127.0.0.1:8080/` |
| Local SOCKS5 for tun2socks | `127.0.0.1:1080` |

It has no backend of its own: it rewrites the game's login URL to its loopback
proxy, re-issues the request to `ggpolarbear.com`, and reads the plaintext body
on the way through. Those hostnames appear in this repo only as inert strings in
test fixtures; nothing here contacts them.

## Reconstructed (this repo)

* `VpnService` + `ParcelFileDescriptor` → userspace TCP/IP stack.
* SYN handling: answer as the destination (smoltcp AnyIP + a route via the
  interface's own address) rather than initiating a second connection.
* Local capture point (SOCKS5) and per-flow dissection.
* TLS ClientHello SNI/ALPN, TLS record labels, HTTP request/response, DNS
  question, JSON document detection.
* Floating overlay UI and an app-scoped capture list.

## Not reconstructed, on purpose

| Original capability | Why it is absent |
|---|---|
| `setKey` with AES key/IV scraped from Free Fire's logcat via a Shizuku shell service | Cross-app secret extraction to defeat another app's transport encryption |
| `editAndSendDetailed` / packet re-injection | Writing into a live third-party session; tunlens has no API that can alter a payload |
| `verifyAppSignature` native gate | Meaningless once the cheat-specific code is gone |
| URL rewriting to a local proxy, then re-issuing to the real API | That is the seam that enables body editing; tunlens dials exactly what the app dialled |

## Scope

Use tunlens on apps you own or are authorised to test. Capturing other people's
traffic, or using it to tamper with a game or another service, is out of scope.
