# Technical architecture / معماری فنی

[README فارسی](../README.md) · [English README](../README.en.md) · [Security policy](../SECURITY.md)

**Version:** Manager 3.2.2 · **persistent config schema:** 3 · **secure wire:** 4 · **topology:** exactly one Iran VPS and one overseas VPS.

**خلاصه:** Pingtunnel Manager فقط دو VPS دارد. کاربر به پورت TCP/UDP سرور ایران وصل می‌شود؛ هسته Go ترافیک را در ICMP رمزنگاری‌شده به VPS خارج می‌رساند و سرور خارج آن را به پورت سرویس محلی خودش تحویل می‌دهد. Rust تنها کارهای راه‌اندازی، ذخیره تنظیمات و کنترل systemd را انجام می‌دهد.

## 1. Responsibilities and boundaries

| Component | Role | Persistent process? |
| --- | --- | --- |
| **Rust manager** (`Rust/src/main.rs`, `Rust/src/setup.rs`) | Five-question wizard, pairing-key handling, JSON validation, service unit, installation/update UI, diagnostics | No; executes only when invoked |
| **Go transport client** (Iran) | TCP/UDP ingress, outbound ICMP, session handshake, retransmission/congestion logic and adaptive measurements | Yes, under systemd |
| **Go transport server** (overseas) | ICMP reception, peer checks, authenticated decrypt and forwarding to a fixed local destination | Yes, under systemd |
| **Installer** (`Source/install.sh`) | Download matched release binaries, validate integrity/identity and install atomically with rollback | No |
| **Application / VPN service** | User's Hysteria 2, s-ui or another local TCP/UDP service | Managed separately; not part of this repo |

The underlying transport is based on [esrrhs/pingtunnel](https://github.com/esrrhs/pingtunnel), with a repository-specific Go overlay. Do not replace the modified Go core with the unmodified upstream executable; the security protocol is different.

## 2. Topology and port mapping

~~~text
User / VPN client
    |
    | application traffic: Iran_IP:ingress_port (TCP or UDP)
    v
[ Iran VPS / Go Client ]
    | ICMP Echo, encrypted wire v4
    | IP source/destination = configured VPS IPv4 pair
    v
[ Overseas VPS / Go Server ]
    | fixed_target = 127.0.0.1:service_port
    v
Hysteria 2 / s-ui / application listener on overseas VPS
~~~

- **Outer transport:** ICMP, which has no TCP or UDP port number.
- **Iran ingress:** user-selected local TCP or UDP port, suggested **TCP 443 / UDP 444**.
- **Overseas service port:** separately user-selected, delivered via loopback (for example **UDP 8443**).
- **One transport choice:** current setup configures either TCP or UDP forwarding per tunnel, not simultaneous TCP+UDP.
- **Direction:** currently Iran initiates the ICMP control/data exchange. Reversing this initiation direction is **not implemented**. Physical role is kept separate from handshake roles to make future engineering possible, not to claim current reverse support.

Example Hysteria 2 mapping: `Iran_IP:444/UDP → ICMP → 127.0.0.1:8443/UDP` overseas. The VPN client sees only the Iran IP and port; Hysteria 2 is configured on the overseas VPS.

### Trusted destination policy

The overseas Go server checks the configured peer IPv4 and replaces the tunnel packet's requested forwarding target with its own `fixed_target` from config. The target must be `127.0.0.1:1..65535`; the specified TCP/UDP mode is enforced. The Iran client does not get to select an arbitrary overseas address.

## 3. Persistent configuration and pairing

The manager uses `/opt/pingtunnel/conf/config.json`, with a required `schema_version = 3`. A typical configuration shape is:

~~~json
{
  "schema_version": 3,
  "region": "iran",
  "peer_ip": "203.0.113.10",
  "pair_key": "<32-random-bytes-encoded-as-canonical-base64>",
  "transport": "udp",
  "port": 444,
  "memory_mb": 0,
  "autostart": true
}
~~~

This is an **illustrative, nonfunctional example**, not a generated live key. The corresponding overseas config has region `foreign`, peer IP set to the Iran VPS, and its own service port (for example `8443`). Both must use the same pairing key and transport choice.

The pairing root is created from the operating system CSPRNG (`/dev/urandom`) at the **first overseas setup** and entered once on the Iran VPS. Re-running the wizard preserves this root. A separate numeric Go packet identifier is deterministically derived from the root by a namespaced SHA-256 calculation; it is **not** an independent user-supplied password.

The Rust manager generates a temporary private `/run/pingtunnel-core.json` with Go's parameters, rather than leaking the root in command-line arguments. The manager and core are both managed by a systemd service.

## 4. Wire protocol and session security

**Version 3.2:** persistent schema 3, **wire version 4**.

1. **Authenticated greeting:** The Iran Go client initiates a negotiation. The two peers authenticate control messages with material derived from the shared pairing root.
2. **Ephemeral agreement:** Each peer generates an ephemeral X25519 key pair. The shared ECDH secret and pairing-root material feed HKDF-SHA256.
3. **Key confirmation:** A four-message handshake provides proof of the resulting ephemeral key agreement before authenticated application data is accepted.
4. **Directional AEAD:** Separate send/receive session keys and nonce prefixes for Iran→foreign and foreign→Iran. The application-data algorithm is **AES-256-GCM or XChaCha20-Poly1305**, chosen at startup using a CPU benchmark.
5. **Replay defense:** Data frames carry a session identifier and authenticated 64-bit sequence. The receiver authenticates first, then applies a **1,024-frame sliding replay window**. Legitimate out-of-order frames are accepted within the window, duplicates/old frames are rejected.
6. **Renegotiation:** In version 3.2, a new signed ClientHello does not immediately replace an authenticated active session. The overseas server holds a bounded candidate handshake, promoting it only after a valid ephemeral-key Finish proof.

The control and data frames use recognizable **`PTH4`** and **`PTD4`** markers. These are not traffic camouflage; a network operator can still observe ICMP. This custom protocol has not been independently audited and should be reviewed before high-assurance use.

## 5. Adaptation and failure recovery

### Adaptive Performance

The Iran client uses existing Pingtunnel ICMP probes for smoothed RTT, jitter and response-loss heuristics. This controls **initial resend timeout and frame window for new TCP sessions**. Established TCP streams keep the original Go core's `BB` congestion behavior. There is **no** live modification of existing stream windows or independent adaptive UDP rate controller.

### Smart Recovery

When a session is silent for a sustained interval while there is active traffic demand, the Iran client negotiates fresh session keys. Handshake retransmission uses bounded backoff. DATA arriving before the new secure session is ready may be queued, capped globally at:

- **256 frames**
- **2 MiB of bytes**
- **12 seconds maximum waiting time**

Queue expiration/overflow is counted and reported. **Recovery is best effort:** ICMP blocking, process restart, old frame state and application-side timeouts can still force the VPN client to reconnect. No HA or additional VPS is used.

### Diagnostics

Go emits secret-free, permission-restricted runtime reports:

| File | Values |
| --- | --- |
| `/run/pingtunnel-security.json` | Session state, wire/schema versions, authentication failures, replay drops, recovery, pending data |
| `/run/pingtunnel-performance.json` | RTT, jitter, estimated ping loss and next TCP session settings |

Rust CLI presents these through `pingtunnel security` and `pingtunnel performance`. A stale health report is **not** evidence of a healthy process; check `systemctl status pingtunnel.service` and journal logs.

## 6. Source tree

~~~text
Rust/
  Cargo.toml             Rust manager package (3.2.2)
  src/main.rs            CLI, systemd and config generation
  src/setup.rs           Unified pairing wizard

Go/
  client.go              Modified upstream Go client
  server.go              Modified upstream Go server
  pingtunnel.go          ICMP envelope + control/data handling
  secure_session.go      X25519 negotiation, session AEAD, anti-replay, recovery
  server_policy.go       Fixed overseas target + peer restrictions
  auto_crypto.go         Automatic AEAD benchmarking and crypto glue
  crypto.go              Integration with core encryption interfaces
  adaptive_performance.go RTT/loss/jitter adaptation
  config.go              Extra JSON config fields
  cmd/main.go            Modified Go executable entry point
  *_test.go              Security and network-state unit tests

Source/
  install.sh             Version-pinned installation and integrity verification
  update.sh              Installer entry-point

.github/workflows/rust.yml
README.md
README.en.md
SECURITY.md
CHANGELOG.md
~~~

## 7. Development and release workflow

The Go folder is an **overlay**, not a full standalone copy of all upstream source. CI fetches the upstream repository, checks out commit:

`df16e52771ee67f1f9770ec68763b425672a36fc`

It then copies the local Go files onto the pinned upstream tree and runs the Go tests, Race Detector and Linux AMD64/ARM64 builds. To reproduce that pipeline locally, use the same pinned upstream commit and the copy steps in [.github/workflows/rust.yml](../.github/workflows/rust.yml).

Rust code is independently testable:

~~~bash
cargo test --manifest-path Rust/Cargo.toml
cargo build --release --manifest-path Rust/Cargo.toml
~~~

Release builds are verified with SHA256 and a release manifest specifying **manager 3.2.1 / config schema 3 / wire 4**. The installer rejects unexpected core identity before changing installed binaries. The pinned published release is [v3.2.1](https://github.com/MSMSofts/Pingtunnel_manager/releases/tag/v3.2.1); rolling assets may also exist for compatibility.

## 8. Compatibility contract and limitations

| Version | Schema | Wire | Can connect directly to 3.2? |
| --- | --- | --- | --- |
| **3.2.1** | 3 | 4 | Yes |
| **3.1.0** | 3 | 4 | Wire-compatible; mixed-version field testing still advised |
| **3.0.0** | 3 | Earlier frame format | No, without upgrading the peer |
| **Earlier** | Legacy | Legacy | No supported automatic migration |

Further changes must preserve schema 3 unless explicitly versioned and provide a documented migration path. Wire protocol modifications require explicit version negotiation or a planned, fail-closed coordinated upgrade. **Never silently fall back to plaintext or earlier unauthenticated packet formats.**

Current omissions: genuine reverse forwarding, automatic Direct/Reverse selection, multiple VPSs/HA, simultaneous TCP and UDP in one tunnel, independent cryptographic audit and proven DPI resistance. Testing over a real two-VPS ICMP path—including packet loss, high jitter and actual Hysteria 2 sessions—is still required.
