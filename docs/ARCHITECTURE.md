# Technical architecture / معماری فنی

[README فارسی](../README.md) · [English README](../README.en.md) · [Security policy](../SECURITY.md)

**Version:** Manager 3.3.4 · **persistent config schema:** 3 · **secure wire:** 4 · **topology:** exactly one Iran VPS and one overseas VPS.

**خلاصه:** Pingtunnel Manager فقط دو VPS دارد. کاربر به پورت TCP/UDP سرور ایران وصل می‌شود؛ هسته Go ترافیک را در ICMP رمزنگاری‌شده به VPS خارج می‌رساند و سرور خارج آن را به پورت سرویس محلی خودش تحویل می‌دهد. Rust تنها کارهای راه‌اندازی، ذخیره تنظیمات و کنترل systemd را انجام می‌دهد.


## Bidirectional Reverse poll scheduling (v3.3.4)

The foreign Go poller was initially paced by successfully authenticated Iran-to-Foreign DATA alone. For download-heavy QUIC video, a temporary lack of return ACKs could incorrectly cool the poller from 2–12 ms to 80–250 ms, creating a self-reinforcing return-path delay. The scheduler now tracks a second signal: Foreign-to-Iran encrypted application DATA send attempts. It uses whichever side requires the shorter polling interval, holding the return path warm through short ACK silences with staged 12/24/45-ms cooldown. Only application DATA drives the new demand signal: handshake control, routine PINGs and unauthenticated PTR4 replies do not count.

Queue observability adds maximum and EWMA dequeue wait, computed from the original enqueue timestamp when a queued frame is taken for attempted sending. These measurements are **process-lifetime** diagnostics and do not include downstream congestion/packet loss after a successful raw-socket write. No plaintext or new wire-protocol fields are introduced; diagnostics are local JSON only.

## Overseas PTR4 Echo reflection filtering (v3.3.3)

The overseas reverse poller sends a 36-byte `PTR4` control payload inside a standard ICMP Echo Request. Linux on the Iran host can automatically return that *same* payload inside an Echo Reply. Such a reply is not a `PTH4` authenticated handshake frame or a `PTD4` AEAD data frame. Previously the overseas receiver could route the reflected payload to session decrypt and increment `authentication_failures` in the non-session-frame branch.

v3.3.3 tests the pinned peer source IP first, then filters only **ICMP Type 0** replies with **exactly 36 bytes** of Echo payload and **PTR4** prefix before the session decoder. Ordinary data and authenticated control frames do not match this filter. Filtered reflections increment `reverse_poll_echo_reflections` and never count as security failures, proof of data delivery or fresh authenticated peer traffic. This is an internal receive-path change only, not an ICMP wire-format modification.

## Reverse-first Auto failover safety (v3.3.2)

Auto starts with Reverse on both peers. The Iran endpoint alone decides when sustained failure merits emergency Direct; the overseas peer follows authenticated ICMP negotiation. This prevents short packet-loss bursts, an idle VPN, or the previous unconditional 25-second handshake deadline from preempting a functioning Reverse tunnel.

The Iran transport records sustained local client demand separately from the last authenticated peer data and last verified reverse poll timestamp. Direct is eligible only if real client demand continues and one of three conditions holds: (1) no signed Reverse polls at all for at least 90 seconds, (2) signed polls arrive but the authenticated four-step handshake remains incomplete for 150 seconds, or (3) an established reverse path has seen neither authenticated polls nor decrypted authenticated peer frames for at least 150 seconds. Direction dwell and later recovery opportunities remain bounded. A mode switch reports its reason and accounts for queued ciphertext that cannot be replayed across sessions.

Authenticated inbound polls prove that the foreign-origin ICMP request arrived in Iran; they do not independently prove that Iran's Echo Reply reached Foreign. For complete reachability, use authenticated handshake/data receipts and application throughput statistics. Avoid inferring transport availability from process liveness or generic Ping.

## Reverse throughput scheduling (v3.3.1)

The overseas Go transport sends authenticated foreign-initiated Echo Requests. An event-driven timer selects nominal inter-poll delays of **200 ms negotiating / 250 ms idle / 80 ms quiet with active connections / 40 ms one useful frame / 12 ms moderate burst / 2 ms sustained burst**. All acceleration is gated on successfully authenticated incoming application DATA, never on untrusted ICMP packets. The resulting schedule is demand-aware, not congestion-aware: middlebox rate limits, ICMP loss and scheduling jitter may still reduce performance.

On Iran, encrypted frames are held in a FIFO queue bounded by **256 frames, 2 MiB, 12 seconds**. One authenticated poll can retrieve one queued encrypted frame in a matching Echo Reply. If the raw socket reports a write failure, the unsent frame is restored to the front without refreshing its lifetime; under pressure the queue drops the newest tail first to preserve the failed older frame. Normal empty polls do not cause an extra userspace reply; system-generated ICMP Echo behavior is controlled by Linux. Direction switching retains the existing reverse-first Auto selection and Direct fallback rules.

For predominantly Iran→Foreign flows, Foreign sends an encrypted delivery receipt at most every eight seconds **only** while genuine authenticated incoming DATA has arrived within the previous ten seconds. Iran validates it using the existing session AEAD, which is useful evidence that Foreign received data and helps avoid an accidental reverse-to-direct switch during one-way traffic. Unsigned Echo Replies are not delivery evidence.

Runtime JSON at `/run/pingtunnel-security.json` now reports `reverse_queue_packets`, `reverse_queue_bytes`, `reverse_queue_peak`, `reverse_queue_drops`, `reverse_write_failures`, `reverse_poll_interval_ms` and `reverse_last_data_age_seconds` along with the existing handshake and replay data. Do not treat incoming HMAC-verified polls alone as proof of a functioning reverse return path.

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
- **Direction:** Default Auto starts with **Reverse**: Foreign sends authenticated ICMP Echo Requests and Iran carries encrypted ingress data in matching Echo Replies. Only after prolonged Reverse failure under genuine sustained local demand may Iran attempt **Direct**, and sustained loss may trigger later recovery; roles and directional encryption remain fixed to physical regions.

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
  Cargo.toml             Rust manager package (3.3.4)
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

Release builds are verified with SHA256 and a release manifest specifying **manager 3.3.4 / config schema 3 / wire 4**. The installer rejects unexpected core identity before changing installed binaries. The pinned published release is [v3.3.2](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.2); rolling assets may also exist for compatibility.

## 8. Compatibility contract and limitations

| Version | Schema | Wire | Can connect directly to 3.2? |
| --- | --- | --- | --- |
| **3.2.1** | 3 | 4 | Yes |
| **3.1.0** | 3 | 4 | Wire-compatible; mixed-version field testing still advised |
| **3.0.0** | 3 | Earlier frame format | No, without upgrading the peer |
| **Earlier** | Legacy | Legacy | No supported automatic migration |

Further changes must preserve schema 3 unless explicitly versioned and provide a documented migration path. Wire protocol modifications require explicit version negotiation or a planned, fail-closed coordinated upgrade. **Never silently fall back to plaintext or earlier unauthenticated packet formats.**

Remaining omissions: multiple VPSs/HA, simultaneous TCP and UDP in one tunnel, independent cryptographic audit, and proven DPI resistance. Reverse-first Auto is implemented but needs field testing over an actual two-VPS ICMP path—including packet loss, high jitter, ICMP Echo kernel reply interactions, and application sessions.
