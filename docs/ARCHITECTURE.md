# Technical architecture / معماری فنی

[README فارسی](../README.md) · [English README](../README.en.md) · [Security policy](../SECURITY.md)

**Version:** Manager 3.4.7 · **persistent config schema:** 3 · **secure wire:** 4 · **topology:** exactly one Iran VPS and one overseas VPS.

**خلاصه:** Pingtunnel Manager فقط دو VPS دارد. کاربر به پورت TCP/UDP سرور ایران وصل می‌شود؛ هسته Go ترافیک را در ICMP رمزنگاری‌شده به VPS خارج می‌رساند و سرور خارج آن را به پورت سرویس محلی خودش تحویل می‌دهد. Rust تنها کارهای راه‌اندازی، ذخیره تنظیمات و کنترل systemd را انجام می‌دهد.


## Encrypted PING reflections and bounded TTL FIFO signature cache (v3.3.8)

In the 3.3.7 foreign sender, only successfully encrypted application DATA Echo Requests had outbound fingerprints. Authenticated PING (and other secured PTD4 message types) use the same Echo Request pathway, so the Iran kernel can return their own original ciphertext as type-0 replies; these cannot authenticate under the foreign receive-direction AEAD key. An on-host 47-second measurement counted 34 authentication errors despite 4,277 blocked exact DATA reflections, supporting (but not proving) this hypothesis.

v3.3.8 tags each outbound encrypted PTD4 Echo Request as DATA, PING or other and registers its **full encrypted payload SHA-256 plus ICMP ID/sequence** before raw socket write. The incoming foreign receive path still requires an Echo Reply, configured source IP and an exact fingerprint match within 8 seconds. Failed writes cancel registration. Only successful **application DATA** updates BBR return-poll activity; PING never promotes polling.

The signature tracking cache remains a fixed 16,384-element chronological ring plus a bounded map. Each send/receive/security-status access prunes expired and canceled oldest entries amortized O(1). On capacity pressure it evicts oldest entries; an evicted signature cannot be used to suppress a packet. Metrics: `reverse_data_echo_reflections`, `reverse_ping_echo_reflections`, `reverse_other_echo_reflections`, `reverse_data_echo_cache_entries`, `reverse_echo_cache_expired`, and `reverse_echo_cache_capacity_evicted`. No plaintext is stored. All cryptography, session frame layout, polling, replay protections and Reverse-first fallback rules remain unchanged.

## Exact encrypted-data echo reflection matching (v3.3.7)

Linux on the Iran VPS can automatically Echo Reply a foreign-origin encrypted PTD4 Echo Request, copying its PTD4 ciphertext bytes verbatim. This can return the *foreign transmit-direction ciphertext* to the foreign receive-direction AEAD decoder. Because QUIC ACKs legitimately use PTD4 too, filtering all inbound PTD4 is unsafe. In a 10-second live capture, 1,453 of 2,047 inbound PTD4 replies were exact byte-for-byte matches of the 1,465 outbound encrypted requests; the other 594 inbound replies were unmatched (not necessarily all valid).

For every successfully encrypted outgoing foreign DATA Echo Request, the transport stages a SHA-256 digest of the **complete** ciphertext plus ICMP Echo ID and sequence **before writing** the packet to its raw ICMP socket. Raw-write failure revokes registration. The structure is a fixed 16,384-slot ring and a lookup map of signatures, bounded in space; entries are eligible for matching only for 8 seconds. After verifying pinned peer source IP, the receiver discards a Type 0 Echo Reply before AEAD decrypt **only if** its full ciphertext digest and ICMP Echo ID/sequence exactly match a recent staged outbound DATA Echo Request. Real Iran→Foreign authenticated frames with distinct ciphertext cannot match by marker alone; no private session keys or plaintext are held in this cache. Matches and cache entries are reported as `reverse_data_echo_reflections` and `reverse_data_echo_cache_entries`.

This reduces pointless decrypt processing and separates Linux reflections from authentication errors. It does not guarantee higher throughput, lower network loss or complete elimination of video stalls. Wire format, authenticated session, reverse polling and BBR configuration remain unchanged.

## Bounded BBR jitter polling and rolling queue-delay distribution (v3.3.6)

The foreign reverse poll scheduler requires real successfully written outbound DATA or authenticated incoming DATA before sustaining high poll rates. Its fast intervals now survive short 1–3s QUIC/BBR ACK-silence and congestion-recovery gaps without indefinitely polling at the 2ms ceiling: 2ms for 2.4s after bursts of incoming DATA; 4ms for up to 4.5s after outbound DATA bursts; then 6/12/25ms as those hints expire. Empty reflected PTR4 Echo Replies and mere socket existence never refresh these windows. Negotiation/idle pacing remains 200/250ms. These intervals are targets only and do not prevent ICMP carrier packet loss.

In Iran, each successful encrypted-data Echo Reply stores its enqueue-to-socket-write residence time in a bounded 128-element ring. A status snapshot computes the integer mean and nearest-rank P95 over those recent sends, plus a cumulative counter of 1s+ send queue delays. The ring uses no per-frame allocation; read-time sorting is bounded. Failed writes preserve original enqueue timestamps and do not become successful measurements. A successful socket send does not prove end-to-end delivery; use these stats with foreign authenticated receive age and network capture when investigating stalls.

## Replay nonce cache capacity during high-rate Reverse polling (v3.3.5)

The overseas poller may send about 500 authenticated ICMP Echo Requests per second. The Iran-side replay cache previously allowed only 4,096 live nonces under a 20-second replay window. That is smaller than the roughly 10,000 legitimate nonces simultaneously in flight at maximum rate. Exhaustion could reject valid polls and delay the return path for QUIC acknowledgements.

v3.3.5 uses a **16,384-entry bounded replay cache**, retains HMAC validation, the 20-second timestamp window and nonce uniqueness checks, and exposes `reverse_replay_capacity_rejections` separately. Expired entries are pruned periodically. The new Go test sends 10,000 distinct valid polls at a simulated 500Hz over 20 seconds, ensures they authenticate, then checks replay rejection and bounded memory. The secure wire v4 and Reverse-first Auto remain unchanged.

## Video/QUIC return-path scheduling and delay telemetry (v3.3.4)

Hysteria/QUIC video traffic is often asymmetric: the overseas endpoint streams application DATA to Iran, then expects acknowledgements carried in the Iran→Foreign reverse reply queue. The previous poll scheduler accelerated only on inbound authenticated Iran→Foreign DATA, creating a feedback loop when delayed ACKs caused an outbound-video stall.

The overseas sending path now records *successfully written* encrypted application DATA separately from inbound DATA. Its reverse poller uses both traffic directions, a decaying warm window, and active connection count. Target intervals: handshake 200 ms, no application 250 ms, active but quiet 25 ms, initial/warm outbound video 12 ms, sustained outbound video 4 ms, sustained authenticated inbound DATA 2 ms. A single idle Ping, reflected PTR4 Echo or HMAC poll does not count as video DATA.

On Iran, the bounded FIFO measures actual age of its oldest waiting ciphertext and the delay on each **successful userspace Echo Reply write**; failed socket writes and expired entries are excluded from successful-delivery counters. Exported JSON: `reverse_oldest_queue_age_ms`, `reverse_last_delivery_delay_ms`, `reverse_max_delivery_delay_ms`, `reverse_delivered_frames`, `reverse_delayed_frames` (>=250 ms), and `reverse_last_outbound_data_age_ms`. These metrics are independent of retransmission, path loss and external Hysteria congestion. Do not claim bandwidth gains until on-host playback and loss are measured.

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

## Per-service v3.3.24 dispatch and TCP reply protocol fix (v3.4.7)

After v3.4.3, Multi-Port received every encrypted TCP/UDP response on one shared ICMP socket and selected a *shared protocol queue* by `MyMsg.Tcpmode`. **All four Foreign DATA reply calls passed literal `0`** even for established TCP connections, a legacy artifact from the old single-protocol version. This caused TCP response frames to be admitted into the **UDP** dispatcher, sharing its 256-frame queue and loss policy with game/QUIC/video traffic.

The corrected Foreign sender uses `conn.tcpmode` for all DATA replies. Iran additionally consults the authenticated **connection ID mapped to its own registered `ClientConn.tcpmode`** to route return frames robustly, even during rolling upgrade from a legacy mislabeled Foreign peer. The Foreign incoming direction uses the pinned, authenticated service alias and the explicitly supplied protocol as before, rejecting mismatches.

Each enabled TCP or UDP service gets an independent dispatch goroutine and **10,000-frame TCP or 256-datagram UDP FIFO**, matching the original v3.3.24 per-process queue capacity. FIFO UDP drops newly arriving DATA when saturated and preserves already accepted frames. TCP saturation is shed per-service for FrameMgr retransmission rather than waiting for the original 3-second single-protocol TCP reader timeout (which would block all UDP over today's shared ICMP socket). The same authenticated ICMP receiver, AEAD/replay state, pinned peer and independent PING/KICK/control lane are kept. The security status adds a per-service queue occupancy/capacity/drop map for both VPSs.

**Limitation:** service queue independence does NOT create independent kernel ICMP sockets, physical path bandwidth, or isolated secure sessions. Real two-VPS performance claims require measured before/after A/B tests.

## Restoring pre-Multi-Port UDP admission and processing (v3.4.6)

The v3.3.24 codebase already used `packetQueueCapacity(true)==256` and `enqueueICMPPacket(queue, packet, true)` for authenticated UDP DATA. When saturated it **drops the newly arriving datagram** and retains the existing FIFO order; control frames wait rather than being deliberately evicted. v3.4.3's Multi-Port-specific `enqueueFreshMixedUDP` reversed this admission policy by evicting the **oldest accepted DATA** to admit the newest. That speculative change is removed: mixed UDP DATA now directly calls the identical legacy helper as single-service UDP.

In the same pre-Multi-Port source, UDP-only server dispatch used the configured `maxprocessthread` worker pool (typically 100); mixed Multi-Port had capped the independent UDP pool at 16. The separate UDP pool now uses the **full configured worker count** to restore original per-flow hash worker parallelism while avoiding unrelated TCP connection dials. This is not an unbounded queue and does not change the 256 UDP queue capacity or port mappings.

The 12-service mixed sender still shares a single ICMP socket and authenticated session, so exactly reproducing pre-Multi-Port per-process socket isolation requires a separate single-service deployment. Retain independent TCP/control receive lanes and the Wire v4 authentication, anti-replay and Echo reflection filters. No production-vs-previous throughput improvement is claimed without field A/B comparisons.

## Upstream fair TCP underlay and raw tail diagnosis (v3.4.5)

Reference: [esrrhs/pingtunnel upstream commit a557d216 (2026-11-08)](https://github.com/esrrhs/pingtunnel/tree/a557d2169ff8b13ca64f227b0549bbd6f1f84587). Its `underlay_share.go` avoids a single connection dumping its entire congestion window into the kernel ICMP buffer; FIFO underlay scheduling yields every **8 KiB of TCP FrameMgr payload**. The MSM Go overlay now uses one fair share **per client/server process**, across all TCP service aliases and all TCP send phases (initial, active and close/drain). This is send-side scheduling only; the 3-lane Multi-Port receive queue and independent UDP worker pool remain unchanged. Independent UDP traffic and authenticated controls **bypass** the TCP gate to avoid new video latency.

Adaptive idle-loop scheduling reuses lazily allocated timers with the original 2–80/250ms bounds instead of repeated `time.After` allocations. Neither change modifies existing congestion-control or cryptographic semantics. `pingtunnel security` adds the cumulative `tcp_icmp_fair_turns`, `tcp_icmp_fair_contended` and `tcp_icmp_fair_max_wait_ms` counters. Adaptive performance now stores the most recent 128 *individual* authenticated ICMP RTT samples no older than 120s and reports raw P50/P95/P99/max, counts above 250ms/1000ms, rather than presenting only averages of smoothed RTT. A 1s application pause with no simultaneous probe can still evade detection.

## Direct ICMP kernel Echo reflection filtering (v3.4.4)

The Linux kernel on the **Foreign** host can respond to an Iran-origin encrypted ICMP Echo Request with an automatic Echo Reply containing identical outgoing bytes. Iran receives that kernel reflection in addition to the Foreign userspace application reply. Since receive-direction AEAD keys are distinct, passing our own copied ciphertext to Iran's decryptor generates a **spurious AEAD tag error**. The earlier exact-reflection filter applied only to Foreign-origin Reverse Echo Requests.

For **both** Foreign Reverse and Iran Direct, senders now stage SHA-256 of the **entire encrypted request payload**, ICMP Echo ID/sequence, message kind and time in the existing 16,384-entry / eight-second bounded signature cache. A failed socket write removes its pending record. Receivers first enforce the pinned peer IP; type-0 Echo Reply is suppressed only if digest **and** both ICMP identifiers match an unexpired own request. Never drop PTD4 based solely on a prefix, packet length or source IP: a valid peer's opposite-direction encrypted ACK must survive. Direct and Reverse counters remain distinct. Local `pingtunnel security` also separates malformed framing, wrong session, failed AEAD tags, and handshake control authentication errors.

The user-observed high Iran authentication-failure counter is *consistent* with this missing Direct filter, but not proof that every error was a kernel reflection, nor proof that Instagram's 1–3-second stalls will be removed. Evaluate per-minute deltas against a real packet capture or test. Wire v4 and all destination restrictions are unchanged.

## Multi-Port latency isolation (v3.4.3 compared with v3.3.24)

The 3.3.24 tunnel processed a single TCP **or** UDP ingress protocol per process. v3.4.1–3.4.2 allowed 12 mixed services and had two receive queues, but dispatched both through one sequential goroutine and Foreign's shared hash-sharded thread pool. Slow TCP connection setup (up to 1s per target) and frame processing could therefore cause UDP head-of-line blocking even with independent receive channel capacities.

v3.4.3 separates **TCP DATA**, **UDP DATA**, and authenticated **PING/KICK control** into three packet processing goroutines on each peer. Foreign additionally routes UDP DATA to an independent 16-worker-maximum hash-by-flow thread pool, so a delayed TCP dial cannot monopolize a UDP worker. Under UDP receive overload the bounded 256-frame UDP queue evicts only the oldest UDP DATA, never an authenticated control frame. Control has a dedicated reliable queue of 128. TCP's unchanged 10,000-frame queue uses immediate overflow shedding in Multi-Port rather than multiplying 2ms waits; its reliable FrameMgr retransmits missing TCP frames. The original single-port dispatch behavior is unaffected.

Queue troubleshooting: `pingtunnel security` exposes `udp_dispatch_queue_max_delay_ms` / `tcp_dispatch_queue_max_delay_ms` and counts exceeding 250ms. These measure **local post-authentication dispatch delay**, not IP/ICMP roundtrip time, remote service delay, or application buffering. Long-duration real two-VPS evidence is still required.

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
- **Direction:** Default Auto starts with **Reverse**: Foreign sends authenticated ICMP Echo Requests and Iran carries encrypted ingress data in matching Echo Replies. If Reverse cannot authenticate within its bounded startup window, Iran attempts **Direct**, and sustained loss may trigger later recovery; roles and directional encryption remain fixed to physical regions.

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
  Cargo.toml             Rust manager package (3.3.8)
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
cargo test --locked --manifest-path Rust/Cargo.toml
cargo build --locked --release --manifest-path Rust/Cargo.toml
~~~

Release builds are verified with SHA256 and a release manifest specifying **manager 3.4.7 / config schema 3 / wire 4**. The installer rejects unexpected core identity before changing installed binaries. The versioned release is [v3.4.7](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.4.7); rolling assets may also exist for compatibility.

## 8. Compatibility contract and limitations

| Version | Schema | Wire | Can connect directly to 3.2? |
| --- | --- | --- | --- |
| **3.2.1** | 3 | 4 | Yes |
| **3.1.0** | 3 | 4 | Wire-compatible; mixed-version field testing still advised |
| **3.0.0** | 3 | Earlier frame format | No, without upgrading the peer |
| **Earlier** | Legacy | Legacy | No supported automatic migration |

Further changes must preserve schema 3 unless explicitly versioned and provide a documented migration path. Wire protocol modifications require explicit version negotiation or a planned, fail-closed coordinated upgrade. **Never silently fall back to plaintext or earlier unauthenticated packet formats.**

Remaining omissions: multiple VPSs/HA, an independently audited cryptographic protocol, proven DPI resistance and real two-hour field performance. Mixed TCP/UDP is supported for up to 12 services; its overload shedding and telemetry need real network validation. Reverse-first Auto is implemented but needs field testing over an actual two-VPS ICMP path—including packet loss, high jitter, ICMP Echo kernel reply interactions, and application sessions.
