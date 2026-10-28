# Pingtunnel Manager

**A lightweight, encrypted ICMP tunnel between exactly two Linux VPSs, with a five-question setup wizard.**

[فارسی / Persian](README.md) · [Technical architecture](docs/ARCHITECTURE.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md) · [Download v3.3.8](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.8)

![Version](https://img.shields.io/badge/version-3.3.8-2563eb) ![Platform](https://img.shields.io/badge/Linux-AMD64%20%7C%20ARM64-444) ![License](https://img.shields.io/badge/license-Apache--2.0-137333) [![CI](https://github.com/MSMSofts/MSM-Pingtunnel/actions/workflows/rust.yml/badge.svg)](https://github.com/MSMSofts/MSM-Pingtunnel/actions/workflows/rust.yml)

Pingtunnel Manager sets up and operates an **ICMP-based transport tunnel** between an **Iran-side VPS** and an **overseas VPS**. Local TCP or UDP traffic enters the Iran VPS, travels inside authenticated, encrypted ICMP packets, and is forwarded by the overseas VPS to its configured local service.

**This is a transport layer—not a standalone VPN server.** Services such as Hysteria 2, s-ui or other TCP/UDP applications run and are configured separately.

**Current release: 3.3.8** · Rust manager, Go core, schema **3**, secure wire **4** · **Reverse-first Auto:** Foreign starts ICMP polls; Direct is reserved for prolonged confirmed outages with client demand. Video latency improvements require measured live testing.


## Reflected encrypted PING detection and active TTL eviction (v3.3.8)

In the user's 47-second foreign-VPS measurement, filtering 4,277 exact PTD4 reflections still left 34 authentication errors (~0.72/s). Code review found that the existing outbound signature cache covered only DATA, even though foreign-origin authenticated PING and other PTD4 Echo Requests can also be reflected by the Iran Linux kernel. These are a plausible source of periodic authentication errors; the mechanism is not yet field proven.

This release tracks **all foreign-origin encrypted PTD4 Echo Requests** as DATA, PING or other. As before, the filter requires an **exact full-ciphertext SHA-256, ICMP Echo ID and sequence match**, a pinned source-IP check and an 8-second freshness bound. **PING does not accelerate BBR/QUIC adaptive polling**; only successfully sent actual DATA does. A bounded chronological 16,384-slot ring now prunes expired/canceled signatures during sending, receiving and once-per-second status reads, rather than retaining stale entries until an eventual wrap. New counters distinguish DATA/PING/other reflections, TTL expirations and capacity evictions.

Secure wire v4, encryption, BBR configuration and Reverse-first priority are unchanged. Live playback improvements remain unverified pending installation on both VPSs.

## Exact-match filtering of reflected encrypted DATA (v3.3.7)

On a live overseas VPS, an inbound/outbound 10-second ICMP capture identified **1,453 byte-exact reflected Echo Replies among 2,047 inbound PTD4 responses**, matched to the foreign-origin Echo Requests using complete encrypted payload bytes and ICMP Echo ID/sequence. These Linux kernel reflections are **not new authenticated peer DATA**; the remaining 594 unmatched replies may carry valid Iran→Foreign QUIC ACKs and must not be filtered by marker alone.

v3.3.7 tracks outgoing encrypted PTD4 signatures (SHA-256 over the **entire** ciphertext plus Echo ID and sequence) *before the raw socket send*, in a bounded **16,384-entry** ring with an **8-second** match window; failed writes cancel their registrations. Only a byte-exact reflected Type 0 Echo Reply from the already pinned peer IP is discarded before AEAD decryption. Different encrypted payloads, legitimate handshakes and foreign-origin Echo Requests remain unaffected. The manager now reports `Filtered exact PTD4 Echo reflections` and `Outbound PTD4 reflection cache entries` separately from actual authentication failures.

No secure wire, encryption, reverse-first priority or poll schedule change. **Playback improvement is not assumed; verify on the deployed VPS pair**.

## BBR/QUIC short-stall reverse polling and recent queue-delay P95 (v3.3.6)

Authenticated data bursts hold the overseas Reverse poller at responsive intervals during brief 1–3 second BBR ACK/recovery pauses. Return DATA bursts can hold 2ms target polls for up to 2.4s; sustained Foreign→Iran video DATA can hold 4ms polls for up to 4.5s before decaying through 6ms/12ms/25ms as traffic disappears. Single packets do not enable 2ms polling; idle/handshake cadences remain 250ms/200ms. Timings are adaptive targets, not guaranteed network pacing.

Iran's `sudo pingtunnel security` now shows the rolling mean and nearest-rank P95 send-queue residence time for the **last 128 successfully written Echo Reply frames**, the sample count, and cumulative frames waiting at least 1 second. Failed writes are excluded. Socket-write success **does not prove overseas reception**, so low queue latency during buffering should shift investigation to ICMP packet loss, MTU and QUIC congestion response. No secure wire, BBR configuration or reverse-first Auto change; paired VPS upgrade and measured field testing remain essential.

## High-rate Reverse replay cache correction (v3.3.5)

At 500 signed polls/sec, the 20-second anti-replay window can contain roughly **10,000 distinct valid nonces**. The previous 4,096-entry replay cache was too small, temporarily rejecting legitimate poll requests during sustained traffic. This can delay the Iran-to-Foreign reply opportunities required by QUIC acknowledgements even when ping and encrypted sessions appear healthy.

v3.3.5 increases the bounded cache to **16,384** with unchanged HMAC verification, replay uniqueness and expiration rules. `sudo pingtunnel security` now reports `Reverse poll replay-cache capacity rejections`; the expected normal value is zero. Duplex-aware polling and queue telemetry from v3.3.4 remain enabled. Field playback, queueing and rate-limit effects still require measurement.


## Reverse streaming and ACK latency — v3.3.4

The previous reverse poll accelerator largely observed authenticated **Iran→Foreign** application data. With video over Hysteria 2, the larger stream often travels **Foreign→Iran**, while QUIC acknowledgements must travel back through the Reverse reply queue. When return ACK traffic temporarily dried up, the poll cadence could slow and delay subsequent ACK delivery.

In v3.3.4, **successfully written, encrypted Foreign→Iran DATA** also drives ACK-return poll pacing. Nominal intervals are 25 ms for an open but quiet session, about 12 ms on initial outbound video data, 4 ms during sustained outbound video flow, and as low as 2 ms for bursts of authenticated inbound return DATA. Polling decays through warm intervals rather than immediately dropping to the old 80 ms active-session baseline. True idle remains at 250 ms. These are **target send intervals, not guaranteed latency, loss, or throughput**.

On Iran, `sudo pingtunnel security` now reports oldest queued frame age, last/maximum successful queue delivery delays, and number of queued frames delayed at least 250 ms. On Foreign, `Last successful Foreign->Iran DATA send` indicates video-driven poll demand. These distinguish a real reverse-queue bottleneck from Hysteria congestion/MTU issues.

No change to the ICMP packet layout, secure Wire v4, X25519/session authentication, or Reverse-first with emergency Direct-only fallback. Actual video playback improvements require real VPS testing.

## ICMP Echo reflection filtering (v3.3.3)

On a real two-VPS path, the overseas host was observed receiving hundreds of 44-byte ICMP Echo Replies containing a 36-byte `PTR4` payload. These are automatic Linux kernel echoes of foreign-origin Reverse poll requests, **not authenticated application ciphertext**. v3.3.4 filters only these exact-size, exact-marker Echo Replies, *after verifying the pinned peer source IP and before attempting AEAD decrypt*. Genuine `PTD4` DATA and `PTH4` handshakes remain unaffected; neither the network packet format nor session cryptography changes.

The overseas `sudo pingtunnel security` output now includes `Filtered kernel PTR4 Echo reflections` separately from `Authentication failures`. This reduces pointless decrypt attempts and improves diagnostics, but **does not prove the Hysteria/Shorts stalling problem is solved**. Measure authenticated error deltas, Iran's reverse queue and playback performance separately after upgrading.

## Reverse throughput and stability (3.3.1 and 3.3.2)

The foreign Go core uses an **event-driven adaptive timer** instead of a permanently fast polling loop. The following are target program intervals, **not guaranteed end-to-end latencies**:

| Authenticated reverse traffic | Target poll interval |
| --- | ---: |
| Session handshake | 200 ms |
| No active connections | 250 ms |
| Open but quiet connection | 80 ms |
| One valid application data frame | 40 ms |
| Small burst of frames | 12 ms |
| Sustained useful data stream | 2 ms |

One isolated packet cannot trigger a long 500-polls/s burst. Failed ICMP Echo Reply writes put the encrypted frame back at the queue head while retaining the original 12-second expiry. Empty userspace replies are skipped, avoiding duplication of the Linux kernel's normal echo response behavior where enabled. The externally visible ICMP Echo structure and the authenticated wire v4 protocol remain unchanged.

A low-rate encrypted receipt is generated by Foreign **only after successfully receiving authenticated Iran→Foreign DATA**. It is sent no more often than every 8 seconds while real payloads arrived in the preceding 10 seconds, preventing false stale-session failover during otherwise one-way transfers. An ordinary ICMP echo cannot count as delivery confirmation.

Run `sudo pingtunnel security` on either VPS to inspect reverse queue size/bytes, peak depth, overflow/expiry drops, reply write failures, last authenticated reverse data age, and active polling interval. A persistent rise in drops is evidence of queue pressure or network loss; an aggressive poll interval does **not** imply guaranteed throughput.

**Validation:** v3.3.0 Reverse connectivity was reported working on a live pair. v3.3.1 builds, tests, and race checking are automated, but the actual bandwidth, VPS overhead, loss recovery, and resilience still require measured two-host testing.

## ICMP direction in v3.3.4

- **Auto (default):** start with **Reverse** foreign-origin ICMP Echo Requests. **Direct is an emergency-only fallback** after sustained local client demand and a prolonged failed Reverse: no authenticated polls for 90 seconds, unconfirmed negotiation for 150 seconds, or absence of both authenticated polls and encrypted peer traffic for 150 seconds on an established route. Selection has a 60-second minimum dwell to reduce flapping.
- **Reverse:** foreign-origin Echo Requests only.
- **Direct:** Iran-origin Echo Requests only.

The physical roles are fixed regardless of direction: users connect to Iran, and the overseas endpoint forwards to its pinned local loopback service. `icmp_direction` is optional in persistent config; omitting it selects Auto. Reverse was observed working on a live pair with v3.3.0, but automated failover and 3.3.3 performance still require live validation.

## Highlights

| Feature | How it works |
| --- | --- |
| **Two VPSs only** | No HA node, backup server, resident management daemon, or separate proxy transport |
| **Unified five-step wizard** | Region, opposite VPS IPv4, shared pairing key, TCP/UDP, and this VPS's port |
| **Independent ports** | For example, receive UDP **444** in Iran and forward to UDP **8443** overseas |
| **ICMP transport** | Reverse-first Echo polling, authenticated reply data and bounded fallback to Direct; no TCP/UDP port on the outer tunnel |
| **Automatic AEAD** | AES-256-GCM or XChaCha20-Poly1305, selected by a startup CPU benchmark |
| **Per-session forward secrecy** | Authenticated ephemeral X25519 exchange with HKDF directional session keys |
| **Anti-replay** | Authenticated 64-bit packet sequences, a 1,024-packet window, and renegotiation protections |
| **Smart Recovery** | Controlled re-negotiation with bounded buffering during connection recovery |
| **Adaptive Performance** | Learns RTT/jitter from existing ICMP probes and tunes **new TCP sessions** |
| **Operations** | Rust CLI, systemd supervision, security/performance status and logs |
| **Verified releases** | AMD64/ARM64 binaries, SHA256 assets, release manifest and core/manager identity check |

## Architecture

~~~text
           VPN / TCP / UDP client
                     |
         Iran VPS: TCP 443 or UDP 444
                     |
              Go Pingtunnel Client
                     |
        +-----------------------------+
        | Authenticated ICMP tunnel   |
        | X25519 + HKDF + AEAD        |
        | Packet anti-replay          |
        +-----------------------------+
                     |
              Go Pingtunnel Server
                     |
        Foreign VPS: 127.0.0.1:PORT
                     |
          VPN / application service
~~~

**ICMP does not have TCP or UDP port numbers.** The port in Iran is where a local application connects; the overseas port belongs to the final service. These values can be equal or different. **A single configured tunnel forwards either TCP or UDP**, not both simultaneously.

### Hysteria 2 / s-ui example

| | Iran VPS | Overseas VPS |
| --- | --- | --- |
| Region selected | Iran | Foreign |
| Forwarded transport | UDP | UDP |
| This VPS's port | **444** | **8443** |
| Opposite VPS IP | Public IPv4 of overseas VPS | Public IPv4 of Iran VPS |
| Pairing key | Enter the shared key | Generate the original shared key |

The Hysteria 2 client connects to `IRAN_IP:444`. The overseas Go server sends the forwarded UDP traffic to `127.0.0.1:8443`, where Hysteria 2 is running.

The overseas server **enforces its own loopback destination**. It does not trust a client-supplied arbitrary forwarding target. Configure your Hysteria 2 server, TLS certificate, SNI, and s-ui separately.

## Requirements

- Exactly two reachable IPv4 Linux VPSs: one in Iran and one overseas.
- Debian/Ubuntu with **systemd**, root/sudo, and an **AMD64 or ARM64** processor.
- Working ICMP traffic between the two VPSs; filtering or rate limits may prevent the tunnel from operating.
- The chosen ingress TCP/UDP port reachable by your users on the Iran VPS.
- GitHub Releases access during installation.
- A running target service on the overseas VPS (for example, a Hysteria 2 UDP listener).

## Install

Run the **same installer on both VPSs**:

~~~bash
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/main/Source/install.sh -o /tmp/pingtunnel-install.sh
sudo bash /tmp/pingtunnel-install.sh
~~~

Review downloaded scripts before executing them with elevated privileges.

The installer pins the [v3.3.0 release](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.0), checks SHA256 and the release manifest, verifies manager/core compatibility, and backs up existing installed files for failure rollback.

### Set up the overseas VPS first

~~~bash
sudo pingtunnel setup
~~~

The wizard asks:

1. **Region:** Foreign.
2. **Opposite VPS IPv4:** the Iran VPS's address.
3. **Pairing key:** generated randomly on the first overseas setup; copy it securely.
4. **Forwarded protocol:** TCP or UDP.
5. **This VPS's port:** the local target application's TCP/UDP port (for example, **8443**).

### Set up the Iran VPS

Run the same command and answer:

1. **Region:** Iran.
2. **Opposite VPS IPv4:** the overseas VPS's address.
3. **Pairing key:** paste the *same* 256-bit key from the overseas VPS; input is hidden.
4. **Forwarded protocol:** select the *same* TCP or UDP choice.
5. **This VPS's port:** the TCP/UDP port clients should reach in Iran (for example, **444**).

Suggested default ports are **TCP 443** and **UDP 444** on either VPS, but you can choose independent ports. The shared key is **not regenerated** when setup is repeated. To retrieve it intentionally, use `sudo pingtunnel key` and protect its output.

## Interactive terminal menu

**Fixed in v3.2.4:** raw-mode CRLF prevents diagonal terminal output; the menu uses a single column with **strictly ascending 1–14 actions from top to bottom**, responsive width and compact layout for smaller terminal windows.


Run `sudo pingtunnel` to open the redesigned **v3.2.4** menu. The header shows the physical server location, opposite VPS IPv4, this VPS's TCP/UDP port, and the current systemd service state **without revealing the pairing key**. The interface groups all **14 original numbered actions** into four sections.

~~~text
================================================================
  PINGTUNNEL  /  CONTROL CENTER
  v3.3.0   |   Encrypted ICMP   |   Wire v4
----------------------------------------------------------------
LIVE TUNNEL STATUS
  Location     Foreign (service)
  Peer IPv4    203.0.113.10
  Transport    UDP / 444
  Service      active
  CPU (10s)    0.3%          avg 60s 0.3%
  RAM (RSS)    13.9 MiB      avg 60s 13.9 MiB

SERVICE CONTROLS
  1) Status
  2) Start
  3) Stop
  4) Restart
  5) Logs
SETUP & CONFIGURATION
  6) Setup Wizard
  7) Pairing key
DIAGNOSTICS
  8) Performance
  9) Validate
MAINTENANCE
 10) Update
 11) Uninstall
 12) Exit
SECURITY & HEALTH
 13) Security
 14) Health
~~~

This is an illustrative screen, not live server output. With a UTF-8 terminal the interface uses subtle cyan section headings and a Unicode border. It automatically disables ANSI color codes for redirected output, `NO_COLOR`, or `TERM=dumb` and falls back to ASCII for non-UTF-8 locales. The displayed version is taken from the actual manager package, not hard-coded into the Rust menu.

### Every menu option explained

| No. | Group | Action |
| --- | --- | --- |
| **1 — Status** | Service | Show systemd status |
| **2 — Start** | Service | Start the encrypted ICMP service |
| **3 — Stop** | Service | Stop the service |
| **4 — Restart** | Service | Restart service; active VPN sessions may be interrupted |
| **5 — View logs** | Service | Show the last 100 systemd journal lines |
| **6 — Setup Wizard** | Configuration | Configure the current VPS using the five-question wizard |
| **7 — Show pairing key** | Configuration | Reveal the **sensitive** shared 256-bit secret; keep it private |
| **8 — Adaptive Performance** | Diagnostics | View ICMP RTT/jitter, probe loss estimate, and new-TCP tuning |
| **9 — Validate config** | Diagnostics | Verify persisted configuration schema and key format |
| **10 — Update** | Maintenance | Download the version-pinned signed-off release set via the installer |
| **11 — Uninstall** | Maintenance | Remove service/binaries with explicit confirmation; config remains by default |
| **12 — Exit** | Maintenance | Leave manager without stopping the running service |
| **13 — Security status** | Diagnostics | View authenticated session, replay drops, authentication errors, recovery |
| **14 — Health check** | Diagnostics | Check service liveness and Go core heartbeat freshness |

### Five-step setup explained

Complete the wizard on the **overseas VPS first**, then on the **Iran VPS**. Menu option **6** and the command `sudo pingtunnel setup` start exactly the same wizard.

1. **Physical region:** Choose *Foreign* on the overseas VPS and *Iran* on the Iran VPS. This is not a direct/reverse tunnel switch.
2. **Opposite VPS IPv4:** Enter the public IPv4 address of the *other* server. The overseas VPS needs the Iran address; the Iran VPS needs the overseas address.
3. **Pairing key:** On first setup, the overseas VPS generates a random 256-bit root secret. Transfer it securely and enter that same value using the Iran VPS's hidden input. Re-running Setup retains the existing pairing root.
4. **TCP or UDP:** Select the **same forwarded protocol** on both VPSs. The outside carrier remains ICMP.
5. **This VPS's port:** Select the users' ingress TCP/UDP port on Iran; select the actual local target service port overseas. The ports can **differ** (e.g. UDP 444 in Iran, UDP 8443 overseas). Suggested defaults: TCP 443, UDP 444.

The manager stores the configuration with restricted permissions, configures systemd, and applies it. Runtime cryptographic algorithm selection and performance measurement require no extra setup questions. For Hysteria 2, configure the overseas service to listen at `127.0.0.1:8443/UDP` and users to reach `IRAN_IP:444`.

After setup, use menu **1 / 13 / 14 / 8** or run `pingtunnel status`, `pingtunnel security`, `pingtunnel health`, and `pingtunnel performance`.

### Live CPU & RAM dashboard (v3.2.5)

Directly below **Service status**, the interactive TUI shows recent Go tunnel resource consumption:

~~~text
  Service status      : active
  CPU (10s)           :  6.2%           Avg 60s:  5.1%
  RAM (RSS)           : 31.8 MiB        Avg 60s: 30.4 MiB
  LIVE / Refresh every 10s / CPU 100% = 1 vCPU
~~~

**Values above are illustrative, not live server measurements.**

- **CPU:** process CPU time measured over consecutive 10-second intervals; **100% represents one saturated vCPU**. Multi-threaded Go workloads may exceed 100%.
- **RAM:** the Linux `VmRSS` resident memory of the systemd `MainPID` process, in MiB. This is not whole-VPS memory usage.
- **Avg 60s:** rolling mean of the **last six samples**, initially using the available observations.
- **Stopped/missing service:** metrics show `—` rather than a fabricated zero. When the Go process restarts or the PID is reused, old CPU/RAM averages are cleared.
- **Input preservation:** in a supported interactive terminal the screen refreshes every 10 seconds without clearing partially typed menu numbers; `Enter` selects, `Backspace` edits, `q`/`Esc` exits. The terminal returns to normal mode **before** invoking setup/password prompts or service commands.
- **Fallback:** non-interactive stdin/stdout or `TERM=dumb` uses the original line-input mode without timed screen refresh.
- **Footprint:** sampling occurs **only while the management menu is open**; no permanent monitoring agent or systemd service is added.

### Automatic tunnel restart after Update

Menu **10 — Update** and `sudo pingtunnel update` install the pinned, checksum/manifest-verified manager+Go release. Since **v3.2.4**, a VPS with **valid existing pairing configuration** always **restarts its tunnel after an update**, including when that service was deliberately stopped or disabled beforehand. The installer verifies that systemd has a live main process and that the Go health heartbeat is fresh; on failure it rolls back to the prior installed binaries.

**Notice:** running VPN sessions may be interrupted by that restart. A fresh VPS without completed Setup is not automatically started. A previously stopped service becomes active following a successful update.

## CLI reference

| Command | Purpose |
| --- | --- |
| `pingtunnel` | Unified interactive menu |
| `sudo pingtunnel setup` | Configure this VPS using five questions |
| `sudo pingtunnel validate` | Validate configuration schema and pairing key |
| `sudo pingtunnel status` | Inspect the systemd service |
| `sudo pingtunnel start` / `stop` / `restart` | Service controls |
| `sudo pingtunnel security` | View secure-session state, replay/authentication failures and recovery counters |
| `sudo pingtunnel health` | Verify active systemd service and current Go health heartbeat |
| `sudo pingtunnel performance` | View RTT/jitter and adaptive TCP settings |
| `sudo pingtunnel logs 100` | Show the last 100 service log lines |
| `sudo pingtunnel dry-run` | Show redacted Go core invocation |
| `sudo pingtunnel key` | Reveal the **sensitive** root pairing key |
| `sudo pingtunnel update` | Upgrade using the pinned installer |
| `sudo pingtunnel uninstall` | Remove the manager/service; keep configuration unless explicitly purged |

Useful health checks:

~~~bash
sudo pingtunnel status
sudo pingtunnel security
sudo pingtunnel performance
~~~

## Security design

- A 32-byte random **pairing root** shared between physical VPSs; no weak password-only or plaintext mode in valid manager configurations.
- A four-message, PSK-authenticated **ephemeral X25519** handshake, with session keys derived using **HKDF-SHA256**.
- Independent send and receive keys for the **Iran → foreign** and **foreign → Iran** directions, regardless of future initiation roles.
- Automatic AES-256-GCM / XChaCha20-Poly1305 choice based on the CPU benchmark executed at startup. Both peers can decrypt either algorithm.
- Authenticated sequence numbers, replay rejection, and staged re-negotiation to avoid tearing down an active session upon a known replayed hello.
- A source-IP restriction and a locally enforced **`127.0.0.1:PORT`** forwarding policy on the overseas VPS.
- Private, permission-restricted configuration and status files; the pairing key is not sent on the Go command line.

**Important:** This is a custom security protocol and **has not been independently cryptographically audited**. Encrypted ICMP is **not invisible to traffic analysis or DPI** and is not a promise to bypass every network restriction. See [SECURITY.md](SECURITY.md) for threat model, risks and responsible reporting.

## Adaptive Performance & Smart Recovery

The Iran-side Go client samples RTT and jitter using its existing ICMP Ping traffic. It adjusts initial resend timing and window parameters for **new TCP sessions**; the Go core's `BB` congestion controller continues to handle established TCP streams.

After sustained loss with active demand, Smart Recovery negotiates a new authenticated X25519 session with bounded backoff. A global temporary DATA queue is capped at **256 packets, 2 MiB and 12 seconds**; expired/overflow packets are counted and exposed in security status.

These features **do not guarantee uninterrupted VPN sessions**, live adaptation of established TCP session window parameters, automatic UDP rate control, or complete recovery of application state after a long outage.

## Compatibility & upgrades

| Version | Config schema | Wire format | Compatibility |
| --- | --- | --- | --- |
| **3.3.8** | 3 | **v4** (`PTH4/PTD4`) | Exact PING/DATA reflection filtering; bounded actively pruned signature cache |
| **3.3.7** | 3 | **v4** (`PTH4/PTD4`) | Drop only exact tracked PTD4 kernel echoes; bounded full-ciphertext signatures and independent diagnostics |
| **3.3.6** | 3 | **v4** (`PTH4/PTD4`) | BBR jitter-window return polling and rolling 128-send queue latency mean/P95 |
| **3.3.5** | 3 | **v4** (`PTH4/PTD4`) | Correct sustained 500/s Reverse poll replay-cache capacity; bounded authentication nonce memory |
| **3.3.4** | 3 | **v4** (`PTH4/PTD4`) | Bidirectional DATA-aware poll pacing and queue wait telemetry |
| **3.3.3** | 3 | **v4** (`PTH4/PTD4`) | Ignore kernel PTR4 Echo reflections before decrypt, count separately |
| **3.3.2** | 3 | **v4** (`PTH4/PTD4`) | Reverse preferred, Direct only after sustained failure |
| **3.3.1** | 3 | **v4** (`PTH4/PTD4`) | Adaptive Reverse polls, retry of failed Echo Reply writes, queue telemetry |
| **3.3.0** | 3 | **v4** (`PTH4/PTD4`) | Reverse-first authenticated transport |
| **3.2.6** | 3 | **v4** (`PTH4/PTD4`) | Peer watchdog honors authenticated traffic |
| **3.2.5** | 3 | **v4** (`PTH4/PTD4`) | Status pause, worker and lost-link recovery |
| **3.2.4** | 3 | **v4** (`PTH4/PTD4`) | Current; raw-mode and menu-order fix |
| **3.2.3** | 3 | **v4** | Previous release; resource dashboard |
| **3.2.2** | 3 | **v4** | Previous compatible patch |
| **3.2.1** | 3 | **v4** | Previous compatible maintenance release |
| **3.2.0** | 3 | **v4** | Previous patch release; wire-compatible |
| **3.1.0** | 3 | **v4** | Introduced ephemeral exchange and anti-replay |
| **3.0.0** | 3 | Earlier `PTA1` | Config preserved but incompatible with 3.1/3.2 over the wire |
| **Before 3.0** | Legacy | Legacy | No automatic migration |

Upgrading both VPSs is recommended during a maintenance window. The manager preserves a valid v3 configuration and pairing root, but service restarts may interrupt active application traffic. Mixed old/new **wire protocols do not silently downgrade**.

> **Repository transfer note:** For updates, use the canonical installer URL under `MSMSofts/MSM-Pingtunnel` shown in the Install section. Earlier manager binaries may still use the former repository owner in the built-in `pingtunnel update` URL.

[Version history](CHANGELOG.md) · [Pinned release](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.8) · [Rolling assets](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/rust-latest)

## Important paths

| Path | Contents |
| --- | --- |
| `/usr/local/bin/pingtunnel` | Rust management executable |
| `/opt/pingtunnel/bin/pingtunnel` | Modified Go transport core |
| `/opt/pingtunnel/conf/config.json` | Persistent v3 configuration and pairing secret |
| `/run/pingtunnel-core.json` | Private Go runtime configuration |
| `/run/pingtunnel-security.json` | Secret-free security status |
| `/run/pingtunnel-performance.json` | Adaptive performance status |
| `/etc/systemd/system/pingtunnel.service` | systemd service |

## Troubleshooting

**No tunnel traffic:** Check that both VPSs use the same pairing root and TCP/UDP selection, have the correct opposite IPv4, and can exchange ICMP packets. Also inspect the server status, firewall and journal.

**Hysteria 2 fails:** Verify that the client points to the Iran IP and chosen Iran UDP port, that the overseas local service is reachable on `127.0.0.1:PORT`, and that both Pingtunnel instances are configured for UDP.

**After upgrading:** Run `pingtunnel security` and `pingtunnel logs 100` on both VPSs. Versions 3.0 and 3.1/3.2 cannot negotiate the same wire protocol.

**After extended packet loss:** Inspect the session status and queue-drop counter; the VPN client may need to reconnect.

## Scope & limitations

**Not provided in v3.3.8:** high availability, multiple VPSs, simultaneous TCP+UDP forwarding through one tunnel, guaranteed filtering resistance, or independent security audit. Reverse/Auto passed CI tests but requires a real two-VPS integration test. Previously, v3.2.4 did not support reverse forwarding; see the changelog.

**Still required before high-assurance deployment:** testing two real VPSs with ICMP packet loss/jitter, Hysteria 2 end-to-end testing, restart/upgrade interruption testing, and independent cryptographic review.

The project modifies the Go core from [esrrhs/pingtunnel](https://github.com/esrrhs/pingtunnel). Rust handles setup and systemd without a continuously running management daemon. Licensed under [Apache-2.0](LICENSE). This repository is not officially endorsed by the Hysteria 2, s-ui, or upstream Pingtunnel projects.
