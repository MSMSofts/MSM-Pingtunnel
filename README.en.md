# MSM Pingtunnel

**An authenticated, encrypted ICMP tunnel for forwarding TCP/UDP traffic between two Linux VPSs, with a Go transport core and a Rust control menu.**

[فارسی](README.md) · [Stable release: v3.4.3](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.4.3) · [All release notes](https://github.com/MSMSofts/MSM-Pingtunnel/releases) · [CI](https://github.com/MSMSofts/MSM-Pingtunnel/actions/workflows/rust.yml) · [Apache 2.0](LICENSE)

## Features

- **Authenticated encryption:** shared 256-bit pairing key, ephemeral X25519 sessions, AEAD transport encryption and anti-replay controls.
- **Three routing choices:** automatic Reverse-first, automatic Direct-first, or Manual with a locked Direct / Reverse direction.
- **Adaptive Reverse polling:** signed FIFO queue-age/depth observations, bounded demand-responsive ICMP opportunities and write-error backoff.
- **Mixed Multi-Port:** up to 12 TCP and UDP services over one authenticated ICMP session, each mapped from an Iran ingress port to an overseas loopback target.
- **Unified Rust manager:** setup, route selection, systemd controls, health and security diagnostics, RTT/jitter observations, and logs.
- **Conservative compatibility:** config schema 3 and Wire v4, installation checks/rollback, experimental segmentation and UDP repair opt-in only.

Pingtunnel **is not a VPN server**. It forwards traffic from multiple Iran-side TCP/UDP listeners over one encrypted ICMP tunnel to Foreign VPS loopback services. See the [Multi-Port setup guide](docs/MULTI_PORT.en.md) for port mapping, firewall and profile import/export.

## v3.4.3 — Resolve mixed Multi-Port UDP head-of-line blocking

**Why v3.3.24 felt smoother:** It effectively handled one application protocol per process. v3.4.3 added separate TCP/UDP receive channels but still had **one sequential packet processor and a shared Foreign worker pool**. A slow TCP destination dial or frame-processing task could therefore delay unrelated UDP/QUIC video packets.

- **End-to-end protocol isolation:** TCP, UDP and authenticated control have separate dispatch workers on both peers. Foreign UDP also has a bounded dedicated keyed worker pool, separate from blocking TCP dial processing.
- **Fresh UDP under saturation:** The unchanged 256-packet UDP queue now evicts the oldest UDP DATA on overflow to keep newer video/QUIC traffic; authenticated control has a separate reliable 128-packet lane and cannot be evicted as UDP.
- **Immediate saturated TCP admission:** The 10,000-packet mixed TCP queue is unchanged; repeated 2ms waits when completely full are eliminated. Excess TCP DATA is counted and left to existing TCP FrameMgr retransmission.
- **Operational evidence:** `sudo pingtunnel security` now shows maximum UDP/TCP local dispatch queue delay and counts of DATA frames waiting over 250ms. If those stay flat during app stalls, investigate ICMP shaping, upstream link loss, reverse polling and the application.
- **Compatibility:** Four route policies, secure Wire 4, config schema 3, same pairing keys and up to 12 mixed services. Single-port legacy handling remains intact.

[Full explanation and limitations](docs/RELEASE_NOTES_v3.4.3.md) · [CI and testing](https://github.com/MSMSofts/MSM-Pingtunnel/actions/workflows/rust.yml)

**Scope:** This targets one evidenced source of head-of-line stalls; it is not a guarantee of real-world Instagram or game performance on a particular two-VPS path.

## Choose a route policy

Run `sudo pingtunnel` and select **15) Route Policy**. Choose **16) Multi-Port** to manage the service mappings.

| Menu choice | Effective policy | Initial direction | Switching behavior |
| --- | --- | --- | --- |
| **1. AUTO Reverse-first** | Prefer Reverse | Reverse | Confirmed failure → Direct; authenticated return to Reverse |
| **2. AUTO Direct-first** | Prefer Direct | Direct | Confirmed failure → Reverse; authenticated return to Direct |
| **3. Manual → Reverse** | Locked Reverse | Reverse | **None** |
| **3. Manual → Direct** | Locked Direct | Direct | **None** |

CLI: `sudo pingtunnel route auto-reverse`, `auto-direct`, `manual-reverse`, `manual-direct`, or `show`.

**Configure the same policy on BOTH VPSs**. Each local change restarts its service; coordinate changes to avoid path mismatch. The pairing secret and forwarding parameters are preserved. There is no scheduled three-hour route rotation.

### Four-mode UDP RTT comparison — v3.3.24 CI

| Policy | Baseline p95 RTT | Impaired p95 RTT | After restoration p95 RTT | UDP echoes after restoration |
| --- | ---: | ---: | ---: | ---: |
| **Manual Direct** | **0.5 ms** | **64.7 ms** | **58.5 ms** | 28/32 |
| **AUTO Direct-first** | **0.6 ms** | **62.4 ms** | **64.9 ms** | 28/32 |
| **Manual Reverse** | **4.9 ms** | **75.5 ms** | **81.4 ms** | 30/32 |
| **AUTO Reverse-first** | **5.0 ms** | **69.0 ms** | **72.6 ms** | 30/32 |

**Source and interpretation:** [Successful 12 Nov 2026 CI run](https://github.com/MSMSofts/MSM-Pingtunnel/actions/runs/43178280092). These are **authenticated application UDP echo round-trip times in disposable Linux namespaces**, **not public-Internet/game RTT**. The impaired test configured 25±9ms egress delay, 4% loss and 2% reordering on **each side**. After a brief one-way 100% Iran egress blackhole, links returned to the **impaired profile**, not to the clean baseline. p95 excludes lost packets, reported separately; the short outage did **not** exercise full automatic route-failover grace.

[Full p50/p95, packet-loss results and testing methodology](docs/FOUR_ROUTE_RTT_COMPARISON_v3.3.24.md). Choose the best route using comparable measurements on your own two VPSs.


## Queue-aware latency control

In Reverse, Iran signs and conceals real FIFO queue depth and oldest-wait age in short **PTQ4** hints. The foreign peer responds to real backlog pressure with bounded fast ICMP polling and returns to low-rate idle as queues drain. Outstanding, authenticated demand can retain a brief six-second warm opportunity window; stale queue reports are not presented as current pressure. This targets transport queueing delay; **game RTT, jitter and uninterrupted delivery are not guaranteed**.

Details: [Route policy & recovery](docs/ROUTE_MODES_AND_QUEUE_RECOVERY.md) and [Queue-adaptive pacing](docs/AUTHENTICATED_QUEUE_ADAPTIVE_PACING.md). Version-by-version changes are documented under [GitHub Releases](https://github.com/MSMSofts/MSM-Pingtunnel/releases).

### Optional, reversible suppression of duplicate kernel Echo Replies

Linux may automatically Echo Reply to a signed `PTR4` / `PTS4` request while the Go core sends a **different** reply carrying queued data or control. `Source/icmp-echo-dedupe.sh` provides a **peer-IP-scoped nftables rule** that discards **only** kernel reflections with the unchanged PTR4/PTS4 prefixes. It does not suppress normal ping responses, signed `PRA4` replies, authenticated `PTH4` handshakes or `PTD4` data.

This script is **never run by the installer or service**. On the Iran VPS only, after reviewing packet captures, use `sudo bash Source/icmp-echo-dedupe.sh show|apply|remove`; nftables is required. Do not enable it blindly as a purported fix for unproven upstream filtering. The scoped rule is not persisted across reboot automatically.

`sudo pingtunnel security` now displays current and peak **userspace-generated** ICMP packet rates, Reverse polls sent/coalesced, authenticated return proofs, and direction-switch attempts. Kernel-generated replies and provider-level network drops are not included.

## Encryption and authentication flow

By default, traffic between the two VPSs uses an **authenticated encrypted session (Wire v4)**. Its security handshake is independent of whether Reverse or Direct ICMP carries the packets.

1. **Initial pairing:** Setup generates a random **256-bit (32-byte)** pairing key on the overseas VPS. The same key is securely transferred to Iran and stored on both peers. It authenticates the handshake; it is **not** reused directly as a static encryption key for every session packet.
2. **Session initiation:** Each new handshake creates ephemeral **X25519** keys. Initial `ClientHello` and `ServerHello` messages are authenticated with **HMAC-SHA256**, using a handshake key derived from the pairing secret.
3. **Key agreement and confirmation:** The peers derive an X25519 shared secret. **HKDF-SHA256** combines that secret with the pairing key and handshake transcript to derive distinct directional send/receive keys. `Finish` and `Ack` prove possession of the newly derived confirmation key. Application data is not accepted as authenticated traffic before the handshake completes.
4. **Packet encryption:** At startup, the Go core benchmarks **AES-256-GCM** and **XChaCha20-Poly1305** and selects a suitable algorithm for outgoing packets; peers may choose differently. Each encrypted packet uses a sequence-derived nonce, and its session header is authenticated as **AEAD** associated data.
5. **Receiver checks:** The peer validates the session identifier and AEAD authentication tag, then applies a bounded sequence-number **anti-replay** window. Invalid, altered or replayed packets are rejected. When recovery requires a new session, fresh keys are negotiated.

```text
TCP/UDP application data
    ↓
Authenticated session + ephemeral X25519 / HKDF keys
    ↓
AEAD encryption + sequence number + authentication tag
    ↓
ICMP Echo Request / Echo Reply (Reverse or Direct)
    ↓
Session and replay checks → decryption → data delivery
```

**Security boundaries:** Application data in authenticated frames is encrypted, but outer IP/ICMP headers and the presence of ICMP traffic are not hidden. This does not guarantee anonymity, resistance to filtering or an independent security audit. Keep the pairing key private, and inspect authentication/replay counters with `sudo pingtunnel security`.

## Requirements

- Two Linux VPSs with public IPv4 addresses: one in Iran, one overseas
- Debian/Ubuntu with `systemd`, AMD64 or ARM64, and root / sudo access
- ICMPv4 connectivity between VPSs and direct SSH access for administration and recovery

## Quick installation

> **v3.4.3:** fully isolated TCP/UDP/control application lanes, preserved Multi-Port capacities and no implicit enabled service ports.\n
### ⚠️ Important: install and set up the OVERSEAS VPS first

> **Required first-time setup order: 1) Overseas VPS → 2) Iran VPS.**
>
> **Finish installation and Setup on the overseas VPS and save its newly generated pairing key before starting installation and Setup in Iran.** The overseas setup generates the initial shared pairing key; Iran must use that **exact same key**. This order applies to **first-time pairing**; an existing installation must retain its pairing key during updates.

**Step 1 — Overseas VPS (Foreign)**

Connect to the **overseas VPS** via SSH and run:

~~~bash
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/v3.4.3/Source/install.sh -o /tmp/pingtunnel-install.sh
sudo bash /tmp/pingtunnel-install.sh
sudo pingtunnel setup
~~~

Select **Foreign**, enter the Iran VPS public IPv4 address, choose **TCP or UDP**, and specify the port of the local overseas service. On first setup, the wizard generates a random **256-bit pairing key**. Transfer this key securely for the next step.

**Step 2 — Iran VPS (Iran)**

**Only after finishing overseas setup**, connect to the Iran VPS and run:

~~~bash
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/v3.4.3/Source/install.sh -o /tmp/pingtunnel-install.sh
sudo bash /tmp/pingtunnel-install.sh
sudo pingtunnel setup
~~~

Select **Iran**, enter the overseas VPS public IPv4, use **the exact pairing key generated overseas**, and choose **the same TCP/UDP transport**. Configure the port on which Iran accepts client connections.

**Step 3 — Verify both VPSs**

On **each VPS**, check the core heartbeat and authenticated session:

~~~bash
sudo pingtunnel health
sudo pingtunnel security
~~~

The installer checks matching Manager/Go core assets using SHA-256 and the release manifest. Existing configuration is validated before installation, and upgrades must preserve the pairing key. **An active systemd service alone does not prove application traffic is flowing.**

## Useful commands

| Command | Purpose |
| --- | --- |
| `sudo pingtunnel` | Interactive management menu |
| `sudo pingtunnel setup` | Configure or adjust the paired tunnel |
| `sudo pingtunnel status` | systemd service status |
| `sudo pingtunnel route show` | Display the configured route policy |
| `sudo pingtunnel route auto-direct` | Set Direct-first AUTO on this VPS |
| `sudo pingtunnel route auto-reverse` | Set Reverse-first AUTO on this VPS |
| `sudo pingtunnel route manual-reverse` | Lock manual Reverse with no automatic switching |
| `sudo pingtunnel route manual-direct` | Lock manual Direct with no automatic switching |
| `sudo pingtunnel health` | Core heartbeat |
| `sudo pingtunnel security` | Authentication, session and Reverse diagnostics |
| `sudo pingtunnel performance` | RTT, jitter and passive performance metrics |
| `sudo pingtunnel logs 100` | Most recent 100 service log lines |
| `sudo pingtunnel validate` | Validate the existing configuration |
| `sudo pingtunnel update` | Update and restart the tunnel |
| `sudo pingtunnel uninstall` | Remove binaries and service; retain pairing config |
| `sudo pingtunnel uninstall --purge` | Remove all Pingtunnel data with explicit confirmation |

**Important:** An update of a running service may briefly interrupt active sessions. Back up the configuration and pairing key before significant changes, and use compatible versions on both peers. Never publish the pairing key or full private config.

## Paths and troubleshooting

| Path | Purpose |
| --- | --- |
| `/opt/pingtunnel/conf/config.json` | Private configuration and pairing key |
| `/opt/pingtunnel/bin/pingtunnel` | Go transport core |
| `/usr/local/bin/pingtunnel` | Rust manager |
| `/etc/systemd/system/pingtunnel.service` | systemd service |

If traffic fails, check both peers' pairing keys, matching transport, opposite IPv4 addresses, allowed ICMP traffic, Iran listener port and the overseas service bound to its local loopback port. Inspect `security` and `logs` on both sides.

## Project scope

The Go core is based on [esrrhs/pingtunnel](https://github.com/esrrhs/pingtunnel); the Rust manager handles setup and service controls. The project provides a two-VPS transport, not a VPN service, high-availability cluster or guarantee against filtering or packet loss.

[Architecture](docs/ARCHITECTURE.md) · [Security](SECURITY.md) · [Release notes by version](https://github.com/MSMSofts/MSM-Pingtunnel/releases) · [License](LICENSE)
