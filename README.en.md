# MSM Pingtunnel

**A lightweight, encrypted ICMP tunnel between an Iran VPS and an overseas VPS**, forwarding TCP or UDP traffic through a Go core and a simple Rust manager.

[فارسی](README.md) · [Current preview: v3.3.22](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.22) · [CI status](https://github.com/MSMSofts/MSM-Pingtunnel/actions/workflows/rust.yml) · [Apache 2.0 license](LICENSE)

## Features

- **Authenticated encryption:** 256-bit pairing key, ephemeral secure sessions, peer authentication and replay protection.
- **Three routing policies:** automatic Reverse-first, automatic Direct-first, and manual locked direction; no scheduled timed rotation.
- **TCP or UDP forwarding:** Connect applications such as Hysteria 2 or Xray running on the overseas VPS.
- **Unified management:** Setup wizard, systemd service controls, logs, health checks, security reports and passive performance metrics.
- **Conservative defaults:** Experimental ICMP segmentation and UDP parity repair are disabled by default; existing connection settings are preserved.

Pingtunnel is **not a VPN server**. It transports traffic arriving at the Iran VPS over encrypted ICMP to a local application endpoint on the overseas VPS, for example `127.0.0.1:444`. Each tunnel instance forwards either TCP or UDP, as configured.

## Route Policy: menu item 15 (v3.3.22)

The menu offers **three options**:

1. **AUTO Reverse first:** starts Reverse; switches to Direct only on
   sustained authenticated Reverse failure and restores Reverse on two
   independent signed return-path proofs.
2. **AUTO Direct first:** starts Direct (like original PingTunnel); after
   prolonged Direct failure plus two fresh signed proofs of real Iranian
   application demand, switches to verified Reverse. Returns to Direct
   after two signed Direct-path proofs and a matched PTX4/PTB4 handoff.
3. **MANUAL:** choose Reverse-only or Direct-only in a submenu. Neither
   direction is switched automatically, regardless of link quality.

CLI: `sudo pingtunnel route auto-reverse|auto-direct|manual-reverse|manual-direct`,
or `sudo pingtunnel route show`.

**Select the same route policy on both VPS peers.** Each local change
restarts that peer. The pairing key, forwarding config, Wire v4 and
config schema 3 remain unchanged; authenticated successful path handoffs
keep the live AEAD session. Time-based three-hour route rotation remains
disabled in all options.

Reverse PTQ4 backlog-aware polling now keeps a short 25ms maximum
opportunity interval for up to six seconds while authenticated,
undelivered queue pressure exists. As DATA is received, the remote
queue estimate drains and the poller returns to low-rate idle. Stale
remote metrics and historical p95 send queues are explicitly labeled.

See [Route policies and recovery](docs/ROUTE_MODES_AND_QUEUE_RECOVERY.md).

### Signed queue-aware Reverse pacing (3.3.21)

Iran transmits **PTQ4**, a short authenticated queue hint containing the
real encrypted FIFO depth, oldest wait and pending bytes. Its metadata
is masked with a nonce-derived pairing-key pad; it carries no user
traffic. Foreign rapidly polls for the initial 120ms after a genuine
packet and then adapts between 8–16ms as demand evolves. Stale hints
return to idle rates; socket write failures cause a bounded backoff.

Both VPS peers should upgrade together. Wire v4, config schema 3 and
Reverse-first failover are unchanged. This is a Preview, not a measured
game latency claim. See `docs/AUTHENTICATED_QUEUE_ADAPTIVE_PACING.md`.

### Reverse-first authenticated AUTO recovery (3.3.20)

AUTO starts **Reverse** and never schedules a timer-driven healthy
Reverse-to-Direct rotation. Direct is only a fallback after a sustained
authenticated Reverse outage with live application demand. During Direct,
Foreign probes Reverse every **10 seconds** and requires **two separate,
matched HMAC-authenticated return-path proofs** before a signed takeover,
after at least **60 seconds** of dwell. A pending handoff retries every
2 seconds for up to 30 seconds; keys and Wire v4 are preserved.

Reverse foreign-origin DATA now receives unique ICMP Echo sequences.
Only genuine DATA (not periodic PING) may wake high-frequency polling.
See `docs/ORIGINAL_SEND_COMPARE_REVERSE_FIRST.md`.
This remains a **Preview**; no real-game latency guarantee is implied.

### Long-running game / QUIC latency fixes (3.3.19)

The previous anti-replay `big.Int` bitmap grew with total authenticated
packets, increasing per-packet decryption work during sustained sessions.
It now uses a fixed 1024-bit window. The UDP-only authenticated dispatcher
is capped at 256 queued packets; on saturation it counts dropped UDP DATA
rather than blocking the sole ICMP receiver for up to 3 seconds. ICMP
receive capacity is now 65,535 bytes.

This is a **Preview**, not a demonstrated fix for any particular live VPS.
Compare two-hour gaming runs before and after upgrading both peers.
Diagnostics: `Source/long_session_probe.py` and
`docs/LONG_SESSION_LAG_AUDIT.md`. The upstream Go 1.26 source snapshot
is vendored under `Upstream/pingtunnel-df16/` for reproducible builds.

### Lower first-packet latency during idle Reverse (3.3.17)

Previously, a quiet Reverse poller might wait up to **one second** to issue another Echo Request after Iran queued new user data. Now Iran sends a root-HMAC-authenticated, replay-protected `PTW4` hint **only after actual encrypted data is queued**. The foreign VPS immediately wakes its single poll timer and briefly uses **8ms** intervals for up to **1.2 seconds**. No application plaintext, encryption keys, or route-switch commands travel in the hint, and it never changes Smart Rotation state.

Iran sends no more than **two** backlog hints per second; Foreign independently rate-limits valid hints. Once the demand pulse expires, normal **1Hz idle** polling resumes. When genuinely active, base polling improves **40ms → 25ms**, warm intervals **16ms → 12ms**, and sustained throughput **10ms → 8ms**. If the wake message cannot traverse the current network path, the normal poller still operates. This is a bounded latency/packet-rate tradeoff, not a bypass or a cure for unknown provider ICMP filtering.

`sudo pingtunnel security` shows verified, sent and rate-limited backlog wakeups. The ordinary host-to-host ping RTT (previously about 86ms) is constrained by the real path; improvement is targeted at **queueing latency**, not the physical network RTT. Real Hysteria 2, streaming, stability and ICMP PPS measurements are required to quantify results.

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

## Resource usage in a real-world test

During a user-observed test with an **active tunnel, UDP forwarding on port 444 and one VPN connection used for Instagram and YouTube**, the Pingtunnel monitoring dashboard on **v3.3.13** displayed:

| VPS | CPU (10s) | Average CPU (60s) | RAM / RSS | Average RAM (60s) |
| --- | ---: | ---: | ---: | ---: |
| Iran | 3.4% | 4.2% | 16.9 MiB | 17.0 MiB |
| Overseas | 5.6% | 6.4% | 35.4 MiB | 35.4 MiB |

These figures are **one real-world observation**, not a controlled benchmark, a capacity limit or a resource-usage guarantee. CPU percentages follow the dashboard convention (100% represents one vCPU); RAM is the process's **resident set size (RSS)**, not total system memory. Actual usage varies with VPS specifications, traffic volume and concurrent connections.

## Requirements

- Two Linux VPSs with public IPv4 addresses: one in Iran, one overseas
- Debian/Ubuntu with `systemd`, AMD64 or ARM64, and root / sudo access
- ICMPv4 connectivity between VPSs and direct SSH access for administration and recovery

## Quick installation

> **Release status:** This is a **preview** addressing one-way ICMP recovery. Passing CI does not prove reliability on a real two-VPS network. Back up operational configurations and upgrade both peers together only after a controlled test.

### ⚠️ Important: install and set up the OVERSEAS VPS first

> **Required first-time setup order: 1) Overseas VPS → 2) Iran VPS.**
>
> **Finish installation and Setup on the overseas VPS and save its newly generated pairing key before starting installation and Setup in Iran.** The overseas setup generates the initial shared pairing key; Iran must use that **exact same key**. This order applies to **first-time pairing**; an existing installation must retain its pairing key during updates.

**Step 1 — Overseas VPS (Foreign)**

Connect to the **overseas VPS** via SSH and run:

~~~bash
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/v3.3.22/Source/install.sh -o /tmp/pingtunnel-install.sh
sudo bash /tmp/pingtunnel-install.sh
sudo pingtunnel setup
~~~

Select **Foreign**, enter the Iran VPS public IPv4 address, choose **TCP or UDP**, and specify the port of the local overseas service. On first setup, the wizard generates a random **256-bit pairing key**. Transfer this key securely for the next step.

**Step 2 — Iran VPS (Iran)**

**Only after finishing overseas setup**, connect to the Iran VPS and run:

~~~bash
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/v3.3.22/Source/install.sh -o /tmp/pingtunnel-install.sh
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

[Architecture](docs/ARCHITECTURE.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md) · [License](LICENSE)
