# MSM Pingtunnel

**A lightweight, encrypted ICMP tunnel between an Iran VPS and an overseas VPS**, forwarding TCP or UDP traffic through a Go core and a simple Rust manager.

[فارسی](README.md) · [Current preview: v3.3.15](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.15) · [CI status](https://github.com/MSMSofts/MSM-Pingtunnel/actions/workflows/rust.yml) · [Apache 2.0 license](LICENSE)

## Features

- **Authenticated encryption:** 256-bit pairing key, ephemeral secure sessions, peer authentication and replay protection.
- **Adaptive ICMP direction:** Reverse ICMP is preferred, with a guarded Direct fallback after sustained failure.
- **TCP or UDP forwarding:** Connect applications such as Hysteria 2 or Xray running on the overseas VPS.
- **Unified management:** Setup wizard, systemd service controls, logs, health checks, security reports and passive performance metrics.
- **Conservative defaults:** Experimental ICMP segmentation and UDP parity repair are disabled by default; existing connection settings are preserved.

Pingtunnel is **not a VPN server**. It transports traffic arriving at the Iran VPS over encrypted ICMP to a local application endpoint on the overseas VPS, for example `127.0.0.1:444`. Each tunnel instance forwards either TCP or UDP, as configured.

## How automatic Reverse and Direct ICMP work

The Setup Wizard sets `icmp_direction` to `auto` by default. Both VPSs keep their fixed physical roles (Iran and overseas). **Reverse and Direct only determine which VPS initiates the ICMP exchange**—they do not swap VPN endpoints, keys or application ports.

**1. Reverse — preferred primary path**

```text
Overseas  ── ICMP Echo Request (poll or data) ──>  Iran
Overseas  <── ICMP Echo Reply (queued data) ────  Iran
```

The overseas VPS originates ICMP Echo Requests. When Iran receives an authenticated request, it sends a matching Echo Reply, carrying queued encrypted traffic when available. Overseas-to-Iran data can travel in the request itself. Polling adapts to real traffic activity: it becomes more responsive during active transfers and backs off when idle. Version 3.3.15 reduces the synthetic Reverse poll ceiling from 500 to **100 per second** and idle polling to about **1 per second**; synthetic polls coinciding with real encrypted outbound DATA are coalesced. This may reduce peak throughput on packet-hungry links and needs field testing.

**2. Direct — fallback after sustained Reverse-path failure**

```text
Iran  ── ICMP Echo Request ──>  Overseas
Iran  <── ICMP Echo Reply ────  Overseas
```

If Reverse has been unavailable for a sustained period **while local users are actively requesting traffic**, the core may fall back to Direct. The decision accounts for the authenticated session and validated Reverse probes. A single lost reply, brief interruption or idle application alone does not trigger a switch.

**3. Guarded recovery to Reverse**

**In AUTO, Reverse always has absolute priority, regardless of speed, RTT or observed Direct stability.** After proven sustained Reverse failure with real local demand, the core uses Direct as a guarded fallback. While Direct remains fully healthy, Foreign checks Reverse **every 10 seconds**. Iran returns a userspace HMAC-authenticated `PRA4` proof without disturbing the Direct AEAD session. Foreign waits for **two independently matched, valid proofs** (challenge nonce and ICMP ID/sequence), enforces a **60-second minimum dwell**, and then sends an authenticated `PTS4` takeover request. Only then does the normal four-message X25519 session handshake switch the channel back to Reverse. If Reverse cannot complete authentication or actual transfer, Direct fallback is retried with cooldown. **Completely interruption-free switching is not guaranteed.**

The process runs **inside the Go core** without manually changing the pairing key, service ports or Exclave/Hysteria 2 configuration. Run `sudo pingtunnel security` to inspect the selected direction and recovery diagnostics.

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
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/v3.3.15/Source/install.sh -o /tmp/pingtunnel-install.sh
sudo bash /tmp/pingtunnel-install.sh
sudo pingtunnel setup
~~~

Select **Foreign**, enter the Iran VPS public IPv4 address, choose **TCP or UDP**, and specify the port of the local overseas service. On first setup, the wizard generates a random **256-bit pairing key**. Transfer this key securely for the next step.

**Step 2 — Iran VPS (Iran)**

**Only after finishing overseas setup**, connect to the Iran VPS and run:

~~~bash
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/v3.3.15/Source/install.sh -o /tmp/pingtunnel-install.sh
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
