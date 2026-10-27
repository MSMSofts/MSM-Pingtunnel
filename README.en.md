# Pingtunnel Manager

**A lightweight, encrypted ICMP tunnel between exactly two Linux VPSs, with a five-question setup wizard.**

[فارسی / Persian](README.md) · [Technical architecture](docs/ARCHITECTURE.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md) · [Download v3.2.5](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.2.5)

![Version](https://img.shields.io/badge/version-3.2.5-2563eb) ![Platform](https://img.shields.io/badge/Linux-AMD64%20%7C%20ARM64-444) ![License](https://img.shields.io/badge/license-Apache--2.0-137333) [![CI](https://github.com/MSMSofts/MSM-Pingtunnel/actions/workflows/rust.yml/badge.svg)](https://github.com/MSMSofts/MSM-Pingtunnel/actions/workflows/rust.yml)

Pingtunnel Manager sets up and operates an **ICMP-based transport tunnel** between an **Iran-side VPS** and an **overseas VPS**. Local TCP or UDP traffic enters the Iran VPS, travels inside authenticated, encrypted ICMP packets, and is forwarded by the overseas VPS to its configured local service.

**This is a transport layer—not a standalone VPN server.** Services such as Hysteria 2, s-ui or other TCP/UDP applications run and are configured separately.

**Current release: 3.2.5** · Rust management CLI · Modified Go Pingtunnel core · Config schema **3** · Secure wire protocol **4** · Direct Iran → foreign ICMP only.

## Highlights

| Feature | How it works |
| --- | --- |
| **Two VPSs only** | No HA node, backup server, resident management daemon, or separate proxy transport |
| **Unified five-step wizard** | Region, opposite VPS IPv4, shared pairing key, TCP/UDP, and this VPS's port |
| **Independent ports** | For example, receive UDP **444** in Iran and forward to UDP **8443** overseas |
| **ICMP transport** | No TCP/UDP port on the *outer* tunnel itself |
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

The installer pins the [v3.2.4 release](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.2.5), checks SHA256 and the release manifest, verifies manager/core compatibility, and backs up existing installed files for failure rollback.

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
  v3.2.5   |   Encrypted ICMP   |   Wire v4
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
| **3.2.5** | 3 | **v4** (`PTH4/PTD4`) | Status pause, worker and lost-link recovery |\n| **3.2.4** | 3 | **v4** (`PTH4/PTD4`) | Current; raw-mode and menu-order fix |
| **3.2.3** | 3 | **v4** | Previous release; resource dashboard |
| **3.2.2** | 3 | **v4** | Previous compatible patch |
| **3.2.1** | 3 | **v4** | Previous compatible maintenance release |
| **3.2.0** | 3 | **v4** | Previous patch release; wire-compatible |
| **3.1.0** | 3 | **v4** | Introduced ephemeral exchange and anti-replay |
| **3.0.0** | 3 | Earlier `PTA1` | Config preserved but incompatible with 3.1/3.2 over the wire |
| **Before 3.0** | Legacy | Legacy | No automatic migration |

Upgrading both VPSs is recommended during a maintenance window. The manager preserves a valid v3 configuration and pairing root, but service restarts may interrupt active application traffic. Mixed old/new **wire protocols do not silently downgrade**.

> **Repository transfer note:** For updates, use the canonical installer URL under `MSMSofts/MSM-Pingtunnel` shown in the Install section. Earlier manager binaries may still use the former repository owner in the built-in `pingtunnel update` URL.

[Version history](CHANGELOG.md) · [Pinned release](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.2.5) · [Rolling assets](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/rust-latest)

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

**Not implemented as of 3.2.4:** actual reverse tunnel forwarding, automatic Direct/Reverse switching, high availability, multiple VPSs, simultaneous TCP+UDP forwarding through one configured tunnel, or guaranteed ICMP traffic camouflage.

**Still required before high-assurance deployment:** testing two real VPSs with ICMP packet loss/jitter, Hysteria 2 end-to-end testing, restart/upgrade interruption testing, and independent cryptographic review.

The project modifies the Go core from [esrrhs/pingtunnel](https://github.com/esrrhs/pingtunnel). Rust handles setup and systemd without a continuously running management daemon. Licensed under [Apache-2.0](LICENSE). This repository is not officially endorsed by the Hysteria 2, s-ui, or upstream Pingtunnel projects.
