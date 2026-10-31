# MSM Pingtunnel

**A lightweight, encrypted ICMP tunnel between an Iran VPS and an overseas VPS**, forwarding TCP or UDP traffic through a Go core and a simple Rust manager.

[فارسی](README.md) · [Current release: v3.3.13](https://github.com/MSMSofts/MSM-Pingtunnel/releases/tag/v3.3.13) · [CI status](https://github.com/MSMSofts/MSM-Pingtunnel/actions/workflows/rust.yml) · [Apache 2.0 license](LICENSE)

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

The overseas VPS originates ICMP Echo Requests. When Iran receives an authenticated request, it sends a matching Echo Reply, carrying queued encrypted traffic when available. Overseas-to-Iran data can travel in the request itself. Polling adapts to real traffic activity: it becomes more responsive during active transfers and backs off when idle.

**2. Direct — fallback after sustained Reverse-path failure**

```text
Iran  ── ICMP Echo Request ──>  Overseas
Iran  <── ICMP Echo Reply ────  Overseas
```

If Reverse has been unavailable for a sustained period **while local users are actively requesting traffic**, the core may fall back to Direct. The decision accounts for the authenticated session and validated Reverse probes. A single lost reply, brief interruption or idle application alone does not trigger a switch.

**3. Guarded recovery to Reverse**

While using Direct, the core checks whether Reverse can be safely re-established. After eligibility checks and authenticated negotiation, it can return to its preferred Reverse path. A minimum dwell interval helps prevent repeated route flapping. Direction changes can require session renegotiation, so **seamless switching is not guaranteed**.

The process runs **inside the Go core** without manually changing the pairing key, service ports or Exclave/Hysteria 2 configuration. Run `sudo pingtunnel security` to inspect the selected direction and recovery diagnostics.

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

Run these commands **on the overseas VPS first**, then **on the Iran VPS**:

~~~bash
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/v3.3.13/Source/install.sh -o /tmp/pingtunnel-install.sh
sudo bash /tmp/pingtunnel-install.sh
~~~

The installer checks matching Manager and Go core assets using SHA-256 checksums and the release manifest. Existing configuration, if any, is validated before installation.

For initial setup, run on each VPS:

~~~bash
sudo pingtunnel
~~~

Select **6) Setup Wizard**. It asks for five values: server region, opposite VPS public IPv4, shared pairing key, TCP/UDP transport and local port.

1. **Overseas VPS:** Select Foreign. A random pairing key is generated on first setup; transfer it securely to Iran. Select the transport and enter the local destination service port.
2. **Iran VPS:** Select Iran, enter the overseas public IPv4 and **the same pairing key and transport**, then choose the port clients will connect to.
3. Check service health and the authenticated session **on both VPSs**. An active systemd service alone does not prove application traffic is flowing.

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
