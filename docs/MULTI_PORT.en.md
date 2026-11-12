# MSM-Pingtunnel Multi-Port Guide

## Architecture

Multi-Port forwards up to 12 TCP/UDP services over one authenticated ICMP tunnel and one secure session. Each row has a stable ID (S01–S12), protocol, Iran ingress port, Foreign target port and enabled state.

- Iran: opens the configured TCP or UDP listener.
- Foreign: forwards only to `127.0.0.1:<foreign_port>`; do not expose target ports publicly.
- TCP and UDP may share the same numeric port.
- Both VPSs must use the same Service Profile.

The service ID is an alias in the authenticated Wire v4 `Target` field. Foreign validates it against a local allowlist and never trusts an arbitrary peer-supplied destination. Wire version and cryptographic negotiation remain unchanged.

## Wizard suggestions

A fresh setup offers 12 editable suggestions:

| ID | Protocol | Iran ingress | Foreign loopback target |
|---|---|---:|---:|
| S01 | TCP | 8443 | 8443 |
| S02 | UDP | 8444 | 8444 |
| S03 | TCP | 2053 | 2053 |
| S04 | UDP | 2054 | 2054 |
| S05 | TCP | 2083 | 2083 |
| S06 | UDP | 2084 | 2084 |
| S07 | TCP | 2087 | 2087 |
| S08 | UDP | 2088 | 2088 |
| S09 | TCP | 2096 | 2096 |
| S10 | UDP | 2097 | 2097 |
| S11 | TCP | 10081 | 10081 |
| S12 | UDP | 10082 | 10082 |

On a fresh setup **all twelve port suggestions are disabled** until explicitly enabled. TCP 443 is not in the default suggestions and is never auto-bound. Each row is editable as `protocol,iran_port,foreign_port,on/off`. These are suggestions; check for conflicts. At least one TCP and one UDP row must remain enabled.

Existing single-port installs keep their previous setup unless Multi-Port is explicitly selected in the Wizard. The first `services add` no longer silently creates active S01/TCP443. Existing Multi-Port entries are not rewritten on upgrade; keep S01 disabled if another tunnel owns 443.

## Pair setup and profile transfer

1. Install and configure Foreign first.
2. Set the Foreign target ports in the Wizard.
3. Ensure destination applications listen on `127.0.0.1:<foreign_port>`.
4. Export the profile on Foreign:
   ```bash
   sudo pingtunnel services export /root/pingtunnel-services.json
   ```
5. Transfer it securely to Iran:
   ```bash
   scp /root/pingtunnel-services.json root@IRAN_VPS:/root/
   ```
6. Import and validate on Iran:
   ```bash
   sudo pingtunnel services import /root/pingtunnel-services.json
   sudo pingtunnel services check
   ```

The profile contains service IDs, protocols and port mappings only. It does not contain the Pairing Key or other secrets.

## Firewall and destination services

**Iran:** allow each enabled ingress port using its matching protocol. TCP and UDP need separate firewall rules. Inspect listeners with:

```bash
sudo ss -lntup
```

**Foreign:** destination applications must listen on loopback. Inspect them with:

```bash
sudo ss -lntp
sudo ss -lnup
```

Do not expose target ports publicly. Permit the required ICMPv4 path between the VPSs and the Iran ingress ports only. If another process already owns an Iran port, that listener cannot bind.

## Menu and CLI

Open **16) Multi-Port** from `sudo pingtunnel`, or use:

```bash
sudo pingtunnel services list
sudo pingtunnel services add
sudo pingtunnel services edit S01
sudo pingtunnel services enable S01
sudo pingtunnel services disable S01
sudo pingtunnel services remove S12
sudo pingtunnel services check
sudo pingtunnel services export /root/pingtunnel-services.json
sudo pingtunnel services import /root/pingtunnel-services.json
```

Service changes are saved atomically and applied with a controlled restart; this version does not claim live hot-reload. Synchronize the profile on both VPSs after each edit.

## Preserving existing queues and performance

v3.4.1 isolates UDP DATA in its existing **256-packet bounded short dispatch queue** with nonblocking UDP-only overflow drops; reliable TCP and control use the existing **10,000-packet queue**. This prevents UDP video/game packets from sitting behind TCP backlog while preserving both queue sizes and policies. This change extends only the listener and destination-dispatch layers. ICMP/UDP queue capacities and policies, enqueue/overflow/drop algorithms, Reverse FIFO, Queue Hint, Backlog Wake, Smart Rotation, Adaptive Performance, TCP framing, congestion control, timeouts, recovery, FEC and ICMP segmentation remain unchanged.

The existing `transport` value remains the dispatcher/queue profile; fresh setups default to TCP. Each service still uses its own TCP or UDP protocol, while the Multi-Port receive queues are separated by protocol. All original capacities, drop policies, route scheduling, FEC and recovery behavior are preserved.

## Limitations

Twelve ports do not multiply ICMP bandwidth by twelve. Destination applications must be installed and running on Foreign. A TCP check does not prove UDP reachability; use an application-level UDP test for the target service.
