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
| S01 | TCP | 443 | 443 |
| S02 | UDP | 443 | 443 |
| S03 | TCP | 2053 | 2053 |
| S04 | UDP | 444 | 444 |
| S05 | TCP | 2083 | 2083 |
| S06 | UDP | 1194 | 1194 |
| S07 | TCP | 2087 | 2087 |
| S08 | UDP | 1701 | 1701 |
| S09 | TCP | 2096 | 2096 |
| S10 | UDP | 500 | 500 |
| S11 | TCP | 8443 | 8443 |
| S12 | UDP | 4500 | 4500 |

Each row is editable as `protocol,iran_port,foreign_port,on/off`. These are suggestions; check for conflicts. At least one TCP and one UDP row must remain enabled.

Existing single-port installs default to keeping their current setup. Explicitly opt into Multi-Port to convert; the existing service is retained and a complementary protocol is suggested.

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

This change extends only the listener and destination-dispatch layers. ICMP/UDP queue capacities and policies, enqueue/overflow/drop algorithms, Reverse FIFO, Queue Hint, Backlog Wake, Smart Rotation, Adaptive Performance, TCP framing, congestion control, timeouts, recovery, FEC and ICMP segmentation remain unchanged.

The existing `transport` value remains the dispatcher/queue profile; fresh setups default to TCP. Each service still uses its own TCP or UDP protocol, while the queue and scheduler remain shared under the existing policy.

## Limitations

Twelve ports do not multiply ICMP bandwidth by twelve. Destination applications must be installed and running on Foreign. A TCP check does not prove UDP reachability; use an application-level UDP test for the target service.
