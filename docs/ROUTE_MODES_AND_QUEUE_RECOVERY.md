# Route policies and queue-demand recovery (v3.3.22)

This build adds three selectable operator workflows on **both** VPS peers.
Use `sudo pingtunnel` -> **15) Route Policy**, or use CLI commands:

| Operator mode | UI | CLI | JSON `icmp_direction` |
|---|---|---|---|
| Reverse-first, automatic | 1 | `sudo pingtunnel route auto-reverse` | `auto` |
| Direct-first, automatic | 2 | `sudo pingtunnel route auto-direct` | `auto_direct` |
| Manual Reverse | 3 -> Reverse | `sudo pingtunnel route manual-reverse` | `reverse` |
| Manual Direct | 3 -> Direct | `sudo pingtunnel route manual-direct` | `direct` |

The "Manual" menu is one top-level option with a Reverse/Direct subchoice.
It never changes direction because of route probes, timed rotation, latency,
or application traffic. The global `Wire v4` and config schema `3` stay
unchanged. The 256-bit pair key, local listener, foreign loopback target,
UDP/TCP forwarding and encryption parameters survive routing changes.
Each command applies local settings atomically and restarts only the local
service. **Set the same policy on BOTH VPSs** in a coordinated maintenance
window. Mismatched policies can interrupt traffic.

## Reverse-first AUTO (unchanged failure safety)

Iran starts in Reverse. Only sustained local application demand plus
authenticated Reverse feedback failure permits switching to Direct.
Foreign continues signed PTR4/ PRA4 checks, requires two fresh independent
roundtrips, and uses matched PTS4/PTA4 before returning to Reverse.
Key/session continuity is preserved for recovery.

## Direct-first AUTO (new)

Iran starts sending ICMP Echo Requests, Foreign Echo Replies, like the
historical Direct sender. Foreign sends a low-rate signed PTR4 Reverse-path
check every 10 seconds, even when Direct is selected. On Iran, an
HMAC-protected *PRF4* proof explicitly marks recent local application
demand; an idle client sends ordinary PRA4 instead. Foreign requires
**two** independently matched PRF4 requests in 25 seconds AND over 90
seconds without authenticated Direct peer traffic before considering a
Direct-to-Reverse fallback. Foreign then sends a fresh PTS4 request,
Iran responds with matching PTA4 and both change ICMP roles while
preserving the current session. Unauthenticated ICMP cannot trigger
a path change.

When Reverse is carrying traffic, Iran periodically sends signed PTC4
Direct return-path probes. Two independently validated PDA4 Echo Replies
plus 60 seconds of minimum route dwell permit a PTX4 Direct handoff.
Foreign authenticates PTX4, responds with a matching PTB4 ACK and switches
to Direct. Iran switches only after a valid matched PTB4. If the ACK is
lost, Iran retries with a new nonce every two seconds for up to 30
seconds; Foreign may answer repeated requests even if already on Direct.
There is a 30-second retry cooldown after exhaustion. Legacy timed
"Smart Rotation" is still disabled.

## Queue and telemetry fixes

A new or recently reported signed PTQ4 packet with outstanding encrypted
Reverse FIFO data keeps Foreign's opportunity polling at **up to 40/s**
(25ms interval) for at most **six seconds**, not the stale 1Hz idle rate
after just 1.2 seconds. On actual authenticated data delivery, Foreign
decrements its remote queue estimate and clears obsolete byte/age counts.
The short 8ms fast-attack and existing 8–16ms pressure adaptation continue.
No unbounded fast polling or blind 2ms flood. Failed socket writes still
cause the bounded 25ms backoff.

Diagnostics no longer print misleading old queue depth/bytes as live
data when the signed PTQ4 sample has expired, and report the age of the
last successful Iran-side queued send. The queue-delay p95 remains a
*historical last-128* metric; a value from an hour ago does not measure
current gameplay lag. Track both route `auto_route_policy` and physical
`icmp_direction` in `sudo pingtunnel security`.

## Validation and limits

Unit tests must cover all four machine values, both AUTO initial
directions, forged/stale/replayed PRF4, fixed manual non-switching,
two-proof authenticated return, loss and retry cooldown, and pressure
warmdown. GitHub CI builds on AMD64 and ARM64; those tests do **not**
establish end-to-end gameplay jitter improvement. User-side Call of Duty,
YouTube and Instagram comparisons are still necessary.

For live benchmarking, run `Source/long_session_probe.py` on both peers
while sending real application data; send the resulting JSONL files for
aligned analysis. Do not expose `/opt/pingtunnel/conf/config.json` or the
pairing key.
