# Sustained game/QUIC latency: code audit and measurement plan

**Scope:** `MSMSofts/MSM-Pingtunnel` after v3.3.18. This document
distinguishes a source-code defect from a field-confirmed explanation.
No SSH access, capture, VPS metrics, or real two-hour gaming session
was available during the source audit.

## Confirmed code-level defects

1. **AEAD replay window grew without a bound.** `Go/secure_session.go`
   shifted a `math/big.Int` left for every newly authenticated sequence,
   never masking out bits older than the specified 1024-packet window.
   The integer therefore expanded throughout a long session; each
   incoming authenticated packet triggered progressively more copying,
   allocation and CPU work under the secure-session mutex. This is a
   plausible cause of worsening jitter after an hour or more of high-PPS
   UDP/QUIC, but not a remotely verified root cause.
   **Fix:** a fixed 16-word / 1024-bit replay bitmap, constant space and
   bounded per-packet work, preserving out-of-order/replay rejection.
   Tests simulate 600,000 packets, shifts across 64-bit word boundaries
   and randomized reorder/duplicate patterns against a reference model.

2. **ICMP application dispatcher could queue 10,000 messages and block
   its sole receiver for up to 3 seconds** when the queue filled. That
   can produce long tail latency under saturation, even after the replay
   fix. **Fix:** when and only when the configured forward transport is
   UDP, cap the authenticated application dispatch queue to 256 entries.
   If full, discard a new UDP DATA message promptly and increment
   `udp_dispatch_overflow_drops`. QUIC and games can recover from some
   packet loss; keeping the receiver responsive avoids unbounded
   head-of-line delay. TCP's 10,000-entry queue and existing 3-second
   fail-safe are unchanged. UDP control messages still take the safe
   non-dropping path. A full UDP queue can now cause measurable packet
   loss: this is a low-latency tradeoff, not a guarantee of faster
   throughput.

3. **Previous UDP receive buffer truncation** in v3.3.18 was fixed by
   65,535-byte reads with Linux `MSG_TRUNC` detection. This remains in
   place. The security status now exposes
   `udp_truncated_datagrams` as well as dispatcher-overflow drops.

4. **Raw ICMP receive buffer size:** despite the v3.3.18 UDP socket
   improvements, the encrypted ICMP read path still allocated only
   10,240 bytes. The receiver now buffers up to 65,535 bytes so the
   raw ICMP layer does not silently truncate an otherwise valid larger
   encrypted datagram. This is an integrity fix, not a recommendation
   to increase UDP gaming packet sizes.

## Reproducible Go source

The original pinned upstream commit `df16e52771ee67f1f9770ec68763b425672a36fc`
became disconnected from upstream's public Git refs after a history
rewrite. New upstream tags introduced unrelated and incompatible
APIs/Go dependencies. Instead of swapping a new core underneath
Wire v4, the project now archives the 25 text/module/license files of
the verified original source under `Upstream/pingtunnel-df16/`. Its
`SNAPSHOT.md` lists every verified Git blob SHA. CI overlays current
`Go/*.go` onto this immutable local base and retains Go 1.26.0.
No runtime network configuration or cryptographic protocol is changed.

## Other bounded or scheduled behavior checked

- Reverse encrypted FIFO is already capped at 256 frames / 2 MiB and
  frames expire after 12 seconds; inspect its *actual* drop and queue
  delay counters instead of raising poll frequency blindly.
- Reverse polling adapts to traffic. A 125-poll/s burst is a poll request
  schedule, not a guaranteed application packet delivery rate.
- Smart Rotation targets **three hours** and requires authenticated path
  proofs. It does not inherently explain a spike at the one-hour mark.
- The `time.Sleep(time.Hour)` in Go `cmd/main.go` is the process's
  idle keep-alive loop, NOT an hourly network reset or packet timer.
- TCP BB loss-recovery is maintained separately from UDP. Wire v4,
  AEAD and pairing keys are unchanged.

## Collect two-hour evidence on BOTH VPSs

Download this script from the matching release **after validating its
checksum and reviewing its source**; it does not install or restart
services, configure networking or read the pairing key:

```bash
python3 Source/long_session_probe.py --label iran --duration 7200 --interval 5 --output /tmp/pingtunnel-iran-2h.jsonl
python3 Source/long_session_probe.py --analyze /tmp/pingtunnel-iran-2h.jsonl
```

Use `--label foreign` and a different filename on the other VPS.
The process writes `0600`-mode JSONL files, including a monotonic
clock for correlation, per-process RSS/CPU/threads/fd counts, allowlisted
`/run/pingtunnel-security.json` and
`/run/pingtunnel-performance.json` counters, and host-wide Linux UDP
SNMP counters. It does not collect `config.json`, pairing secrets,
target IP addresses, credentials or packet payloads.

Use baseline v3.3.18 and the candidate build with the same game/workload
and both ICMP directions when practical. Compare before/after an hour:
CPU trend, RSS, replay drops, Reverse p95 queue delay, Reverse queue
drops, dispatcher overflow, ICMP write failures, kernel UDP buffer
errors, and RTT/jitter, including 15 minutes *around* the first severe
lag. Kernel UDP SNMP counters are HOST-WIDE (not per tunnel). Confirm
application-level game latency or QUIC RTT separately; ICMP health
alone is not enough.

## Release safety

Go tests and race-detector builds, two-architecture release binaries,
Python diagnostic tests and install-manifest checks are necessary but
**insufficient** to claim field resolution. Do not silently change
previously saved transport/fragmentation/FEC settings or VPN service
configuration. Snapshot and preserve both peers' pairing keys; perform
a coordinated deployment with rollback capability and observe a real
two-hour game before declaring the incident solved.
