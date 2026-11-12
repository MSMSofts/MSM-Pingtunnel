# Phase 1: security and transport health hardening (candidate)

This document describes the proposed changes on the `fix/v3.3.24-security-health-phase1` branch. **No new stable release is implied.** Deploy both sides together only after CI, test-VPS smoke checks and an explicit rollback plan.

## Production Go CLI: fail closed

The `cmd` binary now rejects omitted encryption, `none`, `aes128`, `aes256` and `chacha20`. Only `-encrypt auto` with the mandatory region/peer and 32-byte authenticated pairing key may start a production tunnel, whether called through the Rust manager or directly. Library legacy modes remain for upstream test compatibility but are not accepted by the production CLI.

When `-profile` is explicitly enabled, the pprof listener is loopback-only (`127.0.0.1`) instead of public `0.0.0.0`. Do not expose diagnostic endpoints through an untrusted reverse proxy.

## Separate process and authenticated-peer checks

`pingtunnel health` continues to validate local systemd/worker liveness and a fresh Go heartbeat. Its output now states that this is **not** an end-to-end application-data test.

`pingtunnel health --peer` is stricter: it fails with a nonzero exit status unless there has been authenticated peer traffic within 35 seconds. This mode is intended for checks during active traffic. A naturally idle authenticated connection can fail this check without proving network failure; do not use it unconditionally as a systemd restart trigger.

The installer retains process-only validation on upgrade, because an unrelated temporary remote outage must not cause a misleading local binary rollback. It clearly labels that limitation.

## Oversized Reverse frames

The encrypted Reverse FIFO has a 10,240-byte per-frame limit. Previously its oversized-frame rejection was not counted. It now increments both `reverse_queue_drops` and the separate `reverse_oversized_drops` metric; `pingtunnel security` displays that counter.

This is observability, **not** a fragmentation protocol change. The existing opt-in segmentation remains disabled by default. Large application datagrams require explicit compatible segmentation settings on both peers and field testing.

## Test and release gates

1. GitHub CI: Go unit tests, Go race detector, Rust manager tests, Linux AMD64/ARM64 builds, and real raw-ICMP Direct/Direct-first smoke.
2. CI negative checks: plain/legacy/missing-encryption Go client arguments must fail with the mandatory authenticated Wire-v4 message.
3. Unit tests: oversize Reverse drops increment both drop counters; strict peer health rejects unknown, stale or unauthenticated state.
4. Test VPS: verify `pingtunnel health` vs `pingtunnel health --peer` during active demand and idle; ensure no unintended service restarts.
5. Before production release: run Reverse and Direct traffic, one-way outage/failover/return and a two-hour UDP/QUIC gaming-style soak test on both peers, with p50/p95/p99 latency and loss.

**Not in this phase:** changes to route grace periods, Poll cadence, default fragmentation/FEC, Wire v4, the shared pairing key, or real VPS configuration.
