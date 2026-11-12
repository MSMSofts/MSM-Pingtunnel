# Phase 2: lock contention and realistic Direct-path impairments

This proposal **builds on** phase-one security/health fixes in PR #47.
It is NOT a released stable version, and no production VPS was modified.

## Authenticated AEAD concurrency

Before this patch, every Wire-v4 `encrypt` and `decrypt` held the
`secureSession.mu` mutex while the AES-GCM/XChaCha20-Poly1305 computation
ran. Unrelated UDP/QUIC flows contend on that mutex even though independent
cipher operations do not require shared mutable state.

The lock is now held only for:
- Checking authenticated session state, reserving a unique outbound
  sequence number and snapshotting the immutable cipher/session ID.
- Verifying that an inbound frame still belongs to the active session,
  atomically claiming the anti-replay sequence, and refreshing peer
  liveness **after** AEAD tag validation.

`Seal` and `Open` run without the session lock. A session-key pointer
change during `Open` causes the frame to be refused with
`ErrSecureNegotiation`, so stale ciphertext cannot be accepted or
refresh the new session's peer heartbeat.

The nonce format, X25519/HKDF handshake, replay window (1024), cipher
suite negotiation, protocol/Wire-v4 format and pairing secrets DO NOT CHANGE.

### Regression checks

- `TestConcurrentSecureAEADMaintainsUniqueNoncesAndReplayWindow`
  encrypts/decrypts 480 uniquely marked packets from 8 goroutines over
  the same session; all must authenticate and a replay must be rejected.
- Existing replay, rekey, AEAD tag-tamper and handshake tests remain enabled.
- `go test -race -count=1 ./...` must pass.
- `BenchmarkConcurrentSecureAEADEncrypt` reports ns/op and allocation data
  as a **diagnostic**; no unsupported universal speedup is claimed.

## Raw-ICMP network impairment testing

`Source/direct_mode_smoke.py --impairment` creates two disposable Linux
network namespaces with real raw-ICMP sockets and two production Go processes.
It first authenticates an encrypted UDP echo exchange (existing test), then
keeps those processes running across:

1. Baseline: 24 phase-tagged UDP echo packets.
2. Egress impairment on both veth interfaces:
   25ms delay with 9ms jitter, 4% random loss and 2% reordering.
3. Deliberate **asymmetric** outage: 100% loss of Iran-side egress only,
   while foreign-side egress remains impaired but online. Three uniquely
   tagged requests MUST NOT get through.
4. Restore Iranian egress to the impaired link profile. 32 additional
   phase-tagged requests must produce at least 12 replies without
   restarting either Go process.
5. Remove both netem qdiscs even on a failure.

Both locked manual Direct and Direct-first AUTO are tested separately.
Each phase prints observed application-layer loss and successful RTT
p50/p95. These are measured within an isolated CI environment and
**cannot** be advertised as measured Internet/VPS gaming latency.

Short fault windows validate no premature failsafe churn, not full
90–150-second route-failover hysteresis or a two-hour real-world soak.

## Diagnostics

`pingtunnel security` now prints cumulative UDP dispatcher overflow
and socket receive truncation counters alongside the Reverse queue
loss/latency counters introduced in phase one. This makes it possible to
distinguish socket overload, queue congestion and oversized datagrams
without changing scheduler defaults.

## Deployment gates still required

- [ ] Every GitHub Actions job passes, including network namespace smoke.
- [ ] Compare the 512-byte, parallel AEAD benchmark with the previous
      committed version on **equivalent hardware**; expect lower lock
      contention but do not treat one noisy CI number as a guarantee.
- [ ] Two real VPSs: test Reverse-first and Direct-first during a 90–180s
      one-way blackhole, signed return-path proofs, automatic recovery and
      route dwell; verify real TCP and UDP flows.
- [ ] Two-hour game/short-video/QUIC soak with packet loss and p50/p95/p99
      latency, before any changes to poll cadence or queue lifetime.
- [ ] Keep a verified rollback to stable v3.3.23.

**No default FEC/fragmentation enablement, no changes to route policy,
poll timing, session wire format or release assets.**
