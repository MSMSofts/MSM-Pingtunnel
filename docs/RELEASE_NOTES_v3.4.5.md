# MSM-Pingtunnel v3.4.5 — upstream TCP fairness and tail latency diagnostics

## Compared with original esrrhs/pingtunnel

Upstream reference: [esrrhs/pingtunnel master, 2026-11-08](https://github.com/esrrhs/pingtunnel/tree/a557d2169ff8b13ca64f227b0549bbd6f1f84587), especially `underlay_share.go` and `loop_adaptive.go`.

Original Pingtunnel uses a shared FIFO *underlay share* for TCP FrameMgr writes. Each connection emits a bounded **8 KiB quantum** before handing the ICMP socket to the next waiting TCP flow. Without this, one big bulk TCP window can flood the raw ICMP socket kernel buffer in a single tight send loop, starving unrelated flows. Upstream also reuses TCP idle-loop timers instead of allocating `time.After` for every spin.

v3.4.4 MSM-Pingtunnel already had:
- Separate TCP DATA, UDP DATA and authenticated control **receive/dispatch lanes** in mixed Multi-Port;
- Foreign-only dedicated UDP processing worker pool;
- Bounded mixed UDP queue of 256 packets retaining the most recent packet under overload; distinct control queue; retransmission-managed TCP queue;
- Stronger authenticated secure Wire 4, replay and exact Direct/Reverse kernel Echo-reflection filters.

It **did not** share the TCP send side fairly across individual TCP flows; it emitted every FrameMgr send list uninterrupted on both VPSs, including handshake/active/close loops. One connection could therefore burst a large ICMP window despite an uncongested UDP receive queue.

## What v3.4.5 changes

1. **Upstream-inspired per-core FIFO TCP ICMP fair-sharing.** A single fair scheduler is shared across all TCP Multi-Port connections in each peer. Every connection sends up to **8 KiB** of its already-admitted FrameMgr frames and hands off to the next waiter. Fairness covers *initial connect, steady-state data and close/drain loops* on both Iran and Foreign.
2. **Preserve UDP latency and control.** UDP and authenticated control do **not** wait on the TCP fairness gate, preserving their independent 3-lane ingress and the best-effort newest-first UDP overload policy. The TCP FrameMgr's original per-flow ordering, BB congestion decisions, ACK handling and resend remain unchanged.
3. **Reusable lazy idle timers.** Client/server TCP loops reuse the same timer with the existing 2ms-to-80/250ms adaptive waits. Timers are allocated only when actually needed, stopped at loop exit, and no longer repeatedly allocated through `time.After`.
4. **Tail-latency observability.** The existing adaptive RTT ring now stores up to **128 individual authenticated ICMP probe samples** within the most recent 120 seconds (not merely 16 samples). `pingtunnel performance` exposes **raw individual RTT P50/P95/P99/max**, counts of RTT samples over **250ms/1000ms**, alongside existing smoothed RTT/Jitter/probe-loss estimates. The raw distribution cannot prove application delivery or reveal a spike with no coincident probe.
5. **Fair scheduling telemetry.** `pingtunnel security` reports cumulative TCP fair turns, contention events and the maximum fairness handoff wait in milliseconds: `tcp_icmp_fair_turns`, `tcp_icmp_fair_contended`, `tcp_icmp_fair_max_wait_ms`. The long-session sampler captures this and the raw RTT tail.
6. **Expanded regression tests.** Go unit/race tests verify a contending TCP flow obtains the ICMP turn after the 8 KiB limit, 12 concurrent TCP flows complete without lost/reordered frames, and timers rearm safely. The Linux namespace smoke sends twelve simultaneous 16 KiB bulk TCP requests across six TCP aliases while two video-like UDP flows remain active. Standard encrypted 12-service four-policy and 60-second regression remain enabled.

## Not changed / compatibility

- No Wire-v4 or persistent config-schema-3 change, no new implicit ports, and no change to 12-service TCP/UDP Multi-Port routing, paired-IP restrictions, current route preferences or authenticated exact Echo-reflection filters.
- TCP queues remain 10,000 frames, UDP 256, control 128; no new unconditional UDP drops or speculative buffer-size tuning on the production VPS.
- This is an upstream-informed **fairness/performance hardening**, not a quantified production performance improvement. High kernel/network ICMP packet rate, link shaping, protocol retransmission or app buffering can still cause 1–3 second Instagram pauses. Compare actual RTT tail and fair-wait metrics with the *timestamp* of each pause on both VPSs.
- No live VPS was changed. Update both peers to a verified, checksum-matched v3.4.5 release together after backups. For rollback retain installed v3.4.4 binaries and configuration.

## Verification gate

Merge and publish only if AMD64/ARM64 Go tests including `-race`, Rust `cargo test --locked`, all four authenticated Linux ICMP route modes and mixed TCP/UDP smoke/soak pass. Real cross-border packet captures and timed application playback remain separate evidence.
