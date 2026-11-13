# MSM-Pingtunnel v3.4.6 — restore v3.3.24 UDP admission/processing semantics

## Why this is a rollback, not another speculative "queue optimization"

The operator reported **severely degraded UDP responsiveness after mixed Multi-Port**, despite earlier v3.4.4 Direct authentication/reflection counters reaching zero and ten-minute monitoring showing no authentication errors, observed local UDP queue stalls, socket write failures, or CPU/RAM pressure. Those clean counters cannot rule out real-world ICMP path shaping, dropped packets, short app stalls or interference between concurrent services.

We compared the actual **v3.3.24 source tag (before Multi-Port)** with **v3.4.5**, rather than merely comparing README descriptions.

| Area | v3.3.24 before Multi-Port | v3.4.5 mixed Multi-Port | v3.4.6 restored |
| --- | --- | --- | --- |
| Authenticated UDP DATA receive queue | 256 frames | 256 frames | **256 frames** |
| UDP queue on overflow | **FIFO; preserve already accepted frames; discard incoming DATA** | **evict oldest accepted frame to admit newest** (introduced v3.4.3) | **v3.3.24 FIFO, drop incoming** |
| Server UDP processing workers | All configured general workers (typically **100**) in dedicated UDP-only process | New independent UDP pool **capped at 16**, regardless of configured 100 | Independent UDP pool with **full configured count**, typically 100 |
| UDP application send/return | Direct sends with Go socket reads, per-flow UDPConn at Foreign | Same datagram framing plus required authenticated per-service alias/port mapping | Retain the original Go UDP send/return path and per-flow hashing |
| Mixed TCP/UDP isolation | Not needed: one protocol per process | Independent UDP/TCP/control dispatch lanes | Retained: TCP cannot block the pre-Multi-Port UDP FIFO lane |

The **legacy UDP queue baseline already dropped incoming DATA when full**. This release restores that exact admission, not a lossless or infinitely buffered queue. Under real link saturation, UDP delivery can still fail. We intentionally do **not** increase queues, add retry of old game/video datagrams, or invent a new bandwidth controller.

## Code changes

1. Remove the speculative `enqueueFreshMixedUDP` oldest-eviction implementation from `Go/mixed_dispatch.go`. Route all authenticated mixed UDP DATA through the original v3.3.24 `enqueueICMPPacket(udpRecv, packet, true)`. The original branch for non-Multi-Port keeps this same function.
2. Remove the `udpThreads>16` cap in `Go/server.go`. An independent UDP pool now has the **same configured worker count** as original v3.3.24, while still isolated from TCP dial/FrameMgr jobs. Per-flow hash ordering is unchanged.
3. Preserve **security Wire 4 / config schema 3 / exact Echo-reflection filtering**, legacy UDP socket buffers and both Direct/Reverse policies. Preserve 12 mixed TCP+UDP service port mappings, source IP pinning and authenticated alias restrictions. No rewrite of the transport encryption or kernel ICMP Echo handling.
4. `pingtunnel security` now prints `udp_dispatch_policy: v3.3.24-fifo-drop-new` and on Foreign the configured `udp_legacy_server_workers`, so the operator can directly verify the rollback is active.
5. Regression tests compare the output of the actual **baseline v3.3.24 enqueue function** against the mixed UDP lane for capacities 1, 3, 16 and 256, verifying FIFO identity/order, equal overflow accounting, nonblocking operation and reliable control isolation. The original full four-route 12 mixed-service smoke, 12 bulk TCP plus continuous UDP tests and one-minute clean-network soak remain mandatory.

## Limits and practical next step

**A shared 12-service Multi-Port encrypted ICMP socket is not architecturally identical to v3.3.24's one-protocol-per-process UDP-only instance.** This release rolls back the *changed UDP queue policy and worker-count throttling* without deleting existing services. A byte-for-byte return to v3.3.24 requires going back to a **single legacy UDP service configuration**, and would remove the mixed 12-service topology. We have **not** silently modified the operator's live configuration or deployed to either VPS.

This release is not a measured guarantee that Instagram, gaming or other UDP sessions have recovered their original quality. After installing on both peers, compare manual Direct under the same actual traffic and record timestamps, TCP and UDP service load, `pingtunnel security`, `pingtunnel performance`, and application stalls. If still degraded, the next controlled A/B is **one UDP service with no concurrent TCP/multi-service load**, not another blind queue tuning iteration.
