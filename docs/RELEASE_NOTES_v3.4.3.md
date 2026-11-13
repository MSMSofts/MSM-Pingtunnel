# MSM-Pingtunnel v3.4.3 — Multi-Port latency isolation and UDP freshness

## What changed from v3.4.2

v3.3.24 effectively processed **one** application transport (TCP or UDP) per tunnel process. v3.4.1/3.4.2 introduced simultaneous TCP+UDP Multi-Port but, although they created separate receive queues, they still drained **both through one sequential application dispatcher**. When a TCP frame or a destination-connect/worker-pool submission was slow, authenticated UDP video/game datagrams could wait behind it. On Foreign, TCP and UDP also shared the original per-flow thread pool; the default TCP target connect timeout can reach 1 second.

- **Dedicated full receive lanes:** Multi-Port now uses three independent dispatch goroutines for TCP DATA, UDP DATA, and authenticated PING/KICK controls on **both VPSs**. One slow TCP handler cannot stall the UDP queue consumer.
- **Separate Foreign UDP work pool:** Hashed, in-order UDP flow processing uses up to 16 workers in a **separate thread pool** from TCP dial/frame processing. Single-port mode and the original pool settings remain unchanged.
- **Fresh UDP on congestion:** The existing 256-packet UDP Multi-Port queue evicts the oldest authenticated UDP DATA packet instead of rejecting the newest one when full. Control packets have their **own 128-packet reliable lane**, never enter this evicting queue, and retain fail-safe admission semantics. UDP is still best-effort: evicted datagrams are intentionally lost.
- **No per-frame TCP full-queue sleep:** The v3.4.2 2ms wait under a fully saturated 10,000-frame mixed TCP queue has been removed; overflowing TCP DATA is counted and immediately shed for the existing reliable FrameMgr to retransmit. This prevents thousands of saturated TCP packets from accumulating seconds of wait in the sole ICMP reader. Ordinary under-capacity TCP is unchanged.
- **Security observability:** `pingtunnel security` exposes the maximum measured local authenticated dispatch wait for UDP/TCP and the number of DATA frames exceeding 250ms, alongside existing overflow counts. The JSON keys are `udp_dispatch_queue_max_delay_ms`, `tcp_dispatch_queue_max_delay_ms`, `udp_dispatch_delayed_over_250ms` and `tcp_dispatch_delayed_over_250ms`.
- **Expanded regressions:** Go tests prove UDP and control advance while a TCP handler is blocked, newest-UDP admission under a full queue, overload is nonblocking, and local queue-delay metrics work. Linux raw-ICMP namespace smoke exercises all four route modes and continuous concurrent UDP against all six TCP service aliases.

## Preserved compatibility and safeguards

- Config schema **3** and authenticated secure Wire **4** remain unchanged. Both VPSs should use matching manager/core binaries and service profiles; existing pairing keys must be preserved.
- Up to **12 mixed TCP/UDP services**, unchanged TCP DATA queue of **10,000**, UDP DATA queue of **256**, separate new control queue of **128**; no implicit ports and no default TCP 443.
- AEAD, anti-replay, reverse signed polling/proofs, manual path locks, guarded automatic failover, fragmentation/FEC opt-ins and firewall policies are unchanged.
- The release does **not** promise the disappearance of 1–3 second Instagram stalls: app buffering, route/provider ICMP shaping, remote UDP target service congestion, retransmission, and reverse poll scheduling can also cause them. Compare both VPSs' queue wait/overflow counters with real application stalls.

## Release validation

Require passing Rust `--locked` builds/tests, Go unit/race/vet, encrypted raw-ICMP tests, all four Multi-Port policies and continuous mixed UDP/TCP smoke before publishing. The optional 2-hour synthetic soak and a real two-VPS video/game test remain valuable separate evidence, not interchangeable.

## Installation

Download the versioned `Source/install.sh` script from the exact `v3.4.3` tag. The installer verifies checksums and the manifest. For upgrades, retain the current pairing key, matching route policy, and port map on both VPSs.
