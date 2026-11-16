# MSM-Pingtunnel v3.4.8 — Reverse egress fairness and worker-lifecycle hardening

## What is fixed
- The Multi-Port ingress queues remain per-service (TCP 10,000 frames; UDP 256 datagrams), as repaired in v3.4.7. **Reverse egress**, previously a single undifferentiated 256-frame/2-MiB FIFO, now uses authenticated local protocol/service classification. A bulk TCP frame cannot displace queued UDP or encrypted control.
- One shared, bounded Reverse egress queue is still used; it is **logically class-aware**, not a separate physical link or independent kernel socket. Encrypted control is selected first; under simultaneous UDP and TCP backlog, the scheduler grants at most four consecutive UDP DATA sends before one TCP DATA send. A round-robin opportunity across active service IDs retains FIFO order within each service. Under all-UDP or all-TCP load, that class uses the entire available link.
- An overflowing incoming TCP frame can evict only older TCP; an incoming UDP frame can displace older TCP or UDP, never control. A control frame can displace data. Rejected, expired, or evicted frames are counted by class. Failed socket writes restore the same ciphertext to the head with its original age/class (bounded by the existing 12-second TTL). The serialized AEAD nonce and original network frame are not rewritten.
- Protocol and service metadata are retained across authenticated segmentation and queued DATA during X25519 rekey. Wire v4, config schema 3, pairing, replay protection, Direct/Reverse route selection, and existing destination allowlists are unchanged.
- Client and server dynamically accepted worker registration is guarded by the same mutex used when entering shutdown, preventing late positive WaitGroup.Add operations from racing with Wait. No new accepting worker registers after shutdown.
- The DATA send helper reports accepted queued packets or successful ICMP writes; application send counters no longer increment on a known send failure. A local write or queue admission does **not** prove that the far-end application received the data.

## Diagnostics
`pingtunnel security` exposes `reverse_pending_tcp`, `reverse_pending_udp`, `reverse_pending_control`, class-specific `reverse_priority_*_drops`, and `reverse_scheduled_*` counters. The existing aggregate Reverse drops, queue delay and physical ICMP write failure counters are kept. Class-specific scheduled counts represent dequeues; the existing delivery metrics only increase on successful Echo Reply socket writes.

## Tests and limits
- New unit regressions cover UDP/control preservation under bulk TCP, 4:1 fairness, cross-service ordering, bounded memory/TTL, failed-write restoration and concurrent worker registration/shutdown.
- Mixed 12-service CI now enforces at least ~95% UDP packet delivery and p95 <=250ms, p99 <=500ms, max <=1000ms for a 90-packet per-service synthetic check. The old threshold allowed 25% loss and p95 800ms.
- CI still exercises Go/race/vet on AMD64 and ARM64, Rust locked builds, encrypted Linux namespace Direct/Reverse modes and short mixed soak. These are **local isolated-network tests**. They do not prove lower latency on the Iranian Internet, high sustained two-VPS throughput, video smoothness, or zero stalls under ISP ICMP filtering.
- TCP retains the pre-existing 8-KiB fair ICMP send quantum; UDP and control bypass it. Queue prioritization cannot create bandwidth or more Reverse Echo-Reply opportunities. The fast-poll floor remains 8ms; do not treat it as unlimited bandwidth.

## Update / rollback
Back up both VPSs before updating. Upgrade **both peers** via the manager's verified `sudo pingtunnel update`, and compare `pingtunnel security`, `performance`, and application UDP echo RTT / drops at equivalent loads. The pinned release artifacts and manifest must match v3.4.8. For rollback, use the verified tagged v3.4.7 release and preserved config; never silently downgrade the 12-service config or disable encryption.

No VPS is modified by publication, and no unmeasured production performance improvement is claimed.
