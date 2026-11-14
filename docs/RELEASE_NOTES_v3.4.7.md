# MSM-Pingtunnel v3.4.7 — restore pre-Multi-Port protocol and service isolation

## Root cause found in code, not inferred from zero-error dashboards

The operator confirmed v3.4.6's FIFO/UDP worker rollback improved responsiveness, but mixed Multi-Port still performed much worse than pre-Multi-Port v3.3.24.

The source comparison uncovered **two actual post-Multi-Port routing defects** that previous small-payload integration tests did not detect:

1. **Foreign TCP DATA responses were mislabeled as UDP on the wire.** In all four `Go/server.go` reply paths (connect, stream, drain, and UDP), the server passed literal `Tcpmode=0` to `sendICMP`. This was harmless in v3.3.24 because each instance was single-protocol and the receiver knew whether it served TCP or UDP. Starting with Multi-Port v3.4.3, the shared client receiver used `packet.my.Tcpmode==0` to choose its small UDP channel, so **TCP ACK/stream frames and actual UDP/QUIC frames competed in the same 256-frame queue**. The TCP frames could also be silently dropped by the UDP overflow policy instead of preserving TCP retransmission semantics.
2. **All services of one protocol shared one dispatch FIFO.** Original v3.3.24 ran *one protocol per instance* with a dedicated queue (10,000 TCP frames or 256 UDP datagrams). v3.4.6 separated protocol classes but had ONE 10,000-frame TCP queue for all six TCP ports and ONE 256-datagram UDP queue for all six UDP ports. One heavy service could crowd out unrelated ports.

## v3.4.7 changes

- **Correct the actual protocol metadata on Foreign DATA replies:** all four server send paths now serialize the originating connection's `conn.tcpmode`, so actual TCP traffic is tagged as TCP and UDP as UDP. No Wire-v4 layout change.
- **Classify Iran-side DATA by local registered connection ID:** the Iranian client uses its own `ClientConn.tcpmode` and `serviceID`, not an untrusted/historical server-side flag. This remains compatible with the v3.4.6 foreign peer during a staged upgrade.
- **Per-service TCP+UDP dispatch:** each enabled service gets its **own** v3.3.24-sized FIFO, 10,000 entries for TCP or 256 for UDP, and an independent dispatch goroutine. This restores the old single-service separation *inside* the 12-service process. Service queues never evict accepted UDP datagrams; only arriving UDP DATA drops on saturation.
- **Keep independent authenticated control and a SINGLE ICMP reader:** a single raw ICMP socket owns the AEAD/replay/reassembly state, and after authentication dispatches frames to the right private service queue. PING/KICK/rekey controls remain reliable in a separate lane; malformed/unlisted aliases are still rejected under the pinned peer and allowlist policy.
- **Keep v3.4.6 configured Foreign UDP worker count** (normally 100), rather than reverting to v3.4.3's cap of 16. Per-flow hash worker ordering remains unchanged.
- **Live diagnostics:** `pingtunnel security` prints per-service protocol, pending FIFO depth, capacity and admission drops. The original total UDP/TCP overflow counters remain for compatibility.

## A necessary limitation: single shared ICMP path

The physical ICMP socket, secure session and network congestion domain are still common. This release isolates software queueing **per service**, not ICMP bandwidth per physical socket. No amount of queue tuning can guarantee the same link behavior as a truly separate pre-Multi-Port UDP-only process under simultaneous heavy TCP load. The pre-Multi-Port **TCP full-queue 3-second blocking wait is intentionally NOT recreated** inside the shared ICMP reader: it would freeze every UDP port. Instead, an overflowing per-service 10,000-frame TCP admission drops that frame for FrameMgr retransmission, protecting unrelated UDP and control. Under normal non-saturated operation ordering and capacity match the old semantics.

No installed production configuration or VPS is modified by this GitHub release. No quantified Iranian Internet latency improvement has been proven without a real A/B load/playback test.

## Regression tests

- NEW: 12 independent per-service queues with the exact v3.3.24 capacities and FIFO/drop-new policy; saturation of one UDP or TCP service cannot consume another service's queue.
- NEW: reproduction of original v3.4.6 defect: incoming TCP reply marked `Tcpmode=0` is routed as TCP based on registered connection rather than being admitted as UDP.
- NEW: server-side authenticated opaque service target mismatch/incorrect protocol is not routed to another service's queue.
- NEW: one service's blocked TCP handler does not block another TCP service's or any UDP service's queue.
- NEW: source-level AST guard for **all four** Foreign outgoing DATA send calls: `Tcpmode` must be `conn.tcpmode`, never the literal zero.
- Stronger real encrypted ICMP network-namespace smoke: all six UDP services stream concurrently during 12 bulk TCP transfers in **Direct, Auto Direct, Reverse, Auto Reverse**. Existing security, Go/race, Rust locked builds, 12-service, and 60-second mixed soak still mandatory.

### Update and verification

Upgrade **both** VPS peers (back up first); execute `sudo pingtunnel update` and then `sudo pingtunnel health`, `sudo pingtunnel security`, `sudo pingtunnel performance` on both. Check `Isolated pre-Multi-Port service queues` and see per-service queue depths/drops. Compare game/video behavior and these counters with v3.4.6 under similar real traffic. For strictly identical v3.3.24 isolation, use an independently configured single-service (non-Multi-Port) environment; do **not** silently delete the operator's active 12-service configuration.

**Compatibility:** config schema 3, encrypted Wire v4 and the existing service aliases remain unchanged; no plaintext fallback.
