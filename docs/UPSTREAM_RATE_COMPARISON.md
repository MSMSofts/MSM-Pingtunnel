# PingTunnel upstream traffic-rate comparison (code review)

Reference: `esrrhs/pingtunnel`, `client.go`, `server.go`, `fairbb.go` and `USAGE.md`, reviewed 2026-11-02.

- **There is no universal fixed upstream data rate.** TCP uses a reliable `FrameMgr` with an 888-byte frame payload bound, an ACK-driven sliding window and retransmission scheduling. `-tcp_mw=20000`, `-tcp_bs=1048576`, and `-tcp_rst=400` are upstream defaults; they are *not* packets-per-second caps. The upstream TCP loops are activity-driven (adaptive waits on idle), rather than sending one packet per fixed time slot.
- UDP sends on datagram arrival and does not gain TCP `FrameMgr` reliability; successful local ICMP writes are not evidence of remote reception.
- In our fork, Reverse mode has an independent, demand-sensitive Echo Request poller, nominally 1 Hz idle, ~40 Hz while connections are open, and up to 125 Hz during short authenticated bursts (8 ms period). These requests are *not* synonymous with useful payload packets or achieved throughput.
- Adding unconditional high-frequency polls would increase ICMP overhead and may worsen loss. Do not confuse the displayed userspace packet counters with router- or kernel-level ICMP counts.
- **Change in this branch:** adopt the newer upstream loss-recovering BB controller on both TCP endpoints. If an entire ACK update interval is lost, its previous in-flight counter no longer blocks retransmission forever. An explicit recovery probe floor keeps the sender conservative. Existing Wire v4 AEAD, pairing, route direction, UDP forwarding, and poll timing remain unchanged.
- The benefit is **TCP stall recovery**, not a guaranteed latency or throughput improvement; a production claim requires loss/RTT/throughput measurements on both peers, in Direct and Reverse modes, with representative TCP and UDP workloads.
- Test with `go test ./...` and `go test -race ./...` in the pinned-upstream overlay constructed by the GitHub Actions workflow. Capture 60-second p50/p95 RTT, jitter, throughput, retransmissions and real ICMP loss before updating the two live VPSs. No production service or cryptographic keys are changed by this source patch.

Deployment caution: this source branch is not a versioned release asset. Do not run the current installer expecting this patch until a matching two-architecture Go core and manager release passes CI.
