# MSM-Pingtunnel v3.4.2 — Mixed-load latency and release hardening

## Safety and latency
- Mixed TCP/UDP retains the existing 10,000-entry TCP queue and 256-entry UDP queue.
- When the mixed TCP DATA queue is **fully saturated**, admission waits for no more than 2ms, then drops the newest TCP frame and increments `tcp_dispatch_overflow_drops` instead of blocking the sole ICMP receiver for three seconds. TCP's existing reliable FrameMgr must retransmit missing frames. Single-port behavior is unchanged. UDP frames retain their existing bounded nonblocking drop policy.
- Authenticated control traffic can bypass a saturated TCP queue via the separate UDP dispatch queue; no new unauthenticated control path is added.
- Added regression tests for saturated TCP, live UDP and control admission, and ordinary burst behavior. Record both TCP and UDP overload counters and keep them at zero during normal operation.

## Update security
- The Rust manager selects the latest **published stable** GitHub release, validates its numeric semantic tag and resolves the tag to a concrete immutable Git commit, including annotated tags.
- It downloads and executes the installer from that exact commit, **never mutable `main`**. The installer still verifies matching binaries, hashes and the release manifest; rollback on process-health failure remains.
- The legacy `Source/update.sh` delegates to the manager's verified updater.

## CI and observability
- Changes under `Upstream/**` and network-smoke scripts now trigger CI.
- Go dependency verification, `go vet`, uncached unit tests and race tests are included.
- Rust dependency lockfile generation is captured in CI so that the lock can be committed and `--locked` enforced.
- A separate opt-in sustained Linux namespace soak is provided; this does NOT substitute for real Iran/Foreign VPS gaming, latency or provider measurements.

## Compatibility and validation
Config schema **3** and authenticated Wire **4** are unchanged. Match the same release on both VPSs, preserve pairing keys, verify service-profile fingerprints, and measure real user traffic before assuming a performance improvement. A queue overflow is an overload signal, not a throughput guarantee. No automatic route timeouts are shortened: they remain fail-closed pending real two-peer evidence. Direct/Reverse route policies, encryption, FEC, segmentation, BBR and TCP settings otherwise remain unchanged.

**Release condition:** do not publish or merge without successful Rust/Go CI (including raw ICMP namespace tests), a committed reproducible Cargo lockfile, and a coordinated deployment plan.
