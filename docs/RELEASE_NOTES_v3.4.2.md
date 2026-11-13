# MSM-Pingtunnel v3.4.2 — Mixed-load latency and release hardening

## Safety and latency
- Mixed TCP/UDP retains the existing 10,000-entry TCP queue and 256-entry UDP queue.
- When the mixed TCP DATA queue is **fully saturated**, admission waits for no more than 2ms, then drops the newest TCP frame and increments `tcp_dispatch_overflow_drops` instead of blocking the sole ICMP receiver for three seconds. TCP's existing reliable FrameMgr must retransmit missing frames. Single-port behavior is unchanged. UDP frames retain their existing bounded nonblocking drop policy.
- Authenticated control traffic can bypass a saturated TCP queue via the separate UDP dispatch queue; no new unauthenticated control path is added.
- Added regression tests for saturated TCP, live UDP and control admission, and ordinary burst behavior. Record both TCP and UDP overload counters and keep them at zero during normal operation.

## Verified and bounded Reverse-first recovery
- For a genuinely active application with at least 60s of sustained demand and missing authenticated return traffic, two independent nonce-matched root-HMACed Direct path proofs permit a **verified fast fallback at 60 seconds**.
- The Direct probe cadence temporarily increases to one per 10 seconds only while user activity is fresh and authenticated traffic has been stale for at least 25 seconds; probes remain authenticated and rate-limited.
- Mere ICMP ping, an idle TCP connection, transient RTT spikes and unverified reachability cannot invoke the fast path. If proof is absent, the original conservative 90–150s gates remain. Emergency recovery still rekeys the Wire-v4 session.
- No premature healthy-route rotation; the four manual/auto policies remain unchanged.

## Update security
- The Rust manager selects the latest **published stable** GitHub release, validates its numeric semantic tag and resolves the tag to a concrete immutable Git commit, including annotated tags.
- It downloads and executes the installer from that exact commit, **never mutable `main`**. The installer still verifies matching binaries, hashes and the release manifest; rollback on process-health failure remains.
- The legacy `Source/update.sh` delegates to the manager's verified updater.

## CI and observability
- Changes under `Upstream/**` and network-smoke scripts now trigger CI.
- Go dependency verification, `go vet`, uncached unit tests and race tests are included.
- The CI-resolved `Rust/Cargo.lock` is committed and all Rust tests/releases use `--locked`.
- A separate opt-in sustained Linux namespace soak is provided; this does NOT substitute for real Iran/Foreign VPS gaming, latency or provider measurements.

## CI acceptance (13 November 2026)
- [GitHub Actions run 43441487148](https://github.com/MSMSofts/MSM-Pingtunnel/actions/runs/43441487148) passed Rust locked tests and amd64/arm64 builds; Go static build, unit tests, race verification and Linux namespace ICMP integration.
- Manual Direct, AUTO Direct-first, Manual Reverse and AUTO Reverse-first each passed mixed 12-service TCP/UDP network trials. The 60-second continuous mixed workload completed 295 cycles and 1,180 successful application probes.
- A separately defined scheduled/on-demand namespace soak allows up to 7,200 seconds of continuous testing; **that long-duration check and real Iran/Foreign field performance have not yet been established**. A successful synthetic run is not a guarantee against hour-long game latency spikes.

## Compatibility and validation
Config schema **3** and authenticated Wire **4** are unchanged. Match the same release on both VPSs, preserve pairing keys, verify service-profile fingerprints, and measure real user traffic before assuming a performance improvement. A queue overflow is an overload signal, not a throughput guarantee. Only the dual-verified 60-second failure path is accelerated; otherwise fail-closed conservative timeouts remain. Direct/Reverse route policies, encryption, FEC, segmentation, BBR and TCP settings otherwise remain unchanged.

**Release condition:** do not publish or merge without successful Rust/Go CI (including raw ICMP namespace tests), the reproducible Cargo lockfile, and a coordinated deployment plan.
