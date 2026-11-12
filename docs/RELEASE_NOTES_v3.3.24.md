# MSM-Pingtunnel v3.3.24 — Hardened authentication and lower-contention transport

**Release status:** intended stable release, subject to the versioned GitHub CI and release artifact checks.

v3.3.24 combines the production security hardening in PR #47 with the AEAD concurrency and real Linux netem fault-injection work in PR #48. The authenticated **Wire v4**, persistent **config schema 3**, 256-bit pairing key, Direct/Reverse routing choices, on-wire packet format, and default congestion/polling policy are unchanged.

## Changes

### Security and operational correctness

- Production Go core is **fail-closed** for missing, disabled or legacy encryption even if the executable is run outside the Rust manager. Only authenticated `-encrypt auto` may start the production binary; no silent plaintext fallback.
- Optional Go pprof server listens on `127.0.0.1` rather than all interfaces.
- `pingtunnel health` remains a **local process/heartbeat** check and explicitly warns that this is not proof of a usable peer data path.
- New `pingtunnel health --peer` also requires authenticated peer traffic no older than 35 seconds. An intentionally idle link may fail this strict diagnostic; do not attach it unconditionally to a restart watchdog.
- Oversized Reverse encrypted frames rejected by the 10,240-byte FIFO limit are now counted in `reverse_queue_drops` and `reverse_oversized_drops`, and displayed in `pingtunnel security`.
- Additional security diagnostics expose UDP dispatch overflow drops and receive-buffer truncation.
- The installer continues to validate matching version, config schema, Wire version, SHA256 asset digests and release manifest, preserves existing pairing configuration, and rolls back locally on installation failure.

### UDP/QUIC transport performance

- Wire-v4 encryption now reserves unique sequence numbers under a short mutex, then performs AES-GCM / XChaCha20-Poly1305 `Seal` **outside the shared session lock**.
- Decryption similarly performs `Open` without holding the shared lock, then rechecks active session identity and atomically validates the fixed 1024-packet replay window. Old-session frames are refused after a rekey.
- Multiple simultaneous flows can do AEAD work without serializing the expensive cipher operation on the session-wide mutex.
- New 8-goroutine, 480-packet concurrent auth/replay regression test and parallel 512-byte AEAD microbenchmark.
- No speculative changes to the default ICMP polling interval, route grace, fragment size or FEC settings.

### Linux network-path resilience testing

The CI smoke now exercises the actual Linux raw-ICMP Go binary inside **two isolated network namespaces** with an authenticated Wire-v4 UDP echo. It tests both manual Direct and AUTO Direct-first, and adds explicit manual Reverse / AUTO Reverse-first coverage in the v3.3.24 candidate.

Fault injection via `tc netem` adds **25ms ±9ms egress delay, 4% packet loss and 2% reordering on each side**, followed by a 100% **Iran-side-only egress blackhole** and restoration of the impaired link. Unique per-phase UDP probes must be rejected during the blackhole and recover after restoration **without restarting the Go workers**.

The already-passed phase-2 isolated CI run (before Reverse was added) recorded:

| Policy | Impaired UDP echoes | After restoring one-way outage | Recovered p95 RTT |
| --- | --- | --- | --- |
| Manual Direct | 28 / 32 | 28 / 32 | 61.7 ms |
| AUTO Direct-first | 29 / 32 | 30 / 32 | 63.0 ms |

These numbers are **from ephemeral CI network namespaces only**, not real VPS or Internet/game latency. The benchmark on that CI runner was 442.9 ns/op at 512 bytes, 624 B/op, 3 allocs/op; there is **no controlled baseline speedup measurement**.

## Supported modes

- AUTO Reverse-first: prefer Reverse and fail over to Direct only after confirmed failure; return on authenticated recovery proof.
- AUTO Direct-first: prefer Direct and fail over to Reverse after confirmed failure; return on authenticated recovery proof.
- Manual Direct or Manual Reverse: stay fixed and **never** switch directions automatically.

Both VPS peers must have the **same route policy**, matching pairing key, compatible protocol settings, and the matching released manager/Go core.

## Installation / upgrade

Back up both peers' pairing config securely and schedule the upgrade for both VPSs. The release installer downloads and verifies paired AMD64/ARM64 Linux binaries from the **version-pinned tag**:

```bash
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/v3.3.24/Source/install.sh -o /tmp/pingtunnel-install.sh
sudo bash /tmp/pingtunnel-install.sh
sudo pingtunnel health
sudo pingtunnel security
# During authenticated activity:
sudo pingtunnel health --peer
```

When a brand-new installation needs pairing, set up the overseas (Foreign) VPS first and the Iran VPS second, transferring the pairing key securely. Avoid recreating the key on an upgrade.

## Verification and limitations

- Automated Go tests, race detector, Rust tests, Linux AMD64/ARM64 builds and namespace-based ICMP smoke run in GitHub Actions. Versioned release assets should include four binaries, SHA256 sidecars and `release-manifest.txt`.
- Source-level failover tests cover authenticated Reverse→Direct→Reverse and both AUTO policies. **CI is not a substitute for a multi-minute real two-VPS one-way outage test or a two-hour mixed TCP/UDP soak.**
- A 100% blackhole cannot be defeated while no physical ICMP route is reachable; short recovery checks intentionally exercise restoration without waiting for the 90–150-second AUTO grace.
- Custom cryptographic transport has **not undergone a published independent security audit**. Outer ICMP traffic remains observable, and networks may drop, shape or block ICMP.
- In very large UDP datagrams, the bounded Reverse queue can still reject frames if optional interoperable segmentation is not enabled; the new metric makes this loss visible.

## نسخه فارسی خلاصه

در v3.3.24، اجرای بدون رمزنگاری هسته Go مسدود شده، سرویس عیب‌یابی به Loopback محدود است، بررسی سخت‌گیرانهٔ احراز هویت همتا و شمارندهٔ افت بسته‌ها اضافه شده و رمزنگاری AEAD هم‌زمان برای کاهش انتظار روی قفل بهینه شده است. تست‌های واقعی ICMP با تزریق افت بسته، نوسان، تغییر ترتیب و قطع یک‌طرفه در CI انجام می‌شوند. **نسخه روی سرورهای واقعی شما نصب نشده است**؛ دو طرف را با هماهنگی و داشتن نسخهٔ پشتیبان ارتقا دهید.
