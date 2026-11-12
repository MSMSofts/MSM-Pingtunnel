# MSM-Pingtunnel v3.4.1 — Explicit Multi-Port ports and Manual Direct UDP regression fix

## What changed

- **No automatic TCP 443.** All twelve editable Wizard suggestions are disabled by default, and the suggested port list no longer includes 443. The operator explicitly selects the TCP and UDP services to enable. The Manager rejects `services add` when Multi-Port has not been configured rather than silently migrating and activating a legacy TCP 443 listener.
- **Fix mixed UDP/TCP queue coupling.** In v3.4.0, mixed Multi-Port used one global ICMP dispatch FIFO (usually the large TCP queue), so latency-sensitive UDP data from video/games could build up behind TCP. v3.4.1 now **classifies authenticated packets after AEAD decryption/reassembly**. UDP application DATA uses the same existing **256-packet** bounded short queue and UDP-only overflow-drop behavior previously used by single-port Manual Direct. TCP and control traffic use the existing **10,000-packet** reliable FIFO, isolated from UDP backlog.
- **Preserve all existing transport tuning.** The queue capacities, overflow rules, TCP frame manager, retransmission and BBR, adaptive performance, ICMP Direct/Reverse state machines, wakeup, FEC, segmentation, encryption, peer recovery and timeouts are not modified. Single-service queue behavior is unchanged.
- Mixed Multi-Port continues to share one authenticated ICMP session for up to 12 TCP/UDP services. Existing service definitions, the Pairing Key, and previously disabled S01/443 settings stay intact on upgrade.

## Validation

- Go regression tests verify that overflowing the 256-packet UDP queue cannot block or drop TCP/control packets, and that the existing single-port queue semantics are unchanged.
- End-to-end Linux network namespaces run 12 mixed TCP/UDP services across four route policies, including Manual Direct, using authenticated raw ICMP.
- Manual Direct CI also sends sustained video-like UDP datagrams on two ports alongside a simultaneous TCP payload stream. The test checks echo delivery and measures p50/p95 RTT on the **isolated CI network**.
- Release CI tests and builds static Go Core and Rust Manager for Linux AMD64/ARM64; versioned artifacts include SHA-256 integrity checks and a matching manifest.

This addresses a demonstrable queue coupling regression but does **not** claim that real-world video/game ping on the Iran–Foreign Internet route has been measured. Test the corrected build on the actual two VPSs.

## Deployment

Install this exact tag on **both** VPSs using the version-pinned `Source/install.sh`. Check `sudo pingtunnel services list` and compare the SHA-256 fingerprints on both peers. The installer does not unilaterally modify any previously configured S01/443; if you disabled it, it remains disabled. If another tunnel owns TCP 443, keep S01 disabled. Configure the Foreign target service on `127.0.0.1:<foreign_port>`, and ensure each Iran ingress port is unoccupied and firewall-accessible.

**Wire v4 and config schema v3 remain unchanged.** No credential migration, auto-tune or unsafe transparent fallback is introduced.
