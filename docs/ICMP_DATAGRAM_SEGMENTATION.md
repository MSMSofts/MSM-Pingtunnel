# Encrypted ICMP datagram segmentation (v3.3.10 preview)

**Why:** Real Iran/Foreign VPS counters during Instagram Reels playback showed
`IpFragCreates +8354` on Iran, `IpReasmReqds +8382` on Foreign,
`IcmpOutErrors +308` and `IpOutDiscards +308` on Iran in 60 seconds.
These are HOST-wide counters, not proof that all errors came from Pingtunnel.
Authenticated RTT was ~87–91 ms with low reverse-queue P95; blindly increasing
UDP buffers cannot fix path fragmentation.

## Mechanism

The Go core now serializes the original protobuf `MyMsg` exactly as before.
For plaintext <=1127 bytes, the existing encrypted ICMP wire frame is unchanged.
For larger messages, the sender splits the protobuf plaintext into <=1107-byte
chunks, each with a 20-byte fragment header **inside independently authenticated
PTD4 encryption**. A 1200-byte IPv4 budget includes 20-byte IPv4, 8-byte ICMP,
29-byte session header, 16-byte AEAD tag and fragment plaintext.

The single ICMP receiver decrypts and replay-checks each fragment before
reassembly, accepts out-of-order fragments, and delivers the complete original
protobuf message only after all authenticated chunks arrive. Missing chunks
drop that UDP datagram (no partial application packets). Resource limits:
70 KiB original max, 65 parts, 128 groups, 2 MiB reserved group capacity
and 3-second expiration. A 64-bit random ID separates concurrently transmitted
messages. Reverse-mode authenticated polling receives queued replies for each
fragment (including incomplete ones), preventing a return-ACK starvation loop.

This is not an FEC protocol, does not promise zero packet loss, and does not
alter QUIC/Hysteria/Exclave congestion control. It trades a small amount of
extra AEAD/ICMP overhead for avoiding kernel IPv4 fragmentation of large
UDP datagrams, and deliberately does **not** alter any global sysctl, eth0 MTU
or unrelated VPN configuration.

## Compatibility / Auto Tune

**Upgrade both VPS cores together.** Small packets remain wire-compatible
with v3.3.8/v3.3.9, but older peers cannot decode the new authenticated
fragment plaintext for large frames; mismatched versions cause UDP loss.
Manager and Go core must both report `3.3.10`. Keep direct SSH access
and a tested v3.3.8 rollback installer and pairing-key backup.

Auto Tune retains its independent `udp_buf` and `timeout` tuning. ICMP
segmentation is a built-in 1200-byte budget on BOTH physical regions, including
both UDP directions, and does not depend on whether Auto Tune was used.
The safe Auto Tune preview/explicit `--apply` mechanism is retained.

`pingtunnel security` reports the process-lifetime totals:
- `icmp_fragmented_datagrams`: outgoing original MyMsg split into fragments;
- `icmp_reassembled_datagrams`: incoming messages fully reconstructed;
- `icmp_fragment_drops`: malformed/expired/incomplete assemblies;
- `icmp_write_failures`, `icmp_write_emsgsize`: outgoing kernel errors.

On matched Reels tests, check that outgoing IPv4 `IpFragCreates` falls sharply
for the same workload and application startup/video-stall metrics improve.
Counters from unrelated services can still move. Zero kernel fragment failures
does not prove zero network loss, and tail loss may be due to CDN/QUIC congestion.

## Required validation before production adoption

The GitHub checks cover unit tests, race tests, Go/Rust builds and installer
syntax. This remains a **pre-release** until a live pair is compared against
the v3.3.8 baseline on the SAME mobile client/content and measured for
60-second sample windows with Reels plus long streaming sessions.
Do not assume low RTT alone proves healthy QUIC.
