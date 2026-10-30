# UDP single-fragment loss recovery (v3.3.11 preview)

## Motivation and limitations

After the v3.3.10 ICMP segmentation change, a large UDP datagram is carried in
two separately authenticated ICMP packets. If just one packet is lost, that UDP
datagram cannot be delivered, even though kernel IP fragmentation was avoided.
Short video feeds such as Instagram Reels may stall when QUIC must recover
lost application datagrams. This is a *hypothesis*, not yet measured on
the user's Android Exclave/VPS pair.

## Rate-limited single-erasure parity

For two-fragment **UDP DATA** messages only, the sender may add a third
fragment containing XOR parity. The two data chunks and the parity chunk are
encrypted separately with the existing ephemeral AEAD and replay protection.
The receiver can reconstruct the *exact original protobuf message* from any
two of the three fragments; if too few arrive, no UDP datagram is delivered.

Parity uses the existing 20-byte authenticated fragment header, with the high
bit of the 16-bit count as a feature flag and index 2 for the parity frame.
The third chunk is at most 1107 bytes. The external ICMP/IPv4 packet limit
remains **1200 bytes**, including IP, ICMP, AEAD, and fragment headers.

A simple per-core cap permits at most **24 parity frames per second**. The
entire repair feature is **never** used for TCP or a fragmented message that
requires 3+ chunks. The cap is deliberate to limit extra bytes and ICMP
traffic; it is not a dynamic estimate of actual UDP loss or QUIC health. If
underlying ICMP is rate-limited, even this limited repair traffic may hurt
video performance. No throughput or stall reduction is guaranteed.

Receiver controls: 3-second fragment TTL, 2 MiB total reservation, 128
groups, 70 KiB original upper bound, 256 completed IDs kept for at most 3
seconds to suppress late parity/duplicates. Invalid fragments are discarded
and must already have passed authenticated AEAD validation before consuming
reassembly memory.

## Auto Tune and operational diagnostics

Auto Tune remains a preview by default and can explicitly apply **socket
buffer** preferences. Neither TCP nor UDP socket buffer sizes control ICMP
segment/repair framing, and this extension needs no Auto Tune run.

New `pingtunnel security` counters:
- `icmp_fec_parity_generated`: number of repair fragments constructed;
- `icmp_fec_recovered_datagrams`: original messages reconstructed after
  precisely one missing data fragment.

Also compare `icmp_fragment_drops`, `icmp_write_failures`,
`icmp_write_emsgsize`, kernel IP fragment counters and actual Reels stalls.
These are per-process counters and don't directly measure network loss.

## Rollout gate

v3.3.10 receivers do NOT understand the FEC flag for two-part messages.
**Upgrade both Iran and Foreign Go cores to v3.3.11 together**, keeping direct
SSH and a v3.3.10/v3.3.8 rollback. If deploying to a working VPN is risky,
evaluate on a disposable two-VPS pair first. A mixed 3.3.10/3.3.11
deployment will drop some large UDP datagrams.

Production promotion requires paired-VPS A/B tests demonstrating that repair
improves Reels stall frequency/duration without increasing ICMP send errors,
drops, RTT tails or limiting throughput. CI tests alone do not establish that.
