# UDP/QUIC datagram integrity and tuning (Linux)

## Source changes

On the local Iran UDP ingress, on Foreign target UDP responses, and on
the client SOCKS5 UDP ingress, the Go core now reads into a 65535-byte
datagram buffer. Previously the first path used 10240 bytes and the
Foreign response path used 2000 bytes, so a larger datagram would be
silently truncated and its prefix forwarded as if complete.

All three paths use `ReadMsgUDP` and reject a receive where Linux
reports `MSG_TRUNC`. The process-local
`udpTruncatedDatagrams` counter tracks this condition. This avoids
delivering a corrupt partial QUIC/UDP datagram. It does NOT prevent
packet loss in the network or restore a datagram already dropped by the
kernel. A full-size buffer is used per active UDP receive loop (memory
cost: roughly 64 KiB per flow on the Foreign endpoint).

## Existing transport behavior preserved

- UDP is connectionless and does not use TCP ACK/retransmission windows.
- Existing authenticated Wire v4 and reverse adaptive polling remain
  unchanged; no fixed send rate or artificial per-packet sleep is added.
- Optional ICMP segmentation (1200-byte IPv4 packet budget) and bounded
  XOR parity for two-fragment datagrams remain opt-in and disabled by
  default. Enable them only on a mutually compatible, measured pair.
- An optional `udp_buf` socket queue preference is applied only when
  configured; the Linux kernel may cap the actual queue size. Existing
  configuration is preserved.

## Validation gates

The pinned-upstream overlay CI runs the complete Go test suite and race
detector. Unit tests send a 32.5-KiB real loopback UDP datagram and
verify exact bytes, then verify the Linux MSG_TRUNC signal on an
intentionally undersized receive buffer.

Before promoting a release, compare at least 60-second sustained
bidirectional Hysteria 2 / QUIC flows on both VPSs using the *same*
workload, first with the current stable version and then with the patch.
Measure useful throughput, end-to-end loss, QUIC retransmissions,
application jitter, p50/p95 latency, CPU and RSS. Test both regular
and reverse ICMP paths, idle recovery, queue pressure and low-MTU
segments. Systemd healthy alone is NOT evidence of successful UDP.
No production claims or automatic rollout are made by this code patch.
