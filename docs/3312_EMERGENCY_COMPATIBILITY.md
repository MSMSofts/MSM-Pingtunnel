# v3.3.12 emergency transport compatibility hotfix

## Why

An operator reported complete tunnel loss immediately after upgrading to
v3.3.11. Without VPS systemd/packet logs we cannot attribute the entire
outage to one cause, but code review confirmed a serious mixed-version issue:

- v3.3.11 parity modified the **count field in both ordinary PTF4 data
  chunks**, even though they contained the original UDP datagram.
- A v3.3.10 receiver rejects those otherwise valid chunks as malformed.
- During a staggered two-VPS upgrade, a subset of 2-part UDP datagrams
  therefore fails even when both original data chunks arrive.

## v3.3.12 design

**Restore connectivity first.** Segmentation and parity repair are both
disabled by default. Without explicit opt-in, outgoing encrypted packets use
the legacy framing expected by v3.3.8. This also means the original IP
fragmentation on large UDP packets may return. The hotfix is not a promise
to eliminate Reels stalls.

Optional flags (`icmp_segment` and `udp_fec`) exist for *separate* staging
tests, and the Rust manager rejects `udp_fec=true` without
`icmp_segment=true`. Do not turn these flags on on production merely
to experiment. They require paired compatible cores.

For future opt-in, the two original PTF4 chunks remain byte-for-byte intact.
A PTF5 parity chunk is an independent, authenticated *additional* frame.
An older v3.3.10 receiver can still reassemble the two PTF4 chunks and
will ignore the PTF5 repair chunk. Parity generation is bounded at 24/s,
and reassembly remains AEAD-authenticated and capacity-limited.

Auto Tune continues to touch only TCP/UDP socket and timeout preferences;
it must not automatically activate fragmentation/FEC.

## Verification and rollback

Run Rust tests, Go tests and race tests, and complete both architecture
builds. Field validation still requires both server logs and live data
delivery, because successful heartbeat authentication alone cannot prove
UDP/VPN health.

To recover an already disconnected VPN, install the **known-working
v3.3.8** release on both servers over direct SSH first, preserving the
current pairing configuration. Avoid auto-tuning while the link is down.
Test this hotfix on separate VPSs before replacing the restored tunnel.

Never publish or reuse the old v3.3.11 assets for this hotfix; build a
new v3.3.12 versioned manager/core pair and verify its release manifest.
