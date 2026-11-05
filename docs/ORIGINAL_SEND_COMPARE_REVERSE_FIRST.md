# PingTunnel upstream vs MSM transport and Reverse-first AUTO (v3.3.20)

## Audited source trees

- Original reference: `Upstream/pingtunnel-df16/` (verbatim source from
  historical `esrrhs/pingtunnel` commit `df16e52771ee67f1f9770ec68763b425672a36fc`).
- Modified core: `Go/`, overlaid onto that pinned source during GitHub Actions.
- Package/protocol: `Wire v4`, `config_schema=3`, authenticated X25519
  ephemeral session and AEAD. No sharing/pairing-key, port, or JSON changes.

| Behavior | Original PingTunnel | MSM-Pingtunnel v3.3.20 |
|---|---|---|
| Direct local UDP receive | `ReadFromUDP`, max 10,240 bytes; call `sendICMP` for every datagram | `ReadMsgUDP`, max 65,535 bytes and `MSG_TRUNC` check; forward immediately, encrypt before ICMP |
| Direct foreign UDP response | `ReadFromUDP`, 2,000-byte buffer; send ICMP immediately using last inbound Echo ID/Seq | `ReadMsgUDP`, full-size buffer; preserve last Iranian Echo ID/Seq in Direct to match the request |
| Reverse foreign UDP response | No reverse role in original | Foreign **owns the Echo Request**: send immediately with its **own fresh sequence per DATA**; previous fork reused the last Iran Echo reply sequence for multiple packets |
| Reverse Iran UDP uplink | Not present | Encrypt, enqueue bounded FIFO (256 frames / 2 MiB, 12s TTL), transmit at next Foreign-owned Echo Request. This cannot be made fully equivalent to Direct for return packets because ICMP Echo Reply needs a matching request |
| Reverse early wake | Not present | HMACed `PTW4` wake only when **real application DATA** was queued; keepalive Ping or Kick do not trigger high-rate polls |
| UDP reliability | Datagrams, no implicit TCP retransmission | Datagrams, no hidden TCP-style retransmits; optional existing segmentation/FEC retained but not switched on silently |
| TCP delivery | FrameMgr with send window/ACK and BB controller | Same framing, with upstream loss-recovery BB fix from v3.3.18; independent from UDP queue and route controller |

There is **no single mandatory send rate** for application DATA: the socket
and ICMP send calls are driven by datagram arrivals. Reverse **control poll
frequency**, however, is constrained by who can legally send Echo Requests.
The existing authenticated poller uses about 1 Hz when idle, ~40 Hz with
an established connection, and a bounded 125 Hz burst on actual traffic.
These are *poll opportunities*, not application-packet throughput claims;
outbound Foreign DATA requests can themselves provide opportunities
for Iran Echo Replies.

## AUTO state machine

```text
                          normal startup
                                |
                                v
                   REVERSE (always preferred)
                     |    ^            |
     verified sustained failure |      | healthy Reverse
     plus user demand     |      |      | never timer-rotates
                     v    |      |
                  DIRECT FALLBACK
                     |
           PTR4 signed Echo Requests
                   every 10s
                     |
         2 separate matched PRA4 replies
          (root-HMAC + nonce + ID/Seq)
                     |
            >=60s minimum dwell
                     |
             PTS4 switch challenge
              /       |       \
      PTA4 HMAC ACK  retry 2s    fail
              |      up to 30s   |
              v                  |
      REVERSE restored      remain DIRECT,
       same AEAD keys       retry probing 10s
```

- AUTO starts Reverse, never rotates a healthy Reverse session to Direct
  after three hours or any other arbitrary time. Signed Direct health
  checks are observational while Reverse works.
- Iran switches to Direct after sustained Reverse failure and local
  application demand; depending on the condition, existing grace periods
  are 90–150s. This is deliberately not a zero-evidence, single-ping
  failover. The existing Direct X25519 handshake remains authenticated.
- Foreign keeps testing preferred Reverse while healthy Direct carries
  traffic: a signed PTR4 poll alone is insufficient. Iran must return
  a distinct PRA4 response that matches a live Foreign-issued
  challenge, Echo ID and sequence. Two independent proofs are required,
  separated by the already bounded reply policy.
- Foreign starts PTS4 only after those proofs and 60-second stabilization,
  retries while awaiting signed PTA4 acknowledgment at 2-second
  intervals, and resets to 10-second checks if the attempt fails.
  The attempted Return is **independent of Direct outage or demand**.
- The successful handoff preserves the active Wire v4 session keys and
  anti-replay window. Stale/replayed/forged proofs and unmatched ACKs do
  not authorize a switch. Startup and explicit manual `icmp_direction`
  settings (direct-only / reverse-only) remain available.

## New operational evidence

`pingtunnel security` reports `auto_route_policy`,
`auto_reverse_proof_confirmations`, `auto_reverse_last_proof_age_ms`,
`auto_pending_reverse_handoff`, and
`auto_preferred_reverse_returns`, in addition to the legacy
`auto_direct_fallback_count` / reason. A zero-valued
`smart_rotation_interval_seconds` signals disabled timer rotation.

## Constraints and validation

- A true bidirectional, authenticated return proof is necessary, but a
  test reply is *not* a guarantee that an arbitrary sized QUIC packet
  will succeed. Check real application performance on both VPSs.
- A 60-second dwell and two ~10s proofs prevent rapid flapping; if a
  network middlebox occasionally permits only small ICMP replies,
  a signed control proof can pass while application DATA still suffers.
  Compare packet loss, application RTT/jitter and queue counters.
- No background rollout to live VPSs was performed. Upgrade both ends
  together and keep the v3.3.19 binaries as rollback. Capture a two-hour
  game with `Source/long_session_probe.py` before claiming resolution.
