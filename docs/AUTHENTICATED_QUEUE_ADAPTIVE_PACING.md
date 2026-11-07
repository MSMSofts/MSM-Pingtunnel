# Authenticated queue-aware Reverse ICMP pacing (v3.3.21 preview)

## Why fixed intervals were insufficient

The upstream `esrrhs/pingtunnel` Direct UDP path forwards an application
datagram immediately. In Reverse mode, Iran must send each DATA fragment as
an Echo Reply paired with Foreign's Echo Request. This introduces an
opportunity-queue that does not exist in the original Direct sender.

Before v3.3.21, Foreign estimated demand from the local target-connection
count, signed PTW4 wakeups and recent authenticated DATA bursts, but did
**not** know Iran's FIFO depth or age. Every valid PTW4 wake activated the
same 8 ms / 125 polls/s burst even for one short UDP packet. No telemetry
from the actual Iranian pending queue influenced the rate.

## Signed queue observation: PTQ4

When **real encrypted application DATA** waits in Iran's 256-frame / 2 MiB
Reverse FIFO, Iran sends a single 44-byte `PTQ4` ICMP Echo Request (no user
payload). Its MAC-covered fields are:

- 4-byte `PTQ4` identifier, 8-byte UTC seconds, 8-byte crypto-random nonce;
- 8-byte encrypted/masked metadata containing FIFO depth, oldest local
  queue wait in milliseconds, and pending bytes;
- 16-byte truncated root-key HMAC-SHA256 authenticator.

The 8-byte metadata is concealed with a distinct HMAC-derived pad keyed
by the root pairing secret and nonce; passive observers cannot read queue
age or depth from the packet. The receiver verifies HMAC *before* unmasking.
It authenticates the pinned peer IP first, enforces the 20-second clock
window, rejects duplicates with a bounded replay map, caps incoming hints
to approximately two accepted messages per second and rejects impossible
queue sizes. PTQ4 cannot change path, select Direct, validate an encrypted
session or count as a two-way Reverse switch proof.

`PTW4` legacy wake validation remains implemented. Older peers will ignore
new PTQ4 queue hints, so **upgrade both VPS endpoints together**; application
Wire v4 and schema 3 do not change.

## Deterministic smart controller (no hidden learned model)

The foreign poller reads a *fresh authenticated* PTQ4 sample for at most
1.2 seconds, and combines it with existing indicators of genuine DATA,
active application sessions and foreign-to-Iran traffic:

| Authentic pending queue observation | Target probe interval | Upper bound (polls/s) |
|---|---:|---:|
| New queue sample, first 120 ms | 8 ms | 125 |
| 1 waiting packet; oldest wait below 20 ms | 16 ms | 62.5 |
| At least 2 packets, or 20 ms oldest | 12 ms | 83.3 |
| At least 6 packets, or 40 ms oldest | 10 ms | 100 |
| At least 16 packets, or 80 ms oldest | 8 ms | 125 |
| Stale/empty queue | Existing demand-adaptive rates | Existing bounds |
| Recent local ICMP socket write failures | No faster than 25 ms for 3 seconds | 40 |

The poll interval is the minimum of base traffic-driven interval and
queue-based target: real heavy downstream data retains its existing
adaptive polling behavior. An empty or expired signal does **not** force
permanent high-rate polling. Receiving authenticated Iran DATA decrements
the remote queue estimate, preventing unnecessary requests after progress.
A once-per-second, demand-gated client maintenance hint prevents isolated
queued packets from remaining undiscovered if no new UDP data arrives.
A local ICMP write error can temporarily reduce poll pressure, but will
not force Direct or reset session keys.

These are starting **bounded control-policy thresholds**, not promises
about packet delivery time, gamer ping or ISP ICMP acceptance. In
particular, 125 polls/s is an upper rate for poll opportunities, not
a guarantee of 125 returned application datagrams/s.

## Existing safety invariants

- AUTO remains Reverse-first; sustained Reverse failure is the only
  reason to fall back to Direct. Authentic return-path proofs control
  Direct-to-Reverse restoration. PTQ4 cannot affect these decisions.
- Direct UDP and TCP forwarders remain unchanged.
- No UDP retransmission, additional FEC, MTU increase, or raw ICMP flood.
- Existing fixed anti-replay 1,024-bit window and queue TTL remain in force.
- Older PTW4 behavior is accepted for staged receiver compatibility.
- PTQ4 leaks neither pairing keys nor packet payloads, but has a distinct
  ICMP payload signature; it is not traffic-analysis invisible.

## Check on BOTH VPSs

After backing up pairing keys and config and installing both endpoints:

```bash
sudo pingtunnel health
sudo pingtunnel security
```

Monitor `reverse_queue_hints_received`, `reverse_remote_queue_hint_depth`,
`reverse_remote_queue_hint_oldest_ms`, `reverse_remote_queue_hint_age_ms`,
`reverse_poll_interval_ms`, `reverse_poll_backoff_remaining_ms`,
`reverse_queue_drops` and `icmp_write_failures`. On Iran,
`reverse_oldest_queue_age_ms` and `reverse_p95_delivery_delay_ms`
are **locally measured** queue latency. On Foreign, queue statistics are
authenticated, delayed reports, not independently measured RTT.

During a one- to two-hour COD session compare gameplay p50/p95/p99 latency,
packet loss and the rate of short stalls against v3.3.20 using the same
network and route. Streaming should continue to work without persistent
excess polling. If the new version is worse, restore the prior v3.3.20
release binaries. No live VPS testing has been performed by CI.
