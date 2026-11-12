# MSM-Pingtunnel v3.4.0 — Mixed TCP/UDP Multi-Port

**Release target:** v3.4.0. The workflow publishes the Stable tag only after merge and successful CI.

## Multi-Port

- Up to 12 mixed TCP/UDP service mappings, each with S01–S12 identity, Iran ingress port, Foreign loopback target and enabled state.
- Wizard with 12 editable suggestions and a safe opt-in path for existing single-port configurations.
- Main-menu option 16 and `pingtunnel services` commands: list, add, edit, remove, enable, disable, check, export and import.
- Service-only profile transfer; Pairing Keys are never exported.
- Foreign validates authenticated service aliases against its allowlist and forwards only to `127.0.0.1`.
- Existing single-service configurations remain supported.

## Compatibility and performance safety

- Keep config schema 3 and authenticated Wire v4. The service ID uses the existing authenticated `MyMsg.Target` field as an opaque alias.
- Preserve the existing `transport` selector as the dispatcher/queue profile.
- Do not change queue capacities, enqueue/overflow/drop behavior, Reverse FIFO, Queue Hint, Backlog Wake, Smart Rotation, adaptive pacing, TCP framing, congestion control, timeouts, recovery, FEC or ICMP segmentation.
- Mixed listeners share the existing ICMP session and global dispatcher policy. No per-service queue tuning or hot-reload is introduced.
- Service edits are atomically saved and applied with a controlled systemd restart.

## Operator guidance

Configure Foreign first; run target applications on `127.0.0.1:<foreign_port>`. Import the same Service Profile on Iran and allow matching TCP/UDP ingress ports. Do not expose Foreign target ports publicly. Check port conflicts and validate the profile on both peers.

## Validation scope

The PR CI passed on 2026-11-12: Rust tests, Go unit/race tests, AMD64/ARM64 builds and existing Direct/Reverse fault-injection checks all succeeded ([workflow run](https://github.com/MSMSofts/MSM-Pingtunnel/actions/runs/43215426916)). This does not replace a real 12-port soak test across two production VPSs. Stage the change with a small number of TCP and UDP services before enabling all 12.
