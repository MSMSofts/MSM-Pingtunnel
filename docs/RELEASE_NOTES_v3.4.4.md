# MSM-Pingtunnel v3.4.4 — Direct ICMP kernel Echo reflection diagnostics

## Why the Iran-side error counter could be high

In Manual Direct, **Iran sends encrypted ICMP Echo Requests**. Linux on the overseas peer can emit a conventional kernel-generated Echo Reply containing the **unchanged outgoing ciphertext**, while MSM-Pingtunnel userspace separately sends a legitimate response using the opposite session's receive-direction keys. v3.4.3 filtered exact self-Echo reflections only when **Foreign initiated Reverse**, not when **Iran initiated Direct**. Consequently, the Iran receiver may attempt to decrypt its own outgoing ciphertext using its receive-direction AEAD key and count an authentication failure. The characteristic operator report was many Iran-side auth failures with an authenticated healthy session and zero failures on Foreign.

This is a **supported, code-confirmed missing Direct filter**, but not proof that all previously observed failures were reflections or that this caused all 1–3-second Instagram stalls. Authentication failures are cumulative; timestamped deltas and actual network-path tests must determine the contribution.

## Fix and diagnostics

- Track every successfully dispatched encrypted Echo Request originating from Iran in Direct (as Foreign already did for Reverse). Stage the full-ciphertext SHA-256 digest plus ICMP ID/sequence **before** socket write, and cancel on a failed socket write. The existing cache is bounded at **16,384 entries, eight-second TTL**, and retains **no plaintext or raw ciphertext**.
- After checking the configured peer IP, suppress an incoming ICMP Echo Reply only if its **entire encrypted PTD4 payload, Echo ID, and sequence exactly match** a recently sent request from that endpoint. This rejects kernel reflections *before* invoking wrong-direction AEAD while preserving every different legitimate authenticated peer DATA/ACK packet.
- Keep Direct and Reverse reflection counters separate. New local JSON counters are `direct_data_echo_reflections`, `direct_ping_echo_reflections` and `direct_other_echo_reflections`.
- Break down actual authentication failures into `authentication_invalid_frame_failures`, `authentication_wrong_session_failures` and `authentication_aead_tag_failures` in `pingtunnel security`. Existing cumulative `authentication_failures` and anti-replay protections remain.
- Include Go regression tests with a **real paired v4 ephemeral X25519/AEAD session**: kernel-reflected own ciphertext must match, the actual peer's independently encrypted reply must survive, different IDs/sequence/ciphertexts and expired digests cannot match; no cache registration for failed writes. Invalid-format, wrong-session and tampered AEAD tags remain rejected.
- This does not change application packet queues, service maps, polling, route policy or session key derivation; **secure Wire 4 and config schema 3 are unchanged**.

## Validation and field troubleshooting

Require Rust locked CI, Go unit/race/vet, actual raw-ICMP Linux namespace tests and concurrent 12-service TCP+UDP smoke across all four route policies. After upgrade on both VPSs, compare two timestamps (for example 30 seconds apart) of `authentication_failures`, `authentication_aead_tag_failures`, `direct_data_echo_reflections`, and `udp_dispatch_overflow_drops`. Exact-reflection counts should rise as ordinary kernel Echo Replies arrive; authentic tag errors should remain low when the route is healthy. Never infer a 1–3-second pause from a **cumulative** counter alone. A 15-minute+ real Instagram/video test with time-correlated network loss/RTT is still necessary.

Compatibility: same 256-bit pairing secret, schema 3, Wire 4, up to 12 TCP/UDP Multi-Port services, Direct/Reverse policies, and prior release rollback. Update both ends coherently and retain configuration backups.
