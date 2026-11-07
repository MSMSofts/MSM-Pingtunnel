# MSM-Pingtunnel v3.3.23 — Direct route recovery and validation

**Stable release** · Linux AMD64 / ARM64 · Config schema 3 · Encrypted Wire v4

This maintenance release fixes an asymmetric Direct-first AUTO failover defect, adds a real raw-ICMP end-to-end regression test for manual Direct and automatic Direct, and preserves the existing Reverse-first defaults, three routing choices and pairing keys.

## Fixes

- **Direct-first, one-way failures:** Foreign previously decided that Direct was alive whenever Iran's encrypted packets still arrived. If **Foreign→Iran replies were blocked**, switching to Reverse could stall indefinitely. Iran now answers signed Foreign-origin health challenges with a distinct **PRF4** only after **35 seconds without an authenticated reply**, at least **20 seconds of genuine ongoing local application demand**, and a matched two-way HMAC challenge. Foreign accepts **two independent signed reports** even if its Iran→Foreign inbound link still works, then switches using the existing signed PTS4/PTA4 handoff. Healthy or idle Direct connections do not trigger fallback.
- **Direct-first, failed initial pairing:** If the initial Direct X25519 handshake never completes, after **90 seconds** plus sustained local demand Iran may authenticate its failure evidence over the alternative Reverse probe path. The matched, root-authenticated PTS4/PTA4 exchange can select Reverse *before* AEAD setup; the normal Wire-v4 handshake must still complete before any user data is accepted. No plaintext or key downgrade.
- **Manual Direct regression coverage:** The ordinary Direct Echo Request/Reply send path and fully encrypted UDP echo have been successfully verified in **two isolated Linux network namespaces** on CI. Its fixed direction still never switches automatically. Raw network path filters, a mismatched route policy on the opposite VPS, and an inaccessible foreign UDP/TCP target can still prevent Direct from working in deployment.

## Tests

- Linux AMD64 and ARM64 Go tests (including race detector) and Rust manager tests/builds.
- **Real raw ICMP** `ip4:icmp` Go core on both simulated VPS peers, X25519 handshake, authenticated AEAD UDP request to a loopback foreign service and round-trip response in `direct` **and** `auto_direct`.
- Deterministic tests for forged and replayed signed fallback, idle/no-demand behavior, initial handshake timeout, asymmetric packet loss, path-switch handoffs and cooldowns.

## Upgrade and checks

Install **on both VPSs** in the same maintenance window. Existing settings and pairing keys are preserved, but the service restarts:

```bash
curl -fsSL https://raw.githubusercontent.com/MSMSofts/MSM-Pingtunnel/v3.3.23/Source/install.sh -o /tmp/pingtunnel-install.sh
sudo bash /tmp/pingtunnel-install.sh
sudo pingtunnel route show
sudo pingtunnel health
sudo pingtunnel security
```

For **manual Direct**, run `sudo pingtunnel route manual-direct` on **both** VPSs. For Direct-first AUTO, run `sudo pingtunnel route auto-direct` on **both**. The policy on both peers must match, and the Iran→Foreign ICMP Echo Request plus Foreign→Iran Echo Reply path must be allowed by the network.

**Scope of verification:** The tests prove the code can carry encrypted Direct UDP through isolated Linux networks, **not** that your two VPS providers allow both directions. If Direct still fails, collect `route show`, `security` and `health` from both endpoints immediately after a test; exclude private keys/configuration secrets. On a provider blocking Direct ICMP, manual Direct cannot automatically switch paths; use Reverse-first AUTO until routing is available.
