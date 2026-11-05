# Immutable upstream source snapshot

Source: https://github.com/esrrhs/pingtunnel
Historical upstream commit: `df16e52771ee67f1f9770ec68763b425672a36fc` (2026-10-21)
Historical upstream tree: `4c544af18a7b96d4477ab8cd6370df68d931965f`
Go module version: 1.26.0
License: MIT (see `LICENSE` in this directory).

This directory contains 25 verbatim source/license/module files from the
upstream Git tree above. Their Git blob hashes were individually checked
against the historical source tree when imported. No compiled artifacts,
private configuration, credentials or binaries are vendored.

The build copies this snapshot into a temporary `upstream/` directory,
then overlays `Go/*.go` and `Go/cmd/main.go`. Previously it checked out
`df16e52771ee67f1f9770ec68763b425672a36fc` directly after cloning the
external repository. The historical commit became unreachable from that
repository's rewritten public refs, breaking CI on 2026-11-05.
This archive preserves the original base rather than silently upgrading
dependencies or changing the authenticated wire protocol.

## Git blob verification

```text
b252c995cf1ce11f67a3ac8ce4ef4a848592e40d  LICENSE
f6da6be582118b00793a6cc19a5c9c616e34eb29  activity_notify.go
b124fc89175c429bdc9e3eb6811d8fd942781c2b  client.go
142c799f83abc4443f14190ad97f469e15ebbdb8  cmd/main.go
997f267e9cc03ae1609811e37c37d0211315b2d8  config.go
874985288c0b3579018c339f744900fd8fafaf4f  config_test.go
e6ec073702e897a56eec67fd115de4c25745b71c  crypto.go
046d02183121dc23fc0c6c82a2fecf5444e62f22  crypto_test.go
330b693ba6a0cf7f3a5785701dfd0c3357cf9561  forward.go
49e281611125f5c82329e280944368ec7e061ae7  forward_test.go
a0e5e5bdc39a137b22eb481947d17ccb8e315be9  go.mod
21379a76ee0783b86b5fd83ef52f1a3b5a0ff254  go.sum
4a490af35b2fb506af51ac362a1b7950e9813ee8  icmp_addr.go
47b3168496732dcd1f3947ea333b5963cac51479  icmp_listen_android.go
d2d4e3e5e7b0677e20c8622bf3519e994b31a13e  icmp_listen_other.go
de193cd68b85fc5c94dd2359c0e5686c02da2cea  loop_adaptive.go
5efa6b7ff9e3404788ffd23a799feb77910635b3  msg.pb.go
e8b1dd4cf3716feae58df5348daf938efb95d4ef  msg.proto
0fd9e602ab2c320d77497f3babe28addef3bc029  pingtunnel.go
1cdc0e9951dc8282fb20b8ef8e2767666b0fabb2  pingtunnel_test.go
ae02637ec0c8c42086212328cca2cfc7176c8911  server.go
6edda48b2b71281f6aaa119474fc6c532839bf0f  socks5.go
4c9738bf627e80ab371b469000dd967aa28056d0  socks5_test.go
beb4bb59c290cda3228e982d378382dd4efb5044  version.go
890360e019b0901a82415792e35939f5dfd0e20f  version_test.go
```
