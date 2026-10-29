# Safety, rollback and uninstall (development branch)

> This is an unreleased hardening branch, **not** a confirmed fix for the
> reported high-latency v3.3.9 VPN/UDP incident. Do **not** switch a healthy
> v3.3.8 two-VPS deployment to this branch just to test it. First validate
> against an isolated pair and measure application throughput and losses.

## Auto Tune behavior

- `pingtunnel auto-tune`, `pingtunnel auto-tune --dry-run`, and menu option
  `15` are **previews**, never persisting a config or restarting a service.
- On the **Foreign** relay these commands explain that tuning is Iran-side
  only, then exit successfully without probes or changes.
- On **Iran**, preview requires an already authenticated peer and fresh
  authenticated RTT samples. Ordinary ICMP probes are only diagnostic; they
  do not measure application loss or path MTU.
- `pingtunnel auto-tune --apply` is the **only** tuning command allowed to
  modify TCP/UDP queue settings or timeouts. It requires conservative recent
  quality (`<=800ms` RTT, `<=150ms` jitter, `<=0.10` PING/PONG loss EWMA
  and at least 8 recent authenticated RTT samples), saves a 0600 config
  backup, and **restarts** the service. This drops live UDP/QUIC sessions.
  Use only during an approved maintenance window.
- After `--apply`, a new process and authenticated traffic must be observed;
  the previous config is restored if that fails. This is not an end-to-end
  VPN-data success check, and no automatic PMTU or QUIC tuning is attempted.

## ICMP/MTU diagnostics

New `pingtunnel security` metrics on both nodes:

- `ICMP socket write failures (all paths)`
- `ICMP EMSGSIZE / message-too-long errors`

The counters are per Go-core lifetime. Kernel `EMSGSIZE` is evidence of
an unsendable outgoing ICMP datagram. Zero `EMSGSIZE` **does not** exclude
IP fragmentation, downstream fragment filtering, or application loss.
There is deliberately no automatic packet-size adjustment in this patch.

## Uninstall

Use `sudo pingtunnel uninstall` (confirmation `YES`) to remove the
systemd unit, all Pingtunnel-specific drop-ins, manager, Go core, runtime
status/config and old wrapper files. The private pairing config at
`/opt/pingtunnel/conf/config.json` is **preserved**.

Use `sudo pingtunnel uninstall --purge` (confirmation `PURGE`) to also
delete `/opt/pingtunnel` and `/var/log/pingtunnel`, including secret keys.
The application binary is removed last. The uninstall aborts if systemd
still reports the Pingtunnel service active.

If the manager is **already missing** from an incomplete uninstall,
download the standalone script from this reviewed branch and run
`sudo bash Source/uninstall.sh [--purge]`. It is safe to repeat on an
already cleaned host. Downloading via the default `main` installer is
**not** a rollback or a clean-up strategy.

Both uninstall implementations intentionally leave unrelated services,
s-ui, user firewall rules and network interfaces untouched.

## Release and live validation gate

Run Rust tests, Go tests and `bash -n Source/uninstall.sh`; then verify
a new build on a nonproduction Iran/Foreign VPS pair with a real UDP
application and at least ten minutes of normal and deliberately oversized
traffic. Compare to the same workload on v3.3.8 and v3.3.9.

Only promote after recording: core versions, RTT/jitter, application
packet delivery, outgoing ICMP socket errors, ICMP fragmentation, and
rollback/uninstall behavior. Merely receiving `authenticated` is not
a substitute for the application test.
