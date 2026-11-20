# AutoSSL (hardened integration)

A maintained wrapper for **Let's Encrypt** certificates on **systemd Linux** hosts. This component is independent of the Pingtunnel transport. Derived from [monhacer/AutoSSL](https://github.com/monhacer/AutoSSL), MIT licensed; original script and license are preserved under `upstream/`.

## Features
- Installs **acme.sh 3.1.7**, **signed upstream release** pinned to annotated tag SHA `36d7fb616455b0f60b4dc45f2ebdea91019bcd95` and verified against the pinned maintainer SSH public key.
- No `curl | sh`, no random email addresses, no forced certificate issuance.
- Explicit dependency installer (APT/DNF/YUM/Pacman), fail-fast checks, protected key directory, and single-operation lock.
- HTTP-01 **standalone** or **webroot**, ECC P-256 certificate, installed at stable paths outside acme.sh's working directory.
- Daily **systemd timer**, persistent missed-run recovery, randomized delay, and opt-in service reload on successfully installed/renewed certificates.
- `doctor`, `status`, noninteractive CLI, CI static checks, and mocked certificate smoke tests.

## Prerequisites
Linux with **systemd**, root access, network access to GitHub and Let's Encrypt, DNS A/AAAA records pointing to the server as appropriate, public TCP **80** reachable from the Internet for HTTP-01. Standalone additionally requires TCP 80 **unoccupied during issuance and every renewal**; webroot requires a working web server that serves `/.well-known/acme-challenge/` from the given document root. Opening the firewall or configuring routing is **not** automatic. Wildcards require DNS-01, which this wrapper intentionally does not implement.

Dependencies: `bash`, `git`, `curl`, `openssl`, `socat`, `openssh-client`/`ssh-keygen`, `util-linux`/`flock`, `ca-certificates`, `systemctl`; optionally `iproute2` and `getent` for diagnostics.

## Installation

```bash
git clone https://github.com/MSMSofts/MSM-Pingtunnel.git
cd MSM-Pingtunnel
sudo bash tools/autossl/autossl.sh install --email admin@example.com --install-deps
```

**Replace the example email with a real, monitored address.** The `--install-deps` flag permits package-manager changes; omit it when prerequisites are already installed. The installer creates `/usr/local/sbin/autossl` and `autossl-renew.timer`. It only reinstalls acme.sh when the wrapper's pinned-version record is absent/mismatched; existing ACME account data is retained.

## Certificate issuance

**Standalone**, when TCP port 80 is free and inbound:

```bash
sudo autossl issue --domain sub.example.com --challenge standalone
```

**Webroot**, when Nginx/Apache already serves port 80:

```bash
sudo autossl issue --domain sub.example.com --challenge webroot --webroot /var/www/html --reload-service nginx
```

A service reload is optional, explicit, and validated by `systemctl cat`. Ensure your service's own TLS configuration references these files, or reloading will have no effect:

```text
/etc/autossl/certs/sub.example.com/private.pem
/etc/autossl/certs/sub.example.com/fullchain.pem
```

The certificate is renewed and copied to the same paths by acme.sh. A requested reload command is persisted by acme.sh for renewal. When no service is specified, no service is restarted or reloaded. If a service cannot hot-reload, configure it separately. **Do not configure a service to read acme.sh's internal files.**

## Operations

```bash
sudo autossl doctor --domain sub.example.com
sudo autossl status --domain sub.example.com
sudo autossl renew
systemctl status autossl-renew.timer
systemctl list-timers autossl-renew.timer
journalctl -u autossl-renew.service -n 100 --no-pager
```

The timer checks daily; it does not reissue certificates unnecessarily. For HTTP-01 standalone, port 80 must remain available whenever a renewal is due. If another service takes port 80, switch to webroot and re-issue/configure the challenge on that domain, or deliberately manage downtime. Re-running `install` from a fresh checkout updates the installed wrapper.

## Security, scope and limitations
- Certificates and keys live in a root-only directory. Adjust **access controls** carefully when a non-root application needs to read the key; do not chmod private keys world-readable.
- This tool manages ACME certificates, **not** DNS, network firewalls, proxy configuration, or Pingtunnel's own encrypted ICMP pairing.
- acme.sh code is pinned to a specific signed release, so upgrades require a reviewed edit to `ACME_VERSION` and `ACME_TAG_SHA`. Check upstream security releases periodically.
- systemd's sandbox limits write access during renewal. Custom ACME/DNS hooks and arbitrary cert installation destinations are not supported.
- Test commands use a fake ACME client and **do not prove** successful public certificate issuance; validate on a disposable staging domain/server before production rollout.

[فارسی](README.fa.md) · [Issue audit and fixes](ISSUES.md) · [Original source](upstream/AutoSSL.sh) · [MIT license](upstream/LICENSE)
