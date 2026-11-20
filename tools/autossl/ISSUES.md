# AutoSSL upstream code review and remediation

Source reviewed: [monhacer/AutoSSL](https://github.com/monhacer/AutoSSL) at commit `db5a0372f1462fd3e5032b817a35b0f5e4c99e55` (AutoSSL.sh, 2,320 bytes). Findings below are **code-review observations**, not exploit demonstrations.

| Severity | Original behavior | Risk / limitation | Implemented remediation |
| --- | --- | --- | --- |
| High | `curl https://get.acme.sh | sh` executed as root | Unpinned remote script, no integrity check, piped command can hide download failure | Fetch pinned acme.sh 3.1.7 annotated tag, check SHA and SSH tag signature against embedded trust anchor, then install |
| High | When email omitted, fabricated a `@gmail.com` mailbox | Recovery/expiration notices could go to an unowned address or registration could be rejected | Mandatory validated operator email |
| High | No `set -e`, no checked results from issuance and `--install-cert` | Potential false success after a failure | Strict mode, explicit return-code checks, post-install X.509 verification |
| High | Standalone TCP/80 assumed even when web server runs | Issuance/renewals fail if port 80 is occupied | Explicit standalone vs webroot; document renewal preconditions |
| Medium | `--force` used on each issue | Unneeded fresh orders, rate-limit exposure | No force; a skipped valid issuance is handled |
| Medium | Restarted any detected Nginx/Apache/HAProxy | Unrelated services interrupted; reload errors did not abort | Only explicitly selected service, using `systemctl reload`; acme.sh persists reload hook |
| Medium | Relied on acme.sh's default Cron and shell profile | Unclear renewal state and limited diagnosis | Dedicated persistent daily systemd timer and journal logs |
| Medium | Saved certs in `/root/cert/$DOMAIN` without validating input | Unvalidated directory component / trust of caller | Strict hostname validation and root-only directory `/etc/autossl/certs/$DOMAIN` |
| Medium | No locking | Concurrent installs/renewals could collide | `flock` around mutating commands |
| Low | Auto-installed only `socat` | Missing git/crypto/tls/diagnostic tools would fail later | Explicit per-package-manager dependency installer and doctor checks |
| Low | No test workflow or structured docs | Difficult to detect regressions | ShellCheck, Bash syntax check, mocked issue/renew tests, bilingual docs |

## Security upstream dependency
acme.sh [3.1.7](https://github.com/acmesh-official/acme.sh/releases/tag/3.1.7), published 2026-11-19, includes a security fix concerning attacker-controlled values from a CA breaking quoting when persisted. This integration pins that release rather than its mutable master branch.

## Remaining caveats / validation required
1. **Real issuance not tested in CI:** requires reachable domain/ports and contacts the CA.
2. **Webroot verification is the administrator's responsibility:** the web server must serve the ACME challenge path on HTTP port 80.
3. **Standalone renewal requires free TCP/80 in the future**, not only once.
4. **Service reload is opt-in** and requires manually configuring the web server or proxy to use the installed paths.
5. **No wildcard/DNS-01 integration** or non-systemd scheduler in this iteration.
6. **Pinned dependency requires manual review for security updates**. Do not auto-upgrade to unverified HEAD.
7. Package-manager behavior and systemd confinement require on-host verification for each distribution; CI is Ubuntu-focused.
