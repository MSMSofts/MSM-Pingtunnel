#!/usr/bin/env bash
# AutoSSL hardened integration; see README.md and upstream/LICENSE.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly ACME_VERSION="3.1.7"
readonly ACME_TAG_SHA="36d7fb616455b0f60b4dc45f2ebdea91019bcd95"
readonly ACME_HOME="/opt/autossl/acme"
readonly VERSION_FILE="/opt/autossl/.acme-version"
readonly CERT_ROOT="/etc/autossl/certs"
readonly BIN_PATH="/usr/local/sbin/autossl"
readonly TIMER_NAME="autossl-renew.timer"
readonly SIGNING_KEY="github@neilpang.com namespaces=\"git\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBTjI0HBJn3uhfT2DsNcFybfAZi3ADbIacMpz1BItKdB"

info() { printf '[AutoSSL] %s\n' "$*" >&2; }
die() { printf '[AutoSSL] ERROR: %s\n' "$*" >&2; exit 1; }
require_root() { (( EUID == 0 )) || die "Run this command with sudo/root."; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1. Run: sudo bash autossl.sh install-deps"; }
acme() { [[ -x "$ACME_HOME/acme.sh" ]] || die "acme.sh is not installed. Run: sudo bash autossl.sh install --email you@example.com"; "$ACME_HOME/acme.sh" --home "$ACME_HOME" "$@"; }
lock() {
  need flock
  mkdir -p /run/lock
  exec 9>/run/lock/autossl.lock
  flock -n 9 || die "Another AutoSSL operation is already running."
}
valid_domain() {
  local d="$1" label
  [[ ${#d} -le 253 && "$d" == *.* && "$d" != .* && "$d" != *. ]] || die "Invalid FQDN: $d"
  [[ "$d" =~ ^[a-zA-Z0-9.-]+$ ]] || die "Invalid domain characters."
  local -a labels
  IFS='.' read -r -a labels <<< "$d"
  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 && "$label" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || die "Invalid DNS label in $d"
  done
  [[ "${labels[-1]}" =~ ^[a-zA-Z]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || die "Invalid domain suffix."
}
valid_email() {
  [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "Provide a valid real email address using --email."
}
valid_service() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]*$ ]] || die "Invalid service name."
  [[ "$1" != *.service ]] || die "Pass the service name without .service."
}
install_deps() {
  require_root
  info "Installing prerequisites using the detected package manager."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git openssl socat openssh-client iproute2 util-linux
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl git openssl socat openssh-clients iproute util-linux
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl git openssl socat openssh-clients iproute util-linux
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Syu --needed --noconfirm ca-certificates curl git openssl socat openssh iproute2 util-linux
  else
    die "Unsupported package manager. Install curl, git, openssl, socat, OpenSSH, iproute2, util-linux and CA certificates manually."
  fi
}
check_deps() {
  local cmd
  for cmd in curl git openssl socat ssh-keygen flock systemctl; do need "$cmd"; done
  [[ -d /run/systemd/system ]] || die "This integration requires systemd as PID 1."
}
install_acme() (
  local email="$1" work checkout tag_sha
  work=$(mktemp -d)
  trap 'rm -rf -- "$work"' EXIT
  checkout="$work/source"
  mkdir -p "$checkout" "$ACME_HOME" /opt/autossl
  chmod 700 /opt/autossl "$ACME_HOME"
  printf '%s\n' "$SIGNING_KEY" >"$work/allowed_signers"
  git -C "$checkout" init -q
  git -C "$checkout" remote add origin https://github.com/acmesh-official/acme.sh.git
  git -C "$checkout" fetch -q --depth=1 origin "refs/tags/$ACME_VERSION:refs/tags/$ACME_VERSION"
  tag_sha=$(git -C "$checkout" rev-parse "refs/tags/$ACME_VERSION")
  [[ "$tag_sha" == "$ACME_TAG_SHA" ]] || die "acme.sh release tag SHA mismatch; aborting."
  git -C "$checkout" -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$work/allowed_signers" verify-tag "$ACME_VERSION" >/dev/null || die "acme.sh signature verification failed."
  git -C "$checkout" checkout -q --detach "$ACME_VERSION"
  info "Verified signed acme.sh release $ACME_VERSION."
  ( cd "$checkout" && ./acme.sh --install --home "$ACME_HOME" --nocron -m "$email" )
  chmod 700 "$ACME_HOME"
  "$ACME_HOME/acme.sh" --home "$ACME_HOME" --set-default-ca --server letsencrypt
  printf '%s\n' "$ACME_VERSION" >"$VERSION_FILE"
  chmod 600 "$VERSION_FILE"
)
install_timer() {
  [[ -d /run/systemd/system ]] || die "systemd is not running."
  cat >/etc/systemd/system/autossl-renew.service <<'UNIT'
[Unit]
Description=AutoSSL automatic ACME certificate renewal
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/autossl renew
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/autossl /etc/autossl /run
UNIT
  cat >/etc/systemd/system/autossl-renew.timer <<'UNIT'
[Unit]
Description=Check ACME certificates for renewal every day

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true
Unit=autossl-renew.service

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now "$TIMER_NAME"
}
do_install() {
  require_root
  valid_email "$EMAIL"
  if [[ "$INSTALL_DEPS" == 1 ]]; then install_deps; fi
  check_deps
  lock
  mkdir -p /opt/autossl "$CERT_ROOT" /usr/local/sbin
  chmod 700 /opt/autossl "$CERT_ROOT"
  if [[ ! -x "$ACME_HOME/acme.sh" || ! -f "$VERSION_FILE" || "$(cat "$VERSION_FILE")" != "$ACME_VERSION" ]]; then
    install_acme "$EMAIL"
  else
    info "Verified-version acme.sh installation already present ($ACME_VERSION)."
  fi
  local source_path temp_path
  source_path=$(readlink -f -- "$0")
  if [[ "$source_path" != "$BIN_PATH" ]]; then
    temp_path=$(mktemp /usr/local/sbin/.autossl.XXXXXX)
    install -m 0755 "$source_path" "$temp_path"
    mv -f "$temp_path" "$BIN_PATH"
  fi
  install_timer
  info "Installed. Next: sudo autossl issue --domain example.com --challenge standalone"
}
do_issue() {
  require_root
  [[ -n "$DOMAIN" ]] || die "Missing --domain."
  valid_domain "$DOMAIN"
  [[ "$CHALLENGE" == standalone || "$CHALLENGE" == webroot ]] || die "Choose --challenge standalone or webroot."
  if [[ "$CHALLENGE" == webroot ]]; then
    [[ -n "$WEBROOT" && "$WEBROOT" == /* && -d "$WEBROOT" ]] || die "Provide an existing absolute --webroot path."
    [[ -w "$WEBROOT" ]] || die "Webroot is not writable."
  else
    [[ -z "$WEBROOT" ]] || die "--webroot can only be used with --challenge webroot."
  fi
  if [[ -n "$RELOAD_SERVICE" ]]; then
    valid_service "$RELOAD_SERVICE"
    systemctl cat "$RELOAD_SERVICE.service" >/dev/null 2>&1 || die "Service not found: $RELOAD_SERVICE"
  fi
  lock
  local cert_dir rc
  cert_dir="$CERT_ROOT/$DOMAIN"
  mkdir -p "$cert_dir"
  chmod 700 "$cert_dir"
  local -a args=(--issue -d "$DOMAIN" --server letsencrypt --keylength ec-256)
  if [[ "$CHALLENGE" == standalone ]]; then
    info "Standalone HTTP-01 needs reachable, unoccupied TCP port 80 now AND during renewal."
    args+=(--standalone)
  else
    args+=(--webroot "$WEBROOT")
  fi
  rc=0
  acme "${args[@]}" || rc=$?
  # acme.sh returns 2 if issuance was skipped because the existing cert is still valid.
  (( rc == 0 || rc == 2 )) || die "ACME certificate issuance failed (exit $rc)."
  local -a install_args=(--install-cert -d "$DOMAIN" --ecc
    --key-file "$cert_dir/private.pem" --fullchain-file "$cert_dir/fullchain.pem")
  if [[ -n "$RELOAD_SERVICE" ]]; then
    install_args+=(--reloadcmd "systemctl reload $RELOAD_SERVICE.service")
  fi
  acme "${install_args[@]}" || die "Certificate installation or reload failed."
  chmod 600 "$cert_dir/private.pem"
  chmod 644 "$cert_dir/fullchain.pem"
  openssl x509 -in "$cert_dir/fullchain.pem" -noout -checkend 0 >/dev/null || die "Installed certificate is invalid or expired."
  info "Certificate ready at $cert_dir (private.pem, fullchain.pem)."
}
do_renew() {
  require_root
  lock
  acme --cron || die "Automatic renewal failed; inspect journalctl -u autossl-renew.service."
  info "Renewal check completed."
}
do_status() {
  require_root
  [[ -n "$DOMAIN" ]] || die "Missing --domain."
  valid_domain "$DOMAIN"
  local cert="$CERT_ROOT/$DOMAIN/fullchain.pem"
  [[ -f "$cert" ]] || die "No installed certificate found for $DOMAIN."
  openssl x509 -in "$cert" -noout -subject -issuer -dates
  openssl x509 -in "$cert" -checkend 2592000 -noout >/dev/null && info "More than 30 days remain." || info "Certificate expires within 30 days (or already expired)."
  systemctl is-enabled "$TIMER_NAME" || true
  systemctl list-timers --all "$TIMER_NAME" --no-pager || true
}
do_doctor() {
  local cmd missing=0
  for cmd in git curl openssl socat ssh-keygen flock systemctl; do
    if command -v "$cmd" >/dev/null 2>&1; then
      info "OK: $cmd"
    else
      info "MISSING: $cmd"
      missing=1
    fi
  done
  [[ -x "$ACME_HOME/acme.sh" ]] && info "OK: acme.sh installed" || { info "MISSING: acme.sh"; missing=1; }
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-enabled "$TIMER_NAME" >/dev/null 2>&1 && info "OK: renewal timer enabled" || { info "MISSING: renewal timer"; missing=1; }
  fi
  if [[ -n "$DOMAIN" ]]; then
    valid_domain "$DOMAIN"
    if command -v getent >/dev/null 2>&1; then
      getent ahostsv4 "$DOMAIN" | head -n 1 || info "DNS A lookup returned no result."
    fi
    [[ -f "$CERT_ROOT/$DOMAIN/fullchain.pem" ]] && info "OK: certificate files exist" || info "No issued certificate found for $DOMAIN."
  fi
  (( missing == 0 )) || die "Doctor found missing prerequisites."
}
usage() {
  cat <<'HELP'
AutoSSL: verified acme.sh + Let's Encrypt with unattended systemd renewal.
Usage:
  sudo bash autossl.sh install-deps
  sudo bash autossl.sh install --email you@example.com [--install-deps]
  sudo autossl issue --domain example.com [--challenge standalone]
  sudo autossl issue --domain example.com --challenge webroot --webroot /var/www/html
  sudo autossl issue --domain example.com --reload-service nginx
  sudo autossl renew
  sudo autossl status --domain example.com
  sudo autossl doctor [--domain example.com]
Notes:
  * Use a real email; there are no generated addresses.
  * HTTP-01 requires inbound TCP/80 for issuance AND all future renewals.
  * For a running web server, use webroot with a working ACME challenge route.
  * Reload service is opt-in; it must actually read the specified cert paths.
  * Use one --domain per certificate. Wildcards require DNS-01 (not supported).
HELP
}
COMMAND="${1:-help}"
if (($#)); then shift; fi
DOMAIN="" EMAIL="" CHALLENGE="standalone" WEBROOT="" RELOAD_SERVICE="" INSTALL_DEPS=0
while (($#)); do
  case "$1" in
    --domain|--email|--challenge|--webroot|--reload-service)
      (($# >= 2)) || die "Missing value after $1"
      case "$1" in
        --domain) DOMAIN="$2" ;;
        --email) EMAIL="$2" ;;
        --challenge) CHALLENGE="$2" ;;
        --webroot) WEBROOT="$2" ;;
        --reload-service) RELOAD_SERVICE="$2" ;;
      esac
      shift 2 ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    -h|--help) COMMAND="help"; shift ;;
    *) die "Unknown option: $1" ;;
  esac
done
case "$COMMAND" in
  install-deps) install_deps ;;
  install) do_install ;;
  issue) do_issue ;;
  renew) do_renew ;;
  status) do_status ;;
  doctor) do_doctor ;;
  help|-h|--help) usage ;;
  *) usage; die "Unknown command: $COMMAND" ;;
esac
