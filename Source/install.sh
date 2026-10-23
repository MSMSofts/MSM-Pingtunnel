#!/usr/bin/env bash
# Rust Pingtunnel Manager: release-first installer with failure rollback.
set -Eeuo pipefail
RELEASE="https://github.com/meysamrn/Pingtunnel_manager/releases/download/rust-latest"
CORE_RELEASE="https://github.com/esrrhs/pingtunnel/releases/latest/download"
MANAGER="/usr/local/bin/pingtunnel"
CORE="/opt/pingtunnel/bin/pingtunnel"
CONFIG="/opt/pingtunnel/conf/config.json"
UNIT="/etc/systemd/system/pingtunnel.service"
DROPIN="/etc/systemd/system/pingtunnel.service.d/memory.conf"
if (( EUID != 0 )); then echo "Run as root with sudo." >&2; exit 1; fi
if [[ ! -d /run/systemd/system ]] || ! command -v systemctl >/dev/null; then
  echo "This edition requires systemd." >&2; exit 1
fi
if ! command -v apt-get >/dev/null; then
  echo "Automatic installer supports Debian/Ubuntu apt-get." >&2; exit 1
fi
case "$(uname -m)" in
  x86_64|amd64) release_arch="amd64"; go_arch="amd64" ;;
  aarch64|arm64) release_arch="arm64"; go_arch="arm64" ;;
  armv7l|armv6l) release_arch=""; go_arch="arm" ;;
  i386|i686) release_arch=""; go_arch="386" ;;
  *) echo "Unsupported architecture." >&2; exit 1 ;;
esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates unzip tar
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p /opt/pingtunnel/bin /opt/pingtunnel/conf
chmod 700 /opt/pingtunnel/conf

echo "[1/4] Obtain Rust manager..."
prebuilt=0
if [[ -n "$release_arch" ]] &&
  curl -fsSL --retry 2 "$RELEASE/pingtunnel-manager-linux-$release_arch" -o "$work/manager" &&
  curl -fsSL --retry 2 "$RELEASE/pingtunnel-manager-linux-$release_arch.sha256" -o "$work/sha"; then
  digest="$(awk '{print $1; exit}' "$work/sha")"
  if printf '%s  %s\n' "$digest" "$work/manager" | sha256sum --check --status; then
    prebuilt=1
  else
    echo "Manager SHA256 mismatch; installation aborted." >&2
    exit 1
  fi
fi
if (( ! prebuilt )); then
  echo "No published Rust binary yet; compiling from source (requires RAM)."
  if [[ "${PINGTUNNEL_NO_COMPILE:-0}" == "1" ]]; then
    echo "Compilation disabled. Check GitHub Releases for binary assets." >&2
    exit 1
  fi
  if ! command -v cargo >/dev/null; then
    apt-get install -y --no-install-recommends cargo rustc
  fi
  curl -fsSL --retry 3 \
    https://github.com/meysamrn/Pingtunnel_manager/archive/refs/heads/main.tar.gz \
    -o "$work/repository.tar.gz"
  mkdir -p "$work/source"
  tar -xzf "$work/repository.tar.gz" -C "$work/source"
  cargo build --release --manifest-path "$work/source/Pingtunnel_manager-main/Rust/Cargo.toml"
  cp "$work/source/Pingtunnel_manager-main/Rust/target/release/pingtunnel" "$work/manager"
fi
# Refuse stale rolling-release assets from the previous 2.1 release.
# Do not silently install a TCP-only HA manager when the user requested UDP HA.
manager_version="$("$work/manager" --version)"
if [[ "$manager_version" != "2.2.0" ]]; then
  echo "Expected Pingtunnel Manager 2.2.0 with UDP HA, got: $manager_version" >&2
  echo "Check the current rust-latest release assets before retrying." >&2
  exit 1
fi
chmod 755 "$work/manager"
echo "[2/4] Check config and Go tunnel core..."
if [[ "${PINGTUNNEL_REFRESH_GO:-0}" == "1" || ! -f "$CORE" ]]; then
  curl -fsSL --retry 3 "$CORE_RELEASE/pingtunnel_linux_$go_arch.zip" -o "$work/core.zip"
  entry="$(unzip -Z1 "$work/core.zip" | awk -F/ '$NF ~ /^pingtunnel([_-].*)?$/ && $NF !~ /\.(txt|md|json)$/ {print;exit}')"
  if [[ -z "$entry" ]]; then echo "Missing core in ZIP." >&2; exit 1; fi
  unzip -p "$work/core.zip" "$entry" > "$work/core"
  [[ -s "$work/core" ]] || { echo "Empty core." >&2; exit 1; }
  chmod 755 "$work/core"
fi
if [[ -f "$CONFIG" ]]; then
  "$work/manager" validate
else
  echo "First-time configuration:"
  "$work/manager" configure
fi
chmod 600 "$CONFIG"

echo "[3/4] Atomic manager installation..."
previously_active=0
if systemctl is-active --quiet pingtunnel.service; then previously_active=1; fi
had_manager=0; had_core=0; had_unit=0; had_dropin=0
if [[ -e "$MANAGER" || -L "$MANAGER" ]]; then cp -a "$MANAGER" "$work/old-manager"; had_manager=1; fi
if [[ -e "$CORE" ]]; then cp -a "$CORE" "$work/old-core"; had_core=1; fi
if [[ -e "$UNIT" ]]; then cp -a "$UNIT" "$work/old-unit"; had_unit=1; fi
if [[ -e "$DROPIN" ]]; then cp -a "$DROPIN" "$work/old-dropin"; had_dropin=1; fi
rollback() {
  code=$?
  trap - ERR
  echo "Installation failed ($code). Restoring previous files." >&2
  if [[ -n "${manager_new:-}" ]]; then rm -f "$manager_new"; fi
  if [[ -n "${core_new:-}" ]]; then rm -f "$core_new"; fi
  if (( had_manager )); then rm -f "$MANAGER"; cp -a "$work/old-manager" "$MANAGER"; else rm -f "$MANAGER"; fi
  if (( had_core )); then cp -a "$work/old-core" "$CORE"; else rm -f "$CORE"; fi
  if (( had_unit )); then cp -a "$work/old-unit" "$UNIT"; else rm -f "$UNIT"; fi
  if (( had_dropin )); then mkdir -p "$(dirname "$DROPIN")"; cp -a "$work/old-dropin" "$DROPIN"; else rm -f "$DROPIN"; fi
  systemctl daemon-reload || true
  if (( previously_active )); then systemctl restart pingtunnel.service || true; fi
  exit "$code"
}
manager_new=""
core_new=""
trap rollback ERR
systemctl stop pingtunnel.service >/dev/null 2>&1 || true
# Stage on the same filesystem as the destination for atomic rename.
manager_new="$(mktemp /usr/local/bin/.pingtunnel.XXXXXX)"
install -m 0755 "$work/manager" "$manager_new"
mv -f "$manager_new" "$MANAGER"
manager_new=""
if [[ -f "$work/core" ]]; then
  core_new="$(mktemp /opt/pingtunnel/bin/.pingtunnel.XXXXXX)"
  install -m 0755 "$work/core" "$core_new"
  mv -f "$core_new" "$CORE"
  core_new=""
fi
"$MANAGER" service-install
if (( previously_active )) || systemctl is-enabled --quiet pingtunnel.service; then
  systemctl restart pingtunnel.service
fi
trap - ERR
echo "[4/4] Installed. Use: sudo pingtunnel ; sudo pingtunnel status"
