#!/usr/bin/env bash
# Rust Pingtunnel Manager: release-first installer with failure rollback.
set -Eeuo pipefail
RELEASE="https://github.com/meysamrn/Pingtunnel_manager/releases/download/rust-latest"
CORE_RELEASE="$RELEASE"
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
  armv7l|armv6l|i386|i686) echo "Auto-AEAD release supports AMD64 or ARM64 only." >&2; exit 1 ;;
  *) echo "Unsupported architecture." >&2; exit 1 ;;
esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates unzip tar nano
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
# Do not install stale rolling assets when removing legacy HA.
chmod 755 "$work/manager"
manager_version="$("$work/manager" --version)"
if [[ "$manager_version" != "3.1.0" ]]; then
  echo "Expected Pingtunnel Manager 3.1.0 (v4 secure session, v3 pairing compatibility), got: $manager_version" >&2
  echo "Check the current rust-latest release assets before retrying." >&2
  exit 1
fi
chmod 755 "$work/manager"
echo "[2/4] Download matching authenticated Go core and check configuration..."
# Do not install the upstream Go binary: it does not support the auto-AEAD
# authenticated frame and would silently break encrypted two-peer sessions.
# Both manager and Go core MUST come from the same v3 release.
curl -fsSL --retry 3 "$CORE_RELEASE/pingtunnel-core-linux-$release_arch" -o "$work/core"
curl -fsSL --retry 3 "$CORE_RELEASE/pingtunnel-core-linux-$release_arch.sha256" -o "$work/core.sha"
core_digest="$(awk '{print $1; exit}' "$work/core.sha")"
if ! printf '%s  %s\n' "$core_digest" "$work/core" | sha256sum --check --status; then
  echo "Patched Go core checksum mismatch; installation aborted." >&2
  exit 1
fi
chmod 755 "$work/core"
if ! "$work/core" -version >/dev/null; then
  echo "Downloaded Go core failed to start." >&2
  exit 1
fi

# Fail before touching an existing service or its stored secrets.
# Old configurations are intentionally unsupported. Operator must make an
# explicit fresh v3 pairing choice on both VPSs.
if [[ -f "$CONFIG" ]] && ! "$work/manager" validate; then
  echo "Existing configuration is not v3-compatible. No files or running services were changed." >&2
  echo "Backup then manually move $CONFIG outside the config directory; rerun installer and unified setup on BOTH VPSs." >&2
  exit 1
fi
configured=0
if [[ -f "$CONFIG" ]]; then
  # No legacy settings migration: keep old config unchanged and fail safely.
  chmod 600 "$CONFIG"
  configured=1
else
  echo "First install: the lightweight menu wizard is available after installation."
  echo "No peer identity has been invented. Run pingtunnel and choose Setup."
fi

echo "[3/4] Atomic manager installation..."
previously_active=0
if systemctl is-active --quiet pingtunnel.service; then previously_active=1; fi
had_manager=0; had_core=0; had_unit=0; had_dropin=0; had_config=0
if [[ -e "$MANAGER" || -L "$MANAGER" ]]; then cp -a "$MANAGER" "$work/old-manager"; had_manager=1; fi
if [[ -e "$CORE" ]]; then cp -a "$CORE" "$work/old-core"; had_core=1; fi
if [[ -e "$UNIT" ]]; then cp -a "$UNIT" "$work/old-unit"; had_unit=1; fi
if [[ -e "$DROPIN" ]]; then cp -a "$DROPIN" "$work/old-dropin"; had_dropin=1; fi
if [[ -e "$CONFIG" ]]; then cp -a "$CONFIG" "$work/old-config"; had_config=1; fi
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
  if (( had_config )); then cp -a "$work/old-config" "$CONFIG"; fi
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
if (( configured )); then
  "$MANAGER" validate
  "$MANAGER" service-install
  if (( previously_active )) || systemctl is-enabled --quiet pingtunnel.service; then
    systemctl restart pingtunnel.service
  fi
else
  # A fresh install must not start an unconfigured service.
  systemctl daemon-reload
fi
trap - ERR
echo "[4/4] Installed successfully."
echo "Type: pingtunnel"
echo "One Iran VPS + one foreign VPS. Choose Setup on foreign first, then Iran."
