#!/usr/bin/env bash
# Rust Pingtunnel Manager: release-first installer with failure rollback.
set -Eeuo pipefail
RELEASE="https://github.com/MSMSofts/Pingtunnel_manager/releases/download/v3.2.3"
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
apt-get install -y --no-install-recommends curl ca-certificates
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p /opt/pingtunnel/bin /opt/pingtunnel/conf
chmod 700 /opt/pingtunnel/conf

echo "[1/4] Obtain Rust manager..."
# Fail closed: matched release assets are mandatory. Do not silently
# compile mutable main from source or install an unreviewed Go/Rust pair.
curl -fsSL --retry 3 "$RELEASE/pingtunnel-manager-linux-$release_arch" -o "$work/manager"
curl -fsSL --retry 3 "$RELEASE/pingtunnel-manager-linux-$release_arch.sha256" -o "$work/sha"
digest="$(awk '{print $1; exit}' "$work/sha")"
if ! printf '%s  %s\n' "$digest" "$work/manager" | sha256sum --check --status; then
  echo "Manager SHA256 mismatch; installation aborted." >&2
  exit 1
fi
chmod 755 "$work/manager"
manager_version="$("$work/manager" --version)"
if [[ "$manager_version" != "3.2.3" ]]; then
  echo "Expected Pingtunnel Manager 3.2.3 (wire 4, config schema 3, security fixes), got: $manager_version" >&2
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
# The release manifest binds the manager and core to the same tagged build.
curl -fsSL --retry 3 "$RELEASE/release-manifest.txt" -o "$work/manifest"
for invariant in "release=v3.2.3" "config_schema=3" "wire=4"; do
  if ! grep -Fxq "$invariant" "$work/manifest"; then
    echo "Release manifest is missing $invariant; aborting." >&2
    exit 1
  fi
done
for file in "pingtunnel-manager-linux-$release_arch" "pingtunnel-core-linux-$release_arch"; do
  expected="$(awk -v file="$file" '$2 == file {print $1}' "$work/manifest")"
  if [[ "$file" == pingtunnel-manager-* ]]; then local_asset="$work/manager"; else local_asset="$work/core"; fi
  actual="$(sha256sum "$local_asset" | awk '{print $1}')"
  if [[ -z "$expected" || "$actual" != "$expected" ]]; then
    echo "Release manifest rejected mismatched $file" >&2
    exit 1
  fi
done
if [[ "$("$work/core" -security-protocol)" != "pingtunnel-go-core=3.2.3 config-schema=3 wire=4" ]]; then
  echo "Downloaded Go core is not the matching v3.2.3 secure wire-4 build." >&2
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
  if (( previously_active )); then
    systemctl restart pingtunnel.service || true
  else
    # Restore the pre-update stopped state if this was an offline service.
    systemctl stop pingtunnel.service || true
  fi
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
  # Every successful configured upgrade must leave the tunnel running with
  # the new Go executable, even if it was stopped/disabled before the update.
  # Never restart a first install that has not completed the pairing wizard.
  echo "[4/4] Restarting updated encrypted tunnel and verifying Go health..."
  systemctl restart pingtunnel.service
  # systemctl restart can succeed before a crashing ExecStart fails.
  sleep 3
  if ! systemctl is-active --quiet pingtunnel.service; then
    echo "New Go core did not remain active; restoring previous installation." >&2
    false
  fi
  running_pid="$(systemctl show -p MainPID --value pingtunnel.service)"
  if [[ ! "$running_pid" =~ ^[1-9][0-9]*$ ]] || ! kill -0 "$running_pid" 2>/dev/null; then
    echo "Go core has no live systemd MainPID; rolling back." >&2
    false
  fi
  if ! "$MANAGER" health; then
    echo "New Go core failed runtime heartbeat validation; rolling back." >&2
    false
  fi
  echo "Updated tunnel restarted successfully; systemd and Go heartbeat are healthy."
else
  # A fresh install must not start an unconfigured service.
  systemctl daemon-reload
fi
trap - ERR
echo "Installed successfully."
echo "Type: pingtunnel"
echo "One Iran VPS + one foreign VPS. Choose Setup on foreign first, then Iran."
