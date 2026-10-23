#!/usr/bin/env bash
# Installer for the user-maintained Pingtunnel Manager fork.
set -Eeuo pipefail

RAW_BASE="https://raw.githubusercontent.com/meysamrn/Pingtunnel_manager/main"
INSTALLER_PATH="/usr/local/bin/install_pingtunnel.py"

if (( EUID != 0 )); then
  echo "Please run as root: sudo bash install.sh" >&2
  exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer currently supports Ubuntu/Debian systems with apt-get." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-colorama curl ca-certificates

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT
curl --fail --location --silent --show-error --retry 3 \
  "$RAW_BASE/Source/Pingtunnel.py" -o "$tmp_file"
install -m 0755 "$tmp_file" "$INSTALLER_PATH"

# Existing /opt/pingtunnel/conf/config.json is deliberately preserved.
python3 "$INSTALLER_PATH" install

echo ""
echo "Installation finished. Run: sudo pingtunnel"
echo "Check service: sudo pingtunnel status"
