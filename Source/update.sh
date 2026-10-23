#!/usr/bin/env bash
# Refresh the manager installer and Pingtunnel binary without deleting config.
set -Eeuo pipefail
RAW_BASE="https://raw.githubusercontent.com/meysamrn/Pingtunnel_manager/main"
if (( EUID != 0 )); then
  echo "Run as root: sudo pingtunnel update" >&2
  exit 1
fi

was_active=0
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  if systemctl is-active --quiet pingtunnel.service; then
    was_active=1
    systemctl stop pingtunnel.service
  fi
fi

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT
curl --fail --location --silent --show-error --retry 3 \
  "$RAW_BASE/Source/install.sh" -o "$tmp_file"
bash "$tmp_file"

if (( was_active )); then
  systemctl restart pingtunnel.service
fi
echo "Update finished. Existing configuration was preserved."
