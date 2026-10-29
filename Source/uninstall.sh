#!/usr/bin/env bash
# Standalone cleanup for partially uninstalled Pingtunnel installations.
# This script intentionally does NOT touch s-ui, Hysteria, firewall rules,
# unrelated services or any user-provided network interface.
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage: sudo bash Source/uninstall.sh [--purge]
  (default)  Remove Pingtunnel binaries/service/runtime; keep private pairing config.
  --purge    Also PERMANENTLY delete Pingtunnel configuration, keys and logs.
Requires typed confirmation. Safe to repeat after a partial uninstall.
USAGE
}
if [[ ${EUID} -ne 0 ]]; then echo "Run as root using sudo." >&2; exit 1; fi
purge=0
case "${1:-}" in
  "") ;;
  --purge) purge=1 ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then usage >&2; exit 2; fi

if (( purge )); then
  echo "WARNING: this permanently deletes Pingtunnel pairing keys, configuration and logs."
  read -r -p "Type PURGE to proceed: " approval
  [[ "$approval" == "PURGE" ]] || { echo "Cancelled without changes."; exit 0; }
else
  echo "This removes only Pingtunnel; pairing configuration is preserved."
  read -r -p "Type YES to proceed: " approval
  [[ "$approval" == "YES" ]] || { echo "Cancelled without changes."; exit 0; }
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop pingtunnel.service >/dev/null 2>&1 || true
  if systemctl is-active --quiet pingtunnel.service; then
    echo "Pingtunnel is still running; refusing to delete live executables." >&2
    exit 1
  fi
  systemctl disable pingtunnel.service >/dev/null 2>&1 || true
fi

rm -f -- /etc/systemd/system/pingtunnel.service
rm -rf -- /etc/systemd/system/pingtunnel.service.d

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl reset-failed pingtunnel.service >/dev/null 2>&1 || true
fi

# Runtime files only. No process belonging to an unrelated VPN is killed.
rm -f -- \
  /run/pingtunnel-core.json \
  /run/pingtunnel-performance.json \
  /run/pingtunnel-security.json \
  /run/pingtunnel.pid \
  /usr/local/bin/install_pingtunnel.py \
  /opt/pingtunnel/run_pingtunnel.py
rm -rf -- /opt/pingtunnel/bin
if (( purge )); then
  rm -rf -- /opt/pingtunnel /var/log/pingtunnel
fi
# Delete the manager executable last.
rm -f -- /usr/local/bin/pingtunnel

if (( purge )); then
  echo "Pingtunnel fully purged (including private configuration)."
else
  echo "Pingtunnel binaries, service and runtime removed."
  echo "Private pairing configuration retained under /opt/pingtunnel/conf/."
fi
