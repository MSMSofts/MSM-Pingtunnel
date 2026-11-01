#!/usr/bin/env bash
# OPTIONAL, operator-controlled reduction of duplicate kernel ICMP echoes.
# Requires Linux nftables. Never executed by the installer or Go/Rust service.
# This does not disable ICMP globally or alter generic Echo Reply handling.
set -euo pipefail

TABLE="pingtunnel_icmp_echo_dedupe"
CONFIG="/opt/pingtunnel/conf/config.json"

usage() {
  cat <<'USAGE'
Usage: sudo bash Source/icmp-echo-dedupe.sh [show|apply|remove]
  show    Read currently installed narrow nftables rules (default).
  apply   Explicitly install output-only rules on the IRAN VPS for PTR4/PTS4.
  remove  Delete only this script's dedicated nftables table.

The rule drops automatic kernel Echo Replies that echo the signed PTR4 or
PTS4 request bytes back unchanged. Genuine Go-generated PRA4, PTH4 and PTD4
responses and ordinary system ping replies remain allowed. Install only after
testing with packet captures; rules are not persisted across reboot by script.
USAGE
}
ACTION="${1:-show}"
if [[ $# -gt 1 ]]; then usage; exit 2; fi
case "$ACTION" in
  show|apply|remove) ;;
  *) usage; exit 2 ;;
esac
if ! command -v nft >/dev/null 2>&1; then
  echo "nft executable not found; no system change made." >&2
  exit 1
fi

if [[ "$ACTION" == "show" ]]; then
  nft list table ip "$TABLE" 2>&1 || true
  exit 0
fi
if (( EUID != 0 )); then
  echo "apply/remove requires root." >&2
  exit 1
fi
if [[ "$ACTION" == "remove" ]]; then
  nft delete table ip "$TABLE"
  echo "Removed only table ip $TABLE."
  exit 0
fi
if nft list table ip "$TABLE" >/dev/null 2>&1; then
  echo "Managed nft table already exists; inspect with 'show', then remove before reapplying." >&2
  exit 1
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "Existing secure Pingtunnel config not found; no changes made." >&2
  exit 1
fi
PEER="$(python3 - "$CONFIG" <<'PY'
import ipaddress, json, sys
config = json.load(open(sys.argv[1], encoding="utf-8"))
if config.get("region") != "iran":
    raise SystemExit("This firewall rule is only permitted on the Iran VPS.")
print(ipaddress.IPv4Address(config["peer_ip"]))
PY
)"
# Raw ICMP transport header starts after IPv4; byte offset 8 is Echo payload.
# Scope to the paired peer and reply type; do not change general ICMP behavior.
nft -f - <<NFT
add table ip $TABLE
add chain ip $TABLE output { type filter hook output priority -150; policy accept; }
add rule ip $TABLE output ip daddr $PEER ip protocol icmp icmp type echo-reply @th,64,32 0x50545234 counter drop
add rule ip $TABLE output ip daddr $PEER ip protocol icmp icmp type echo-reply @th,64,32 0x50545334 counter drop
NFT
echo "Narrow kernel PTR4/PTS4 Echo reflection suppression installed for peer $PEER."
echo "Verify with: sudo nft list table ip $TABLE"
echo "Undo with: sudo bash Source/icmp-echo-dedupe.sh remove"
