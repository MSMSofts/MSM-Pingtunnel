#!/usr/bin/env bash
# Compatibility entry point; the new default is the Rust manager.
set -Eeuo pipefail
if (( EUID != 0 )); then echo "Run with sudo." >&2; exit 1; fi
temp="$(mktemp)"
trap 'rm -f "$temp"' EXIT
curl -fsSL --retry 3 https://raw.githubusercontent.com/meysamrn/Pingtunnel_manager/main/Source/install.sh -o "$temp"
bash "$temp"
