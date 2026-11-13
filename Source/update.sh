#!/usr/bin/env bash
# Use the installed manager's version-tag and immutable-commit verifier.
# Never fetch and execute mutable main branch code with elevated privileges.
set -Eeuo pipefail
if (( EUID != 0 )); then echo "Run as root with sudo." >&2; exit 1; fi
if [[ ! -x /usr/local/bin/pingtunnel ]]; then
  echo "Missing Pingtunnel manager; install an explicitly tagged release first." >&2
  exit 1
fi
exec /usr/local/bin/pingtunnel update
