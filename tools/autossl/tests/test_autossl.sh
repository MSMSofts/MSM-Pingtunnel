#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/autossl.sh"
[[ "$(id -u)" == 0 ]] || { echo "Run smoke tests as root on a disposable CI runner." >&2; exit 1; }
[[ ! -e /opt/autossl/acme/acme.sh ]] || { echo "Refusing to overwrite a real acme.sh installation." >&2; exit 1; }
[[ ! -d /etc/autossl/certs/example.test ]] || { echo "Refusing to overwrite an existing test domain." >&2; exit 1; }
tmp=$(mktemp -d)
cleanup() {
  rm -rf /opt/autossl/acme/acme.sh /etc/autossl/certs/example.test "$tmp"
}
trap cleanup EXIT
bash -n "$SCRIPT"
bash "$SCRIPT" help | grep -q 'systemd renewal'
if bash "$SCRIPT" issue --domain '../bad' >/dev/null 2>&1; then echo "Traversal domain accepted" >&2; exit 1; fi
if bash "$SCRIPT" issue --domain 'invalid..example.com' >/dev/null 2>&1; then echo "Invalid domain accepted" >&2; exit 1; fi
if bash "$SCRIPT" issue --domain 'example.test' --challenge webroot --webroot ../etc >/dev/null 2>&1; then echo "Relative webroot accepted" >&2; exit 1; fi
if bash "$SCRIPT" install --email 'bad@@example.com' >/dev/null 2>&1; then echo "Invalid email accepted" >&2; exit 1; fi
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=example.test \
  -keyout "$tmp/mock.key" -out "$tmp/mock.pem" >/dev/null 2>&1
mkdir -p /opt/autossl/acme "$tmp/webroot"
cat >/opt/autossl/acme/acme.sh <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
mode='' key='' full=''
while (($#)); do
  case "$1" in
    --issue|--install-cert|--cron) mode="$1"; shift ;;
    --key-file) key="$2"; shift 2 ;;
    --fullchain-file) full="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "$mode" in
  --issue|--cron) exit 0 ;;
  --install-cert)
    cp "$MOCK_KEY" "$key"
    cp "$MOCK_CERT" "$full"
    exit 0 ;;
  *) exit 1 ;;
esac
MOCK
chmod 700 /opt/autossl/acme/acme.sh
export MOCK_KEY="$tmp/mock.key" MOCK_CERT="$tmp/mock.pem"
bash "$SCRIPT" issue --domain example.test --challenge webroot --webroot "$tmp/webroot"
bash "$SCRIPT" status --domain example.test | grep -q 'notAfter='
bash "$SCRIPT" renew
[[ -s /etc/autossl/certs/example.test/private.pem ]]
[[ -s /etc/autossl/certs/example.test/fullchain.pem ]]
[[ "$(stat -c %a /etc/autossl/certs/example.test/private.pem)" == 600 ]]
echo "AutoSSL mocked smoke checks: PASS"
