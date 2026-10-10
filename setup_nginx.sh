#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$EUID" -ne 0 ]]; then
    echo "[!] Nginx yapılandırması için root yetkisi gerekir." >&2
    exit 1
fi
if ! command -v nginx >/dev/null 2>&1; then
    echo "[!] Önce dağıtımınızın paket yöneticisiyle nginx kurun." >&2
    exit 1
fi
: "${DSIPS_SERVER_NAME:?Panelin alan adını DSIPS_SERVER_NAME ile belirtin}"
: "${DSIPS_TLS_CERT:?TLS sertifikasını DSIPS_TLS_CERT ile belirtin}"
: "${DSIPS_TLS_KEY:?TLS anahtarını DSIPS_TLS_KEY ile belirtin}"
if [[ ! "$DSIPS_SERVER_NAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; then
    echo "[!] Geçersiz alan adı." >&2
    exit 1
fi
for cert_path in "$DSIPS_TLS_CERT" "$DSIPS_TLS_KEY"; do
    if [[ ! "$cert_path" =~ ^/[a-zA-Z0-9_./-]+$ || ! -f "$cert_path" ]]; then
        echo "[!] Sertifika yolları mevcut, mutlak ve boşluksuz olmalıdır." >&2
        exit 1
    fi
done

CONFIG_PATH=/etc/nginx/conf.d/ds_ips_dashboard.conf
if [[ -e /etc/nginx/sites-enabled/ds_ips_dashboard ]]; then
    echo "[!] Eski sites-enabled/ds_ips_dashboard yapılandırmasını önce taşıyın; mevcut dosya korunuyor." >&2
    exit 1
fi
mkdir -p /etc/nginx/conf.d
STAGING_DIR="$(mktemp -d)"
HAD_CONFIG=false
INSTALLED=false
if [[ -e "$CONFIG_PATH" ]]; then
    cp -p "$CONFIG_PATH" "$STAGING_DIR/previous.conf"
    HAD_CONFIG=true
fi
cleanup() {
    if [[ "$INSTALLED" == true ]]; then
        if [[ "$HAD_CONFIG" == true ]]; then
            cp -p "$STAGING_DIR/previous.conf" "$CONFIG_PATH"
        else
            rm -f "$CONFIG_PATH"
        fi
    fi
    rm -rf "$STAGING_DIR"
}
trap cleanup EXIT
export DSIPS_SERVER_NAME DSIPS_TLS_CERT DSIPS_TLS_KEY
python3 - "$SCRIPT_DIR/config/nginx.conf.example" "$STAGING_DIR/dashboard.conf" <<'PY'
import os
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
for placeholder, variable in (("__SERVER_NAME__", "DSIPS_SERVER_NAME"),
                              ("__TLS_CERT__", "DSIPS_TLS_CERT"),
                              ("__TLS_KEY__", "DSIPS_TLS_KEY")):
    text = text.replace(placeholder, os.environ[variable])
Path(sys.argv[2]).write_text(text)
PY
INSTALLED=true
install -m 644 "$STAGING_DIR/dashboard.conf" "$CONFIG_PATH"
nginx -t
nginx -s reload
INSTALLED=false
echo "[+] HTTPS proxy hazır. .env: DS_IPS_TRUST_PROXY=true ve DS_IPS_COOKIE_SECURE=true"
