#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
DSIPS_PYTHON="${DS_IPS_BOOTSTRAP_PYTHON:-python3}"
"$DSIPS_PYTHON" -m venv .venv
"$SCRIPT_DIR/.venv/bin/python" -m pip install --upgrade pip
"$SCRIPT_DIR/.venv/bin/python" -m pip install -r requirements.txt
echo "[+] Kurulum tamamlandı. Başlatma: .venv/bin/python web_main.py --mode ids"
echo "[+] Paket yakalama için sistemde tshark/libpcap ve uygun yetkiler gerekir."
