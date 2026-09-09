#!/bin/bash
# ========================================================================
# DS-IPS Production Server Runner (Gunicorn + Eventlet)
# ========================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Check for root permissions (required for IPS mode / iptables blocking)
if [ "$EUID" -ne 0 ]; then
    echo "[!] UYARI: IPS modunda iptables kurallarını yönetmek için root yetkisi gereklidir."
    echo "[*] Lütfen sudo ile çalıştırın: sudo ./start_prod.sh"
    exit 1
fi

# Port 53 çakışmasını (DNS Sinkhole için) önlemek adına systemd-resolved servisini durdur
if systemctl is-active --quiet systemd-resolved; then
    echo "[*] Stopping systemd-resolved to free port 53 for DNS Sinkhole..."
    systemctl stop systemd-resolved
fi

echo "[+] Starting DS-IPS Production Server with Eventlet WSGI..."
echo "[*] Local socket: http://127.0.0.1:5000"

exec python3 wsgi.py
