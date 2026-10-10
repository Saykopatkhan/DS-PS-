#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
DSIPS_PYTHON="${DS_IPS_PYTHON:-$SCRIPT_DIR/.venv/bin/python}"
if [[ ! -x "$DSIPS_PYTHON" ]]; then
    echo "[!] Önce ./install.sh ile sanal ortamı kurun veya DS_IPS_PYTHON ayarlayın." >&2
    exit 1
fi
DSIPS_BIND="$("$DSIPS_PYTHON" -c 'from dotenv import load_dotenv; import os; load_dotenv(".env"); print(os.environ.get("DS_IPS_BIND", "127.0.0.1:5000"))')"

# One worker owns the database callbacks, sensors and firewall lifecycle.
exec "$DSIPS_PYTHON" -m gunicorn --worker-class gthread --workers 1 \
    --threads 20 --bind "$DSIPS_BIND" \
    --timeout 60 --graceful-timeout 30 --access-logfile - --error-logfile - wsgi:app
