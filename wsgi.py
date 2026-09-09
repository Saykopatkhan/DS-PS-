#!/usr/bin/env python3
# ========================================================================
# DS-IPS (Premium SOC Edition) - WSGI Production Entrypoint
# ========================================================================

from gevent import monkey
monkey.patch_all()

import os
import sys
import threading

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from web.app import IPSWebApp

# Initialize IPSWebApp instance
webapp = IPSWebApp(
    interface='wlan0',
    mode='ips',
    wifi_enabled=True,
    db_path='ds_ips.db',
    unban_time=3600,
    dry_run=False
)

# Start real-time stats broadcaster background thread for Socket.IO updates
stats_thread = threading.Thread(target=webapp._stats_broadcaster, daemon=True)
stats_thread.start()

# Export Flask app object
app = webapp.app

if __name__ == '__main__':
    webapp.run(host='127.0.0.1', port=5000)
