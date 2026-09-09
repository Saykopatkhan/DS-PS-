#!/bin/bash
set -e

# ========================================================================
# DS-IPS Nginx Reverse Proxy Setup Script
# ========================================================================

if [ "$EUID" -ne 0 ]; then
    echo "[!] ERROR: Root privileges are required to configure Nginx."
    echo "[*] Please run with sudo: sudo ./setup_nginx.sh"
    exit 1
fi

if ! command -v nginx >/dev/null 2>&1; then
    echo "[+] Installing Nginx..."
    apt-get update -y
    apt-get install -y nginx
fi

CONFIG_AVAILABLE="/etc/nginx/sites-available/ds_ips_dashboard"
CONFIG_ENABLED="/etc/nginx/sites-enabled/ds_ips_dashboard"

echo "[+] Writing Nginx configuration to $CONFIG_AVAILABLE..."

cat <<'EOF' > "$CONFIG_AVAILABLE"
# ========================================================================
# DS-IPS Dashboard Reverse Proxy & Security Configuration
# ========================================================================

# 1. Rate Limiting: 5 requests per second per IP (Brute Force Protection)
limit_req_zone $binary_remote_addr zone=ds_ips_req_limit:10m rate=5r/s;

# 2. Connection Limiting: Max connections per IP (Slowloris Protection)
limit_conn_zone $binary_remote_addr zone=ds_ips_conn_limit:10m;

# 3. Map for WebSocket connection headers
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Client Request & Timeout Hardening (Slowloris Mitigation)
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 15s;
    send_timeout 10s;
    client_max_body_size 50M;

    # Apply Connection Limit (Max 10 concurrent connections per IP)
    limit_conn ds_ips_conn_limit 10;

    # Root location
    location / {
        # Apply Rate Limit: 5 req/s with burst of 10
        limit_req zone=ds_ips_req_limit burst=10 nodelay;

        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;

        # WebSocket & Header Forwarding
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Dedicated WebSocket endpoint for Socket.IO
    location /socket.io/ {
        proxy_pass http://127.0.0.1:5000/socket.io/;
        proxy_http_version 1.1;
        proxy_buffering off;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 60s;
        proxy_send_timeout 86400s;
        proxy_read_timeout 86400s;
    }
}
EOF

# Disable default nginx site if present
if [ -f /etc/nginx/sites-enabled/default ]; then
    echo "[*] Disabling default Nginx site..."
    rm -f /etc/nginx/sites-enabled/default
fi

# Enable ds_ips_dashboard
echo "[+] Enabling ds_ips_dashboard site..."
ln -sf "$CONFIG_AVAILABLE" "$CONFIG_ENABLED"

# Test configuration syntax
echo "[+] Testing Nginx configuration syntax..."
nginx -t

# Restart Nginx service (WSL/Container uyumluluğu için service kullanıyoruz)
echo "[+] Restarting Nginx service..."
service nginx restart || /etc/init.d/nginx restart

echo "[✔] Nginx reverse proxy configured and active on port 80!"
