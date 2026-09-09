# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
DNS Sinkhole & Karantina Bildirim Sunucusu Modülü (Port 8099).
Karantinaya alınan veya zararlı DNS istekleri atan cihazları
özel bilgilendirme sayfasına yönlendirir.
"""

import threading
import subprocess
import logging
from flask import Flask, request, render_template_string

logger = logging.getLogger("DSIPS_DNSSinkhole")

QUARANTINE_HTML = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>DS-IPS | Karantina Bildirimi</title>
    <style>
        body {
            background-color: #0a0f1d;
            color: #00f2fe;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            overflow: hidden;
        }
        .container {
            background: rgba(15, 23, 42, 0.95);
            border: 2px solid #ff2a2a;
            border-radius: 16px;
            padding: 40px;
            text-align: center;
            max-width: 550px;
            box-shadow: 0 0 30px rgba(255, 42, 42, 0.4);
            backdrop-filter: blur(10px);
        }
        .shield-icon {
            font-size: 70px;
            color: #ff2a2a;
            animation: pulse 1.5s infinite;
        }
        h1 {
            color: #ff2a2a;
            margin-top: 10px;
            font-size: 26px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        p {
            color: #94a3b8;
            line-height: 1.6;
            font-size: 15px;
        }
        .ip-box {
            background: rgba(255, 42, 42, 0.1);
            border: 1px dashed #ff2a2a;
            padding: 10px 15px;
            border-radius: 8px;
            color: #fff;
            font-weight: bold;
            font-family: monospace;
            margin: 20px 0;
            display: inline-block;
        }
        .footer {
            font-size: 12px;
            color: #64748b;
            margin-top: 25px;
        }
        @keyframes pulse {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.8; }
            100% { transform: scale(1); opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield-icon">🔒</div>
        <h1>Cihazınız Karantinaya Alındı</h1>
        <p>Ağınızdaki <strong>DS-IPS (Intrusion Prevention System)</strong> güvenlik motoru, cihazınızdan şüpheli veya zararlı ağ aktiviteleri tespit etmiştir.</p>
        <div class="ip-box">Karantinadaki IP: {{ ip }}</div>
        <p>İnternet ve ağ erişiminiz güvenlik nedeniyle geçici olarak kısıtlanmıştır. Sistem yöneticiniz ile iletişime geçiniz.</p>
        <div class="footer">DS-IPS Active Defense Engine v5.0 | Protected by Kadir Kırmacı</div>
    </div>
</body>
</html>
"""

class DNSSinkhole:
    def __init__(self, port=8099, db=None):
        self.port = port
        self.db = db
        self.app = Flask("dns_sinkhole")
        self.quarantined_ips = set()
        self.blocklist = []
        self.blocklist_path = 'assets/dns_blocklist.json'
        self.load_blocklist()

        @self.app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
        @self.app.route('/<path:path>', methods=['GET', 'POST'])
        def quarantine_page(path):
            user_ip = request.remote_addr
            
            # Mobil Cihazlar (Captive Portal) için HTTP 200 dönmek zorunludur.
            # Apple cihazları '/hotspot-detect.html', Android cihazları '/generate_204' bekler.
            if request.path in ['/hotspot-detect.html', '/generate_204', '/canonical.html', '/ncsi.txt']:
                return render_template_string(QUARANTINE_HTML, ip=user_ip), 200
                
            return render_template_string(QUARANTINE_HTML, ip=user_ip), 403

    def load_blocklist(self):
        import json, os
        try:
            if os.path.exists(self.blocklist_path):
                with open(self.blocklist_path, 'r') as f:
                    self.blocklist = json.load(f)
            else:
                self.blocklist = ['malware.com', 'phishing.net', 'hacker.io']
        except Exception as e:
            logger.error(f"[!] Error loading blocklist: {e}")
            self.blocklist = ['malware.com', 'phishing.net', 'hacker.io']

    def update_blocklist(self, domains):
        import json, os
        try:
            os.makedirs(os.path.dirname(self.blocklist_path), exist_ok=True)
            with open(self.blocklist_path, 'w') as f:
                json.dump(domains, f)
            self.blocklist = domains
            return True
        except Exception as e:
            logger.error(f"[!] Error saving blocklist: {e}")
            return False

    def is_blocked(self, domain):
        """Check if a domain is in the blocklist."""
        # domain might have a trailing dot
        clean_domain = domain.rstrip('.').lower()
        for bad in self.blocklist:
            if bad.lower() in clean_domain:
                return True
        return False

    def start(self):
        """Karantina Web Portalını başlatır."""
        import logging
        log = logging.getLogger('werkzeug')
        log.disabled = True
        
        t = threading.Thread(
            target=lambda: self.app.run(host='0.0.0.0', port=self.port, debug=False, use_reloader=False),
            daemon=True
        )
        t.start()
        logger.info(f"[+] DNS Sinkhole / Karantina Portalı port {self.port} üzerinde aktif.")
        
        # UDP 53 DNS Dinleyicisini başlat
        t_dns = threading.Thread(target=self._start_dns_server, daemon=True)
        t_dns.start()

    def _start_dns_server(self):
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', 53))
            logger.info("[+] DNS Sinkhole / UDP 53 dinleyicisi aktif.")
            
            while True:
                try:
                    data, addr = sock.recvfrom(512)
                    if len(data) >= 12:
                        tx_id = data[:2]
                        flags = b'\x81\x80'
                        counts = b'\x00\x01\x00\x01\x00\x00\x00\x00'
                        query = data[12:]
                        # 127.0.0.1 (Karantina portaline) yönlendiriyoruz
                        answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01'
                        response = tx_id + flags + counts + query + answer
                        sock.sendto(response, addr)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"[!] DNS Sinkhole UDP 53 dinleyicisi başlatılamadı: {e}")


    def redirect_to_quarantine(self, ip):
        """Saldırgan IP trafiğini Karantina web portalına (8099) yönlendirir.
        Hem direkt hem ağ geçidi modunda çalışır. HTTP → Karantina portali, diğer trafik → DROP."""
        try:
            rules_added = 0
            my_ip = None
            try:
                result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                my_ip = result.stdout.strip().split()[0]
            except Exception:
                my_ip = '127.0.0.1'
            
            # Kural 1: HTTP trafiğini karantina portalına yönlendir (PREROUTING - direkt)
            check = subprocess.run(f"iptables -t nat -C PREROUTING -p tcp -s {ip} --dport 80 -j REDIRECT --to-ports {self.port}",
                                 shell=True, capture_output=True)
            if check.returncode != 0:
                subprocess.run(f"iptables -t nat -A PREROUTING -p tcp -s {ip} --dport 80 -j REDIRECT --to-ports {self.port}",
                             shell=True, check=True, capture_output=True)
                rules_added += 1
            
            # Kural 2: Gateway modunda HTTP trafiğini DNAT ile karantina portalına yönlendir
            if my_ip:
                check2 = subprocess.run(f"iptables -t nat -C PREROUTING -p tcp -s {ip} --dport 80 -j DNAT --to-destination {my_ip}:{self.port}",
                                       shell=True, capture_output=True)
                if check2.returncode != 0:
                    subprocess.run(f"iptables -t nat -A PREROUTING -p tcp -s {ip} --dport 80 -j DNAT --to-destination {my_ip}:{self.port}",
                                 shell=True, capture_output=True)
                    rules_added += 1

            # Kural 3: HTTPS (443) trafiğini engelle (sertifika olmadan yönlendirilemez)
            check3 = subprocess.run(f"iptables -C FORWARD -s {ip} -p tcp --dport 443 -j DROP",
                                  shell=True, capture_output=True)
            if check3.returncode != 0:
                subprocess.run(f"iptables -I FORWARD -s {ip} -p tcp --dport 443 -j DROP",
                             shell=True, check=True, capture_output=True)
                rules_added += 1
            
            # Kural 4: Mobil QUIC (HTTP/3 - UDP 443) Engelle (Cihazı TCP'ye zorla)
            check4 = subprocess.run(f"iptables -C FORWARD -s {ip} -p udp --dport 443 -j REJECT",
                                  shell=True, capture_output=True)
            if check4.returncode != 0:
                subprocess.run(f"iptables -I FORWARD -s {ip} -p udp --dport 443 -j REJECT",
                             shell=True, capture_output=True)
                rules_added += 1

            # Kural 5: DoT (DNS over TLS - Port 853) Engelle
            check5 = subprocess.run(f"iptables -C FORWARD -s {ip} -p tcp --dport 853 -j REJECT",
                                  shell=True, capture_output=True)
            if check5.returncode != 0:
                subprocess.run(f"iptables -I FORWARD -s {ip} -p tcp --dport 853 -j REJECT",
                             shell=True, capture_output=True)
                subprocess.run(f"iptables -I FORWARD -s {ip} -p udp --dport 853 -j REJECT",
                             shell=True, capture_output=True)
                
            # Kural 6: Bilinen DoH Sunucularını Engelle (Google, Cloudflare, Quad9)
            for doh_ip in ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9']:
                subprocess.run(f"iptables -I FORWARD -s {ip} -d {doh_ip} -j REJECT", shell=True, capture_output=True)

            # Kural 7: Sadece Kendi UDP 53'ümüze (DNS Sinkhole) izin ver, diğerlerini düşür
            check7 = subprocess.run(f"iptables -C FORWARD -s {ip} -p udp --dport 53 -j ACCEPT",
                                  shell=True, capture_output=True)
            if check7.returncode != 0:
                subprocess.run(f"iptables -I FORWARD -s {ip} -p udp --dport 53 -j ACCEPT",
                             shell=True, capture_output=True)
            
            check8 = subprocess.run(f"iptables -C FORWARD -s {ip} -p tcp --dport 80 -j ACCEPT",
                                  shell=True, capture_output=True)
            if check8.returncode != 0:
                subprocess.run(f"iptables -I FORWARD -s {ip} -p tcp --dport 80 -j ACCEPT",
                             shell=True, capture_output=True)
                
            # Son olarak: tüm geri kalan trafiği engelle 
            check9 = subprocess.run(f"iptables -C FORWARD -s {ip} -j DROP",
                                  shell=True, capture_output=True)
            if check9.returncode != 0:
                subprocess.run(f"iptables -A FORWARD -s {ip} -j DROP",
                             shell=True, check=True, capture_output=True)
                rules_added += 1
            
            self.quarantined_ips.add(ip)
            logger.info(f"[+] IP {ip} Karantina Portalına ({self.port}) yönlendirildi ({rules_added} kural).")
            return True
        except Exception as e:
            logger.error(f"[!] Karantina yönlendirme hatası: {e}")
            return False

    def remove_quarantine_redirect(self, ip):
        """Karantina yönlendirmesini kaldırır (tüm zincirlerden)."""
        try:
            my_ip = None
            try:
                result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                my_ip = result.stdout.strip().split()[0]
            except Exception:
                pass
            
            # Tüm karantina kurallarını temizle
            subprocess.run(f"iptables -t nat -D PREROUTING -p tcp -s {ip} --dport 80 -j REDIRECT --to-ports {self.port}",
                         shell=True, capture_output=True)
            if my_ip:
                subprocess.run(f"iptables -t nat -D PREROUTING -p tcp -s {ip} --dport 80 -j DNAT --to-destination {my_ip}:{self.port}",
                             shell=True, capture_output=True)
            subprocess.run(f"iptables -D FORWARD -s {ip} -p tcp --dport 443 -j DROP",
                         shell=True, capture_output=True)
            subprocess.run(f"iptables -D FORWARD -s {ip} -p udp --dport 443 -j REJECT",
                         shell=True, capture_output=True)
            subprocess.run(f"iptables -D FORWARD -s {ip} -p tcp --dport 853 -j REJECT",
                         shell=True, capture_output=True)
            subprocess.run(f"iptables -D FORWARD -s {ip} -p udp --dport 853 -j REJECT",
                         shell=True, capture_output=True)
            
            for doh_ip in ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9']:
                subprocess.run(f"iptables -D FORWARD -s {ip} -d {doh_ip} -j REJECT", shell=True, capture_output=True)

            subprocess.run(f"iptables -D FORWARD -s {ip} -p udp --dport 53 -j ACCEPT",
                         shell=True, capture_output=True)
            subprocess.run(f"iptables -D FORWARD -s {ip} -p tcp --dport 80 -j ACCEPT",
                         shell=True, capture_output=True)
            subprocess.run(f"iptables -D FORWARD -s {ip} -j DROP",
                         shell=True, capture_output=True)
            self.quarantined_ips.discard(ip)
            logger.info(f"[-] IP {ip} karantinası kaldırıldı.")
            return True
        except Exception as e:
            logger.error(f"[!] Untrap quarantine hatası: {e}")
            return False
