# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
DS IPS Web Panel - Flask + SocketIO Sunucusu.
Gerçek zamanlı dashboard için REST API ve WebSocket desteği sağlar.
"""
import os
import sys
import time
import threading
import csv
import io
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO, emit

# Proje kök dizinini sys.path'e ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import Database
from core.sniffer import PacketSniffer
from modules.arp_detector import ARPDetector
from modules.scan_detector import ScanDetector
from modules.wifi_detector import WiFiDetector
from modules.dns_detector import DNSDetector
from modules.dhcp_detector import DHCPDetector
from modules.honeypot import Honeypot
from modules.threat_intel import ThreatIntelDetector
from modules.anti_evasion import AntiEvasionDetector
from responder.blocker import Blocker


class IPSWebApp:
    """
    DS IPS Web Panel uygulaması.
    Flask + SocketIO ile gerçek zamanlı dashboard sunar.
    """
    def __init__(self, interface='eth0', mode='ids', wifi_enabled=False,
                 db_path='ds_ips.db', unban_time=3600):
        # Flask uygulaması
        self.app = Flask(__name__,
                         template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
                         static_folder=os.path.join(os.path.dirname(__file__), 'static'))
        import secrets
        self.app.config['SECRET_KEY'] = os.environ.get('DS_IPS_SECRET_KEY', secrets.token_hex(32))
        self.socketio = SocketIO(self.app, cors_allowed_origins=None, async_mode='threading')

        # IPS bileşenleri
        self.interface = interface
        self.mode = mode
        self.wifi_enabled = wifi_enabled
        self.db = Database(db_path)
        self.db.set_socketio(self.socketio)

        # Blocker (sadece IPS modunda)
        self.blocker = None
        if self.mode == 'ips':
            self.blocker = Blocker(self.db, auto_unban_time=unban_time, interface=self.interface)

        # Notifier entegrasyonu (Ayarlardan çekecek)
        from responder.notifier import Notifier
        self.notifier = Notifier()
        self._update_notifier_config()
        self.db.set_alert_callback(self._handle_alert)


        
        # Detektörler
        self.arp_detector = ARPDetector(self.db, self.blocker, auto_ban=False)
        self.scan_detector = ScanDetector(self.db, self.blocker, auto_ban=False)
        self.dns_detector = DNSDetector(self.db, self.blocker, auto_ban=False)
        self.dhcp_detector = DHCPDetector(self.db, self.blocker, auto_ban=False)
        self.honeypot = Honeypot(self.db, self.blocker, auto_ban=False)
        from modules.ssh_honeypot import SSHHoneypot
        self.ssh_honeypot = SSHHoneypot(self.db, self.blocker, auto_ban=False, port=22)
        self.threat_intel = ThreatIntelDetector(self.db, self.blocker, auto_ban=False)
        self.anti_evasion = AntiEvasionDetector(self.db, self.blocker, auto_ban=False)
        from modules.decoy_traffic import DecoyTrafficGenerator
        self.decoy_generator = DecoyTrafficGenerator()
        self.wifi_detector = None
        if self.wifi_enabled:
            self.wifi_detector = WiFiDetector(self.db, self.blocker, auto_ban=False)

        # Sniffer ve Scanner
        self.sniffer = PacketSniffer(interface=self.interface)
        self.sniffer.register_callback(self.arp_detector.analyze)
        self.sniffer.register_callback(self.scan_detector.analyze)
        self.sniffer.register_callback(self.dns_detector.analyze)
        self.sniffer.register_callback(self.dhcp_detector.analyze)
        self.sniffer.register_callback(self.threat_intel.analyze)
        self.sniffer.register_callback(self.anti_evasion.analyze)
        if self.wifi_detector:
            self.sniffer.register_callback(self.wifi_detector.analyze)
            
        from core.scanner import NetworkScanner
        self.scanner = NetworkScanner(self.db, interface=self.interface)

        self.sniffer_running = False
        self.start_time = None

        self.failed_attempts = {}
        self.failed_attempts_lock = threading.Lock()

        import secrets
        self.admin_user = os.environ.get('DS_IPS_USER')
        self.admin_pass = os.environ.get('DS_IPS_PASS')
        if not self.admin_user or not self.admin_pass:
            self.admin_user = 'admin'
            self.admin_pass = secrets.token_hex(8)
            print(f"\n\033[91m[!] DİKKAT: DS_IPS_USER veya DS_IPS_PASS ortam değişkenleri bulunamadı.\033[0m")
            print(f"\033[93m[!] Güvenliğiniz için rastgele şifre üretildi:\033[0m")
            print(f"\033[92m[+] Kullanıcı Adı: {self.admin_user}\033[0m")
            print(f"\033[92m[+] Şifre: {self.admin_pass}\033[0m\n")

        self.ws_token = secrets.token_hex(16)

        # Route'ları ve event'leri kaydet
        print("[DEBUG] Calling _register_routes...")
        self._register_routes()
        print("[DEBUG] Done calling _register_routes...")
        self._register_socketio_events()

    def _register_routes(self):
        """Flask route'larını kaydeder."""
        print("[DEBUG] Registering routes...")

        @self.app.before_request
        def require_auth():
            # Static dosyaları, Socket.IO ve Bubi Tuzaklarını şifreden muaf tut
            if (request.path.startswith('/static') or 
                request.path.startswith('/socket.io') or
                request.path in ['/sirket_sifreleri.pdf', '/banka_bilgileri.xlsx']):
                return None
                
            import hmac
            client_ip = request.remote_addr
            now = time.time()
            
            with self.failed_attempts_lock:
                # Bellek sızıntısını önlemek için süresi dolan IP'leri temizle (DS-11)
                keys_to_delete = [ip for ip, rec in self.failed_attempts.items() if now - rec.get('last_seen', now) > 3600]
                for k in keys_to_delete:
                    self.failed_attempts.pop(k, None)
                
                # Ban kontrolü
                if client_ip in self.failed_attempts:
                    record = self.failed_attempts[client_ip]
                    record['last_seen'] = now
                    if record['lockout_until'] > now:
                        remaining = int((record['lockout_until'] - now) / 60)
                        return Response(
                            f'Bruteforce Korumasi Aktif! 3 kez hatali giris yaptiniz. Lutfen {remaining} dakika sonra tekrar deneyin.', 429
                        )
                    elif record['lockout_until'] != 0 and record['lockout_until'] <= now:
                        self.failed_attempts[client_ip] = {'count': 0, 'lockout_until': 0, 'last_seen': now}
                else:
                    self.failed_attempts[client_ip] = {'count': 0, 'lockout_until': 0, 'last_seen': now}

            # CSRF Koruması (DS-09) - POST/PUT isteklerinde header zorunlu
            if request.method in ['POST', 'PUT', 'DELETE']:
                if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
                    return "CSRF Koruması: X-Requested-With header eksik.", 403

            auth = request.authorization
            
            if not auth or not hmac.compare_digest(auth.username, self.admin_user) or not hmac.compare_digest(auth.password, self.admin_pass):
                # Yanlış şifre denemesi
                if auth:
                    with self.failed_attempts_lock:
                        self.failed_attempts[client_ip]['count'] += 1
                        if self.failed_attempts[client_ip]['count'] >= 3:
                            self.failed_attempts[client_ip]['lockout_until'] = now + (30 * 60)
                            return Response('Cok fazla hatali deneme! 30 dakika banlandiniz.', 429)
                        
                return Response(
                    'Yetkisiz Erisim! Lutfen kullanici adi ve sifre girin.', 401,
                    {'WWW-Authenticate': 'Basic realm="DS IPS Yonetim Paneli"'}
                )
            
            # Başarılı giriş: Hata sayacını sıfırla
            with self.failed_attempts_lock:
                self.failed_attempts[client_ip] = {'count': 0, 'lockout_until': 0, 'last_seen': now}

        @self.app.after_request
        def add_security_headers(response):
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            return response

        @self.app.route('/api/ws_token')
        def get_ws_token():
            return jsonify({'token': self.ws_token})

        @self.app.route('/')
        def index():
            return render_template('index.html', current_interface=self.interface)

        @self.app.route('/api/alerts')
        def get_alerts():
            limit = request.args.get('limit', 50, type=int)
            alerts = self.db.get_alerts(limit=limit)
            return jsonify(alerts)

        @self.app.route('/api/stats')
        def get_stats():
            return jsonify(self._get_stats())

        @self.app.route('/api/bans')
        def get_bans():
            bans = self.db.get_active_bans()
            return jsonify(bans)
        @self.app.route('/sirket_sifreleri.pdf')
        @self.app.route('/banka_bilgileri.xlsx')
        def honeytoken_trigger():
            client_ip = request.remote_addr
            filename = request.path.lstrip('/')
            
            # Kendi IP'sinden geliyorsa (veya localhost ise)
            if client_ip == '127.0.0.1':
                pass # Kendi testleri için alert üretmeyebiliriz veya üretiriz. Üretelim.
                
            self.db.add_alert(
                alert_type='Canary Token İhlali (Bubi Tuzağı)',
                src_ip=client_ip, src_mac='N/A',
                dst_ip='N/A', dst_mac='N/A',
                description=f"Hacker gizli sisteme sızıp şu sahte dosyayı indirmeye çalıştı: {filename}",
                severity='critical'
            )
            from utils.sound import SoundAlert
            SoundAlert.alert_attack("Bubi Tuzağı İhlali")
            return "This file is corrupted or you do not have permission to read it.", 403
        @self.app.route('/api/ban', methods=['POST'])
        def add_ban():
            data = request.get_json()
            ip = data.get('ip', '').strip()
            mac = data.get('mac', '').strip()
            reason = data.get('reason', 'Manuel ban')

            if not ip and not mac:
                return jsonify({'success': False, 'error': 'IP veya MAC adresi gerekli'}), 400

            try:
                if self.blocker:
                    if ip:
                        self.blocker.block_ip(ip, reason=reason)
                    if mac:
                        self.blocker.block_mac(mac, reason=reason)
                else:
                    self.db.add_ban(ip=ip or None, mac=mac or None, reason=reason)
                return jsonify({'success': True})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/unban', methods=['POST'])
        def remove_ban():
            data = request.get_json()
            ip = data.get('ip', '').strip() or None
            mac = data.get('mac', '').strip() or None

            try:
                if self.blocker:
                    if ip:
                        self.blocker.unblock_ip(ip)
                    if mac:
                        self.blocker.unblock_mac(mac)
                else:
                    self.db.remove_ban(ip=ip, mac=mac)
                return jsonify({'success': True})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/control', methods=['POST'])
        def control():
            data = request.get_json()
            action = data.get('action')

            if action == 'start':
                if not self.sniffer_running:
                    new_interface = data.get('interface', self.interface)
                    if new_interface != self.interface:
                        self.interface = new_interface
                        self.sniffer = PacketSniffer(interface=self.interface)
                        self.sniffer.register_callback(self.arp_detector.analyze)
                        self.sniffer.register_callback(self.scan_detector.analyze)
                        self.sniffer.register_callback(self.dns_detector.analyze)
                        self.sniffer.register_callback(self.dhcp_detector.analyze)
                        self.sniffer.register_callback(self.threat_intel.analyze)
                        self.sniffer.register_callback(self.anti_evasion.analyze)
                        if self.wifi_detector:
                            self.sniffer.register_callback(self.wifi_detector.analyze)
                        self.scanner = NetworkScanner(self.db, interface=self.interface)
                        if self.blocker:
                            self.blocker.interface = self.interface
                            
                    self.sniffer.start()
                    self.honeypot.start()
                    self.ssh_honeypot.start()
                    self.decoy_generator.start()
                    self.scanner.start_periodic(60) # Her 60 saniyede bir ağ taraması yap
                    self.sniffer_running = True
                    self.start_time = time.time()
                    self.socketio.emit('status_update', {'running': True}, namespace='/')
                return jsonify({'success': True, 'running': True})

            elif action == 'stop':
                if self.sniffer_running:
                    self.sniffer.stop()
                    self.honeypot.stop()
                    self.ssh_honeypot.stop()
                    self.decoy_generator.stop()
                    self.scanner.stop()
                    self.sniffer_running = False
                    self.socketio.emit('status_update', {'running': False}, namespace='/')
                return jsonify({'success': True, 'running': False})

            return jsonify({'success': False, 'error': 'Geçersiz aksiyon'}), 400

        @self.app.route('/api/records')
        def get_records():
            records = self.db.get_ip_mac_records(limit=100)
            return jsonify(records)
            
        @self.app.route('/api/dns_logs', defaults={'ip': None})
        @self.app.route('/api/dns_logs/<ip>')
        def get_dns_logs_api(ip):
            limit = request.args.get('limit', 100, type=int)
            logs = self.db.get_dns_logs(ip=ip, limit=limit)
            return jsonify(logs)
            
        @self.app.route('/api/scan', methods=['POST'])
        def run_network_scan():
            try:
                # Arka planda taramayı başlat (blocking olmaması için thread)
                def scan_worker():
                    self.scanner.scan_once()
                    records = self.db.get_ip_mac_records(limit=100)
                    try:
                        self.socketio.emit('scan_complete', {'success': True, 'records': records}, namespace='/')
                    except Exception:
                        pass
                
                t = threading.Thread(target=scan_worker, daemon=True)
                t.start()
                return jsonify({'success': True, 'message': 'Tarama başlatıldı'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/settings', methods=['GET', 'POST'])
        def manage_settings():
            if request.method == 'GET':
                dw = self.db.get_setting('discord_webhook', '')
                tt = self.db.get_setting('telegram_token', '')
                return jsonify({
                    'discord_webhook': '********' if dw else '',
                    'telegram_token': '********' if tt else '',
                    'telegram_chat_id': self.db.get_setting('telegram_chat_id', '')
                })
            else:
                data = request.get_json()
                dw = data.get('discord_webhook', '')
                if dw and dw != '********':
                    if not dw.startswith('https://discord.com/'):
                        return jsonify({'success': False, 'error': 'Sadece discord.com adresine izin verilir (SSRF Koruması)'}), 400
                    self.db.set_setting('discord_webhook', dw)
                elif dw == '':
                    self.db.set_setting('discord_webhook', '')

                tt = data.get('telegram_token', '')
                if tt and tt != '********':
                    self.db.set_setting('telegram_token', tt)
                elif tt == '':
                    self.db.set_setting('telegram_token', '')

                tc = data.get('telegram_chat_id', '')
                if tc:
                    self.db.set_setting('telegram_chat_id', tc)

                self._update_notifier_config()
                return jsonify({'success': True})
                
        def sanitize_csv(val):
            s = str(val)
            if s.startswith(('=', '+', '-', '@', '\t', '\r')):
                return "'" + s
            return s

        @self.app.route('/api/export/alerts')
        def export_alerts():
            alerts = self.db.get_alerts(limit=10000)
            si = io.StringIO()
            cw = csv.writer(si)
            cw.writerow(['ID', 'Zaman', 'Tip', 'Kaynak IP', 'Kaynak MAC', 'Hedef IP', 'Açıklama', 'Seviye'])
            for a in alerts:
                cw.writerow([sanitize_csv(x) for x in [a['id'], a['timestamp'], a['alert_type'], a['source_ip'], a['source_mac'], a['destination_ip'], a['description'], a['severity']]])
            return Response(si.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=alerts.csv'})

        @self.app.route('/api/export/devices')
        def export_devices():
            records = self.db.get_ip_mac_records(limit=10000)
            si = io.StringIO()
            cw = csv.writer(si)
            cw.writerow(['IP Adresi', 'MAC Adresi', 'Marka', 'Hostname', 'OS Tipi', 'Tehdit Skoru', 'İlk Görülme', 'Son Görülme'])
            for r in records:
                cw.writerow([sanitize_csv(x) for x in [r['ip_address'], r['mac_address'], r.get('vendor',''), r.get('hostname',''), r.get('os_type',''), r.get('threat_score',0), r['first_seen'], r['last_seen']]])
            return Response(si.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=devices.csv'})

    def _update_notifier_config(self):
        """Ayarları veritabanından çekerek Notifier'ı günceller."""
        self.notifier.discord_webhook = self.db.get_setting('discord_webhook')
        self.notifier.telegram_token = self.db.get_setting('telegram_token')
        self.notifier.telegram_chat_id = self.db.get_setting('telegram_chat_id')

    def _register_socketio_events(self):
        """SocketIO event handler'larını kaydeder."""

        @self.socketio.on('connect')
        def handle_connect(auth):
            import hmac
            if not auth or not hmac.compare_digest(auth.get('token', ''), self.ws_token):
                return False
            emit('status_update', {'running': self.sniffer_running})
            emit('stats_update', self._get_stats())

        @self.socketio.on('request_stats')
        def handle_request_stats():
            emit('stats_update', self._get_stats())

    def _get_stats(self):
        """Sistem istatistiklerini toplar."""
        uptime = 0
        if self.start_time and self.sniffer_running:
            uptime = int(time.time() - self.start_time)

        return {
            'sniffer_running': self.sniffer_running,
            'mode': self.mode.upper(),
            'interface': self.interface,
            'wifi_enabled': self.wifi_enabled,
            'uptime': uptime,
            'total_alerts': self.db.get_total_alert_count(),
            'active_bans': self.db.get_active_ban_count(),
            'alert_counts': self.db.get_alert_counts(),
            'arp_stats': self.arp_detector.get_stats(),
            'scan_stats': self.scan_detector.get_stats(),
            'wifi_stats': self.wifi_detector.get_stats() if self.wifi_detector else {}
        }

    def _stats_broadcaster(self):
        """Periyodik olarak istatistikleri WebSocket üzerinden gönderir."""
        while True:
            time.sleep(3)
            try:
                stats = self._get_stats()
                self.socketio.emit('stats_update', stats, namespace='/')
            except Exception:
                pass

    def _handle_alert(self, alert_data):
        if alert_data.get('severity', '').lower() == 'critical':
            src_ip = alert_data.get('source_ip')
            if src_ip and src_ip != 'N/A':
                self._capture_pcap(src_ip)
                
        # Bildirim gönder
        title = f"DS IPS Alarm: {alert_data['alert_type']}"
        msg = alert_data['description']
        try:
            self.notifier.send_alert(title, msg, severity=alert_data['severity'])
        except Exception:
            pass

    def _capture_pcap(self, target_ip):
        import subprocess, time, os
        pcap_dir = os.path.join(os.path.dirname(__file__), '..', 'pcaps')
        os.makedirs(pcap_dir, exist_ok=True)
        filename = os.path.join(pcap_dir, f"attack_{target_ip}_{int(time.time())}.pcap")
        try:
            subprocess.Popen([
                'tcpdump', '-i', self.interface, 
                'host', target_ip, 
                '-w', filename, 
                '-G', '60', '-W', '1'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"\033[93m[!] Otomatik PCAP kaydı başlatıldı (60s): {filename}\033[0m")
        except Exception:
            pass

    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Web sunucusunu başlatır."""
        # İstatistik yayıncısını başlat
        stats_thread = threading.Thread(target=self._stats_broadcaster, daemon=True)
        stats_thread.start()

        print(f"\n[*] DS IPS Web Panel başlatılıyor...")
        print(f"[*] Dashboard: https://{host}:{port} (HTTPS Aktif!)")
        print(f"[*] Arayüz: {self.interface} | Mod: {self.mode.upper()} | WiFi: {'Aktif' if self.wifi_enabled else 'Pasif'}")
        print(f"[*] Ctrl+C ile kapatabilirsiniz.\n")

        self.socketio.run(self.app, host=host, port=port, debug=debug, ssl_context='adhoc')
