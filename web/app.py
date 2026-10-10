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
import psutil
import secrets
import hmac
import ipaddress
import re
import logging
from datetime import datetime, timedelta
from werkzeug.exceptions import BadRequest, HTTPException
from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for, send_from_directory
from flask_socketio import SocketIO, emit, disconnect

# Proje kök dizinini sys.path'e ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import Database
from core.fast_sniffer import FastSniffer
from core.sniffer import PacketSniffer
from modules.arp_detector import ARPDetector
from modules.scan_detector import ScanDetector
from modules.dns_detector import DNSDetector
from modules.dhcp_detector import DHCPDetector
from modules.honeypot import Honeypot
from modules.threat_intel import ThreatIntelDetector
from modules.anti_evasion import AntiEvasionDetector
from modules.waf_detector import WAFDetector
from modules.dpi_detector import DPIDetector
from core.scanner import NetworkScanner
from core.active_defense import ActiveDefenseManager
from core.response_policy import ResponsePolicy
import atexit


def _text(data, key, default='', max_length=1024):
    value = data.get(key, default)
    if not isinstance(value, str) or len(value) > max_length:
        raise BadRequest(f'{key}: geçerli bir metin gerekli')
    return value.strip()


def _ip(value):
    if not isinstance(value, str) or '%' in value:
        raise BadRequest('Geçerli bir IP adresi gerekli')
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise BadRequest('Geçerli bir IP adresi gerekli') from None


def _mac(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise BadRequest('Geçerli bir MAC adresi gerekli')
    return value.lower()


def _limit(default, maximum=1000):
    value = request.args.get('limit', str(default))
    try:
        value = int(value)
    except (ValueError, TypeError):
        raise BadRequest('limit bir tam sayı olmalı') from None
    if not 1 <= value <= maximum:
        raise BadRequest(f'limit 1 ile {maximum} arasında olmalı')
    return value


def _matches(left, right):
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(
        left.encode('utf-8'), right.encode('utf-8'))


class IPSWebApp:
    """
    DS IPS Web Panel uygulaması.
    Flask + SocketIO ile gerçek zamanlı dashboard sunar.
    """
    def __init__(self, interface='eth0', mode='ids', wifi_enabled=False,
                 db_path='ds_ips.db', unban_time=3600, dry_run=False):
        # Load environment before reading credentials and session settings.
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
        from dotenv import load_dotenv
        from services import env_bool
        load_dotenv(env_path)
        if mode not in {'ids', 'ips'}:
            raise ValueError('mode ids veya ips olmalı')
        if not isinstance(interface, str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,64}', interface):
            raise ValueError('Geçersiz ağ arayüzü')
        if isinstance(unban_time, bool) or not isinstance(unban_time, int) or unban_time <= 0:
            raise ValueError('Ban süresi pozitif bir tam sayı olmalı')
        self.dry_run = dry_run
        self.sniffer_running = False
        self.start_time = None
        self._closed = False
        self._stop_event = threading.Event()
        self._lifecycle_lock = threading.RLock()
        self._scan_lock = threading.Lock()
        self._session_lock = threading.RLock()
        self._active_sessions = {}
        self._socket_sessions = {}
        self._canary_lock = threading.Lock()
        self._canary_alert_times = {}
        self._stats_thread = None
        self.app = Flask(__name__, template_folder='templates', static_folder='static')
        self.app.config.update(
            SECRET_KEY=os.environ.get('DS_IPS_SECRET_KEY') or secrets.token_hex(32),
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',
            SESSION_COOKIE_SECURE=env_bool('DS_IPS_COOKIE_SECURE'),
            PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
            MAX_CONTENT_LENGTH=1024 * 1024,
        )
        if env_bool('DS_IPS_TRUST_PROXY'):
            from werkzeug.middleware.proxy_fix import ProxyFix
            self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_for=1, x_proto=1)
        self.socketio = SocketIO(self.app, cors_allowed_origins=None, async_mode='threading')
        self.pcap_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'pcaps')

        # IPS bileşenleri
        self.interface = interface
        self.mode = mode
        self.wifi_enabled = wifi_enabled
        self.db = Database(db_path)
        self.db.set_socketio(self.socketio)
        self.active_defense_mgr = ActiveDefenseManager(db_path=db_path)

        # Blocker (sadece IPS modunda)
        self.blocker = None
        if self.mode == 'ips':
            from responder.blocker import Blocker
            self.blocker = Blocker(self.db, auto_unban_time=unban_time, interface=self.interface, dry_run=self.dry_run, active_defense_mgr=self.active_defense_mgr)
            self.dry_run = bool(self.blocker.dry_run)

        self.response_policy = ResponsePolicy(
            self.db, self.blocker, mode=self.mode, dry_run=self.dry_run,
            enabled=env_bool('DS_IPS_AUTO_RESPONSE', False))

        # Notifier entegrasyonu (Ayarlardan çekecek)
        from responder.notifier import Notifier
        self.notifier = Notifier()
        self._update_notifier_config()
        self.db.set_alert_callback(self._handle_alert)


        
        self.arp_detector = ARPDetector(self.db, getattr(self, 'blocker', None), auto_ban=False)
        self.scan_detector = ScanDetector(self.db, getattr(self, 'blocker', None), auto_ban=False)
        self.dns_detector = DNSDetector(self.db, getattr(self, 'blocker', None), auto_ban=False)
        self.dhcp_detector = DHCPDetector(self.db, getattr(self, 'blocker', None), auto_ban=False)
        
        # Aktif Savunma & Saldırgan Karşı Önlem Modülleri
        from responder.tarpit import TCPTarpit
        from responder.tcp_reset import TCPResetEngine
        from modules.dns_sinkhole import DNSSinkhole
        
        self.tarpit = TCPTarpit(db=self.db, blocker=getattr(self, 'blocker', None), dry_run=self.dry_run or self.mode != 'ips')
        
        self.tcp_reset = TCPResetEngine(interface=self.interface, db=self.db, dry_run=self.dry_run or self.mode != 'ips')
        
        self.dns_sinkhole = DNSSinkhole(db=self.db, dry_run=self.dry_run or self.mode != 'ips', interface=self.interface)
        self.dns_detector.dns_sinkhole = self.dns_sinkhole

        # Ağ Geçidi Modu (Gateway Mode) - Meşru trafik yönlendirme
        try:
            from responder.gateway_mode import GatewayMode
            self.gateway_mode = GatewayMode(interface=self.interface, db=self.db)
        except ImportError:
            self.gateway_mode = None

        self.honeypot = Honeypot(self.db, getattr(self, 'blocker', None), auto_ban=False, socketio=self.socketio, tarpit=self.tarpit)

        from modules.decoy_traffic import DecoyTrafficGenerator as DecoyGenerator
        self.decoy_generator = DecoyGenerator(dry_run=self.dry_run or self.mode != 'ips')
        from modules.ssh_honeypot import SSHHoneypot
        self.ssh_honeypot = SSHHoneypot(self.db, getattr(self, 'blocker', None), auto_ban=False, port=2222)
        self.threat_intel = ThreatIntelDetector(self.db, getattr(self, 'blocker', None), auto_ban=False)
        self.anti_evasion = AntiEvasionDetector(self.db, getattr(self, 'blocker', None), auto_ban=False)
        self.waf_detector = WAFDetector(self.db, getattr(self, 'blocker', None), auto_ban=False)
        self.dpi_detector = DPIDetector(self.db, getattr(self, 'blocker', None), auto_ban=False)

        
        from modules.c2_detector import C2BeaconingDetector
        self.c2_detector = C2BeaconingDetector(self.db, getattr(self, 'blocker', None), auto_ban=False)
        from modules.ueba_detector import UEBADetector
        self.ueba_detector = UEBADetector(self.db, getattr(self, 'blocker', None), auto_ban=False)
        from modules.vuln_scanner import VulnScanner
        self.vuln_scanner = VulnScanner(self.db, dry_run=self.dry_run)
        
        # Unverified packet sources must not initiate an automatic scan-back.
        self.scan_detector.auto_vuln_scan_cb = None
        
        self.wifi_detector = None
        if self.wifi_enabled:
            from modules.wifi_detector import WiFiDetector
            self.wifi_detector = WiFiDetector(self.db, getattr(self, 'blocker', None), auto_ban=False)

        self.sniffer = FastSniffer(interface=self.interface)
        self.sniffer.register_callback(self._handle_fast_sniffer_event)
        
        self.legacy_sniffer = PacketSniffer(interface=self.interface)
        
        # WAF Bruteforce & Dizin Tarama Koruması
        self.failed_attempts = {}
        self.failed_attempts_lock = threading.Lock()
        
        self.admin_user = os.environ.get('DS_IPS_USER') or 'admin'
        configured_password = os.environ.get('DS_IPS_PASSWORD') or os.environ.get('DS_IPS_PASS')
        self.admin_pass = configured_password or secrets.token_urlsafe(24)
        if not configured_password:
            print(f"\nDS IPS kullanıcı: {self.admin_user} | Geçici şifre: {self.admin_pass}\n")

        self.scanner = NetworkScanner(self.db, interface=self.interface)

        # Temizlik için atexit kaydı
        atexit.register(self._cleanup_on_exit)

        # Route'ları ve event'leri kaydet
        self._register_routes()
        self._register_socketio_events()
        
        # Legacy sniffer callback'leri
        self.legacy_sniffer.register_callback(self.arp_detector.analyze)
        self.legacy_sniffer.register_callback(self.scan_detector.analyze)
        self.legacy_sniffer.register_callback(self.dns_detector.analyze)
        self.legacy_sniffer.register_callback(self.dhcp_detector.analyze)
        self.legacy_sniffer.register_callback(self.threat_intel.analyze)
        self.legacy_sniffer.register_callback(self.anti_evasion.analyze)
        self.legacy_sniffer.register_callback(self.waf_detector.analyze)
        self.legacy_sniffer.register_callback(self.dpi_detector.analyze)
        self.legacy_sniffer.register_callback(self.c2_detector.analyze)
        self.legacy_sniffer.register_callback(self.ueba_detector.analyze)
        if self.wifi_detector:
            self.legacy_sniffer.register_callback(self.wifi_detector.analyze)

    def _handle_fast_sniffer_event(self, event):
        """FastSniffer'dan gelen tespitleri UI ve DB'ye yönlendirir."""
        event_type = event.get('type')
        if not isinstance(event_type, str) or not event_type:
            return
        src_ip = event.get('source_ip')
        details = event.get('details', '')
        
        if event_type == 'DEVICE_DISCOVERED':
            mac = details
            self.db.update_ip_mac(src_ip, mac)
            # Haritanın güncellenmesi için bir sonraki poll'u beklemesi yerine
            # anında UI'ı uyarabiliriz ama UI fetchRecords ile de güncellenir.
        else:
            # Tehdit durumu
            severity = event.get('severity', 'critical' if 'SPOOF' in event_type or 'HONEYPOT' in event_type else 'high')
            self.db.add_alert(
                alert_type=event_type,
                src_ip=src_ip,
                src_mac='N/A',
                dst_ip=event.get('destination_ip', 'N/A'),
                dst_mac='N/A',
                description=details,
                severity=severity
            )


    def _register_routes(self):
        """Flask route'larını kaydeder."""

        @self.app.context_processor
        def csrf_context():
            if 'csrf_token' not in session:
                session['csrf_token'] = secrets.token_urlsafe(32)
            return {'csrf_token': session['csrf_token']}

        @self.app.before_request
        def require_auth():
            public_static = request.endpoint == 'static' and not (
                request.view_args.get('filename', '').lower().endswith('.pcap')
                or request.view_args.get('filename', '').startswith('pcaps/')
            )
            public = request.endpoint in {'login', 'honeytoken_trigger'} or public_static
            if not public and not self._authenticated():
                if request.path.startswith('/api/'):
                    return jsonify(success=False, error='Oturum açılmamış'), 401
                return redirect(url_for('login'))
            if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
                token = request.form.get('csrf_token') if request.endpoint == 'login' else request.headers.get('X-CSRF-Token')
                if not _matches(token, session.get('csrf_token')):
                    return jsonify(success=False, error='Geçersiz CSRF doğrulaması'), 403
                if request.path.startswith('/api/') and request.data:
                    data = request.get_json()
                    if not isinstance(data, dict):
                        raise BadRequest('JSON nesnesi gerekli')

        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'GET':
                if self._authenticated():
                    return redirect(url_for('index'))
                return render_template('login.html')
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            client_ip = request.remote_addr or 'unknown'
            now = time.time()
            with self.failed_attempts_lock:
                self.failed_attempts = {ip: row for ip, row in self.failed_attempts.items()
                                        if row['expires'] > now}
                record = self.failed_attempts.get(client_ip, {'count': 0, 'expires': now + 300})
                if record['count'] >= 5:
                    return render_template('login.html', error='Çok fazla başarısız giriş. 5 dakika sonra tekrar deneyin.'), 429
                if _matches(username, self.admin_user) and _matches(password, self.admin_pass):
                    self.failed_attempts.pop(client_ip, None)
                else:
                    record['count'] += 1
                    if len(self.failed_attempts) >= 10000:
                        self.failed_attempts.pop(next(iter(self.failed_attempts)))
                    self.failed_attempts[client_ip] = record
                    return render_template('login.html', error='Kullanıcı adı veya şifre hatalı.'), 401
            self._revoke_session()
            session.clear()
            session.update(authenticated=True, username=username,
                           session_id=secrets.token_urlsafe(32),
                           csrf_token=secrets.token_urlsafe(32),
                           ws_token=secrets.token_urlsafe(32))
            session.permanent = True
            with self._session_lock:
                self._active_sessions = {key: expiry for key, expiry in self._active_sessions.items() if expiry > now}
                self._active_sessions[session['session_id']] = now + self.app.permanent_session_lifetime.total_seconds()
            return redirect(url_for('index'))

        @self.app.route('/logout', methods=['POST'])
        def logout():
            self._revoke_session()
            session.clear()
            return redirect(url_for('login'))

        @self.app.after_request
        def add_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['Referrer-Policy'] = 'same-origin'
            response.headers['Cache-Control'] = 'no-store'
            return response

        @self.app.errorhandler(HTTPException)
        def handle_http_error(error):
            if request.path.startswith('/api/'):
                response = error.get_response()
                response.data = self.app.json.dumps({'success': False, 'error': error.description})
                response.content_type = 'application/json'
                return response
            return error

        @self.app.route('/api/ws_token')
        def get_ws_token():
            return jsonify({'token': session['ws_token']})

        @self.app.route('/')
        def index():
            return render_template('index.html', current_interface=self.interface)

        @self.app.route('/soc_premium')
        def soc_premium():
            return render_template('soc_premium.html', current_interface=self.interface)

        @self.app.route('/api/alerts')
        def get_alerts():
            limit = _limit(50)
            alerts = self.db.get_alerts(limit=limit)
            return jsonify(alerts)

        @self.app.route('/api/stats')
        def get_stats():
            return jsonify(self._get_stats())

        @self.app.route('/api/incidents')
        def get_incidents():
            return jsonify(self.response_policy.get_incidents(limit=_limit(100)))

        @self.app.route('/api/response-policy')
        def get_response_policy():
            return jsonify(self.response_policy.status())

        @self.app.route('/api/service-health')
        def get_service_health():
            services = getattr(self, 'runtime_services', None)
            return jsonify(services.status() if services else {'running': False, 'services': {}})

        @self.app.route('/api/bans')
        def get_bans():
            bans = self.db.get_active_bans()
            return jsonify(bans)
        @self.app.route('/sirket_sifreleri.pdf')
        @self.app.route('/banka_bilgileri.xlsx')
        def honeytoken_trigger():
            client_ip = request.remote_addr
            filename = request.path.lstrip('/')
            now = time.monotonic()
            key = (client_ip, filename)
            with self._canary_lock:
                previous = self._canary_alert_times.get(key)
                record_alert = previous is None or now - previous >= 300
                if record_alert:
                    # Public URLs can also be fetched by indexing/prefetch tools.
                    # Bound both repeat notifications and the source cache.
                    self._canary_alert_times.pop(key, None)
                    if len(self._canary_alert_times) >= 2048:
                        self._canary_alert_times.pop(next(iter(self._canary_alert_times)))
                    self._canary_alert_times[key] = now
            if record_alert:
                self.db.add_alert(
                    alert_type='Canary Token Erişimi',
                    src_ip=client_ip, src_mac='N/A',
                    dst_ip='N/A', dst_mac='N/A',
                    description=f"Sahte hassas dosya adresine erişim gözlendi: {filename}. "
                                "Bu istek tek başına sisteme sızıldığını doğrulamaz.",
                    severity='medium'
                )
            return "This file is corrupted or you do not have permission to read it.", 403
        @self.app.route('/api/ban', methods=['POST'])
        def add_ban():
            data = request.get_json()
            ip = _text(data, 'ip')
            mac = _text(data, 'mac')
            ip = _ip(ip) if ip else ''
            mac = _mac(mac) if mac else ''
            reason = _text(data, 'reason', 'Manuel ban')

            if not ip and not mac:
                return jsonify({'success': False, 'error': 'IP veya MAC adresi gerekli'}), 400

            if not self.blocker or self.dry_run:
                return jsonify(success=False, error='Engelleme için IPS modu gerekli; dry-run kapalı olmalı'), 409
            targets = {key: value for key, value in (('ip', ip), ('mac', mac)) if value}
            applied = {}

            def failure(message, status):
                if applied:
                    message += ' Bazı engeller uygulandı; etkin engelleri kontrol edin.'
                return jsonify(success=False, error=message, applied=applied,
                               pending={key: value for key, value in targets.items() if key not in applied}), status

            try:
                if self.blocker.start() is False:
                    return failure('Güvenlik duvarı başlatılamadı', 503)
                # start() discovers protected infrastructure. Validate every
                # target before applying the first requested firewall change.
                if ip:
                    self.blocker._validate_ip(ip, protected=True)
                if mac:
                    self.blocker._validate_mac(mac, protected=True)
                if ip:
                    if self.blocker.block_ip(ip, reason=reason) is False:
                        return failure('IP engellenemedi veya zaten engelli', 503)
                    applied['ip'] = ip
                if mac:
                    if self.blocker.block_mac(mac, reason=reason) is False:
                        return failure('MAC engellenemedi veya zaten engelli', 503)
                    applied['mac'] = mac

                self.db.add_alert(
                    alert_type='Manuel Karantina',
                    src_ip=ip or 'N/A', src_mac=mac or 'N/A',
                    dst_ip='N/A', dst_mac='N/A',
                    description=f"Kullanıcı tarafından manuel olarak ağdan izole edildi. Sebep: {reason}",
                    severity='critical'
                )
                return jsonify(success=True, applied=applied, pending={})
            except ValueError as ve:
                return failure(str(ve), 400)
            except Exception:
                logging.exception('API işlemi başarısız')
                return failure('İşlem başarısız; sunucu günlüğünü kontrol edin', 500)

        @self.app.route('/api/ueba_profiles', methods=['GET'])
        def api_ueba_profiles():
            return jsonify(self.ueba_detector.get_profiles())

        @self.app.route('/api/vuln_scans', methods=['GET'])
        def api_vuln_scans():
            scans = []
            try:
                with self.db.lock:
                    self.db.cursor.execute(
                        "SELECT timestamp, source_ip, description, severity FROM alerts WHERE alert_type LIKE 'Auto-Vuln Scanner%' OR alert_type LIKE 'Port Scanner%' ORDER BY id DESC LIMIT 50"
                    )
                    rows = self.db.cursor.fetchall()
                    for row in rows:
                        scans.append({
                            'timestamp': row['timestamp'],
                            'source_ip': row['source_ip'],
                            'description': row['description'],
                            'severity': row['severity']
                        })
            except Exception as e:
                print(f'[!] Vuln scan veri hatası: {e}')
            return jsonify(scans)

        @self.app.route('/api/scan_ip', methods=['POST'])
        def api_scan_ip():
            data = request.get_json()
            ip = _ip(data.get('ip'))
            if self.dry_run:
                return jsonify(success=False, error='Dry-run modunda aktif tarama kapalı'), 409
            
            if hasattr(self, 'vuln_scanner'):
                if self.vuln_scanner.scan_ip_async(ip, 'N/A'):
                    return jsonify(success=True)
                return jsonify(success=False, error='Tarama başlatılamadı; hedef zaten taranmış veya tarayıcı meşgul'), 409
                
            return jsonify({'success': False, 'error': 'Zafiyet tarayıcı modülü aktif değil'})

        @self.app.route('/api/unban', methods=['POST'])
        def remove_ban():
            data = request.get_json()
            ip = _text(data, 'ip')
            mac = _text(data, 'mac')
            ip = _ip(ip) if ip else None
            mac = _mac(mac) if mac else None
            if not ip and not mac:
                raise BadRequest('IP veya MAC adresi gerekli')

            try:
                if self.blocker:
                    if ip:
                        if self.blocker.unblock_ip(ip) is False:
                            return jsonify(success=False, error='IP engeli kaldırılamadı'), 409
                        failed = []
                        for component, method, module in (
                            (self.tarpit, 'untarpit_ip', 'tarpit'),
                            (self.dns_sinkhole, 'remove_quarantine_redirect', 'quarantine'),
                            (self.blocker, 'unrate_limit_ip', 'rate_limit'),
                        ):
                            try:
                                if getattr(component, method)(ip) is False:
                                    failed.append(module)
                                else:
                                    self.active_defense_mgr.remove_rule_by_target(module, ip)
                            except Exception:
                                logging.exception('%s kuralı kaldırılamadı: %s', module, ip)
                                failed.append(module)
                        if failed:
                            return jsonify(success=False, error='Bazı savunma kuralları kaldırılamadı',
                                           remaining_modules=failed), 503
                    if mac:
                        if self.blocker.unblock_mac(mac) is False:
                            return jsonify(success=False, error='MAC engeli kaldırılamadı'), 409
                else:
                    self.db.remove_ban(ip=ip, mac=mac)
                return jsonify({'success': True})
            except ValueError as e:
                return jsonify(success=False, error=str(e)), 400
            except Exception:
                logging.exception('API işlemi başarısız')
                return jsonify(success=False, error='İşlem başarısız; sunucu günlüğünü kontrol edin'), 500

        @self.app.route('/api/active_defense', methods=['GET', 'POST'])
        def active_defense_api():
            if request.method == 'GET':
                stats = {}
                if hasattr(self, 'tarpit'):
                    stats['tarpit'] = self.tarpit.get_stats()
                return jsonify({'success': True, 'stats': stats})

            data = request.get_json() or {}
            action = data.get('action')
            target_ip = _ip(data.get('ip'))
            if self.mode != 'ips' or self.dry_run:
                return jsonify(success=False, error='Aktif savunma için IPS modu gerekli; dry-run kapalı olmalı'), 409
            if not self.sniffer_running:
                return jsonify(success=False, error='Önce izlemeyi başlatın'), 409

            try:
                if action == 'tarpit':
                    if hasattr(self, 'tarpit'):
                        if self.blocker: self.blocker.intercept_ip(target_ip)
                        ok = self.tarpit.tarpit_ip(target_ip)
                        if ok: self.active_defense_mgr.add_rule('tarpit', target_ip=target_ip)
                        return jsonify({'success': ok, 'msg': f'IP {target_ip} TCP Tarpit tuzağına eklendi'})
                elif action == 'untarpit':
                    if hasattr(self, 'tarpit'):
                        ok = self.tarpit.untarpit_ip(target_ip)
                        if ok:
                            self.active_defense_mgr.remove_rule_by_target('tarpit', target_ip)
                            if self.blocker: self.blocker.stop_intercept_ip(target_ip)
                        return jsonify({'success': ok, 'msg': f'IP {target_ip} Tarpit tuzağından çıkarıldı'})
                elif action == 'tcp_reset':
                    if hasattr(self, 'tcp_reset'):
                        # RST işlemi öncesinde trafiği üzerimize çek
                        if self.blocker: self.blocker.intercept_ip(target_ip)
                        
                        # Mobil için donanımsal iptables REJECT metodunu kullan (varsa)
                        if self.blocker and hasattr(self.blocker, 'kill_session_hardware'):
                            ok = self.blocker.kill_session_hardware(target_ip)
                        else:
                            ok = self.tcp_reset.kill_session(target_ip, '0.0.0.0')
                            
                        if ok: self.active_defense_mgr.add_rule('tcp_reset', target_ip=target_ip)
                        if self.blocker: self.blocker.stop_intercept_ip(target_ip) # RST atınca bırak
                        return jsonify({'success': ok, 'msg': f'IP {target_ip} TCP oturumu düşürüldü (RST injected)'})
                elif action == 'quarantine':
                    if hasattr(self, 'dns_sinkhole'):
                        if self.blocker: self.blocker.intercept_ip(target_ip)
                        ok = self.dns_sinkhole.redirect_to_quarantine(target_ip)
                        if ok: self.active_defense_mgr.add_rule('quarantine', target_ip=target_ip)
                        return jsonify({'success': ok, 'msg': f'IP {target_ip} Karantina Portalına (8099) yönlendirildi'})
                elif action == 'unquarantine':
                    if hasattr(self, 'dns_sinkhole'):
                        ok = self.dns_sinkhole.remove_quarantine_redirect(target_ip)
                        if ok:
                            self.active_defense_mgr.remove_rule_by_target('quarantine', target_ip)
                            if self.blocker: self.blocker.stop_intercept_ip(target_ip)
                        return jsonify({'success': ok, 'msg': f'IP {target_ip} karantinası kaldırıldı'})
                elif action == 'rate_limit':
                    if self.blocker and hasattr(self.blocker, 'rate_limit_ip'):
                        ok = self.blocker.rate_limit_ip(target_ip)
                        return jsonify({'success': ok, 'msg': f'IP {target_ip} için paket hızı sınırı işlemi tamamlandı'})
                elif action == 'unrate_limit':
                    if self.blocker and hasattr(self.blocker, 'unrate_limit_ip'):
                        ok = self.blocker.unrate_limit_ip(target_ip)
                        return jsonify({'success': ok, 'msg': f'IP {target_ip} bant genişliği limiti kaldırıldı'})
                return jsonify({'success': False, 'error': 'Bilinmeyen veya desteklenmeyen eylem'}), 400
            except ValueError as e:
                return jsonify(success=False, error=str(e)), 400
            except Exception:
                logging.exception('API işlemi başarısız')
                return jsonify(success=False, error='İşlem başarısız; sunucu günlüğünü kontrol edin'), 500

        @self.app.route('/api/gateway_mode', methods=['GET'])
        def gateway_mode_status():
            if not self.gateway_mode:
                return jsonify({'active': False, 'error': 'Gateway mode modülü yüklenemedi'})
            return jsonify(self.gateway_mode.get_status())

        @self.app.route('/api/gateway_mode/toggle', methods=['POST'])
        def gateway_mode_toggle():
            if self.mode != 'ips' or self.dry_run:
                return jsonify(success=False, error='Ağ geçidi için IPS modu gerekli; dry-run kapalı olmalı'), 409
            if not self.gateway_mode:
                return jsonify({'success': False, 'error': 'Gateway mode modülü yüklenemedi'})
            if self.gateway_mode.active:
                ok = self.gateway_mode.disable()
                return jsonify({'success': ok, 'active': bool(self.gateway_mode.active), 'dhcp_active': bool(self.gateway_mode.dhcp_active), 'msg': 'Ağ Geçidi Modu devre dışı bırakıldı'})
            else:
                ok = self.gateway_mode.enable()
                status = self.gateway_mode.get_status()
                return jsonify({'success': ok, 'active': bool(self.gateway_mode.active), 'dhcp_active': bool(self.gateway_mode.dhcp_active), 'msg': f'Ağ Geçidi Modu aktif. Gateway: {status.get("local_ip", "N/A")}', 'instructions': status.get('instructions', {})})

        @self.app.route('/api/gateway_mode/dhcp', methods=['POST'])
        def gateway_mode_dhcp():
            if self.mode != 'ips' or self.dry_run:
                return jsonify(success=False, error='DHCP için IPS modu gerekli; dry-run kapalı olmalı'), 409
            if not self.gateway_mode:
                return jsonify({'success': False, 'error': 'Gateway mode modülü yüklenemedi'})
            if self.gateway_mode.dhcp_active:
                ok = self.gateway_mode.stop_dhcp()
                return jsonify({'success': ok, 'dhcp_active': bool(self.gateway_mode.dhcp_active), 'msg': 'DHCP Sunucusu durduruldu'})
            else:
                ok = self.gateway_mode.start_dhcp()
                status = self.gateway_mode.get_status()
                return jsonify({
                    'success': ok, 
                    'dhcp_active': bool(self.gateway_mode.dhcp_active),
                    'active': status.get('active', False),
                    'dhcp_range': status.get('dhcp_range', 'N/A'),
                    'local_ip': status.get('local_ip', 'N/A'),
                    'msg': '📡 DHCP Sunucusu aktif! Cihazlar Wi-Fi\'a tekrar bağlandığında otomatik olarak IPS koruması altına girer.'
                })


        @self.app.route('/api/active_defense/save', methods=['POST'])
        def active_defense_save():
            data = request.get_json() or {}
            module = _text(data, 'module', max_length=64)
            if module not in {'tarpit', 'tcp_reset', 'quarantine', 'rate_limit', 'honeypot'}:
                raise BadRequest('Geçersiz savunma modülü')
            target_ip = _text(data, 'target_ip')
            target_mac = _text(data, 'target_mac')
            if not target_ip and not target_mac:
                raise BadRequest('Hedef IP veya MAC gerekli')
            parameters = data.get('parameters', {})
            if not isinstance(parameters, dict):
                raise BadRequest('parameters bir JSON nesnesi olmalı')
            rule_id = self.active_defense_mgr.add_rule(
                module=module, target_ip=_ip(target_ip) if target_ip else None,
                target_mac=_mac(target_mac) if target_mac else None, parameters=parameters)
            return jsonify({'success': True, 'rule_id': rule_id})

        @self.app.route('/api/dns_sinkhole/blocklist', methods=['GET', 'POST'])
        def dns_blocklist_api():
            if not hasattr(self, 'dns_sinkhole'):
                return jsonify({'success': False, 'error': 'DNS Sinkhole modülü aktif değil'}), 400
                
            if request.method == 'GET':
                return jsonify({'success': True, 'domains': self.dns_sinkhole.blocklist})
            else:
                data = request.get_json() or {}
                domains = data.get('domains', [])
                if isinstance(domains, str):
                    domains = [d.strip() for d in domains.splitlines() if d.strip()]
                if not isinstance(domains, list) or len(domains) > 10000:
                    raise BadRequest('domains bir alan adı listesi olmalı (en fazla 10000)')
                normalized = []
                for domain in domains:
                    if not isinstance(domain, str):
                        raise BadRequest('Geçersiz alan adı')
                    try:
                        domain = domain.strip().rstrip('.').encode('idna').decode('ascii').lower()
                    except UnicodeError:
                        raise BadRequest('Geçersiz alan adı') from None
                    if len(domain) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                                     for label in domain.split('.')):
                        raise BadRequest('Geçersiz alan adı')
                    normalized.append(domain)
                domains = list(dict.fromkeys(normalized))
                ok = self.dns_sinkhole.update_blocklist(domains)
                if ok:
                    return jsonify({'success': True, 'msg': 'DNS Blocklist başarıyla güncellendi'})
                return jsonify({'success': False, 'error': 'Blocklist kaydedilirken hata oluştu'}), 500

        @self.app.route('/api/active_defense/list', methods=['GET'])
        def active_defense_list():
            rules = self.active_defense_mgr.get_all_rules()
            return jsonify({'success': True, 'rules': rules})

        @self.app.route('/api/active_defense/cleanup', methods=['POST'])
        def active_defense_cleanup():
            if self.dry_run or self.mode != 'ips':
                return jsonify(success=False, error='Aktif savunma yalnızca IPS modunda kullanılabilir'), 409
            with self._lifecycle_lock:
                success = self._cleanup_defenses()
            return jsonify(success=success, msg='Savunma temizliği tamamlandı' if success else
                           'Bazı kurallar kaldırılamadı; kayıtları korundu'), 200 if success else 503



        @self.app.route('/api/control', methods=['POST'])
        def control():
            data = request.get_json()
            action = _text(data, 'action')
            with self._lifecycle_lock:
                if action == 'start':
                    interface = _text(data, 'interface', self.interface, 64)
                    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,64}', interface):
                        raise BadRequest('Geçersiz ağ arayüzü')
                    if interface != self.interface:
                        # Interface-bound firewall and detector state require a restart.
                        return jsonify(success=False, error='Arayüz değiştirmek için uygulamayı yeni arayüz ile yeniden başlatın'), 409
                    try:
                        self._start_monitoring()
                    except Exception:
                        logging.exception('İzleme başlatılamadı')
                        self._stop_monitoring()
                        return jsonify(success=False, error='İzleme başlatılamadı; sunucu günlüğünü kontrol edin'), 503
                elif action == 'stop':
                    self._stop_monitoring()
                else:
                    raise BadRequest('Geçersiz aksiyon')
            return jsonify(success=True, running=self.sniffer_running)

        @self.app.route('/api/devices')
        @self.app.route('/api/records')
        def get_records():
            records = self.db.get_ip_mac_records(limit=100)
            return jsonify(records)

        @self.app.route('/api/geoip/<ip>')
        def get_geoip(ip):
            """IP adresi için GeoIP bilgisi döndürür (ip-api.com proxy)."""
            import ipaddress
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private or addr.is_loopback:
                    return jsonify({'status': 'private', 'lat': 39.9, 'lon': 32.8, 'country': 'Turkey', 'city': 'Local'})
            except Exception:
                return jsonify({'status': 'fail'})
            try:
                import urllib.request
                import json as _json
                url = f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org'
                with urllib.request.urlopen(url, timeout=4) as resp:
                    data = _json.loads(resp.read().decode())
                return jsonify(data)
            except Exception as e:
                return jsonify({'status': 'fail', 'error': str(e)})

        @self.app.route('/api/dns_logs', defaults={'ip': None})
        @self.app.route('/api/dns_logs/<ip>')
        def get_dns_logs_api(ip):
            limit = _limit(100)
            if ip is not None:
                ip = _ip(ip)
            logs = self.db.get_dns_logs(ip=ip, limit=limit)
            return jsonify(logs)
            
        @self.app.route('/api/scan', methods=['POST'])
        def run_network_scan():
            if self.dry_run:
                return jsonify(success=False, error='Dry-run modunda aktif tarama kapalı'), 409
            if not self._scan_lock.acquire(blocking=False):
                return jsonify(success=False, error='Tarama zaten devam ediyor'), 409
            def scan_worker():
                try:
                    self.scanner.scan_once()
                    self.socketio.emit('scan_complete', {'success': True,
                                       'records': self.db.get_ip_mac_records(limit=100)}, namespace='/')
                except Exception:
                    logging.exception('Ağ taraması başarısız')
                    self.socketio.emit('scan_complete', {'success': False}, namespace='/')
                finally:
                    self._scan_lock.release()
            try:
                threading.Thread(target=scan_worker, daemon=True).start()
            except Exception:
                self._scan_lock.release()
                raise
            return jsonify(success=True, message='Tarama başlatıldı')

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
                updates = {}
                for key in ('discord_webhook', 'telegram_token', 'telegram_chat_id'):
                    if key in data:
                        value = _text(data, key)
                        if value != '********':
                            updates[key] = value
                dw = updates.get('discord_webhook', '')
                if dw:
                    from urllib.parse import urlsplit
                    parsed = urlsplit(dw)
                    if (parsed.scheme != 'https' or parsed.netloc != 'discord.com'
                            or not re.fullmatch(r'/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', parsed.path)
                            or parsed.query or parsed.fragment):
                        raise BadRequest('Geçerli bir Discord webhook adresi gerekli')
                tt = updates.get('telegram_token', '')
                if tt and not re.fullmatch(r'[0-9]+:[A-Za-z0-9_-]+', tt):
                    raise BadRequest('Geçersiz Telegram token')
                tc = updates.get('telegram_chat_id', '')
                if tc and not re.fullmatch(r'-?[0-9]+|@[A-Za-z0-9_]+', tc):
                    raise BadRequest('Geçersiz Telegram sohbet kimliği')
                for key, value in updates.items():
                    self.db.set_setting(key, value)

                self._update_notifier_config()
                return jsonify({'success': True})
                
        def sanitize_csv(val):
            s = str(val)
            if s.lstrip().startswith(('=', '+', '-', '@')) or s.startswith(('\t', '\r', '\n')):
                return "'" + s
            return s

        @self.app.route('/api/pcaps/<filename>')
        def download_pcap(filename):
            if not re.fullmatch(r'alert_[0-9]+\.pcap', filename):
                raise BadRequest('Geçersiz PCAP adı')
            return send_from_directory(self.pcap_dir, filename, as_attachment=True,
                                       mimetype='application/vnd.tcpdump.pcap')

        @self.app.route('/api/export/alerts')
        def export_alerts():
            alerts = self.db.get_alerts(limit=1000)
            from web.report_gen import generate_pdf_report
            import tempfile
            
            # Gecici bir dosya olustur
            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.pdf')
            os.close(tmp_fd)
            
            try:
                generate_pdf_report(alerts, tmp_path)
                with open(tmp_path, 'rb') as f:
                    pdf_data = f.read()
            finally:
                os.remove(tmp_path)
                
            return Response(
                pdf_data,
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment;filename=ds_ips_report_{datetime.now().strftime("%Y%m%d")}.pdf'}
            )

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

    def _authenticated(self):
        session_id = session.get('session_id')
        with self._session_lock:
            return bool(session.get('authenticated') and session_id and
                        self._active_sessions.get(session_id, 0) > time.time())

    def _revoke_session(self):
        session_id = session.get('session_id')
        with self._session_lock:
            self._active_sessions.pop(session_id, None)
            sockets = [sid for sid, value in self._socket_sessions.items() if value == session_id]
        for sid in sockets:
            self.socketio.server.disconnect(sid, namespace='/')

    def _register_socketio_events(self):
        """Require both an active login session and its own WebSocket token."""
        @self.socketio.on('connect')
        def handle_connect(auth=None):
            if (not self._authenticated() or not isinstance(auth, dict)
                    or not _matches(auth.get('token'), session.get('ws_token'))):
                return False
            with self._session_lock:
                self._socket_sessions[request.sid] = session['session_id']
            emit('status_update', {'running': self.sniffer_running})
            emit('stats_update', self._get_stats())

        @self.socketio.on('disconnect')
        def handle_disconnect(reason=None):
            with self._session_lock:
                self._socket_sessions.pop(request.sid, None)

        @self.socketio.on('request_stats')
        def handle_request_stats():
            if not self._authenticated():
                disconnect()
                return
            emit('stats_update', self._get_stats())

    def _get_stats(self):
        """Sistem istatistiklerini toplar."""
        uptime = 0
        if self.start_time and self.sniffer_running:
            uptime = int(time.time() - self.start_time)

        try:
            cpu_usage = psutil.cpu_percent(interval=None)
            ram_usage = psutil.virtual_memory().percent
        except Exception:
            cpu_usage = 0
            ram_usage = 0

        capture = {}
        for name, component in (('scapy', self.legacy_sniffer), ('tshark', self.sniffer)):
            count = getattr(component, 'packet_count', 0)
            last_packet = getattr(component, 'last_packet_at', None)
            error = getattr(component, 'last_error', None)
            capture[name] = {
                'running': bool(component.running),
                'packets': count if isinstance(count, int) else 0,
                'last_packet_at': last_packet if isinstance(last_packet, (int, float)) else None,
                'error': error if isinstance(error, str) else None,
            }
        capturing = self.sniffer_running and any(item['running'] for item in capture.values())
        return {
            'sniffer_running': bool(capturing),
            'monitoring_requested': self.sniffer_running,
            'capture': capture,
            'mode': self.mode.upper(),
            'interface': self.interface,
            'wifi_enabled': self.wifi_enabled,
            'uptime': uptime,
            'cpu_usage': cpu_usage,
            'ram_usage': ram_usage,
            'total_alerts': self.db.get_total_alert_count(),
            'active_bans': self.db.get_active_ban_count(),
            'alert_counts': self.db.get_alert_counts(),
            'arp_stats': self.arp_detector.get_stats(),
            'scan_stats': self.scan_detector.get_stats(),
            'wifi_stats': self.wifi_detector.get_stats() if self.wifi_detector else {},
            'tarpit_stats': self.tarpit.get_stats() if hasattr(self, 'tarpit') else {},
            'telegram_sent': self.notifier.sent_count,
            'telegram_connected': bool(self.notifier.telegram_token and self.notifier.telegram_chat_id),
        }

    def _stats_broadcaster(self):
        """Periyodik olarak istatistikleri WebSocket üzerinden gönderir."""
        while not self._stop_event.wait(3):
            try:
                with self._session_lock:
                    expired = [sid for sid, key in self._socket_sessions.items()
                               if self._active_sessions.get(key, 0) <= time.time()]
                for sid in expired:
                    self.socketio.server.disconnect(sid, namespace='/')
                stats = self._get_stats()
                self.socketio.emit('stats_update', stats, namespace='/')
            except Exception:
                pass

    def _handle_alert(self, alert_data):
        """Database'den gelen alarmları WebSocket üzerinden iletir ve PCAP kaydeder."""
        decision = self.response_policy.observe(alert_data, monitoring=self.sniffer_running)
        if decision is not None:
            alert_data['response'] = decision
        if alert_data.get('severity', '').lower() in {'critical', 'kritik'} and self.sniffer_running:
            pcap_filename = f"alert_{alert_data['id']}.pcap"
            pcap_dir = self.pcap_dir
            os.makedirs(pcap_dir, mode=0o700, exist_ok=True)
            pcap_path = os.path.join(pcap_dir, pcap_filename)
            
            if self.legacy_sniffer.dump_pcap(pcap_path):
                alert_data['pcap_file'] = pcap_filename
                self.db.update_alert_pcap(alert_data['id'], pcap_filename)
                
        
        # Bildirim gönder
        title = f"DS IPS Alarm: {alert_data['alert_type']}"
        msg = alert_data['description']
        try:
            self.notifier.send_alert(title, msg, severity=alert_data['severity'])
        except Exception:
            pass

    def _start_monitoring(self):
        if self.sniffer_running:
            # An exited capture backend must be restartable from the panel.
            if not self.sniffer.running:
                self.sniffer.start()
            if not self.legacy_sniffer.running:
                self.legacy_sniffer.start()
            return
        if self._closed:
            raise RuntimeError('Uygulama kapatıldı')
        self.sniffer.start()
        self.legacy_sniffer.start()
        self.threat_intel.start()
        self.vuln_scanner.start()
        if self.mode == 'ips' and not self.dry_run:
            if self.blocker and hasattr(self.blocker, 'start'):
                if self.blocker.start() is False:
                    raise RuntimeError('Güvenlik duvarı başlatılamadı')
            self.tarpit.start()
            self.dns_sinkhole.start()
            self.honeypot.start()
            self.ssh_honeypot.start()
            import socket
            self.sniffer.honeypot_ips = {
                address.address for interface, addresses in psutil.net_if_addrs().items()
                if self.interface == 'any' or interface == self.interface
                for address in addresses if address.family == socket.AF_INET
            }
            self.decoy_generator.start()
            self.scanner.start_periodic(60)
        self.sniffer_running = True
        self.start_time = time.time()
        self.socketio.emit('status_update', {'running': True}, namespace='/')

    def _cleanup_defenses(self):
        success = True
        for component, attribute, method, module in (
            (self.tarpit, 'trapped_ips', 'untarpit_ip', 'tarpit'),
            (self.dns_sinkhole, 'quarantined_ips', 'remove_quarantine_redirect', 'quarantine'),
        ):
            for ip in tuple(getattr(component, attribute, ())):
                try:
                    if getattr(component, method)(ip):
                        self.active_defense_mgr.remove_rule_by_target(module, ip)
                    else:
                        success = False
                except Exception:
                    logging.exception('%s kuralı kaldırılamadı: %s', module, ip)
                    success = False
        if self.blocker and not self.dry_run:
            try:
                success = self.blocker.cleanup_all() and success
            except Exception:
                logging.exception('Engelleme kuralları temizlenemedi')
                success = False
        return bool(success)

    def _stop_monitoring(self):
        self.sniffer.honeypot_ips = set()
        self.sniffer_running = False
        for name in ('scanner', 'sniffer', 'legacy_sniffer', 'vuln_scanner', 'honeypot', 'ssh_honeypot',
                     'decoy_generator', 'threat_intel'):
            component = getattr(self, name, None)
            if component and hasattr(component, 'stop'):
                try:
                    component.stop()
                except Exception:
                    logging.exception('%s durdurulamadı', name)
        if self.mode == 'ips' and not self.dry_run:
            self._cleanup_defenses()
        if self.gateway_mode:
            try:
                self.gateway_mode.disable()
            except Exception:
                logging.exception('Ağ geçidi durdurulamadı')
        for component in (self.tarpit, self.dns_sinkhole, self.blocker):
            if component:
                try:
                    component.stop()
                except Exception:
                    logging.exception('Savunma bileşeni durdurulamadı')
        self.socketio.emit('status_update', {'running': False}, namespace='/')

    def start_background_tasks(self):
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError('Uygulama kapatıldı')
            if self._stats_thread is None or not self._stats_thread.is_alive():
                self._stats_thread = threading.Thread(target=self._stats_broadcaster, daemon=True)
                self._stats_thread.start()

    def close(self):
        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            self._stop_event.set()
            self._stop_monitoring()
            if self._stats_thread and self._stats_thread is not threading.current_thread():
                self._stats_thread.join(timeout=5)
            for name, method in (('gateway_mode', 'disable'), ('blocker', 'stop'),
                                 ('active_defense_mgr', 'close'), ('db', 'close')):
                component = getattr(self, name, None)
                if component and hasattr(component, method):
                    try:
                        getattr(component, method)()
                    except Exception:
                        logging.exception('%s kapatılamadı', name)
            atexit.unregister(self._cleanup_on_exit)

    def _cleanup_on_exit(self):
        self.close()

    def run(self, host='127.0.0.1', port=5000, debug=False):
        """Start the development server without the privileged debug reloader."""
        self.start_background_tasks()
        # The entrypoint stops HIDS/Telegram before closing this app's database.
        self.socketio.run(self.app, host=host, port=port, debug=False,
                          use_reloader=False, allow_unsafe_werkzeug=True)
