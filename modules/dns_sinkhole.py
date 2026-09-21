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
    def __init__(self, port=8099, db=None, dry_run=False, sinkhole_ip='127.0.0.1', interface=None):
        from pathlib import Path
        import ipaddress
        self.port = int(port)
        if not 1 <= self.port <= 65535:
            raise ValueError('Invalid portal port')
        self.db = db
        self.dry_run = dry_run
        self.sinkhole_ip = str(ipaddress.IPv4Address(sinkhole_ip))
        self.interface = interface
        self.app = Flask('dns_sinkhole')
        self.app.config['MAX_CONTENT_LENGTH'] = 65536
        self.quarantined_ips = set()
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._threads = []
        self._http_server = None
        self._dns_socket = None
        self.running = False
        self.blocklist = []
        self.blocklist_path = str(Path(__file__).resolve().parents[1] / 'assets' / 'dns_blocklist.json')
        self.load_blocklist()

        @self.app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
        @self.app.route('/<path:path>', methods=['GET', 'POST'])
        def quarantine_page(path):
            status = 200 if request.path in ['/hotspot-detect.html', '/generate_204', '/canonical.html', '/ncsi.txt'] else 403
            return render_template_string(QUARANTINE_HTML, ip=request.remote_addr), status

    @staticmethod
    def _normalize_domains(domains):
        import re
        if not isinstance(domains, list) or len(domains) > 100000:
            raise ValueError('Blocklist must be a list of at most 100000 domains')
        result = set()
        for domain in domains:
            if not isinstance(domain, str):
                raise ValueError('Domain must be a string')
            name = domain.strip().rstrip('.').encode('idna').decode('ascii').lower()
            if len(name) > 253 or not name or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in name.split('.')):
                raise ValueError('Invalid domain')
            result.add(name)
        return sorted(result)

    def load_blocklist(self):
        import json
        try:
            with open(self.blocklist_path, encoding='utf-8') as stream:
                domains = self._normalize_domains(json.load(stream))
        except FileNotFoundError:
            domains = []
        except (OSError, ValueError, UnicodeError) as exc:
            logger.error('Error loading blocklist: %s', exc)
            domains = []
        with self._lock:
            self.blocklist = domains

    def update_blocklist(self, domains):
        import json
        import os
        import tempfile
        path = None
        try:
            domains = self._normalize_domains(domains)
            directory = os.path.dirname(os.path.abspath(self.blocklist_path))
            os.makedirs(directory, exist_ok=True)
            with self._lock:
                with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=directory, delete=False) as stream:
                    path = stream.name
                    json.dump(domains, stream)
                os.replace(path, self.blocklist_path)
                path = None
                self.blocklist = domains
            return True
        except (OSError, ValueError, UnicodeError) as exc:
            logger.error('Error saving blocklist: %s', exc)
            return False
        finally:
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def is_blocked(self, domain):
        try:
            if isinstance(domain, bytes):
                domain = domain.decode('ascii')
            name = domain.rstrip('.').encode('idna').decode('ascii').lower()
        except (AttributeError, UnicodeError):
            return False
        with self._lock:
            return any(name == bad or name.endswith('.' + bad) for bad in self.blocklist)

    def start(self):
        if self.running or self.dry_run:
            return
        from werkzeug.serving import make_server
        import ipaddress
        try:
            if ipaddress.ip_address(self.sinkhole_ip).is_loopback and self.interface:
                from scapy.all import get_if_addr
                address = get_if_addr(self.interface)
                if address != '0.0.0.0':
                    self.sinkhole_ip = address
            self._http_server = make_server('0.0.0.0', self.port, self.app)
        except (OSError, SystemExit) as exc:
            logger.error('Quarantine portal could not start: %s', exc)
            return
        self._stop_event.clear()
        self.running = True
        for target in (self._http_server.serve_forever, self._start_dns_server):
            thread = threading.Thread(target=target, daemon=True)
            self._threads.append(thread)
            thread.start()

    def _dns_response(self, data, source_ip):
        from scapy.all import DNS, DNSQR, DNSRR
        import ipaddress
        import struct
        if len(data) < 12:
            return None
        try:
            query = DNS(data)
            if len(data) < 12 or query.qr or query.opcode or query.qdcount != 1 or not query.haslayer(DNSQR):
                return None
            question = query[DNSQR]
            if question.qclass != 1:
                return None
            blocked = source_ip in self.quarantined_ips or self.is_blocked(question.qname)
            response = DNS(id=query.id, qr=1, rd=query.rd, ra=0, qd=question.copy(), rcode=0 if blocked else 5)
            target = ipaddress.ip_address(self.sinkhole_ip)
            if blocked and question.qtype == 1 and not target.is_loopback and not target.is_unspecified:
                response.an = DNSRR(rrname=question.qname, type='A', ttl=10, rdata=str(target))
            return bytes(response)
        except (ValueError, TypeError, IndexError, AttributeError, struct.error):
            return None

    def _start_dns_server(self):
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                self._dns_socket = sock
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(0.5)
                sock.bind(('0.0.0.0', 53))
                while not self._stop_event.is_set():
                    try:
                        data, addr = sock.recvfrom(4096)
                        response = self._dns_response(data, addr[0])
                        if response:
                            sock.sendto(response, addr)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
        except OSError as exc:
            logger.error('DNS listener could not start: %s', exc)
        finally:
            self._dns_socket = None

    def stop(self):
        self.running = False
        self._stop_event.set()
        if self._dns_socket:
            self._dns_socket.close()
        if self._http_server:
            self._http_server.shutdown()
            self._http_server.server_close()
            self._http_server = None
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=2)
        self._threads.clear()
        for ip in list(self.quarantined_ips):
            self.remove_quarantine_redirect(ip)

    def _rules(self, ip):
        # These rules are identifiable and never overlap administrator-owned rules.
        comment = ['-m', 'comment', '--comment', 'dsips-quarantine']
        return [
            (['-t', 'nat'], 'PREROUTING', ['-s', ip, '-p', 'tcp', '--dport', '80', *comment, '-j', 'REDIRECT', '--to-ports', str(self.port)]),
            (['-t', 'nat'], 'PREROUTING', ['-s', ip, '-p', 'udp', '--dport', '53', *comment, '-j', 'REDIRECT', '--to-ports', '53']),
            ([], 'FORWARD', ['-s', ip, *comment, '-j', 'DROP']),
        ]

    @staticmethod
    def _address(ip):
        import ipaddress
        return str(ipaddress.IPv4Address(ip))

    @staticmethod
    def _run_rule(table, action, chain, rule):
        return subprocess.run(['iptables', '-w', '2', *table, action, chain, *rule],
                              capture_output=True, timeout=5)

    def redirect_to_quarantine(self, ip):
        if self.dry_run:
            return False
        added = []
        try:
            ip = self._address(ip)
            with self._lock:
                if ip in self.quarantined_ips:
                    return True
                if not self.dry_run:
                    for table, chain, rule in self._rules(ip):
                        if self._run_rule(table, '-C', chain, rule).returncode != 0:
                            if self._run_rule(table, '-I', chain, rule).returncode != 0:
                                raise RuntimeError('Could not add quarantine rule')
                            added.append((table, chain, rule))
                self.quarantined_ips.add(ip)
            return True
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            for table, chain, rule in reversed(added):
                try:
                    self._run_rule(table, '-D', chain, rule)
                except (OSError, subprocess.SubprocessError):
                    pass
            logger.error('Quarantine redirect failed: %s', exc)
            return False

    def remove_quarantine_redirect(self, ip):
        if self.dry_run:
            return False
        try:
            ip = self._address(ip)
            with self._lock:
                if not self.dry_run:
                    for table, chain, rule in self._rules(ip):
                        if self._run_rule(table, '-C', chain, rule).returncode == 0:
                            if self._run_rule(table, '-D', chain, rule).returncode != 0:
                                raise RuntimeError('Could not remove quarantine rule')
                self.quarantined_ips.discard(ip)
            return True
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            logger.error('Quarantine removal failed: %s', exc)
            return False
