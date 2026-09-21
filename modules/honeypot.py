# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Sahte Tuzak Portlar & Deception Services (Honeyport: 21, 23, 445, 2222, 8080).
Saldırganlar bu açık portlara bağlandığı anda deşifre olup TUZAKLANDI rozeti ile engellenir.
"""

import socket
import threading
import time
import logging
from core.database import Database
from utils.sound import SoundAlert

logger = logging.getLogger("DSIPS_Honeypot")

class Honeypot:
    def __init__(self, db: Database, blocker=None, auto_ban=True, socketio=None, tarpit=None, web_port=8081):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.socketio = socketio
        self.tarpit = tarpit
        self.web_port = web_port
        self._web_server = None
        self.ports = [21, 23, 445] # FTP, Telnet, SMB, SSH Tuzakları
        self.threads = []
        self.running = False
        self.sockets = []

    def start(self):
        if self.running:
            return
        self.running = True
        for port in self.ports:
            t = threading.Thread(target=self._listen_port, args=(port,), daemon=True)
            self.threads.append(t)
            t.start()
            
        # Gelişmiş Web Bal Küpü (Port 8080)
        self._start_fake_web_server()
        logger.info("[+] Honeypot & Deception servisleri aktif (Portlar: 21, 23, 445, 2222, 8081).")

    def _start_fake_web_server(self):
        from flask import Flask, request
        
        self.fake_web = Flask('honeypot_web')
        self.fake_web.config['MAX_CONTENT_LENGTH'] = 65536
        log = logging.getLogger('werkzeug')
        log.disabled = True
        
        @self.fake_web.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
        @self.fake_web.route('/<path:path>', methods=['GET', 'POST'])
        def catch_all(path):
            ip = request.remote_addr
            method = request.method
            
            payload = ""
            if method == 'POST':
                payload = str({key: ('[REDACTED]' if any(word in key.lower() for word in ('pass', 'secret', 'token')) else value) for key, value in request.form.items()}) if request.form else '[request body omitted]'
            elif request.args:
                payload = str(dict(request.args))
                
            msg = f"Sahte Web Admin Paneline Sızmaya Çalıştı! Istek: {method} /{path}"
            if payload:
                msg += f" | Payload: {payload}"
                
            self._trigger_alert(ip, self.web_port, custom_msg=msg)
                
            return '''
            <!DOCTYPE html>
            <html>
                <head>
                    <title>IT Admin Control Panel</title>
                    <style>
                        body { background: #0f172a; color: #fff; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                        .login-box { background: #1e293b; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); text-align: center; width: 320px; border: 1px solid #334155; }
                        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #475569; border-radius: 6px; background: #0f172a; color: #fff; box-sizing: border-box; }
                        button { width: 100%; padding: 12px; background: #00f2fe; color: #0f172a; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; }
                        button:hover { background: #4facfe; }
                    </style>
                </head>
                <body>
                    <div class="login-box">
                        <h2>Admin Portal</h2>
                        <p style="color: #ff4757; font-size: 0.85rem;">Access Denied. Incident Logged.</p>
                        <form method="POST" action="/admin_login.php">
                            <input type="text" name="username" placeholder="Username" required>
                            <input type="password" name="password" placeholder="Password" required>
                            <button type="submit">Login</button>
                        </form>
                    </div>
                </body>
            </html>
            '''
            
        from werkzeug.serving import make_server
        try:
            self._web_server = make_server('0.0.0.0', self.web_port, self.fake_web)
        except (OSError, SystemExit) as exc:
            logger.warning('Web honeypot could not start: %s', exc)
            return
        thread = threading.Thread(target=self._web_server.serve_forever, daemon=True)
        self.threads.append(thread)
        thread.start()

    def _listen_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(('0.0.0.0', port))
                server.listen(5)
                server.settimeout(0.5)
                self.sockets.append(server)
                while self.running:
                    try:
                        conn, addr = server.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        conn.settimeout(2)
                        self._trigger_alert(addr[0], port)
                        if port == 21:
                            conn.sendall(b'220 (vsFTPd 3.0.3 - Secure FTP)\r\n')
                        elif port == 23:
                            conn.sendall(b'Ubuntu 22.04 LTS\r\nlogin: ')
        except OSError as exc:
            if self.running:
                logger.debug('Honeypot port %s unavailable: %s', port, exc)

    def _trigger_alert(self, ip, port, custom_msg=None):
        service = "FTP" if port == 21 else "Telnet" if port == 23 else "SMB" if port == 445 else "SSH" if port == 2222 else f"Port {port}"
        desc = custom_msg or f"Kaynak {ip}, sistemdeki sahte {service} (Port {port}) tuzağına erişti! [TUZAKLANDI]"
        
        self.db.add_alert(
            alert_type=f'🕸️ HONEYPOT TUZAĞI ({service})',
            src_ip=ip, src_mac='N/A',
            dst_ip='N/A', dst_mac='N/A',
            description=desc,
            severity='critical'
        )
        
        # SocketIO üzerinden CANLI TUZAKLANDI bildirimi yolla
        if self.socketio:
            try:
                self.socketio.emit('new_alert', {
                    'id': int(time.time()),
                    'ip': ip,
                    'type': f'🕸️ HONEYPOT TUZAĞI ({service})',
                    'description': desc,
                    'severity': 'critical',
                    'tarpitted': bool(self.auto_ban and self.tarpit),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }, namespace='/')
            except Exception:
                pass

        SoundAlert.alert_attack(f"{service} Honeypot İhlali")
        
        # Otomatik Ban ve Tarpit
        if self.blocker and self.auto_ban:
            self.blocker.block_ip(ip, reason=f"Honeypot Tuzağına Düştü ({service})")
        if self.tarpit and self.auto_ban:
            self.tarpit.tarpit_ip(ip)

    def stop(self):
        self.running = False
        for s in self.sockets:
            try:
                s.close()
            except Exception:
                pass
        self.sockets.clear()
        if self._web_server:
            self._web_server.shutdown()
            self._web_server.server_close()
            self._web_server = None
        for thread in self.threads:
            if thread is not threading.current_thread():
                thread.join(timeout=2)
        self.threads.clear()
