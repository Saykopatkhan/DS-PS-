"""
Sahte Tuzak Portlar (Honeyport: 21, 23, 445 vb.) modülü.
Saldırganlar bu açık portlara bağlandığı anda deşifre olurlar.
"""
import socket
import threading
from core.database import Database
from utils.sound import SoundAlert

class Honeypot:
    def __init__(self, db: Database, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.ports = [21, 23, 445] # FTP, Telnet, SMB tuzakları
        self.threads = []
        self.running = False
        self.sockets = []

    def start(self):
        self.running = True
        for port in self.ports:
            t = threading.Thread(target=self._listen_port, args=(port,), daemon=True)
            self.threads.append(t)
            t.start()
            
        # Gelişmiş Web Bal Küpü (Port 8080)
        self._start_fake_web_server()

    def _start_fake_web_server(self):
        from flask import Flask, request
        import logging
        
        self.fake_web = Flask('honeypot_web')
        # Flask loglarını gizle
        log = logging.getLogger('werkzeug')
        log.disabled = True
        
        @self.fake_web.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
        @self.fake_web.route('/<path:path>', methods=['GET', 'POST'])
        def catch_all(path):
            ip = request.remote_addr
            method = request.method
            
            payload = ""
            if method == 'POST':
                payload = request.get_data(as_text=True)
            elif request.args:
                payload = str(dict(request.args))
                
            # Alert tetikle
            msg = f"Sahte Web Paneline erişti. İstek: {method} /{path}"
            if payload:
                msg += f" | Payload: {payload}"
                
            self.db.add_alert(
                alert_type='Gelişmiş Honeypot İhlali (Web)',
                src_ip=ip, src_mac='N/A',
                dst_ip='N/A', dst_mac='N/A',
                description=msg,
                severity='critical'
            )
            SoundAlert.alert_attack("Kritik Web Honeypot İhlali")
            if self.blocker and self.auto_ban:
                self.blocker.block_ip(ip, reason="Sahte Web Paneline (Honeypot) Sızmaya Çalıştı")
                
            return '''
            <!DOCTYPE html>
            <html>
                <head>
                    <title>IT Admin Control Panel</title>
                    <style>
                        body { background: #f4f4f9; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                        .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); text-align: center; width: 300px; }
                        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
                        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
                        button:hover { background: #0056b3; }
                    </style>
                </head>
                <body>
                    <div class="login-box">
                        <h2>Admin Portal</h2>
                        <p style="color: red; font-size: 0.9rem;">Invalid Credentials. Please try again.</p>
                        <form method="POST" action="/admin_login.php">
                            <input type="text" name="username" placeholder="Username" required>
                            <input type="password" name="password" placeholder="Password" required>
                            <button type="submit">Login</button>
                        </form>
                    </div>
                </body>
            </html>
            '''
            
        t = threading.Thread(
            target=lambda: self.fake_web.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False), 
            daemon=True
        )
        self.threads.append(t)
        t.start()

    def _listen_port(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Port daha önce kapanmamışsa hemen yeniden kullanılabilmesi için
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            self.sockets.append(server)
            
            while self.running:
                try:
                    server.settimeout(1.0)
                    conn, addr = server.accept()
                    attacker_ip = addr[0]
                    
                    self._trigger_alert(attacker_ip, port)
                    
                    # Sahte banner gönder (Saldırganı oyalamak için)
                    if port == 21:
                        conn.send(b"220 (vsFTPd 3.0.3)\r\n")
                    elif port == 23:
                        conn.send(b"Ubuntu 20.04 LTS\r\nLogin: ")
                        
                    conn.close()
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as e:
            print(f"[!] Honeypot port {port} açılamadı: {e} (Zaten kullanımda olabilir mi?)")

    def _trigger_alert(self, ip, port):
        service = "FTP" if port == 21 else "Telnet" if port == 23 else "SMB" if port == 445 else f"Port {port}"
        self.db.add_alert(
            alert_type=f'Honeypot İhlali ({service})',
            src_ip=ip, src_mac='N/A',
            dst_ip='N/A', dst_mac='N/A',
            description=f'Kaynak {ip}, sistemdeki sahte {service} (Port {port}) tuzağına erişti!',
            severity='critical'
        )
        SoundAlert.alert_attack(f"{service} Honeypot İhlali")
        if self.blocker and self.auto_ban:
            self.blocker.block_ip(ip, reason="Honeypot Tuzağına Düştü")

    def stop(self):
        self.running = False
        for s in self.sockets:
            try:
                s.close()
            except:
                pass
