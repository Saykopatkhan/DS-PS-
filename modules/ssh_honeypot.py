import socket
import threading
import paramiko
from core.database import Database
from utils.sound import SoundAlert

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, db: Database, blocker=None, auto_ban=False):
        self.client_ip = client_ip
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Her türlü giriş başarılı sayılsın (Honeypot tuzağı)
        self.db.add_alert(
            alert_type='Deep Honeypot Sızma (SSH)',
            src_ip=self.client_ip, src_mac='N/A',
            dst_ip='N/A', dst_mac='N/A',
            description=f'Kaynak {self.client_ip} SSH paneline sızdı! Denediği kullanıcı: {username} - Şifre: {password}',
            severity='critical'
        )
        SoundAlert.alert_attack("Kritik SSH Sızması")
        # Otomatik Ban plan gereği kapatıldı
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

class SSHHoneypot:
    def __init__(self, db: Database, blocker=None, auto_ban=False, port=2222):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.port = port
        self.running = False
        self.sock = None
        self.thread = None
        
        # Sadece test amaçlı RSA key (normalde daha güvenli saklanmalı)
        from paramiko import RSAKey
        try:
            self.host_key = RSAKey.generate(2048)
        except Exception:
            self.host_key = None

    def start(self):
        if not self.host_key:
            print("[!] SSH Host key oluşturulamadı, SSH Honeypot başlatılmıyor.")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

    def _listen(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('0.0.0.0', self.port))
            self.sock.listen(5)
            
            while self.running:
                try:
                    self.sock.settimeout(1.0)
                    client, addr = self.sock.accept()
                    threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as e:
            print(f"[!] SSH Honeypot port {self.port} açılamadı: {e}")

    def _handle_client(self, client, addr):
        try:
            transport = paramiko.Transport(client)
            transport.add_server_key(self.host_key)
            server = FakeSSHServer(addr[0], self.db, self.blocker, self.auto_ban)
            try:
                transport.start_server(server=server)
            except paramiko.SSHException:
                return

            chan = transport.accept(20)
            if chan is None:
                return

            server.event.wait(10)
            if not server.event.is_set():
                return
                
            chan.send(b"Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-104-generic x86_64)\\r\\n")
            chan.send(b"root@server:~# ")
            
            while self.running:
                try:
                    cmd = b""
                    while True:
                        char = chan.recv(1)
                        if not char:
                            break
                        if char == b'\\r':
                            chan.send(b'\\r\\n')
                            break
                        if char == b'\\x03': # Ctrl+C
                            chan.send(b'^C\\r\\n')
                            cmd = b""
                            break
                        chan.send(char)
                        cmd += char
                        
                    if cmd:
                        cmd_str = cmd.decode('utf-8', errors='ignore').strip()
                        if cmd_str:
                            self.db.add_alert(
                                alert_type='SSH Komut Ihlali (Honeypot)',
                                src_ip=addr[0], src_mac='N/A',
                                dst_ip='N/A', dst_mac='N/A',
                                description=f'Hacker terminale su komutu yazdi: {cmd_str}',
                                severity='critical'
                            )
                            if cmd_str in ['exit', 'quit']:
                                chan.send(b'logout\\r\\n')
                                break
                            elif cmd_str.startswith('ls'):
                                chan.send(b'config.php  database.sql  passwords.txt  readme.md\\r\\n')
                            elif cmd_str.startswith('cat '):
                                chan.send(b'Permission denied\\r\\n')
                            elif cmd_str.startswith('whoami'):
                                chan.send(b'root\\r\\n')
                            else:
                                chan.send(f"bash: {cmd_str}: command not found\\r\\n".encode('utf-8'))
                                
                    chan.send(b"root@server:~# ")
                except Exception:
                    break
            chan.close()
            transport.close()
        except Exception:
            pass

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
