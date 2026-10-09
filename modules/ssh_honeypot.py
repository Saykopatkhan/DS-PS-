# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

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
            description=f'Kaynak {self.client_ip} SSH tuzağında kimlik doğrulamayı denedi. Kullanıcı: {username} - Şifre: [REDACTED]',
            severity='high', source_verified=True,
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
        self.host_key = None
        self._slots = threading.BoundedSemaphore(8)
        self._clients = set()
        self._client_lock = threading.Lock()
        self._workers = set()

    def start(self):
        if self.running:
            return
        if self.host_key is None:
            self.host_key = paramiko.RSAKey.generate(2048)
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

    def _listen(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                self.sock = listener
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(('0.0.0.0', self.port))
                listener.listen(8)
                listener.settimeout(0.5)
                while self.running:
                    try:
                        client, addr = listener.accept()
                    except socket.timeout:
                        continue
                    if not self._slots.acquire(blocking=False):
                        client.close()
                        continue
                    with self._client_lock:
                        self._clients.add(client)
                        worker = threading.Thread(target=self._client_worker, args=(client, addr), daemon=True)
                        self._workers.add(worker)
                    worker.start()
        except OSError as exc:
            if self.running:
                print(f'SSH Honeypot port {self.port} açılamadı: {exc}')
        finally:
            self.running = False
            self.sock = None

    def _client_worker(self, client, addr):
        try:
            self._handle_client(client, addr)
        finally:
            client.close()
            with self._client_lock:
                self._clients.discard(client)
                self._workers.discard(threading.current_thread())
            self._slots.release()

    def _handle_client(self, client, addr):
        transport = None
        channel = None
        try:
            client.settimeout(10)
            transport = paramiko.Transport(client)
            transport.banner_timeout = 5
            transport.handshake_timeout = 5
            transport.auth_timeout = 10
            transport.add_server_key(self.host_key)
            server = FakeSSHServer(addr[0], self.db, self.blocker, self.auto_ban)
            transport.start_server(server=server)
            channel = transport.accept(10)
            if channel is None:
                return
            channel.settimeout(10)
            if not server.event.wait(10) or not self.running:
                return
            channel.sendall(b'Welcome to Ubuntu 20.04.4 LTS\r\nroot@server:~# ')
            while self.running:
                command = bytearray()
                while self.running:
                    char = channel.recv(1)
                    if not char:
                        return
                    if char in (b'\r', b'\n'):
                        channel.sendall(b'\r\n')
                        break
                    if char == b'\x03':
                        command.clear()
                        channel.sendall(b'^C\r\n')
                        break
                    if len(command) >= 4096:
                        return
                    channel.sendall(char)
                    command.extend(char)
                text = command.decode('utf-8', errors='replace').strip()
                if text:
                    self.db.add_alert(alert_type='SSH Komut Ihlali (Honeypot)',
                                      src_ip=addr[0], src_mac='N/A', dst_ip='N/A', dst_mac='N/A',
                                      description=f'Honeypot terminal komutu: {text}', severity='high', source_verified=True)
                    if text in ('exit', 'quit'):
                        channel.sendall(b'logout\r\n')
                        return
                    if text.startswith('ls'):
                        response = 'config.php  database.sql  passwords.txt  readme.md'
                    elif text.startswith('cat '):
                        response = 'Permission denied'
                    elif text == 'whoami':
                        response = 'root'
                    else:
                        response = f'bash: {text}: command not found'
                    channel.sendall((response + '\r\n').encode())
                channel.sendall(b'root@server:~# ')
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            if channel is not None:
                channel.close()
            if transport is not None:
                transport.close()
            client.close()

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        with self._client_lock:
            clients = list(self._clients)
            workers = list(self._workers)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=2)
        for worker in workers:
            worker.join(timeout=1)
