import ipaddress
import logging
import socket
import subprocess
import threading

logger = logging.getLogger('DSIPS_Tarpit')
MAX_TARPIT_IPS = 100
MAX_CONNECTIONS = 500


class TCPTarpit:
    def __init__(self, port=9999, db=None, blocker=None, dry_run=False):
        self.port = int(port)
        if not 1 <= self.port <= 65535:
            raise ValueError('Geçersiz port')
        self.db, self.blocker, self.dry_run = db, blocker, dry_run
        self.running = False
        self.server_socket = None
        self.trapped_ips = set()
        self.total_trapped_connections = 0
        self.active_connections = set()
        self.lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread = None
        self._owned_rules = {}
        self._cleanup_pending = set()

    def start(self):
        if self.dry_run or (self.blocker and self.blocker.dry_run):
            return False
        if self.running:
            return True
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(100)
            self.server_socket.settimeout(1)
            self._stop_event.clear()
            self.running = True
            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
            return True
        except OSError:
            logger.exception('TCP Tarpit başlatılamadı')
            self.running = False
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            return False

    def _listen_loop(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                with self.lock:
                    if len(self.active_connections) >= MAX_CONNECTIONS:
                        conn.close()
                        continue
                    self.active_connections.add(conn)
                    self.total_trapped_connections += 1
                threading.Thread(target=self._tarpit_client, args=(conn, addr[0]), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _tarpit_client(self, conn, ip):
        try:
            conn.settimeout(1)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
            if self._stop_event.wait(2):
                return
            while self.running:
                conn.sendall(b'\x00')
                if self._stop_event.wait(3):
                    break
        except OSError:
            pass
        finally:
            conn.close()
            with self.lock:
                self.active_connections.discard(conn)

    def _rules(self, ip):
        return [
            (['-t', 'nat'], ['PREROUTING', '-p', 'tcp', '-s', ip, '-m', 'comment', '--comment', 'dsips-tarpit', '-j', 'REDIRECT', '--to-ports', str(self.port)]),
            ([], ['FORWARD', '-s', ip, '-p', 'tcp', '-m', 'comment', '--comment', 'dsips-tarpit', '-j', 'REJECT', '--reject-with', 'tcp-reset']),
        ]

    def tarpit_ip(self, ip):
        address = ipaddress.IPv4Address(ip)
        ip = str(address)
        if (address.is_loopback or address.is_unspecified or address.is_multicast
                or ip == '255.255.255.255'
                or (self.blocker and self.blocker.is_protected_ip(ip))):
            return False
        if self.dry_run or (self.blocker and self.blocker.dry_run) or not self.running:
            return False
        with self.lock:
            if ip in self.trapped_ips:
                return ip not in self._cleanup_pending
            if len(self.trapped_ips) >= MAX_TARPIT_IPS:
                return False
            added = []
            try:
                for table, rule in self._rules(ip):
                    result = subprocess.run(['iptables', *table, '-C', *rule], capture_output=True, timeout=5)
                    if result.returncode == 1:
                        subprocess.run(['iptables', *table, '-I', *rule], capture_output=True, check=True, timeout=5)
                        added.append((table, rule))
                    elif result.returncode != 0:
                        raise subprocess.CalledProcessError(result.returncode, result.args)
                self._owned_rules[ip] = added
                self.trapped_ips.add(ip)
                return True
            except (OSError, subprocess.SubprocessError):
                logger.exception('Tarpit yönlendirme hatası')
                remaining = list(added)
                for table, rule in reversed(added):
                    try:
                        subprocess.run(['iptables', *table, '-D', *rule], capture_output=True, check=True, timeout=5)
                        remaining.remove((table, rule))
                    except (OSError, subprocess.SubprocessError):
                        logger.exception('Tarpit rollback failed')
                if remaining:
                    # Keep failed cleanup visible and retryable via untarpit/stop.
                    self._owned_rules[ip] = remaining
                    self.trapped_ips.add(ip)
                    self._cleanup_pending.add(ip)
                return False

    def untarpit_ip(self, ip):
        ip = str(ipaddress.IPv4Address(ip))
        if self.dry_run or (self.blocker and self.blocker.dry_run):
            return False
        with self.lock:
            rules = self._owned_rules.get(ip, [])
            for table, rule in list(reversed(rules)):
                try:
                    result = subprocess.run(['iptables', *table, '-C', *rule], capture_output=True, timeout=5)
                    if result.returncode == 0:
                        subprocess.run(['iptables', *table, '-D', *rule], capture_output=True, check=True, timeout=5)
                    elif result.returncode != 1:
                        raise subprocess.CalledProcessError(result.returncode, result.args)
                    rules.remove((table, rule))
                except (OSError, subprocess.SubprocessError):
                    logger.exception('Untarpit failed')
                    self._cleanup_pending.add(ip)
                    return False
            self._owned_rules.pop(ip, None)
            self.trapped_ips.discard(ip)
            self._cleanup_pending.discard(ip)
            return True

    def get_stats(self):
        with self.lock:
            return {'active_tarpit_ips': sorted(self.trapped_ips),
                    'cleanup_pending_ips': sorted(self._cleanup_pending),
                    'total_trapped_connections': self.total_trapped_connections,
                    'active_connections': len(self.active_connections),
                    'tarpit_count': len(self.trapped_ips)}

    def stop(self):
        self.running = False
        self._stop_event.set()
        if self.server_socket:
            self.server_socket.close()
        with self.lock:
            for conn in tuple(self.active_connections):
                conn.close()
            self.active_connections.clear()
            for ip in tuple(self.trapped_ips):
                self.untarpit_ip(ip)
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
