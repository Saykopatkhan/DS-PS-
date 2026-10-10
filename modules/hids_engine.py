import asyncio
import re
import os
import time
import ipaddress
from collections import OrderedDict, deque
from urllib.parse import unquote

class HIDSEngine:
    """
    Katman 7 Asenkron Web ve Sistem Log Analiz Motoru (HIDS/WAF).
    Log dosyalarını non-blocking (asyncio) okur ve regex imzalarıyla eşleştirir.
    """
    def __init__(self):
        self.callbacks = []
        self.running = False
        self.tasks = []
        self._loop = None
        self._last_cleanup = 0
        self.MAX_SOURCES = 10000
        self.ALERT_COOLDOWN = 60
        self._last_alert = OrderedDict()
        
        # İzlenecek Log Dosyaları
        self.LOG_FILES = {
            'nginx_access': '/var/log/nginx/access.log',
            'apache_access': '/var/log/apache2/access.log',
            'auth_log': '/var/log/auth.log'
        }
        
        # Regex İmza Kütüphanesi
        self.SIGNATURES = {
            'SQL_INJECTION': re.compile(r'(?i)(\bunion\s+(?:all\s+)?select\b|\bselect\b.+\bfrom\b|\binsert\s+into\b|\bdrop\s+table\b|\bwaitfor\s+delay\b|[\'\"]\s*(?:or|and)\s+1\s*=\s*1)'),
            'RCE_COMMAND_INJ': re.compile(r'(?i)([;|&]\s*(?:wget|curl|nc|bash|sh|perl|python|ruby)\b|`|\$\()'),
            'LFI_DIR_TRAVERSAL': re.compile(r'(?i)(\.\./\.\./|/etc/passwd|/windows/win\.ini|php://filter|php://input)'),
            'XSS_REFLECTED': re.compile(r'(?i)(<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=|<img[^>]+on\w+\s*=|alert\s*\(|document\.cookie|<svg[^>]+on\w+)'),
            'SCANNER_USER_AGENT': re.compile(r'(?i)(sqlmap|nikto|gobuster|nmap|dirb|w3af|zmap|masscan)'),
        }
        
        # Seviye Bazlı Haritalama
        self.SEVERITY_MAP = {
            'SQL_INJECTION': 'high',
            'RCE_COMMAND_INJ': 'high',
            'LFI_DIR_TRAVERSAL': 'high',
            'XSS_REFLECTED': 'high',
            'SCANNER_USER_AGENT': 'medium',
            'SSH_BRUTE_FORCE': 'high',
            'HTTP_DDOS': 'medium',
        }
        
        # SSH Brute Force takibi (IP -> list of timestamps)
        self.ssh_failures = OrderedDict()
        self.SSH_BRUTE_LIMIT = 5
        self.SSH_BRUTE_WINDOW = 60 # Saniye
        
        # HTTP DDoS takibi (IP -> deque of timestamps)
        self.http_requests = OrderedDict()
        self.DDOS_THRESHOLD = 100  # istek
        self.DDOS_WINDOW = 10     # saniye

    def register_callback(self, callback):
        self.callbacks.append(callback)
        
    def _trigger_alert(self, alert_type, source_ip, details):
        now = time.monotonic()
        key = (alert_type, source_ip)
        if now - self._last_alert.get(key, float('-inf')) < self.ALERT_COOLDOWN:
            return
        self._last_alert[key] = now
        self._last_alert.move_to_end(key)
        while len(self._last_alert) > self.MAX_SOURCES:
            self._last_alert.popitem(last=False)
        severity = self.SEVERITY_MAP.get(alert_type, 'medium')
        event = {
            'type': alert_type,
            'source_ip': source_ip,
            'details': details,
            'severity': severity,
            'timestamp': time.time()
        }
        if alert_type == 'SSH_BRUTE_FORCE':
            event['source_verified'] = True
        for cb in self.callbacks:
            try:
                cb(event)
            except Exception:
                pass

    async def tail_file(self, file_path, log_type):
        """Follow rotation while always reaping the child on stop/cancellation."""
        if not os.path.exists(file_path):
            return 'unavailable'
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                'tail', '-F', '-n', '0', file_path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            if hasattr(self, 'reader_health'):
                self.reader_health[log_type] = {'state': 'running'}
                if all(value['state'] != 'starting' for value in self.reader_health.values()):
                    self.ready.set()
            while self.running:
                try:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                if not line:
                    raise RuntimeError('HIDS log reader exited unexpectedly')
                decoded = line.decode('utf-8', errors='replace').strip()
                if log_type == 'auth_log':
                    self._analyze_auth_log(decoded)
                else:
                    self._analyze_web_log(decoded)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f'HIDS log reader failed: {log_type}') from exc
        finally:
            if process and process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()

    def _cleanup(self, now):
        if now - self._last_cleanup < 30:
            return
        for table, window in ((self.http_requests, self.DDOS_WINDOW), (self.ssh_failures, self.SSH_BRUTE_WINDOW)):
            for ip in list(table):
                if not table[ip] or now - table[ip][-1] > window:
                    del table[ip]
        self._last_cleanup = now

    def _record(self, table, source, now, window, maximum):
        if source not in table:
            if len(table) >= self.MAX_SOURCES:
                table.popitem(last=False)
            table[source] = deque(maxlen=maximum)
        table.move_to_end(source)
        samples = table[source]
        while samples and samples[0] < now - window:
            samples.popleft()
        samples.append(now)
        return samples

    def _analyze_web_log(self, line):
        """Apache/Nginx access log analizi (Basit Kombine Format Analizi)."""
        # IP'yi çıkartmak için basit regex (Genelde ilk sütundur)
        ip_match = re.match(r'^(\S+)\s', line)
        if not ip_match:
            return
            
        try:
            src_ip = str(ipaddress.ip_address(ip_match.group(1)))
        except ValueError:
            return
        
        # HTTP DDoS Tespiti (IP başına istek hızı)
        now = time.monotonic()
        self._cleanup(now)
        samples = self._record(self.http_requests, src_ip, now, self.DDOS_WINDOW, self.DDOS_THRESHOLD)
        if len(samples) >= self.DDOS_THRESHOLD:
            self._trigger_alert('HTTP_DDOS', src_ip, f"{self.DDOS_WINDOW}s içinde {len(self.http_requests[src_ip])} HTTP isteği")
            self.http_requests[src_ip].clear()  # Alarm sonrası sıfırla
        
        # Attack syntax belongs in the HTTP request, not normal UA punctuation.
        request_match = re.search(r'"([A-Z]+\s+\S+\s+HTTP/[\d.]+)"', line)
        request_text = unquote(unquote(request_match.group(1))) if request_match else ''
        for sig_name, sig_regex in self.SIGNATURES.items():
            # In combined format the last quoted field is the User-Agent.
            # A scanner name in a URL or referrer is not a scanner identity.
            quoted = re.findall(r'"([^"\r\n]*)"', line) if sig_name == 'SCANNER_USER_AGENT' else []
            candidate = (quoted[-1] if len(quoted) >= 3 else '') if sig_name == 'SCANNER_USER_AGENT' else request_text
            if sig_regex.search(candidate):
                self._trigger_alert(sig_name, src_ip, f"HTTP isteğinde şüpheli imza: {sig_name}; başarılı istismar doğrulanmadı.")
                break # Aynı satırdan 1 alarm yeterli

    def _analyze_auth_log(self, line):
        """Count actual sshd failures; disconnects and usernames are not peers."""
        match = re.search(
            r'\bsshd(?:-session)?\[\d+\]: Failed password for (?:invalid user )?\S+ '
            r'from (\S+) port \d+ ssh2(?:\s|$)', line,
        )
        if not match:
            return
        try:
            src_ip = str(ipaddress.ip_address(match.group(1)))
        except ValueError:
            return
        now = time.monotonic()
        self._cleanup(now)
        samples = self._record(self.ssh_failures, src_ip, now, self.SSH_BRUTE_WINDOW, self.SSH_BRUTE_LIMIT)
        if len(samples) >= self.SSH_BRUTE_LIMIT:
            self._trigger_alert('SSH_BRUTE_FORCE', src_ip, f"{self.SSH_BRUTE_WINDOW} saniyede {len(samples)} başarısız SSH denemesi")
            samples.clear()

    async def run(self):
        if self.running:
            return
        self.running = True
        self._loop = asyncio.get_running_loop()
        self.ready = asyncio.Event()
        self.reader_health = {kind: {'state': 'starting'} for kind in self.LOG_FILES}

        def reader_finished(kind, task):
            import logging
            if task.cancelled():
                self.reader_health[kind] = {'state': 'stopped'}
            else:
                error = task.exception()
                if error:
                    self.reader_health[kind] = {'state': 'failed', 'error': type(error).__name__}
                    logging.getLogger(__name__).error(
                        'HIDS reader failed: %s', kind,
                        exc_info=(type(error), error, error.__traceback__))
                else:
                    self.reader_health[kind] = {'state': task.result() or 'stopped'}
            if all(value['state'] != 'starting' for value in self.reader_health.values()):
                self.ready.set()

        self.tasks = []
        for kind, path in self.LOG_FILES.items():
            task = asyncio.create_task(self.tail_file(path, kind))
            task.add_done_callback(lambda done, name=kind: reader_finished(name, done))
            self.tasks.append(task)
        if not self.tasks:
            self.ready.set()
        try:
            results = await asyncio.gather(*self.tasks, return_exceptions=True)
            if self.running and any(isinstance(result, Exception) for result in results):
                raise RuntimeError('No healthy HIDS log reader remains')
        finally:
            self.running = False
            self.tasks.clear()
            self._loop = None

    def stop(self):
        self.running = False
        loop = self._loop
        tasks = list(self.tasks)
        if loop and not loop.is_closed():
            for task in tasks:
                loop.call_soon_threadsafe(task.cancel)
