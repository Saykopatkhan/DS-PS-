import asyncio
import re
import os
import time
import ipaddress
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
        
        # İzlenecek Log Dosyaları
        self.LOG_FILES = {
            'nginx_access': '/var/log/nginx/access.log',
            'apache_access': '/var/log/apache2/access.log',
            'auth_log': '/var/log/auth.log'
        }
        
        # Regex İmza Kütüphanesi
        self.SIGNATURES = {
            'SQL_INJECTION': re.compile(r'(?i)(union.*select|select.*from|insert.*into|drop.*table|waitfor.*delay|1=1|--$)'),
            'RCE_COMMAND_INJ': re.compile(r'(?i)([;|&]\s*(?:wget|curl|nc|bash|sh|perl|python|ruby)\b|`|\$\(|\b(?:wget|curl|nc|bash|sh|perl|python|ruby)\s+)'),
            'LFI_DIR_TRAVERSAL': re.compile(r'(?i)(\.\./\.\./|/etc/passwd|/windows/win\.ini|php://filter|php://input)'),
            'XSS_REFLECTED': re.compile(r'(?i)(<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=|<img[^>]+on\w+\s*=|alert\s*\(|document\.cookie|<svg[^>]+on\w+)'),
            'SCANNER_USER_AGENT': re.compile(r'(?i)(sqlmap|nikto|gobuster|nmap|dirb|w3af|zmap|masscan)'),
        }
        
        # Seviye Bazlı Haritalama
        self.SEVERITY_MAP = {
            'SQL_INJECTION': 'critical',
            'RCE_COMMAND_INJ': 'critical',
            'LFI_DIR_TRAVERSAL': 'high',
            'XSS_REFLECTED': 'high',
            'SCANNER_USER_AGENT': 'medium',
            'SSH_BRUTE_FORCE': 'high',
            'HTTP_DDOS': 'high',
        }
        
        # SSH Brute Force takibi (IP -> list of timestamps)
        self.ssh_failures = {}
        self.SSH_BRUTE_LIMIT = 5
        self.SSH_BRUTE_WINDOW = 60 # Saniye
        
        # HTTP DDoS takibi (IP -> deque of timestamps)
        self.http_requests = {}
        self.DDOS_THRESHOLD = 100  # istek
        self.DDOS_WINDOW = 10     # saniye

    def register_callback(self, callback):
        self.callbacks.append(callback)
        
    def _trigger_alert(self, alert_type, source_ip, details):
        severity = self.SEVERITY_MAP.get(alert_type, 'medium')
        event = {
            'type': alert_type,
            'source_ip': source_ip,
            'details': details,
            'severity': severity,
            'timestamp': time.time()
        }
        for cb in self.callbacks:
            try:
                cb(event)
            except Exception:
                pass

    async def tail_file(self, file_path, log_type):
        """Follow rotation while always reaping the child on stop/cancellation."""
        if not os.path.exists(file_path):
            return
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                'tail', '-F', '-n', '0', file_path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            while self.running:
                try:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                if not line:
                    break
                decoded = line.decode('utf-8', errors='replace').strip()
                if log_type == 'auth_log':
                    self._analyze_auth_log(decoded)
                else:
                    self._analyze_web_log(decoded)
        except (OSError, ValueError) as exc:
            print(f'HIDS Tail Hatası ({file_path}): {exc}')
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
        now = time.time()
        self._cleanup(now)
        from collections import deque
        if src_ip not in self.http_requests:
            self.http_requests[src_ip] = deque()
        self.http_requests[src_ip].append(now)
        while self.http_requests[src_ip] and self.http_requests[src_ip][0] < now - self.DDOS_WINDOW:
            self.http_requests[src_ip].popleft()
        if len(self.http_requests[src_ip]) >= self.DDOS_THRESHOLD:
            self._trigger_alert('HTTP_DDOS', src_ip, f"{self.DDOS_WINDOW}s içinde {len(self.http_requests[src_ip])} HTTP isteği")
            self.http_requests[src_ip].clear()  # Alarm sonrası sıfırla
            return
        
        # Attack syntax belongs in the HTTP request, not normal UA punctuation.
        request_match = re.search(r'"([A-Z]+\s+\S+\s+HTTP/[\d.]+)"', line)
        request_text = unquote(unquote(request_match.group(1))) if request_match else ''
        for sig_name, sig_regex in self.SIGNATURES.items():
            candidate = line if sig_name == 'SCANNER_USER_AGENT' else request_text
            if sig_regex.search(candidate):
                self._trigger_alert(sig_name, src_ip, f"WAF İhlali: {sig_name}")
                break # Aynı satırdan 1 alarm yeterli

    def _analyze_auth_log(self, line):
        """SSH auth.log analizi."""
        # Başarısız SSH girişini yakala
        if "Failed password" in line or "Connection closed by authenticating user" in line:
            # IP adresini bul
            ip_match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if not ip_match:
                # Farklı formattaki IP'ler için alternatif arama
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                
            if ip_match:
                try:
                    src_ip = str(ipaddress.ip_address(ip_match.group(1)))
                except ValueError:
                    return
                now = time.time()
                self._cleanup(now)
                
                if src_ip not in self.ssh_failures:
                    self.ssh_failures[src_ip] = []
                    
                self.ssh_failures[src_ip].append(now)
                
                # Temizlik
                self.ssh_failures[src_ip] = [t for t in self.ssh_failures[src_ip] if now - t <= self.SSH_BRUTE_WINDOW]
                
                if len(self.ssh_failures[src_ip]) >= self.SSH_BRUTE_LIMIT:
                    self._trigger_alert('SSH_BRUTE_FORCE', src_ip, f"{self.SSH_BRUTE_WINDOW} saniyede {len(self.ssh_failures[src_ip])} başarısız SSH denemesi")
                    self.ssh_failures[src_ip] = [] # Alarm sonrası sıfırla

    async def run(self):
        if self.running:
            return
        self.running = True
        self._loop = asyncio.get_running_loop()
        self.tasks = [asyncio.create_task(self.tail_file(path, kind)) for kind, path in self.LOG_FILES.items()]
        try:
            await asyncio.gather(*self.tasks, return_exceptions=True)
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
