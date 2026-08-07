# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Web Application Firewall (WAF) Modülü.
Dizin Kaba Kuvveti (Directory Bruteforce) ve L7 DoS saldırılarını tespit eder.
"""
import time
from collections import defaultdict
from scapy.all import IP, TCP, Raw

class WAFDetector:
    def __init__(self, db, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        
        # IP tabanlı takipler
        self.http_requests = defaultdict(list)
        self.http_404_errors = defaultdict(list)
        
        # Eşik değerleri
        self.time_window = 10.0 # 10 saniyelik analiz penceresi
        self.bruteforce_threshold = 30 # 10 saniyede 30'dan fazla 404 hatası
        self.l7_dos_threshold = 100 # 10 saniyede 100'den fazla HTTP isteği
        
        self.last_cleanup = time.time()

    def analyze(self, packet):
        """HTTP trafiğini analiz eder."""
        self._cleanup()
        
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            src_port = packet[TCP].sport
            
            # Sadece yaygın Web portları (80, 8080)
            if dst_port in [80, 8080] or src_port in [80, 8080]:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # 1. HTTP İstek Sayacı (L7 DoS Tespiti)
                    if payload.startswith("GET ") or payload.startswith("POST ") or payload.startswith("HEAD "):
                        self.http_requests[src_ip].append(time.time())
                        self._check_l7_dos(src_ip)
                        
                    # 2. HTTP 404 Hata Sayacı (Dizin Kaba Kuvveti Tespiti)
                    if "HTTP/1.1 404" in payload or "HTTP/1.0 404" in payload:
                        # Sunucu cevap veriyorsa, hedeften kaynağa dönen bir cevaptır
                        # Bu yüzden saldıran kişi dst_ip olur.
                        attacker_ip = dst_ip 
                        self.http_404_errors[attacker_ip].append(time.time())
                        self._check_bruteforce(attacker_ip)
                        
                except Exception:
                    pass

    def _check_l7_dos(self, ip):
        current_time = time.time()
        recent = [t for t in self.http_requests[ip] if current_time - t < self.time_window]
        self.http_requests[ip] = recent
        
        if len(recent) > self.l7_dos_threshold:
            self.db.add_alert(
                alert_type='Web L7 DoS / Flood',
                src_ip=ip, src_mac='N/A', dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {ip} - {self.time_window}s içinde {len(recent)} HTTP isteği!',
                severity='high'
            )
            if self.blocker and self.auto_ban:
                self.blocker.block_ip(ip)
            # Analizi sıfırla ki üst üste alarm üretmesin
            self.http_requests[ip] = []

    def _check_bruteforce(self, ip):
        current_time = time.time()
        recent = [t for t in self.http_404_errors[ip] if current_time - t < self.time_window]
        self.http_404_errors[ip] = recent
        
        if len(recent) > self.bruteforce_threshold:
            self.db.add_alert(
                alert_type='Web Dir-Bruteforce',
                src_ip=ip, src_mac='N/A', dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {ip} - {self.time_window}s içinde {len(recent)} kez 404 Hatası (Gobuster/Dirb?)',
                severity='high'
            )
            if self.blocker and self.auto_ban:
                self.blocker.block_ip(ip)
            # Analizi sıfırla
            self.http_404_errors[ip] = []

    def _cleanup(self):
        current_time = time.time()
        if current_time - self.last_cleanup > self.time_window * 2:
            for ip in list(self.http_requests.keys()):
                self.http_requests[ip] = [t for t in self.http_requests[ip] if current_time - t < self.time_window]
                if not self.http_requests[ip]:
                    del self.http_requests[ip]
                    
            for ip in list(self.http_404_errors.keys()):
                self.http_404_errors[ip] = [t for t in self.http_404_errors[ip] if current_time - t < self.time_window]
                if not self.http_404_errors[ip]:
                    del self.http_404_errors[ip]
                    
            self.last_cleanup = current_time
