# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Dış İstihbarat (Threat Intelligence) Modülü
Açık kaynaklı zararlı IP listelerini çeker ve ağdaki cihazların bu IP'lere bağlanıp bağlanmadığını kontrol eder.
"""
import urllib.request
import threading
import json
import ipaddress
import time
from scapy.all import IP, TCP, UDP
from core.database import Database
from utils.sound import SoundAlert

class ThreatIntelDetector:
    def __init__(self, db: Database, blocker=None, auto_ban=False, geo_enabled=False):
        self.geo_enabled = geo_enabled
        self._stop_event = threading.Event()
        self._thread = None
        self._geo_slots = threading.BoundedSemaphore(4)
        self._last_alert = {}
        self._lock = threading.RLock()
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.bad_ips = set()
        self.is_loaded = False
        
        # Geo-IP Kalkanı Ayarları
        self.geo_cache = {}
        self.bad_countries = {'RU', 'KP', 'CN', 'IR', 'SY'} # Rusya, K.Kore, Çin, İran, Suriye
        
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._fetch_cins_army, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=11)

    def _allow_alert(self, source, target, kind):
        if self._stop_event.is_set():
            return False
        now = time.time()
        key = (source, target, kind)
        with self._lock:
            if now - self._last_alert.get(key, float('-inf')) < 60:
                return False
            if len(self._last_alert) >= 10000:
                self._last_alert.clear()
            self._last_alert[key] = now
        return True

    def _fetch_cins_army(self):
        try:
            url = "https://cinsscore.com/list/ci-badguys.txt"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read(8 * 1024 * 1024).decode('utf-8')
                loaded_ips = set()
                for line in content.splitlines():
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        try:
                            loaded_ips.add(str(ipaddress.ip_address(ip)))
                        except ValueError:
                            continue
                if not self._stop_event.is_set():
                    self.bad_ips = loaded_ips
            print(f"[+] Dış İstihbarat: CINS Army listesinden {len(self.bad_ips)} zararlı IP yüklendi.")
        except Exception as e:
            print(f"[-] Dış İstihbarat listesi indirilemedi: {e}")
            # Preserve the last valid feed; invented fallback indicators are unsafe.
            pass
        finally:
            self.is_loaded = True

    def analyze(self, packet):
        if self._stop_event.is_set() or not self.is_loaded:
            return
            
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Private (Yerel) IP ise yoksay
            try:
                if not ipaddress.ip_address(dst_ip).is_global:
                    return
            except Exception:
                return
                
            # 1. Bilinen Botnet/C2 kontrolü
            if dst_ip in self.bad_ips:
                self._detect_bad_connection(packet, src_ip, dst_ip)
                return
                
            if not self.geo_enabled:
                return

            # 2. Geo-IP Kalkanı kontrolü
            if dst_ip not in self.geo_cache:
                if not self._geo_slots.acquire(blocking=False):
                    return
                if len(self.geo_cache) >= 10000:
                    self.geo_cache.pop(next(iter(self.geo_cache)))
                self.geo_cache[dst_ip] = 'pending'
                threading.Thread(target=self._geo_worker, args=(packet, src_ip, dst_ip), daemon=True).start()
            elif isinstance(self.geo_cache[dst_ip], dict) and self.geo_cache[dst_ip].get('country_code') in self.bad_countries:
                self._detect_bad_geo(packet, src_ip, dst_ip, self.geo_cache[dst_ip])

    def _geo_worker(self, packet, src_ip, dst_ip):
        try:
            self._check_geo_ip(packet, src_ip, dst_ip)
        finally:
            self._geo_slots.release()

    def _check_geo_ip(self, packet, src_ip, dst_ip):
        try:
            url = f"https://ip-api.com/json/{dst_ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read(65536).decode('utf-8'))
                
                if data.get('status') == 'success':
                    cc = data.get('countryCode', '')
                    geo_info = {
                        'country_code': cc,
                        'country': data.get('country', 'Bilinmiyor'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'isp': data.get('isp', ''),
                        'asn': data.get('as', '')
                    }
                    self.geo_cache[dst_ip] = geo_info
                    
                    if cc in self.bad_countries:
                        self._detect_bad_geo(packet, src_ip, dst_ip, geo_info)
                else:
                    self.geo_cache[dst_ip] = 'unknown'
        except Exception:
            self.geo_cache[dst_ip] = 'unknown'

    def _detect_bad_geo(self, packet, src_ip, dst_ip, geo_info):
        if not self._allow_alert(src_ip, dst_ip, 'geo'):
            return
        src_mac = packet.src if hasattr(packet, 'src') else 'N/A'
        country = geo_info.get('country', 'Bilinmiyor')
        lat = geo_info.get('lat')
        lon = geo_info.get('lon')
        
        from datetime import datetime
        now = datetime.now()
        is_night = (now.hour >= 1 and now.hour <= 5)
        
        alert_type = 'Coğrafi Kalkan (Geo-IP) İhlali'
        desc = f"Yapılandırılmış coğrafi izleme listesine bağlantı: {country}, {dst_ip}. Ülke tek başına saldırı kanıtı değildir."
        
        # UEBA (User Entity Behavior Analytics)
        if is_night:
            alert_type = 'UEBA Anomaly (Olağandışı Saat)'
            desc = f"Olağandışı saatte (01:00-05:00) şüpheli {country} bağlantısı. Olası Veri Sızdırma (Exfiltration)!"
            
        self.db.add_alert(
            alert_type=alert_type,
            src_ip=src_ip, src_mac=src_mac,
            dst_ip=dst_ip, dst_mac='N/A',
            description=desc,
            severity='warning',
            lat=lat, lon=lon, country=country
        )
        from utils.sound import SoundAlert
        SoundAlert.alert_attack(f"Geo-IP İhlali: {country}")

    def _detect_bad_connection(self, packet, src_ip, dst_ip):
        if not self._allow_alert(src_ip, dst_ip, 'feed'):
            return
        src_mac = packet.src if hasattr(packet, 'src') else 'N/A'
        port_info = ""
        if packet.haslayer(TCP):
            port_info = f" (Port: {packet[TCP].dport})"
        elif packet.haslayer(UDP):
            port_info = f" (Port: {packet[UDP].dport})"
            
        self.db.add_alert(
            alert_type='Zararlı C&C Sunucu Bağlantısı',
            src_ip=src_ip, src_mac=src_mac,
            dst_ip=dst_ip, dst_mac='N/A',
            description=f"Cihaz bilinen bir hacker (C&C) sunucusuna bağlanmaya çalıştı: {dst_ip}{port_info}",
            severity='critical'
        )
        SoundAlert.alert_attack("Zararlı Sunucu Bağlantısı")
        if self.blocker and self.auto_ban:
            self.blocker.block_ip(dst_ip)
