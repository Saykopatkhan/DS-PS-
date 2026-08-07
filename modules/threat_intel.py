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
from scapy.all import IP, TCP, UDP
from core.database import Database
from utils.sound import SoundAlert

class ThreatIntelDetector:
    def __init__(self, db: Database, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.bad_ips = set()
        self.is_loaded = False
        
        # Geo-IP Kalkanı Ayarları
        self.geo_cache = {}
        self.bad_countries = {'RU', 'KP', 'CN', 'IR', 'SY'} # Rusya, K.Kore, Çin, İran, Suriye
        
        # Arka planda listeyi güncelle
        threading.Thread(target=self._fetch_cins_army, daemon=True).start()

    def _fetch_cins_army(self):
        try:
            url = "https://cinsscore.com/list/ci-badguys.txt"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8')
                for line in content.splitlines():
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        self.bad_ips.add(ip)
            print(f"[+] Dış İstihbarat: CINS Army listesinden {len(self.bad_ips)} zararlı IP yüklendi.")
        except Exception as e:
            print(f"[-] Dış İstihbarat listesi indirilemedi: {e}")
            self.bad_ips.update(["185.153.196.213", "45.144.225.101", "104.24.112.55", "185.196.8.55"])
        finally:
            self.is_loaded = True

    def analyze(self, packet):
        if not self.is_loaded:
            return
            
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Private (Yerel) IP ise yoksay
            try:
                if ipaddress.ip_address(dst_ip).is_private:
                    return
            except Exception:
                return
                
            # 1. Bilinen Botnet/C2 kontrolü
            if dst_ip in self.bad_ips:
                self._detect_bad_connection(packet, src_ip, dst_ip)
                return
                
            # 2. Geo-IP Kalkanı kontrolü
            if dst_ip not in self.geo_cache:
                self.geo_cache[dst_ip] = 'pending'
                threading.Thread(target=self._check_geo_ip, args=(packet, src_ip, dst_ip), daemon=True).start()
            elif isinstance(self.geo_cache[dst_ip], dict) and self.geo_cache[dst_ip].get('country_code') in self.bad_countries:
                self._detect_bad_geo(packet, src_ip, dst_ip, self.geo_cache[dst_ip])

    def _check_geo_ip(self, packet, src_ip, dst_ip):
        try:
            url = f"http://ip-api.com/json/{dst_ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                
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
        src_mac = packet.src if hasattr(packet, 'src') else 'N/A'
        country = geo_info.get('country', 'Bilinmiyor')
        lat = geo_info.get('lat')
        lon = geo_info.get('lon')
        
        from datetime import datetime
        now = datetime.now()
        is_night = (now.hour >= 1 and now.hour <= 5)
        
        alert_type = 'Coğrafi Kalkan (Geo-IP) İhlali'
        desc = f"Cihaz şüpheli bir ülkeye ({country}) veri sızdırmaya çalışıyor: {dst_ip}. (Arka Kapı / Backdoor Tespiti)"
        
        # UEBA (User Entity Behavior Analytics)
        if is_night:
            alert_type = 'UEBA Anomaly (Olağandışı Saat)'
            desc = f"Olağandışı saatte (01:00-05:00) şüpheli {country} bağlantısı. Olası Veri Sızdırma (Exfiltration)!"
            
        self.db.add_alert(
            alert_type=alert_type,
            src_ip=src_ip, src_mac=src_mac,
            dst_ip=dst_ip, dst_mac='N/A',
            description=desc,
            severity='critical',
            lat=lat, lon=lon, country=country
        )
        from utils.sound import SoundAlert
        SoundAlert.alert_attack(f"Geo-IP İhlali: {country}")
        if self.blocker and self.auto_ban:
            self.blocker.block_ip(src_ip)

    def _detect_bad_connection(self, packet, src_ip, dst_ip):
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
        self.bad_ips.discard(dst_ip)
