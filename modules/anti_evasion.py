# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Anti-Evasion Modülü (MAC Spoofing ve Randomization Koruması)
Saldırganların ban yememek için sürekli MAC adresi değiştirmesini (MAC Randomization)
veya ağda MAC Flooding yapmasını tespit eder.
"""
import time
import ipaddress
from scapy.all import Ether, IP
from core.database import Database
from utils.sound import SoundAlert

class AntiEvasionDetector:
    def __init__(self, db: Database, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        
        # MAC izleme değişkenleri
        self.recent_macs = {}
        self.mac_flood_threshold = 10 # 10 saniyede 10 farklı yeni MAC gelirse şüpheli
        self.time_window = 10.0 # saniye
        self.last_cleanup = time.time()

    def analyze(self, packet):
        if not packet.haslayer(Ether) or not packet.haslayer(IP):
            return
        src_ip = packet[IP].src
        src_mac = packet[Ether].src.lower()
        try:
            address = ipaddress.ip_address(src_ip)
            if address.is_unspecified or address.is_multicast:
                return
        except ValueError:
            return
        now = time.time()
        self._cleanup_old_macs(now)
        if src_ip not in self.recent_macs and len(self.recent_macs) >= 10000:
            self.recent_macs.pop(next(iter(self.recent_macs)))
        macs = self.recent_macs.setdefault(src_ip, {})
        for mac in list(macs):
            if now - macs[mac] >= self.time_window:
                del macs[mac]
        macs[src_mac] = now
        count = len(macs)
        if count >= self.mac_flood_threshold:
            self._trigger_alert(src_ip, src_mac, count)
            self.recent_macs.pop(src_ip, None)

    def _cleanup_old_macs(self, now):
        if now - self.last_cleanup < 1.0:
            return
        for src_ip, macs in list(self.recent_macs.items()):
            for mac in list(macs):
                if now - macs[mac] >= self.time_window:
                    del macs[mac]
            if not macs:
                del self.recent_macs[src_ip]
        self.last_cleanup = now

    def _trigger_alert(self, src_ip, last_mac, count):
        self.db.add_alert(
            alert_type='MAC Spoofing (Anti-Evasion)',
            src_ip=src_ip, src_mac=last_mac,
            dst_ip='N/A', dst_mac='N/A',
            description=f'Aynı IP ({src_ip}) için son {self.time_window:g} saniyede '
                        f'{count} farklı kaynak MAC gözlendi. Ağ geçidi/yedeklilik '
                        'değişimleriyle karşılaştırılmalı; kimlik sahteciliği doğrulanmadı.',
            severity='warning'
        )
        SoundAlert.alert_attack("MAC adres değişimi")
