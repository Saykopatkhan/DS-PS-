# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
ARP Spoofing ve Sniffing tespit modülü.
"""
import time
from collections import defaultdict
from scapy.all import ARP
from core.database import Database

class ARPDetector:
    """
    Ağdaki ARP trafiğini analiz ederek Spoofing, Flood ve Gratuitous ARP 
    anomalilerini tespit eden sınıf.
    """
    def __init__(self, db: Database, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.ip_mac_table = defaultdict(set)
        self.real_mac_table = {}
        self.arp_request_count = defaultdict(int)
        self.arp_reply_count = defaultdict(int)
        self.gratuitous_arp_count = defaultdict(int)
        self.detection_window = 10.0
        self.arp_threshold = 30
        self.last_reset = time.time()
        self._local_macs = self._get_local_macs()
        self._local_ips = self._get_local_ips()
        self._last_spoof_alert = {}
        self._binding_last_seen = {}
        self.binding_ttl = 300.0

    def analyze(self, packet):
        """ARP paketlerini analiz eder."""
        if packet.haslayer(ARP):
            now = time.time()
            if now - self.last_reset > self.detection_window:
                self.arp_request_count.clear()
                self.arp_reply_count.clear()
                self.gratuitous_arp_count.clear()
                self.last_reset = now
            sender_ip = packet[ARP].psrc
            sender_mac = packet[ARP].hwsrc
            if not isinstance(sender_mac, str) or sender_ip == '0.0.0.0':
                return
            
            # ARP op == 1 (request)
            if packet[ARP].op == 1:
                self.arp_request_count[sender_ip] += 1
                self._check_arp_flood(sender_ip)
            
            # ARP op == 2 (reply)
            elif packet[ARP].op == 2:
                self._detect_spoofing(packet)
                self.arp_reply_count[sender_ip] += 1
                self._check_gratuitous_arp(packet)
                self._check_arp_flood(sender_ip)
                
            self.db.update_ip_mac(sender_ip, sender_mac)

    def _get_local_macs(self):
        """Sistemin kendi MAC adreslerini (Whitelist) döndürür."""
        try:
            from scapy.arch import get_if_list, get_if_hwaddr
            macs = []
            for iface in get_if_list():
                try:
                    mac = get_if_hwaddr(iface)
                    if mac:
                        macs.append(mac.lower())
                except:
                    pass
            return macs
        except Exception:
            return []

    def _detect_spoofing(self, packet):
        """Report conflicting observations without treating the first as trusted."""
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc.lower()
        if sender_mac in self._local_macs:
            return
        now = time.time()
        known = self.ip_mac_table.get(sender_ip)
        last_seen = self._binding_last_seen.get(sender_ip, float('-inf'))
        if not known or now - last_seen >= self.binding_ttl:
            if sender_ip not in self.ip_mac_table and len(self.ip_mac_table) >= 10000:
                old_ip = next(iter(self.ip_mac_table))
                self.ip_mac_table.pop(old_ip, None)
                self.real_mac_table.pop(old_ip, None)
                self._binding_last_seen.pop(old_ip, None)
            self.ip_mac_table[sender_ip] = {sender_mac}
            self.real_mac_table[sender_ip] = sender_mac
            self._binding_last_seen[sender_ip] = now
            return
        if sender_mac in known:
            self._binding_last_seen[sender_ip] = now
            return
        key = (sender_ip, sender_mac)
        if now - self._last_spoof_alert.get(key, float('-inf')) < self.detection_window:
            return
        if len(self._last_spoof_alert) >= 10000:
            self._last_spoof_alert.clear()
        self._last_spoof_alert[key] = now
        self.db.add_alert(
            alert_type='ARP Spoofing',
            src_ip=sender_ip, src_mac=sender_mac,
            dst_ip=packet[ARP].pdst, dst_mac=packet[ARP].hwdst,
            description=f'ARP adres çakışması: IP {sender_ip} için MAC {sender_mac}, '
                        f'önceki gözlem {", ".join(sorted(known))}. '
                        'DHCP değişimi/yedekli ağ geçidi veya sahtecilik olabilir; doğrulama gerekli.',
            severity='warning'
        )
        # Neither observed binding is authenticated. Blocking the claimed IP can
        # disconnect the victim/gateway; unsolicited healing can poison the LAN.

    def _check_gratuitous_arp(self, packet):
        """Gratuitous ARP tespiti."""
        sender_ip = packet[ARP].psrc
        target_ip = packet[ARP].pdst
        
        if sender_ip == target_ip:
            self.gratuitous_arp_count[sender_ip] += 1
            if self.gratuitous_arp_count[sender_ip] == 6:
                self.db.add_alert(
                    alert_type='Gratuitous ARP',
                    src_ip=sender_ip, src_mac=packet[ARP].hwsrc,
                    dst_ip=sender_ip, dst_mac='ff:ff:ff:ff:ff:ff',
                    description=f'IP {sender_ip} için aşırı Gratuitous ARP ({self.gratuitous_arp_count[sender_ip]} adet)',
                    severity='high'
                )

    def _get_local_ips(self):
        import subprocess
        try:
            # Sistemdeki tüm yerel IP'leri (wlan0, eth0 vb.) döndürür
            return subprocess.getoutput('hostname -I').split()
        except Exception:
            return ['127.0.0.1']

    def _check_arp_flood(self, sender_ip):
        total = self.arp_request_count[sender_ip] + self.arp_reply_count[sender_ip]
        if sender_ip not in self._local_ips and total == self.arp_threshold + 1:
            self.db.add_alert(
                alert_type='ARP Storm (DDoS)', src_ip=sender_ip, src_mac='N/A',
                dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {sender_ip} - {total} ARP paketi / {self.detection_window}s pencerede',
                severity='high')

    def get_stats(self) -> dict:
        """İstatistikleri döner."""
        return {
            "requests": dict(self.arp_request_count),
            "replies": dict(self.arp_reply_count),
            "gratuitous": dict(self.gratuitous_arp_count)
        }
