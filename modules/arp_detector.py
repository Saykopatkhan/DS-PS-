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
from scapy.all import ARP, Ether
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
        self.arp_request_count = defaultdict(int)
        self.arp_reply_count = defaultdict(int)
        self.gratuitous_arp_count = defaultdict(int)
        self.detection_window = 10.0
        self.arp_threshold = 30
        self.last_reset = time.time()

    def analyze(self, packet):
        """ARP paketlerini analiz eder."""
        if packet.haslayer(ARP):
            sender_ip = packet[ARP].psrc
            sender_mac = packet[ARP].hwsrc
            
            # ARP op == 1 (request)
            if packet[ARP].op == 1:
                self.arp_request_count[sender_ip] += 1
                self._check_arp_flood()
            
            # ARP op == 2 (reply)
            elif packet[ARP].op == 2:
                self._detect_spoofing(packet)
                self.arp_reply_count[sender_ip] += 1
                self._check_gratuitous_arp(packet)
                self._check_arp_flood()
                
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
        """ARP Spoofing tespiti yapar."""
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc
        
        # -------------------------------------------------------------
        # BEYAZ LİSTE (WHITELIST): Kendi IPS sistemimizin MAC'i mi?
        # Blocker modülünün attığı izolasyon paketlerini saldırı sanma.
        # -------------------------------------------------------------
        if sender_mac.lower() in self._get_local_macs():
            return
            
        if sender_ip in self.ip_mac_table:
            if sender_mac not in self.ip_mac_table[sender_ip]:
                known_macs = ', '.join(self.ip_mac_table[sender_ip])
                self.db.add_alert(
                    alert_type='ARP Spoofing',
                    src_ip=sender_ip, src_mac=sender_mac,
                    dst_ip=packet[ARP].pdst, dst_mac=packet[ARP].hwdst,
                    description=f'IP {sender_ip} için yeni MAC {sender_mac} tespit edildi (Bilinen: {known_macs})',
                    severity='critical'
                )
                if self.blocker and self.auto_ban:
                    self.blocker.block_ip(sender_ip)
                    self.blocker.block_mac(sender_mac)
                    
                # -------------------------------------------------------------
                # KULLANICI EKLENTİSİ: Anti-MITM Koruma (Healing Packets)
                # Kurban cihazların ARP tablolarını düzeltmek için ağa doğru 
                # MAC adresiyle düzeltme paketleri yollar.
                # -------------------------------------------------------------
                try:
                    from scapy.all import sendp
                    # Bilinen ilk MAC adresini doğru kabul ediyoruz (Real MAC)
                    real_mac = list(self.ip_mac_table[sender_ip])[0]
                    correct_arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                        op=2, 
                        pdst="255.255.255.255", # Broadcast IP
                        psrc=sender_ip, 
                        hwsrc=real_mac
                    )
                    sendp(correct_arp, count=5, verbose=False)
                    self.db.add_alert(
                        alert_type='Anti-MITM Healing',
                        src_ip='System', src_mac='N/A',
                        dst_ip='Broadcast', dst_mac='ff:ff:ff:ff:ff:ff',
                        description=f'{sender_ip} için onarıcı ARP (Healing) paketleri ağa yayınlandı.',
                        severity='warning'
                    )
                except Exception as e:
                    print(f"Anti-MITM Healing hatası: {e}")
                # -------------------------------------------------------------
                
                self.ip_mac_table[sender_ip].add(sender_mac)
        else:
            self.ip_mac_table[sender_ip].add(sender_mac)

    def _check_gratuitous_arp(self, packet):
        """Gratuitous ARP tespiti."""
        sender_ip = packet[ARP].psrc
        target_ip = packet[ARP].pdst
        
        if sender_ip == target_ip:
            self.gratuitous_arp_count[sender_ip] += 1
            if self.gratuitous_arp_count[sender_ip] > 5:
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

    def _check_arp_flood(self):
        """ARP Flood ve Sniffing tespiti."""
        current_time = time.time()
        if current_time - self.last_reset > self.detection_window:
            local_ips = self._get_local_ips()
            for ip in set(self.arp_request_count.keys()).union(set(self.arp_reply_count.keys())):
                if ip in local_ips:
                    continue # Sistemin kendi yaptığı meşru ağ taramalarını atla
                    
                total = self.arp_request_count[ip] + self.arp_reply_count[ip]
                if total > self.arp_threshold:
                    self.db.add_alert(
                        alert_type='ARP Storm (DDoS)',
                        src_ip=ip, src_mac='N/A',
                        dst_ip='N/A', dst_mac='N/A',
                        description=f'Kaynak {ip} - {total} ARP paketi / {self.detection_window}s pencerede',
                        severity='high'
                    )
            
            self.arp_request_count.clear()
            self.arp_reply_count.clear()
            self.gratuitous_arp_count.clear()
            self.last_reset = current_time

    def get_stats(self) -> dict:
        """İstatistikleri döner."""
        return {
            "requests": dict(self.arp_request_count),
            "replies": dict(self.arp_reply_count),
            "gratuitous": dict(self.gratuitous_arp_count)
        }
