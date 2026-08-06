# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Port Scan tespit modülü (SYN, FIN, XMAS, NULL, UDP).
"""
import time
from collections import defaultdict
from scapy.all import TCP, UDP, IP
from core.database import Database

class ScanDetector:
    """
    Farklı tiplerdeki port tarama saldırılarını (Nmap vb.) tespit eder.
    """
    def __init__(self, db: Database, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.syn_count = defaultdict(lambda: defaultdict(int))
        self.fin_count = defaultdict(lambda: defaultdict(int))
        self.xmas_count = defaultdict(lambda: defaultdict(int))
        self.null_count = defaultdict(lambda: defaultdict(int))
        self.udp_count = defaultdict(lambda: defaultdict(int))
        self.connection_timestamps = defaultdict(list)
        self.scan_threshold = 15
        self.time_window = 5.0
        self.last_cleanup = time.time()

    def analyze(self, packet):
        """Paketi analiz ederek port tarama tespiti yapar."""
        self._cleanup()
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # SYN only (0x02)
                if flags == 0x02:
                    self.syn_count[src_ip][dst_port] += 1
                    self._check_syn_scan(src_ip)
                # FIN only (0x01)
                elif flags == 0x01:
                    self.fin_count[src_ip][dst_port] += 1
                    self._check_fin_scan(src_ip)
                # XMAS (FIN+PSH+URG, 0x29)
                elif flags == 0x29:
                    self.xmas_count[src_ip][dst_port] += 1
                    self._check_xmas_scan(src_ip)
                # NULL (0x00)
                elif flags == 0x00:
                    self.null_count[src_ip][dst_port] += 1
                    self._check_null_scan(src_ip)
                    
                self.connection_timestamps[src_ip].append(time.time())
                self._check_flood(src_ip)
                
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                # DNS (53) ve DHCP (67, 68) trafiği UDP tarama alarmı üretmemeli
                if src_port not in [53, 67, 68] and dst_port not in [53, 67, 68]:
                    self.udp_count[src_ip][dst_port] += 1
                    self._check_udp_scan(src_ip)
                    self.connection_timestamps[src_ip].append(time.time())
                    self._check_flood(src_ip)

    def _check_flood(self, src_ip):
        """DoS / Flood tespiti (Aynı IP'den aşırı paket gelmesi)."""
        # Son 1 saniyedeki paket sayısını kontrol et
        current_time = time.time()
        recent_packets = [t for t in self.connection_timestamps[src_ip] if current_time - t < 1.0]
        self.connection_timestamps[src_ip] = recent_packets
        
        if len(recent_packets) > 500: # Saniyede 500 paket DoS kabul edilir
            self.db.add_alert(
                alert_type='SYN/UDP Flood (DoS)',
                src_ip=src_ip, src_mac='N/A',
                dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {src_ip} - Saniyede {len(recent_packets)} paket (Flood Saldırısı!)',
                severity='critical'
            )
            if self.blocker and self.auto_ban:
                self.blocker.block_ip(src_ip)

    def _check_syn_scan(self, src_ip):
        """SYN Scan tespiti."""
        if len(self.syn_count[src_ip]) > self.scan_threshold:
            ports = list(self.syn_count[src_ip].keys())[:10]
            self.db.add_alert(
                alert_type='SYN Scan',
                src_ip=src_ip, src_mac='N/A',
                dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {src_ip} - {len(self.syn_count[src_ip])} port tarandı (örn: {ports})',
                severity='high'
            )
            if self.blocker and self.auto_ban:
                self.blocker.block_ip(src_ip)

    def _check_fin_scan(self, src_ip):
        """FIN Scan tespiti."""
        if len(self.fin_count[src_ip]) > self.scan_threshold:
            self.db.add_alert(
                alert_type='FIN Scan',
                src_ip=src_ip, src_mac='N/A',
                dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {src_ip} - {len(self.fin_count[src_ip])} port tarandı',
                severity='high'
            )
            if self.blocker and self.auto_ban:
                self.blocker.block_ip(src_ip)

    def _check_xmas_scan(self, src_ip):
        """XMAS Scan tespiti."""
        if len(self.xmas_count[src_ip]) > self.scan_threshold:
            self.db.add_alert(
                alert_type='XMAS Scan',
                src_ip=src_ip, src_mac='N/A',
                dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {src_ip} - {len(self.xmas_count[src_ip])} port tarandı (FIN+PSH+URG)',
                severity='critical'
            )
            if self.blocker and self.auto_ban:
                self.blocker.block_ip(src_ip)

    def _check_null_scan(self, src_ip):
        """NULL Scan tespiti."""
        if len(self.null_count[src_ip]) > self.scan_threshold:
            self.db.add_alert(
                alert_type='NULL Scan',
                src_ip=src_ip, src_mac='N/A',
                dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {src_ip} - {len(self.null_count[src_ip])} port tarandı (Boş flag)',
                severity='critical'
            )
            if self.blocker and self.auto_ban:
                self.blocker.block_ip(src_ip)

    def _check_udp_scan(self, src_ip):
        """UDP Scan tespiti."""
        if len(self.udp_count[src_ip]) > self.scan_threshold:
            self.db.add_alert(
                alert_type='UDP Scan',
                src_ip=src_ip, src_mac='N/A',
                dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {src_ip} - {len(self.udp_count[src_ip])} UDP port tarandı',
                severity='medium'
            )
            if self.blocker and self.auto_ban:
                self.blocker.block_ip(src_ip)

    def _cleanup(self):
        """Eski verileri temizler."""
        if time.time() - self.last_cleanup > self.time_window * 2:
            self.syn_count.clear()
            self.fin_count.clear()
            self.xmas_count.clear()
            self.null_count.clear()
            self.udp_count.clear()
            self.connection_timestamps.clear()
            self.last_cleanup = time.time()

    def get_stats(self) -> dict:
        """İstatistikleri döner."""
        return {
            "syn_scans": len(self.syn_count),
            "fin_scans": len(self.fin_count),
            "xmas_scans": len(self.xmas_count),
            "null_scans": len(self.null_count),
            "udp_scans": len(self.udp_count)
        }
