# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
WiFi atak tespit modülü (Deauth, Beacon Flood, Evil Twin).
"""
import time
from collections import defaultdict
from scapy.all import Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, RadioTap
from core.database import Database

class WiFiDetector:
    """
    802.11 WiFi ağlarındaki saldırıları tespit eden sınıf.
    """
    def __init__(self, db: Database, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.deauth_count = defaultdict(int)
        self.deauth_threshold = 10
        self.beacon_ssids = defaultdict(set)
        self.ssid_bssid_map = defaultdict(set)
        self.beacon_count = defaultdict(int)
        self.beacon_flood_threshold = 50
        self.detection_window = 10.0
        self.last_reset = time.time()
        self.unique_ssids_in_window = set()

    def analyze(self, packet):
        """802.11 paketlerini analiz eder."""
        try:
            if packet.haslayer(Dot11):
                self._reset_window()
                
                # Management frame (type 0)
                if packet.type == 0:
                    # Deauth (subtype 12)
                    if packet.subtype == 12:
                        self._detect_deauth(packet)
                    # Beacon (subtype 8)
                    elif packet.subtype == 8:
                        self._detect_beacon_flood(packet)
                        self._detect_evil_twin(packet)
        except Exception:
            pass # Beklenmeyen paket hatalarını atla

    def _detect_deauth(self, packet):
        """Deauth saldırısı tespiti."""
        try:
            src_mac = packet.addr2
            self.deauth_count[src_mac] += 1
            
            if self.deauth_count[src_mac] > self.deauth_threshold:
                self.db.add_alert(
                    alert_type='Deauth Saldırısı',
                    src_ip='N/A', src_mac=src_mac,
                    dst_ip='N/A', dst_mac=packet.addr1 if packet.addr1 else 'N/A',
                    description=f'Kaynak MAC {src_mac} - {self.deauth_count[src_mac]} deauth frame gönderdi',
                    severity='critical'
                )
                if self.blocker and self.auto_ban:
                    self.blocker.block_mac(src_mac)
        except Exception:
            pass

    def _detect_beacon_flood(self, packet):
        """Beacon Flood saldırısı tespiti."""
        try:
            bssid = packet.addr3
            self.beacon_count[bssid] += 1
            
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                self.unique_ssids_in_window.add(ssid)
                
                if len(self.unique_ssids_in_window) > self.beacon_flood_threshold:
                    self.db.add_alert(
                        alert_type='Beacon Flood',
                        src_ip='N/A', src_mac=bssid if bssid else 'N/A',
                        dst_ip='N/A', dst_mac='ff:ff:ff:ff:ff:ff',
                        description=f'{len(self.unique_ssids_in_window)} benzersiz SSID tespit edildi (eşik: {self.beacon_flood_threshold})',
                        severity='high'
                    )
        except Exception:
            pass

    def _detect_evil_twin(self, packet):
        """Evil Twin saldırısı tespiti."""
        try:
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                bssid = packet.addr3
                
                if ssid and bssid:
                    self.ssid_bssid_map[ssid].add(bssid)
                    
                    if len(self.ssid_bssid_map[ssid]) > 1:
                        bssids = ", ".join(list(self.ssid_bssid_map[ssid]))
                        self.db.add_alert(
                            alert_type='Evil Twin',
                            src_ip='N/A', src_mac=bssid,
                            dst_ip='N/A', dst_mac='ff:ff:ff:ff:ff:ff',
                            description=f"SSID '{ssid}' için çoklu BSSID tespit edildi: {bssids}",
                            severity='critical'
                        )
        except Exception:
            pass

    def _reset_window(self):
        """Zaman penceresini sıfırlar."""
        if time.time() - self.last_reset > self.detection_window:
            self.deauth_count.clear()
            self.beacon_count.clear()
            self.unique_ssids_in_window.clear()
            self.last_reset = time.time()

    def get_stats(self) -> dict:
        """İstatistikleri döner."""
        return {
            "deauth_senders": len(self.deauth_count),
            "beacon_bssids": len(self.beacon_count),
            "evil_twin_ssids": len([ssid for ssid, bssids in self.ssid_bssid_map.items() if len(bssids) > 1])
        }
