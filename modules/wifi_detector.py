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
from scapy.all import Dot11, Dot11Elt
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
        # Only an administrator-approved inventory can identify an unexpected AP.
        self.trusted_bssids = {}

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
            
            if src_mac and self.deauth_count[src_mac] == self.deauth_threshold + 1:
                self.db.add_alert(
                    alert_type='Deauth Saldırısı',
                    src_ip='N/A', src_mac=src_mac,
                    dst_ip='N/A', dst_mac=packet.addr1 if packet.addr1 else 'N/A',
                    description=f'Kaynak MAC {src_mac} - {self.deauth_count[src_mac]} deauth frame gönderdi',
                    severity='critical'
                )
                # Management-frame source addresses are unauthenticated and can
                # name the victim AP; do not block that identity on this evidence.
        except Exception:
            pass

    def _detect_beacon_flood(self, packet):
        """Beacon Flood saldırısı tespiti."""
        try:
            bssid = packet.addr3
            if bssid not in self.beacon_count and len(self.beacon_count) >= 10000:
                oldest = next(iter(self.beacon_count))
                self.beacon_count.pop(oldest)
                self.beacon_ssids.pop(oldest, None)
            self.beacon_count[bssid] += 1
            
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                if not ssid or not bssid:
                    return
                if len(self.unique_ssids_in_window) < 10000:
                    self.unique_ssids_in_window.add(ssid)
                if len(self.beacon_ssids[bssid]) > self.beacon_flood_threshold:
                    return
                self.beacon_ssids[bssid].add(ssid)
                
                if len(self.beacon_ssids[bssid]) == self.beacon_flood_threshold + 1:
                    self.db.add_alert(
                        alert_type='Beacon Flood',
                        src_ip='N/A', src_mac=bssid if bssid else 'N/A',
                        dst_ip='N/A', dst_mac='ff:ff:ff:ff:ff:ff',
                        description=f'Aynı BSSID ({bssid}) için {len(self.beacon_ssids[bssid])} benzersiz SSID gözlendi (eşik: {self.beacon_flood_threshold}).',
                        severity='warning'
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
                    if ssid not in self.ssid_bssid_map and len(self.ssid_bssid_map) >= 10000:
                        self.ssid_bssid_map.pop(next(iter(self.ssid_bssid_map)))
                    if bssid in self.ssid_bssid_map[ssid]:
                        return
                    if len(self.ssid_bssid_map[ssid]) >= 256:
                        return
                    self.ssid_bssid_map[ssid].add(bssid)
                    
                    approved = self.trusted_bssids.get(ssid)
                    if approved and bssid.lower() not in {mac.lower() for mac in approved}:
                        bssids = ", ".join(list(self.ssid_bssid_map[ssid]))
                        self.db.add_alert(
                            alert_type='Evil Twin',
                            src_ip='N/A', src_mac=bssid,
                            dst_ip='N/A', dst_mac='ff:ff:ff:ff:ff:ff',
                            description=f"SSID '{ssid}' için onaylı envanterde bulunmayan BSSID {bssid}. Gözlenenler: {bssids}; envanter değişikliği veya taklit AP olabilir.",
                            severity='warning'
                        )
        except Exception:
            pass

    def _reset_window(self):
        """Zaman penceresini sıfırlar."""
        if time.time() - self.last_reset > self.detection_window:
            self.deauth_count.clear()
            self.beacon_count.clear()
            self.beacon_ssids.clear()
            self.ssid_bssid_map.clear()
            self.unique_ssids_in_window.clear()
            self.last_reset = time.time()

    def get_stats(self) -> dict:
        """İstatistikleri döner."""
        return {
            "deauth_senders": len(self.deauth_count),
            "beacon_bssids": len(self.beacon_count),
            "evil_twin_ssids": sum(bool(self.trusted_bssids.get(ssid)) and
                                   bool({mac.lower() for mac in bssids} -
                                        {mac.lower() for mac in self.trusted_bssids[ssid]})
                                   for ssid, bssids in self.ssid_bssid_map.items())
        }
