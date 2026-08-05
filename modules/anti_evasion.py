"""
Anti-Evasion Modülü (MAC Spoofing ve Randomization Koruması)
Saldırganların ban yememek için sürekli MAC adresi değiştirmesini (MAC Randomization)
veya ağda MAC Flooding yapmasını tespit eder.
"""
import time
from scapy.all import Ether
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

    def analyze(self, packet):
        if not packet.haslayer(Ether):
            return
            
        src_mac = packet[Ether].src
        now = time.time()
        
        # Sadece yeni gördüğümüz MAC'leri veya zamanı güncelliyoruz
        if src_mac not in self.recent_macs:
            self.recent_macs[src_mac] = now
            
        # Pencere dışı (eski) MAC'leri temizle
        self._cleanup_old_macs(now)
        
        # Kalan yeni MAC sayısına bak
        if len(self.recent_macs) >= self.mac_flood_threshold:
            self._trigger_alert(src_mac, len(self.recent_macs))
            # Uyarıyı sürekli patlatmamak için listeyi temizle
            self.recent_macs.clear()

    def _cleanup_old_macs(self, now):
        expired = [mac for mac, ts in self.recent_macs.items() if now - ts > self.time_window]
        for mac in expired:
            del self.recent_macs[mac]

    def _trigger_alert(self, last_mac, count):
        desc = f"DİKKAT: Cihazın IP ve MAC adresleri sürekli değişiyor! Son {int(self.time_window)} saniyede {count} farklı sahte kimlikle ağa girmeye çalıştı. Lütfen bu tehdidi anında BANLAYIN!"
        self.db.add_alert(
            alert_type='MAC Spoofing (Anti-Evasion)',
            src_ip='N/A', src_mac=last_mac,
            dst_ip='N/A', dst_mac='N/A',
            description=desc,
            severity='high'
        )
        SoundAlert.alert_attack("MAC Spoofing İhlali")
