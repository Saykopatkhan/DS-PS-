"""
Sahte DHCP Sunucusu (Rogue DHCP) ve DHCP Starvation tespit modülü.
"""
import time
from collections import defaultdict
from scapy.all import DHCP, BOOTP, IP, Ether, conf
from core.database import Database
from utils.sound import SoundAlert

class DHCPDetector:
    def __init__(self, db: Database, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        
        self.discover_count = defaultdict(int)
        self.starvation_threshold = 20 # Saniyede 20 DISCOVER
        self.detection_window = 5.0
        self.last_reset = time.time()
        
        # Gerçek gateway IP'sini öğren
        self.legit_dhcp = self._get_gateway()

    def _get_gateway(self):
        try:
            gw = conf.route.route("0.0.0.0")[2]
            return gw if gw != '0.0.0.0' else None
        except Exception:
            return None

    def analyze(self, packet):
        if packet.haslayer(DHCP):
            dhcp_options = packet[DHCP].options
            msg_type = self._get_dhcp_type(dhcp_options)
            
            # DHCP Discover (type 1) veya Request (type 3)
            if msg_type in [1, 3]:
                if packet.haslayer(Ether):
                    src_mac = packet[Ether].src
                    
                    if msg_type == 1:
                        self.discover_count[src_mac] += 1
                        self._check_starvation(src_mac)
                        
                    # Option 55 (Parameter Request List) yakalama
                    param_req_list = self._get_dhcp_option(dhcp_options, 'param_req_list')
                    if param_req_list:
                        try:
                            # Parametre listesi genelde byte string veya list of ints olarak gelir
                            if isinstance(param_req_list, bytes):
                                opt_list = list(param_req_list)
                            elif isinstance(param_req_list, str):
                                opt_list = [ord(c) for c in param_req_list]
                            else:
                                opt_list = list(param_req_list)
                                
                            from utils.os_fingerprint import OSFingerprint
                            os_type = OSFingerprint.from_dhcp_options(opt_list)
                            
                            # Eğer OS bulunduysa DB'yi güncelle
                            if os_type != "Bilinmiyor":
                                # src_ip DHCP Discover'da 0.0.0.0'dır, IP sonradan atanır. O yüzden IP kısmına None atıyoruz 
                                # ama veritabanında "Bilinmiyor" olmasın diye sadece mac üzerinden OS güncellenmeli.
                                # Mevcut DB yapımızda update_ip_mac IP ve MAC zorunlu alıyor. IP boş ise atmayalım.
                                src_ip = packet[IP].src if packet.haslayer(IP) else '0.0.0.0'
                                if src_ip != '0.0.0.0':
                                    self.db.update_ip_mac(src_ip, src_mac, os_type=os_type)
                                else:
                                    # IP bilinmiyorsa bile ileride bir paket geldiğinde bu MAC'in OS'unu tutmak için
                                    # bir veritabanı update'i yapılabilir ama şimdilik IP alanına 'N/A' diyebiliriz
                                    self.db.update_ip_mac('N/A', src_mac, os_type=os_type)
                        except Exception:
                            pass
            
            # DHCP Offer (type 2) veya ACK (type 5) -> Rogue DHCP
            elif msg_type in [2, 5]:
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    if self.legit_dhcp and src_ip != self.legit_dhcp:
                        self._detect_rogue_dhcp(src_ip, packet[Ether].src)
                        
        self._reset_window()

    def _get_dhcp_type(self, options):
        for opt in options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                return opt[1]
        return None

    def _get_dhcp_option(self, options, option_name):
        for opt in options:
            if isinstance(opt, tuple) and opt[0] == option_name:
                return opt[1]
        return None

    def _check_starvation(self, src_mac):
        if self.discover_count[src_mac] > self.starvation_threshold:
            self.db.add_alert(
                alert_type='DHCP Starvation',
                src_ip='N/A', src_mac=src_mac,
                dst_ip='255.255.255.255', dst_mac='ff:ff:ff:ff:ff:ff',
                description=f'Ağda aşırı sahte DHCP Discover paketi. (Kaynak: {src_mac})',
                severity='high'
            )
            SoundAlert.alert_attack("DHCP IP Havuzu Tüketme")
            self.discover_count[src_mac] = 0

    def _detect_rogue_dhcp(self, rogue_ip, rogue_mac):
        self.db.add_alert(
            alert_type='Rogue DHCP Sunucusu',
            src_ip=rogue_ip, src_mac=rogue_mac,
            dst_ip='N/A', dst_mac='N/A',
            description=f'Yetkisiz bir DHCP sunucusu ağa IP dağıtmaya çalışıyor! (IP: {rogue_ip})',
            severity='critical'
        )
        SoundAlert.alert_attack("Sahte DHCP Sunucusu")
        if self.blocker and self.auto_ban:
            self.blocker.block_mac(rogue_mac, reason="Rogue DHCP")

    def _reset_window(self):
        if time.time() - self.last_reset > self.detection_window:
            self.discover_count.clear()
            self.last_reset = time.time()
