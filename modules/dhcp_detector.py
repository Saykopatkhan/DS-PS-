# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Sahte DHCP Sunucusu (Rogue DHCP) ve DHCP Starvation tespit modülü.
"""
import time
from collections import defaultdict
from scapy.all import BOOTP, DHCP, IP, Ether, conf
from core.database import Database
from utils.sound import SoundAlert

class DHCPDetector:
    def __init__(self, db: Database, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        
        self.discover_count = defaultdict(int)
        self.total_discovers = 0
        self.starvation_threshold = 20 # Saniyede 20 DISCOVER
        self.detection_window = 5.0
        self.last_reset = time.time()
        self._discover_transactions = set()
        self._rogue_alerts = set()
        
        # Gerçek gateway IP'sini öğren
        # A DHCP server need not be the router. Configure an approved server
        # explicitly instead of automatically accusing legitimate relays.
        self.legit_dhcp = None

    def _get_gateway(self):
        try:
            gw = conf.route.route("0.0.0.0")[2]
            return gw if gw != '0.0.0.0' else None
        except Exception:
            return None

    def analyze(self, packet):
        self._reset_window()
        if packet.haslayer(DHCP):
            dhcp_options = packet[DHCP].options
            msg_type = self._get_dhcp_type(dhcp_options)
            
            # DHCP Discover (type 1) veya Request (type 3)
            if msg_type in [1, 3]:
                if packet.haslayer(Ether):
                    src_mac = packet[Ether].src
                    
                    if msg_type == 1:
                        transaction = (src_mac, packet[BOOTP].xid) if packet.haslayer(BOOTP) else None
                        if transaction is None or transaction not in self._discover_transactions:
                            if transaction is not None:
                                if len(self._discover_transactions) >= 10000:
                                    self._discover_transactions.pop()
                                self._discover_transactions.add(transaction)
                            self.discover_count[src_mac] += 1
                            self.total_discovers += 1
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
                                # An unassigned address is not a device identity;
                                # do not merge every new client into an 'N/A' row.
                        except Exception:
                            pass
            
            # DHCP Offer (type 2) veya ACK (type 5) -> Rogue DHCP
            elif msg_type in [2, 5]:
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    # Replies may arrive through a relay whose IP is not the server.
                    server_ip = self._get_dhcp_option(dhcp_options, 'server_id') or src_ip
                    if self.legit_dhcp and server_ip != self.legit_dhcp and server_ip not in self._rogue_alerts:
                        if len(self._rogue_alerts) >= 10000:
                            self._rogue_alerts.pop()
                        self._rogue_alerts.add(server_ip)
                        self._detect_rogue_dhcp(server_ip, packet[Ether].src if packet.haslayer(Ether) else 'N/A')
                        
        self._reset_window()

    def _get_dhcp_type(self, options):
        for opt in options:
            if isinstance(opt, tuple) and len(opt) > 1 and opt[0] == 'message-type':
                value = opt[1]
                if isinstance(value, bytes):
                    return value[0] if len(value) == 1 else None
                return value
        return None

    def _get_dhcp_option(self, options, option_name):
        for opt in options:
            if isinstance(opt, tuple) and len(opt) > 1 and opt[0] == option_name:
                return opt[1]
        return None

    def _check_starvation(self, src_mac):
        # The configured threshold is a rate per second, not a five-second total.
        if self.total_discovers > self.starvation_threshold * self.detection_window:
            self.db.add_alert(
                alert_type='DHCP Starvation',
                src_ip='N/A', src_mac=src_mac,
                dst_ip='255.255.255.255', dst_mac='ff:ff:ff:ff:ff:ff',
                description=f'{self.detection_window:g}s içinde {self.total_discovers} farklı DHCP Discover işlemi gözlendi. Yoğun istemci açılışı veya havuz tüketme girişimi olabilir.',
                severity='warning'
            )
            SoundAlert.alert_attack("DHCP IP Havuzu Tüketme")
            self.discover_count.clear()
            self.total_discovers = 0

    def _detect_rogue_dhcp(self, rogue_ip, rogue_mac):
        self.db.add_alert(
            alert_type='Rogue DHCP Sunucusu',
            src_ip=rogue_ip, src_mac=rogue_mac,
            dst_ip='N/A', dst_mac='N/A',
            description=f'Yetkisiz bir DHCP sunucusu ağa IP dağıtmaya çalışıyor! (IP: {rogue_ip})',
            severity='critical'
        )
        SoundAlert.alert_attack("Sahte DHCP Sunucusu")
        # The L2 sender can be a legitimate relay, not the advertised server.

    def _reset_window(self):
        if time.time() - self.last_reset > self.detection_window:
            self.discover_count.clear()
            self.total_discovers = 0
            self._discover_transactions.clear()
            self._rogue_alerts.clear()
            self.last_reset = time.time()
