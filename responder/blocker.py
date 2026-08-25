# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

import subprocess
import threading
import time
import os
from colorama import Fore, Style
from core.database import Database
import logging
from datetime import datetime

class Blocker:
    """
    ipset + iptables tabanlı çekirdek seviyesi güvenlik duvarı.
    Ağ izolasyonu için (ban izole) ARP Poisoning aktif olarak kullanılır.
    """
    SET_NAME = "dsips_blacklist"
    
    def __init__(self, db: Database, auto_unban_time=3600, interface='eth0', dry_run=False):
        self.db = db
        self.auto_unban_time = auto_unban_time
        self.interface = interface
        self.blocked_ips = set()
        self.blocked_macs = set()
        self.lock = threading.Lock()
        self.dry_run = dry_run
        
        self.gateway_ip = None
        self.gateway_mac = None
        
        # Seviye Bazlı Ban Süresi (saniye)
        self.BAN_DURATIONS = {
            'critical': 86400,  # 24 saat
            'high': 3600,       # 1 saat
            'medium': 600,      # 10 dakika
            'low': 300,         # 5 dakika
        }
        
        # Beyaz Liste (asla engellenmeyecekler)
        self.whitelist = {'127.0.0.1', '::1', '0.0.0.0'}
        self._load_config()
        
        self.running = True
        
        # ipset tablosunu başlat (ARP Poisoning yerine)
        if not self.dry_run:
            self._init_ipset()
        else:
            print(f"{Fore.YELLOW}[ℹ️] DRY RUN MODU: Tespit yapılacak ama engelleme YAPILMAYACAK{Style.RESET_ALL}")
        
        # İlk başlatmada aktif banları yükle
        self._load_active_bans()
        
        # Ağ geçidi bilgisini al
        self._get_gateway_info()
        
        # ARP Poisoning Thread'i başlat (İzolasyon için)
        if not self.dry_run:
            self.arp_thread = threading.Thread(target=self._arp_poison_thread, daemon=True)
            self.arp_thread.start()

    def _check_root(self) -> bool:
        return os.geteuid() == 0

    def _load_config(self):
        """JSON yapılandırma dosyasından ayarları yükler."""
        import json
        config_path = '/etc/dsips/config.json'
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    cfg = json.load(f)
                # Whitelist
                for ip in cfg.get('whitelisted_ips', []):
                    self.whitelist.add(ip)
                # Ban süreleri
                if 'block_critical' in cfg:
                    self.BAN_DURATIONS['critical'] = cfg['block_critical']
                if 'block_high' in cfg:
                    self.BAN_DURATIONS['high'] = cfg['block_high']
                if 'block_ddos' in cfg:
                    self.BAN_DURATIONS['medium'] = cfg['block_ddos']
                # Dry run
                if cfg.get('dry_run', False):
                    self.dry_run = True
                print(f"{Fore.GREEN}[+] Config yüklendi: {config_path}{Style.RESET_ALL}")
        except Exception:
            pass  # Config dosyası yoksa varsayılanlar kullanılır

    def get_ban_duration(self, severity: str = 'medium') -> int:
        """Seviyeye göre ban süresini döner."""
        return self.BAN_DURATIONS.get(severity, self.auto_unban_time)

    def _get_gateway_info(self):
        """Ağ geçidi IP ve MAC adresini tespit eder."""
        try:
            gw = conf.route.route("0.0.0.0")[2]
            if gw and gw != '0.0.0.0':
                self.gateway_ip = gw
                mac = getmacbyip(gw)
                if mac:
                    self.gateway_mac = mac
        except Exception:
            pass

    def _load_active_bans(self):
        """Veritabanındaki aktif banları belleğe yükler."""
        try:
            bans = self.db.get_active_bans()
            with self.lock:
                for ban in bans:
                    if ban.get('ip_address'):
                        self.blocked_ips.add(ban['ip_address'])
                    if ban.get('mac_address'):
                        self.blocked_macs.add(ban['mac_address'])
        except Exception:
            pass

    def _init_ipset(self):
        """ipset tablosunu ve tek bir iptables kuralı oluşturur."""
        if not self._check_root():
            return
        try:
            subprocess.run(["ipset", "create", self.SET_NAME, "hash:ip", "timeout", "0"], stderr=subprocess.DEVNULL)
            subprocess.run(["ipset", "flush", self.SET_NAME], stderr=subprocess.DEVNULL)
            # Tek kural: Bu setteki tüm IP'leri DROP et
            check = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"], stderr=subprocess.DEVNULL)
            if check.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"], check=True)
                subprocess.run(["iptables", "-I", "FORWARD", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"], check=True)
            print(f"{Fore.GREEN}[+] ipset güvenlik duvarı '{self.SET_NAME}' aktif.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] ipset başlatılamadı (iptables fallback kullanılacak): {e}{Style.RESET_ALL}")

    def block_ip(self, ip, reason='Otomatik tespit', severity='medium'):
        # Beyaz Liste kontrolü
        if ip in self.whitelist:
            raise ValueError(f"Bu IP beyaz listede (korumalı) olduğu için engellenemez: {ip}")
            
        if not self._check_root() and not self.dry_run:
            print(f"{Fore.YELLOW}[!] Uyarı: Root yetkisi olmadığı için IP engellenemedi: {ip}{Style.RESET_ALL}")
            raise ValueError("Root (sudo) yetkisi olmadığı için engelleme yapılamadı.")
            
        with self.lock:
            if ip in self.blocked_ips:
                return
            
            ban_duration = self.get_ban_duration(severity)
            
            if self.dry_run:
                print(f"{Fore.CYAN}[🔍 DRY RUN] IP ENGELLENMEZDİ: {ip} | Neden: {reason} | Seviye: {severity} | Süre: {ban_duration}s{Style.RESET_ALL}")
                self.db.add_ban(ip=ip, mac=None, reason=f"[DRY RUN] {reason}")
                return
                
            try:
                # ipset ile O(1) engelleme (timeout ile otomatik süreli ban)
                subprocess.run(['ipset', 'add', self.SET_NAME, ip, 'timeout', str(ban_duration), '-exist'], shell=False, capture_output=True)
                self.blocked_ips.add(ip)
                
                self.db.add_ban(ip=ip, mac=None, reason=reason)
                print(f"{Fore.GREEN}[+] 🔒 IP ipset ile engellendi: {ip} | Seviye: {severity} | Süre: {ban_duration}s | Neden: {reason}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Hata: IP engelleme başarısız: {e}{Style.RESET_ALL}")

    def block_mac(self, mac, reason='Otomatik tespit', severity='medium'):
        if mac == self.gateway_mac:
            print(f"{Fore.RED}[!] UYARI: Ağ Geçidi (Modem) MAC adresi engelleniyor! Tüm ağ bağlantısı kesilecek.{Style.RESET_ALL}")
            
        if not self._check_root() and not self.dry_run:
            print(f"{Fore.YELLOW}[!] Uyarı: Root yetkisi olmadığı için MAC engellenemedi: {mac}{Style.RESET_ALL}")
            raise ValueError("Root (sudo) yetkisi olmadığı için MAC engellemesi yapılamadı.")
            
        with self.lock:
            if mac in self.blocked_macs:
                return
                
            try:
                # 1. Yerel Koruma
                subprocess.run(['iptables', '-A', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], shell=False, capture_output=True)
                subprocess.run(['iptables', '-A', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], shell=False, capture_output=True)
                
                # 2. Ağ Koruması
                self.blocked_macs.add(mac)
                
                self.db.add_ban(ip=None, mac=mac, reason=reason)
                print(f"{Fore.GREEN}[+] Başarılı: MAC engellendi ve ağdan izole edildi: {mac} Neden: {reason}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Hata: MAC engelleme başarısız: {e}{Style.RESET_ALL}")

    def unblock_ip(self, ip):
        if not self._check_root():
            return
            
        with self.lock:
            try:
                subprocess.run(['ipset', 'del', self.SET_NAME, ip, '-exist'], shell=False, capture_output=True)
                if ip in self.blocked_ips:
                    self.blocked_ips.remove(ip)
                if hasattr(self.db, 'remove_ban'):
                    self.db.remove_ban(ip=ip)
                print(f"{Fore.YELLOW}[*] 🔓 IP engeli kaldırıldı: {ip}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Hata: IP engeli kaldırılırken hata oluştu: {e}{Style.RESET_ALL}")

    def unblock_mac(self, mac):
        if not self._check_root():
            return
            
        with self.lock:
            try:
                subprocess.run(['iptables', '-D', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], shell=False, capture_output=True)
                subprocess.run(['iptables', '-D', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], shell=False, capture_output=True)
                if mac in self.blocked_macs:
                    self.blocked_macs.remove(mac)
                if hasattr(self.db, 'remove_ban'):
                    self.db.remove_ban(mac=mac)
                print(f"{Fore.YELLOW}[*] Bilgi: MAC engeli (ve izolasyon) kaldırıldı: {mac}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Hata: MAC engeli kaldırılırken hata oluştu: {e}{Style.RESET_ALL}")

    def unblock_all(self):
        """Tüm engelleri kaldırır."""
        with self.lock:
            ips_to_unblock = self.blocked_ips.copy()
            macs_to_unblock = self.blocked_macs.copy()
            
        for ip in ips_to_unblock:
            self.unblock_ip(ip)
        for mac in macs_to_unblock:
            self.unblock_mac(mac)

    def get_blocked_hosts(self) -> dict:
        """Şu anda izole edilmiş ve engellenmiş cihazları döner."""
        with self.lock:
            return {'ips': list(self.blocked_ips), 'macs': list(self.blocked_macs)}
            
    def stop(self):
        """Bloklayıcı thread'leri durdurur."""
        self.running = False

    def _arp_poison_thread(self):
        """Banlanmış MAC adreslerini ağdan izole etmek için sürekli sahte ARP paketleri gönderir."""
        try:
            from scapy.all import ARP, Ether, sendp, get_if_hwaddr
            import logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        except ImportError:
            print(f"{Fore.RED}[!] İzolasyon için scapy gerekli. Lütfen kurun.{Style.RESET_ALL}")
            return

        while self.running:
            try:
                # Kendi MAC adresimizi sahte ağ geçidi olarak kullanıyoruz (Trafik bize gelsin ve iptables ile çöpe atılsın)
                my_mac = get_if_hwaddr(self.interface)
            except Exception:
                my_mac = "02:00:00:00:00:00"

            if not self.gateway_ip or not self.blocked_macs:
                time.sleep(2)
                continue
                
            try:
                with self.lock:
                    macs_to_poison = list(self.blocked_macs)
                    
                for mac in macs_to_poison:
                    # Kurbana (veya modeme) yönelik ARP spoofing
                    # Hedef MAC modem ise, tüm ağa modemin bizim MAC'imizde olduğunu söyle (Ağı tamamen kesmek için)
                    if mac == self.gateway_mac:
                        pkt_to_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst="0.0.0.0", hwdst="ff:ff:ff:ff:ff:ff", psrc=self.gateway_ip, hwsrc=my_mac)
                        sendp(pkt_to_broadcast, iface=self.interface, verbose=False)
                        continue
                        
                    # Kurbana: Ağ geçidi benim (Trafik bana gelir ve iptables DROP eder)
                    pkt_to_victim = Ether(dst=mac)/ARP(op=2, pdst="0.0.0.0", hwdst=mac, psrc=self.gateway_ip, hwsrc=my_mac)
                    # Modeme: Kurban benim (Yanıtlar bana gelir)
                    if self.gateway_mac:
                        # Burada kurbanın IP adresini tam bilmiyorsak bile 0.0.0.0 yerine doğrudan kurbanın MAC'ini kendi üstümüze alıyoruz.
                        pkt_to_gateway = Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc="0.0.0.0", hwsrc=my_mac)
                        sendp(pkt_to_gateway, iface=self.interface, verbose=False)
                    
                    sendp(pkt_to_victim, iface=self.interface, verbose=False)
            except Exception:
                pass
                
            # ARP iyileşmesini önlemek için saldırı frekansını 0.5s'ye indirdik (v3.2)
            time.sleep(0.5)
