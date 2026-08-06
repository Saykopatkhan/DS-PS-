import subprocess
import threading
import time
import os
from colorama import Fore, Style
from core.database import Database
from scapy.all import ARP, Ether, sendp, conf, getmacbyip
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from datetime import datetime

class Blocker:
    """
    Hem yerel (iptables) hem de ağ (ARP Blackholing) düzeyinde cihaz engelleyen sınıf.
    Saldırganları sadece bu bilgisayardan değil, tüm ağdan izole eder.
    """
    def __init__(self, db: Database, auto_unban_time=3600, interface='eth0'):
        self.db = db
        self.auto_unban_time = auto_unban_time
        self.interface = interface
        self.blocked_ips = set()
        self.blocked_macs = set()
        self.lock = threading.Lock()
        
        self.gateway_ip = None
        self.gateway_mac = None
        
        self.running = True
        
        # ARP Poisoning Thread (Ağ İzolasyonu için)
        self.arp_poison_thread = threading.Thread(target=self._arp_poison_worker, daemon=True)
        self.arp_poison_thread.start()
        
        # İlk başlatmada aktif banları yükle
        self._load_active_bans()

    def _check_root(self) -> bool:
        return os.geteuid() == 0

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

    def _arp_poison_worker(self):
        """Ağdaki engellenen cihazların internetini kesmek için sürekli sahte ARP gönderir."""
        # '00:00:00:00:00:00' bazı sistemlerce reddedilir. Geçerli formatta sahte MAC:
        dummy_mac = "02:00:00:00:00:00"
        
        while self.running:
            if not self.gateway_ip:
                self._get_gateway_info()
                
            with self.lock:
                ips_to_poison = list(self.blocked_ips)
                macs_to_poison = list(self.blocked_macs)
            
            if self.gateway_ip and (ips_to_poison or macs_to_poison):
                for target_ip in ips_to_poison:
                    try:
                        target_mac = getmacbyip(target_ip)
                        if not target_mac:
                            target_mac = "ff:ff:ff:ff:ff:ff"
                            
                        # Kurbana: Ağ geçidi sahte MAC'te (İnterneti keser)
                        sendp(Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=dummy_mac), iface=self.interface, verbose=False)
                        # Ağ geçidine: Kurban sahte MAC'te (Router'dan yanıt almasını engeller)
                        if self.gateway_mac:
                            sendp(Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip, hwsrc=dummy_mac), iface=self.interface, verbose=False)
                    except Exception as e:
                        pass
                        
                for target_mac in macs_to_poison:
                    try:
                        if target_mac and target_mac != "ff:ff:ff:ff:ff:ff":
                            # MAC tabanlı izolasyon
                            sendp(Ether(dst=target_mac)/ARP(op=2, pdst="0.0.0.0", hwdst=target_mac, psrc=self.gateway_ip, hwsrc=dummy_mac), iface=self.interface, verbose=False)
                    except Exception:
                        pass
            
            time.sleep(1.5)

    def block_ip(self, ip, reason='Otomatik tespit'):
        if not self._check_root():
            print(f"{Fore.YELLOW}[!] Uyarı: Root yetkisi olmadığı için IP engellenemedi: {ip}{Style.RESET_ALL}")
            return
            
        with self.lock:
            if ip in self.blocked_ips:
                return
                
            try:
                # 1. Yerel Koruma (iptables)
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], shell=False, capture_output=True)
                subprocess.run(['iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'], shell=False, capture_output=True)
                
                # 2. Ağ Koruması (ARP İzolasyonu)
                self.blocked_ips.add(ip)
                
                self.db.add_ban(ip=ip, mac=None, reason=reason)
                print(f"{Fore.GREEN}[+] Başarılı: IP engellendi ve ağdan izole edildi: {ip} Neden: {reason}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Hata: IP engelleme başarısız: {e}{Style.RESET_ALL}")

    def block_mac(self, mac, reason='Otomatik tespit'):
        if not self._check_root():
            print(f"{Fore.YELLOW}[!] Uyarı: Root yetkisi olmadığı için MAC engellenemedi: {mac}{Style.RESET_ALL}")
            return
            
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
                subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], shell=False, capture_output=True)
                subprocess.run(['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'], shell=False, capture_output=True)
                if ip in self.blocked_ips:
                    self.blocked_ips.remove(ip)
                if hasattr(self.db, 'remove_ban'):
                    self.db.remove_ban(ip=ip)
                print(f"{Fore.YELLOW}[*] Bilgi: IP engeli (ve izolasyon) kaldırıldı: {ip}{Style.RESET_ALL}")
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
