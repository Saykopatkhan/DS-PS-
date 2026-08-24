import subprocess
import threading
import time
import os
from colorama import Fore, Style
from core.database import Database
from datetime import datetime

class Blocker:
    """
    Çekirdek Seviyesi Güvenlik Duvarı (ipset + iptables).
    O(1) zaman karmaşıklığı ile on binlerce IP'yi anında banlayabilir.
    ARP tabanlı (kararsız) L2 izolasyon tamamen kaldırılmıştır.
    """
    def __init__(self, db: Database, auto_unban_time=3600, interface='eth0'):
        self.db = db
        self.auto_unban_time = auto_unban_time
        self.interface = interface
        self.blocked_ips = set()
        self.lock = threading.Lock()
        self.running = True
        self.SET_NAME = "dsips_blacklist"

        self._init_ipset()
        self._load_active_bans()

    def _check_root(self) -> bool:
        return os.geteuid() == 0

    def _init_ipset(self):
        """ipset tablosunu ve iptables kuralını oluşturur."""
        if not self._check_root():
            return
            
        try:
            # Önce varsa seti temizle (flush) veya oluştur
            subprocess.run(["ipset", "create", self.SET_NAME, "hash:ip", "timeout", "0"], stderr=subprocess.DEVNULL)
            subprocess.run(["ipset", "flush", self.SET_NAME], stderr=subprocess.DEVNULL)
            
            # iptables kuralı: Bu setteki her şeyi DROP et (eğer kural yoksa ekle)
            check_rule = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"], stderr=subprocess.DEVNULL)
            if check_rule.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"], check=True)
                subprocess.run(["iptables", "-I", "FORWARD", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"], check=True)
                
            print(f"[*] Güvenlik Duvarı: '{self.SET_NAME}' ipset tablosu aktif.")
        except Exception as e:
            print(f"[!] ipset/iptables başlatılamadı: {e}")

    def _load_active_bans(self):
        """Veritabanındaki aktif banları belleğe ve ipset'e yükler."""
        try:
            bans = self.db.get_active_bans()
            with self.lock:
                for ban in bans:
                    if ban.get('ip_address'):
                        self.blocked_ips.add(ban['ip_address'])
                        if self._check_root():
                            subprocess.run(["ipset", "add", self.SET_NAME, ban['ip_address'], "-exist"], stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def block_ip(self, ip, reason='Otomatik tespit'):
        if not self._check_root():
            print(f"{Fore.YELLOW}[!] Uyarı: Root yetkisi yok, iptables atlanacak. Cihaz engellenemeyecek: {ip}{Style.RESET_ALL}")
            
        with self.lock:
            if ip in self.blocked_ips:
                return False
            
            self.blocked_ips.add(ip)
            if self._check_root():
                try:
                    # Command Injection Koruması: List parameter form of subprocess
                    subprocess.run(["ipset", "add", self.SET_NAME, ip, "-exist"], check=True)
                    print(f"{Fore.RED}[🔒] {ip} ipset ile engellendi. Neden: {reason}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"[!] ipset ekleme hatası: {e}")
                    
            self.db.add_ban(ip, 'N/A', reason, self.auto_unban_time)
            return True

    def block_mac(self, mac, reason='Otomatik tespit'):
        # MAC bazlı engelleme artık ipset üzerinden yapılamaz (hash:ip kullandık)
        # Sadece veritabanına ekler, L2 arp izolasyonu kaldırıldı.
        self.db.add_ban('N/A', mac, reason, self.auto_unban_time)
        return True

    def unblock_ip(self, ip):
        with self.lock:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            if self._check_root():
                try:
                    subprocess.run(["ipset", "del", self.SET_NAME, ip, "-exist"], stderr=subprocess.DEVNULL)
                    print(f"{Fore.GREEN}[🔓] {ip} ipset engeli kaldırıldı.{Style.RESET_ALL}")
                except Exception:
                    pass
            self.db.remove_ban(ip=ip)
            return True

    def unblock_mac(self, mac):
        self.db.remove_ban(mac=mac)
        return True
        
    def check_expired_bans(self):
        """Web uygulamasında periyodik çalışacak fonksiyon."""
        self.db.cleanup_expired_bans()
        self.blocked_ips.clear()
        self._load_active_bans()
