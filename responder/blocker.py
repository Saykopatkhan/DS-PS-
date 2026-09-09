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
    ipset + iptables + ARP Poisoning tabanlı çekirdek seviyesi güvenlik duvarı.
    Ağ izolasyonu için ARP Poisoning aktif olarak kullanılır.
    
    İzolasyon Mantığı (v5 - Profesyonel):
    1. iptables/ipset: Kali makinesinden geçen trafiği çekirdek seviyesinde engeller
    2. ARP Poisoning: Kurbanın ARP tablosunu zehirleyerek gateway'e ulaşmasını engeller
       - Kurbana: "Gateway benim" der (kurbanın trafiği Kali'ye gelir, DROP edilir)
       - Gateway'e: "Kurban benim" der (gateway'den kurbana gelen trafik Kali'ye gelir, DROP edilir)
    3. Her iki yönde de tam izolasyon sağlanır
    """
    SET_NAME = "dsips_blacklist"
    
    def __init__(self, db: Database, auto_unban_time=3600, interface='eth0', dry_run=False, active_defense_mgr=None):
        self.db = db
        self.active_defense_mgr = active_defense_mgr
        self.auto_unban_time = auto_unban_time
        self.interface = interface
        self.blocked_ips = set()
        self.blocked_macs = set()
        self.intercepted_macs = set() # DROP olmadan sadece trafiği üzerine çeken MAC'ler
        # IP<->MAC eşleştirme tablosu (ARP poisoning için kritik)
        self.ip_mac_map = {}  # {mac: ip, ...}
        self.mac_ip_map = {}  # {ip: mac, ...}
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
        
        # Scapy'yi yükle
        try:
            from scapy.all import conf, getmacbyip, ARP, Ether, sendp, get_if_hwaddr, srp
            self._scapy_available = True
        except ImportError:
            self._scapy_available = False
            print(f"{Fore.RED}[!] Scapy bulunamadı! ARP izolasyonu çalışmayacak.{Style.RESET_ALL}")
        
        # ipset tablosunu başlat
        if not self.dry_run:
            self._init_ipset()
        else:
            print(f"{Fore.YELLOW}[ℹ️] DRY RUN MODU: Tespit yapılacak ama engelleme YAPILMAYACAK{Style.RESET_ALL}")
        
        # İlk başlatmada aktif banları yükle ve kuralları uygula
        self._load_active_bans()
        self._apply_loaded_bans()
        
        # Ağ geçidi bilgisini al
        self._get_gateway_info()
        
        # ARP Poisoning Thread'i başlat (İzolasyon için)
        if not self.dry_run and self._scapy_available:
            self.arp_thread = threading.Thread(target=self._arp_poison_thread, daemon=True)
            self.arp_thread.start()
            print(f"{Fore.GREEN}[+] ARP İzolasyon motoru başlatıldı (Gateway: {self.gateway_ip} / {self.gateway_mac}){Style.RESET_ALL}")

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
        if not self._scapy_available:
            # Fallback: ip route ile gateway bul
            try:
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if 'default via' in line:
                        parts = line.split()
                        idx = parts.index('via') + 1
                        self.gateway_ip = parts[idx]
                        break
            except Exception:
                pass
            return
            
        try:
            from scapy.all import conf, getmacbyip
            gw = conf.route.route("0.0.0.0")[2]
            if gw and gw != '0.0.0.0':
                self.gateway_ip = gw
                self.gateway_mac = getmacbyip(gw)
                self.whitelist.add(self.gateway_ip)
                if self.gateway_mac:
                    print(f"{Fore.GREEN}[+] Gateway tespit edildi: {self.gateway_ip} ({self.gateway_mac}){Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] Gateway IP bulundu ({gw}) ama MAC alınamadı{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Gateway IP bulunamadı{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Gateway tespiti hatası: {e}{Style.RESET_ALL}")

    def _resolve_ip_for_mac(self, mac_address):
        """Bir MAC adresi için IP adresini çözümler."""
        # 1. Önce kendi eşleştirme tablomuzdan bak
        with self.lock:
            if mac_address in self.ip_mac_map:
                return self.ip_mac_map[mac_address]
        
        # 2. Veritabanındaki ip_mac_records tablosundan bak
        try:
            with self.db.lock:
                self.db.cursor.execute(
                    'SELECT ip_address FROM ip_mac_records WHERE mac_address = ? ORDER BY last_seen DESC LIMIT 1',
                    (mac_address,)
                )
                row = self.db.cursor.fetchone()
                if row:
                    ip = row['ip_address'] if isinstance(row, dict) else row[0]
                    with self.lock:
                        self.ip_mac_map[mac_address] = ip
                        self.mac_ip_map[ip] = mac_address
                    return ip
        except Exception:
            pass
        
        # 3. ARP taramasıyla bul
        if self._scapy_available and self.gateway_ip:
            try:
                from scapy.all import ARP, Ether, srp
                # Ağdaki tüm cihazları tara
                network = '.'.join(self.gateway_ip.split('.')[:3]) + '.0/24'
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), 
                           iface=self.interface, timeout=3, verbose=False)
                for _, rcv in ans:
                    if rcv.hwsrc.lower() == mac_address.lower():
                        ip = rcv.psrc
                        with self.lock:
                            self.ip_mac_map[mac_address] = ip
                            self.mac_ip_map[ip] = mac_address
                        return ip
            except Exception:
                pass
        
        return None

    def _resolve_mac_for_ip(self, ip_address):
        """Bir IP adresi için ağa anında ARP atarak MAC adresini bulur."""
        # 1. Önce eşleştirme tablosu
        with self.lock:
            if ip_address in self.mac_ip_map:
                return self.mac_ip_map[ip_address]
                
        # 2. Veritabanına bak (Geçmiş cihaz kayıtları)
        if hasattr(self, 'db') and self.db:
            try:
                with self.db.lock:
                    self.db.cursor.execute(
                        'SELECT mac_address FROM ip_mac_records WHERE ip_address = ? ORDER BY last_seen DESC LIMIT 1',
                        (ip_address,)
                    )
                    row = self.db.cursor.fetchone()
                    if row:
                        mac = row['mac_address'] if isinstance(row, dict) else row[0]
                        with self.lock:
                            self.mac_ip_map[ip_address] = mac
                            self.ip_mac_map[mac] = ip_address
                        return mac
            except Exception:
                pass
        
        # 3. Aktif ARP sorgusu
        if self._scapy_available:
            try:
                from scapy.all import ARP, Ether, srp
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), 
                           iface=self.interface, timeout=2, verbose=False)
                for _, rcv in ans:
                    mac = rcv.hwsrc
                    with self.lock:
                        self.mac_ip_map[ip_address] = mac
                        self.ip_mac_map[mac] = ip_address
                    return mac
            except Exception:
                pass
        return None

    def _load_active_bans(self):
        """Veritabanındaki aktif banları belleğe yükler."""
        try:
            bans = self.db.get_active_bans()
            with self.lock:
                for ban in bans:
                    ip = ban.get('ip_address')
                    mac = ban.get('mac_address')
                    if ip:
                        self.blocked_ips.add(ip)
                    if mac:
                        self.blocked_macs.add(mac)
                    # IP-MAC eşleştirmesini kaydet
                    if ip and mac:
                        self.ip_mac_map[mac] = ip
                        self.mac_ip_map[ip] = mac
        except Exception:
            pass

    def _apply_loaded_bans(self):
        """Belleğe yüklenen banların sistem kurallarını (ipset/iptables) uygular."""
        if not self._check_root() or self.dry_run:
            return
            
        with self.lock:
            # IP'leri ipset'e ekle
            for ip in self.blocked_ips:
                try:
                    subprocess.run(['ipset', 'add', self.SET_NAME, ip, 'timeout', str(self.auto_unban_time), '-exist'], shell=False, capture_output=True)
                except Exception:
                    pass
            
            # MAC kurallarını iptables'a ekle
            for mac in self.blocked_macs:
                try:
                    subprocess.run(['iptables', '-I', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], shell=False, capture_output=True)
                    subprocess.run(['iptables', '-I', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], shell=False, capture_output=True)
                except Exception:
                    pass

    def _init_ipset(self):
        """ipset tablosunu ve iptables kurallarını oluşturur."""
        if not self._check_root():
            return
        try:
            subprocess.run(["ipset", "create", self.SET_NAME, "hash:ip", "timeout", "0"], stderr=subprocess.DEVNULL)
            subprocess.run(["ipset", "flush", self.SET_NAME], stderr=subprocess.DEVNULL)
            # DROP kurallarını en üste ekle (-I = INSERT, her zaman öncelikli)
            check = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"], stderr=subprocess.DEVNULL)
            if check.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"], check=True)
                subprocess.run(["iptables", "-I", "FORWARD", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"], check=True)
            print(f"{Fore.GREEN}[+] ipset güvenlik duvarı '{self.SET_NAME}' aktif.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] ipset başlatılamadı: {e}{Style.RESET_ALL}")

    def block_ip(self, ip, reason='Otomatik tespit', severity='medium'):
        """IP adresini engeller (ipset + iptables + ARP Poisoning)."""
        # Beyaz Liste kontrolü
        if ip in self.whitelist:
            raise ValueError(f"Bu IP beyaz listede (korumalı) olduğu için engellenemez: {ip}")
            
        if not self._check_root() and not self.dry_run:
            raise ValueError("Root (sudo) yetkisi olmadığı için engelleme yapılamadı.")
            
        with self.lock:
            if ip in self.blocked_ips:
                return
            
            ban_duration = self.get_ban_duration(severity)
            
            if self.dry_run:
                print(f"{Fore.CYAN}[🔍 DRY RUN] IP ENGELLENMEZDİ: {ip}{Style.RESET_ALL}")
                self.db.add_ban(ip=ip, mac=None, reason=f"[DRY RUN] {reason}")
                return
                
            try:
                # 1. ipset ile O(1) engelleme
                subprocess.run(['ipset', 'add', self.SET_NAME, ip, 'timeout', str(ban_duration), '-exist'], 
                             shell=False, capture_output=True)
                self.blocked_ips.add(ip)
                
                # 2. MAC adresini de bul ve engelle (tam izolasyon)
                mac = self.mac_ip_map.get(ip)
                if not mac:
                    # Veritabanından MAC'i bul
                    try:
                        with self.db.lock:
                            self.db.cursor.execute(
                                'SELECT mac_address FROM ip_mac_records WHERE ip_address = ? ORDER BY last_seen DESC LIMIT 1',
                                (ip,)
                            )
                            row = self.db.cursor.fetchone()
                            if row:
                                mac = row['mac_address'] if isinstance(row, dict) else row[0]
                    except Exception:
                        pass
                
                # HALA BULAMADIYSA AKTİF ARP SORGUSU AT!
                if not mac:
                    mac = self._resolve_mac_for_ip(ip)
                
                if mac:
                    self.mac_ip_map[ip] = mac
                    self.ip_mac_map[mac] = ip
                    # MAC'i de blocked listesine ekle (ARP thread tarafından izole edilecek)
                    self.blocked_macs.add(mac)
                    # iptables MAC kuralı da ekle
                    subprocess.run(['iptables', '-I', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], 
                                 shell=False, capture_output=True)
                    subprocess.run(['iptables', '-I', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], 
                                 shell=False, capture_output=True)
                
                self.db.add_ban(ip=ip, mac=mac, reason=reason)
                if self.active_defense_mgr:
                    self.active_defense_mgr.add_rule('block_ip', target_ip=ip, target_mac=mac, parameters={'reason': reason})
                print(f"{Fore.GREEN}[+] 🔒 IP ENGELLENDİ VE İZOLE EDİLDİ: {ip} ({mac or 'MAC bilinmiyor'}) | Neden: {reason}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Hata: IP engelleme başarısız: {e}{Style.RESET_ALL}")

    def block_mac(self, mac, reason='Otomatik tespit', severity='medium'):
        """MAC adresini engeller ve ağdan tamamen izole eder."""
        if not self._check_root() and not self.dry_run:
            raise ValueError("Root (sudo) yetkisi olmadığı için MAC engellemesi yapılamadı.")
            
        with self.lock:
            if mac in self.blocked_macs:
                return
                
            try:
                # 1. iptables MAC kuralları (en üste -I ile)
                subprocess.run(['iptables', '-I', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], 
                             shell=False, capture_output=True)
                subprocess.run(['iptables', '-I', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], 
                             shell=False, capture_output=True)
                
                # 2. Bellekteki listeye ekle (ARP thread bunu sürekli kontrol eder)
                self.blocked_macs.add(mac)
                
                # 3. IP adresini de bul ve ipset'e ekle
                victim_ip = self.ip_mac_map.get(mac)
                if not victim_ip:
                    victim_ip = self._resolve_ip_for_mac(mac)
                
                if victim_ip:
                    self.blocked_ips.add(victim_ip)
                    self.ip_mac_map[mac] = victim_ip
                    self.mac_ip_map[victim_ip] = mac
                    subprocess.run(['ipset', 'add', self.SET_NAME, victim_ip, 'timeout', str(self.get_ban_duration(severity)), '-exist'], 
                                 shell=False, capture_output=True)
                    self.db.add_ban(ip=victim_ip, mac=mac, reason=reason)
                    if self.active_defense_mgr:
                        self.active_defense_mgr.add_rule('block_mac', target_ip=victim_ip, target_mac=mac, parameters={'reason': reason})
                    print(f"{Fore.GREEN}[+] 🔒 MAC ENGELLENDİ VE İZOLE EDİLDİ: {mac} (IP: {victim_ip}) | Neden: {reason}{Style.RESET_ALL}")
                else:
                    self.db.add_ban(ip=None, mac=mac, reason=reason)
                    if self.active_defense_mgr:
                        self.active_defense_mgr.add_rule('block_mac', target_ip=None, target_mac=mac, parameters={'reason': reason})
                    print(f"{Fore.GREEN}[+] 🔒 MAC ENGELLENDİ: {mac} (IP bilinmiyor, ARP izolasyon aktif) | Neden: {reason}{Style.RESET_ALL}")
                    
                if mac == self.gateway_mac:
                    print(f"{Fore.RED}[!] *** DİKKAT: AĞ GEÇİDİ (MODEM) ENGELLENDİ - Tüm ağ trafiği kesilecek! ***{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.RED}[!] Hata: MAC engelleme başarısız: {e}{Style.RESET_ALL}")

    def unblock_ip(self, ip):
        """IP engelini kaldırır."""
        if not self._check_root():
            return
            
        with self.lock:
            try:
                subprocess.run(['ipset', 'del', self.SET_NAME, ip, '-exist'], shell=False, capture_output=True)
                if ip in self.blocked_ips:
                    self.blocked_ips.remove(ip)
                # İlişkili MAC'i de kaldır
                mac = self.mac_ip_map.pop(ip, None)
                if mac:
                    self.ip_mac_map.pop(mac, None)
                    self.blocked_macs.discard(mac)
                    subprocess.run(['iptables', '-D', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], 
                                 shell=False, capture_output=True)
                    subprocess.run(['iptables', '-D', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], 
                                 shell=False, capture_output=True)
                if hasattr(self.db, 'remove_ban'):
                    self.db.remove_ban(ip=ip)
                if self.active_defense_mgr:
                    self.active_defense_mgr.remove_rule_by_target('block_ip', ip)
                print(f"{Fore.YELLOW}[*] 🔓 IP engeli kaldırıldı: {ip}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Hata: IP engeli kaldırılırken hata oluştu: {e}{Style.RESET_ALL}")

    def intercept_ip(self, ip):
        """Out-of-band çalışırken kurbanın trafiğini koparmadan üzerimize çeker."""
        if not self._check_root():
            return False
        if ip in self.whitelist:
            return False
        
        mac = self._resolve_mac_for_ip(ip)
        if mac:
            with self.lock:
                self.intercepted_macs.add(mac)
            print(f"{Fore.CYAN}[+] 🧲 INTERCEPT AKTİF: {ip} ({mac}) - Trafiği üzerimize çekiliyor.{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.YELLOW}[!] INTERCEPT BAŞARISIZ: {ip} için MAC adresi bulunamadı!{Style.RESET_ALL}")
            return False

    def stop_intercept_ip(self, ip):
        """Trafik çekme işlemini durdurur (restore yapılır)."""
        mac = self.mac_ip_map.get(ip)
        if mac:
            with self.lock:
                if mac in self.intercepted_macs:
                    self.intercepted_macs.remove(mac)
            
            # ARP Restore paketleri at
            try:
                from scapy.all import ARP, Ether, sendp
                sendp(Ether(dst=mac)/ARP(op=2, pdst=ip, hwdst=mac, 
                                        psrc=self.gateway_ip, hwsrc=self.gateway_mac), 
                      iface=self.interface, count=3, verbose=False)
                sendp(Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                        psrc=ip, hwsrc=mac),
                      iface=self.interface, count=3, verbose=False)
            except:
                pass
            print(f"{Fore.YELLOW}[*] 🔌 INTERCEPT DURDURULDU: {ip}{Style.RESET_ALL}")

    def rate_limit_ip(self, ip, rate="1/s"):
        """Saldırgan IP adresinin bant genişliğini iptables limit ile donanımsal olarak çok düşük seviyeye kilitler.
        Mobil cihazların Bypass etmesini önlemek için TCP/UDP tüm trafiğe uygulanır."""
        if not self._check_root():
            return False
        with self.lock:
            try:
                # 1. FORWARD zinciri (Download / Ingress Limiti) - Cihaz dışarıdan veri indirirken boğ
                subprocess.run(['iptables', '-A', 'FORWARD', '-d', ip, '-m', 'limit', '--limit', rate, '-j', 'ACCEPT'], 
                             shell=False, capture_output=True)
                subprocess.run(['iptables', '-A', 'FORWARD', '-d', ip, '-j', 'DROP'], 
                             shell=False, capture_output=True)
                
                # 2. FORWARD zinciri (Upload / Egress Limiti) - Cihaz dışarı veri yollarken boğ
                subprocess.run(['iptables', '-A', 'FORWARD', '-s', ip, '-m', 'limit', '--limit', rate, '-j', 'ACCEPT'], 
                             shell=False, capture_output=True)
                subprocess.run(['iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'], 
                             shell=False, capture_output=True)
                
                # 3. INPUT zinciri (Direkt Kali'ye gelen trafik için)
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-m', 'limit', '--limit', rate, '-j', 'ACCEPT'], 
                             shell=False, capture_output=True)
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], 
                             shell=False, capture_output=True)
                
                print(f"{Fore.MAGENTA}[☣️] MOBİL UYUMLU BANT GENİŞLİĞİ BOĞULDU ({ip} - {rate}){Style.RESET_ALL}")
                if self.db:
                    self.db.add_alert(
                        alert_type="☣️ Dynamic Rate Limit (Bant Genişliği Boğma)",
                        src_ip=ip, src_mac="N/A", dst_ip="N/A", dst_mac="N/A",
                        description=f"Saldırgan IP {ip} bant genişliği {rate} limitine çekilerek erişimi boğuldu (INPUT+FORWARD).",
                        severity="high"
                    )
                if self.active_defense_mgr:
                    self.active_defense_mgr.add_rule('rate_limit', target_ip=ip, parameters={'rate': rate})
                
                # Trafiğin bize uğraması için ARP zehirle! (DROP yapmadan)
                self.intercept_ip(ip)
                return True
            except Exception as e:
                print(f"{Fore.RED}[!] Rate limit hatası: {e}{Style.RESET_ALL}")
                return False

    def unrate_limit_ip(self, ip, rate="1/s"):
        """Bant genişliği boğma kuralını tüm zincirlerden kaldırır."""
        if not self._check_root():
            return False
        with self.lock:
            try:
                # Download Limiti Kaldır
                subprocess.run(['iptables', '-D', 'FORWARD', '-d', ip, '-m', 'limit', '--limit', rate, '-j', 'ACCEPT'], 
                             shell=False, capture_output=True)
                subprocess.run(['iptables', '-D', 'FORWARD', '-d', ip, '-j', 'DROP'], 
                             shell=False, capture_output=True)
                
                # Upload Limiti Kaldır
                subprocess.run(['iptables', '-D', 'FORWARD', '-s', ip, '-m', 'limit', '--limit', rate, '-j', 'ACCEPT'], 
                             shell=False, capture_output=True)
                subprocess.run(['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'], 
                             shell=False, capture_output=True)
                
                # INPUT Limiti Kaldır
                subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-m', 'limit', '--limit', rate, '-j', 'ACCEPT'], 
                             shell=False, capture_output=True)
                subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], 
                             shell=False, capture_output=True)
                if self.active_defense_mgr:
                    self.active_defense_mgr.remove_rule_by_target('rate_limit', ip)
                print(f"{Fore.YELLOW}[*] IP {ip} bant genişliği kısıtlaması kaldırıldı (INPUT+FORWARD).{Style.RESET_ALL}")
                # Intercept'i durdur (eğer başka bir sebeple (örn: tarpit) izlenmiyorsa)
                self.stop_intercept_ip(ip)
                return True
            except Exception as e:
                print(f"{Fore.RED}[!] Unrate limit hatası: {e}{Style.RESET_ALL}")
                return False

    def kill_session_hardware(self, ip):
        """TCP oturumlarını donanımsal (iptables) TCP RST enjeksiyonuyla milisaniyeler içinde düşürür."""
        if not self._check_root():
            return False
            
        print(f"{Fore.CYAN}[*] ⚡ MOBİL TCP RST ENJEKSİYONU BAŞLATILDI: {ip}{Style.RESET_ALL}")
        
        try:
            # Hem Upload hem Download yönündeki tüm TCP paketlerine RST bas (Oturumu kır)
            subprocess.run(['iptables', '-I', 'FORWARD', '-p', 'tcp', '-s', ip, '-j', 'REJECT', '--reject-with', 'tcp-reset'], 
                         shell=False, capture_output=True)
            subprocess.run(['iptables', '-I', 'FORWARD', '-p', 'tcp', '-d', ip, '-j', 'REJECT', '--reject-with', 'tcp-reset'], 
                         shell=False, capture_output=True)
            
            # Cihazın oturumları algılayıp kapatması için 2 saniye bekle
            time.sleep(2)
            
            # Kuralı kaldır
            subprocess.run(['iptables', '-D', 'FORWARD', '-p', 'tcp', '-s', ip, '-j', 'REJECT', '--reject-with', 'tcp-reset'], 
                         shell=False, capture_output=True)
            subprocess.run(['iptables', '-D', 'FORWARD', '-p', 'tcp', '-d', ip, '-j', 'REJECT', '--reject-with', 'tcp-reset'], 
                         shell=False, capture_output=True)
            
            print(f"{Fore.GREEN}[+] ⚡ TCP RST BAŞARILI: {ip} oturumları düşürüldü.{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] TCP RST Hatası: {e}{Style.RESET_ALL}")
            return False

    def unblock_mac(self, mac):
        """MAC engelini kaldırır ve ARP izolasyonunu durdurur."""
        if not self._check_root():
            return
            
        with self.lock:
            try:
                subprocess.run(['iptables', '-D', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], 
                             shell=False, capture_output=True)
                subprocess.run(['iptables', '-D', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'], 
                             shell=False, capture_output=True)
                if mac in self.blocked_macs:
                    self.blocked_macs.remove(mac)
                # İlişkili IP'yi de kaldır
                ip = self.ip_mac_map.pop(mac, None)
                if ip:
                    self.mac_ip_map.pop(ip, None)
                    self.blocked_ips.discard(ip)
                    subprocess.run(['ipset', 'del', self.SET_NAME, ip, '-exist'], shell=False, capture_output=True)
                if hasattr(self.db, 'remove_ban'):
                    self.db.remove_ban(mac=mac)
                if self.active_defense_mgr:
                    self.active_defense_mgr.remove_rule_by_target('block_mac', mac)
                    
                # ARP tablosunu düzelt (kurbanın ağa geri dönmesini sağla)
                if ip and self._scapy_available and self.gateway_mac:
                    try:
                        from scapy.all import ARP, Ether, sendp
                        # Kurbana gerçek gateway MAC'ini gönder
                        sendp(Ether(dst=mac)/ARP(op=2, pdst=ip, hwdst=mac, 
                              psrc=self.gateway_ip, hwsrc=self.gateway_mac), 
                              iface=self.interface, verbose=False, count=5)
                        # Gateway'e kurbanın gerçek MAC'ini gönder
                        sendp(Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                              psrc=ip, hwsrc=mac),
                              iface=self.interface, verbose=False, count=5)
                        print(f"{Fore.GREEN}[+] ARP tablosu düzeltildi (restore). Cihaz ağa geri döndü.{Style.RESET_ALL}")
                    except Exception:
                        pass
                        
                print(f"{Fore.YELLOW}[*] 🔓 MAC engeli ve izolasyonu kaldırıldı: {mac}{Style.RESET_ALL}")
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

    def cleanup_all(self):
        """Aktif savunma sırasında eklenmiş tüm iptables kurallarını ve kayıtları temizler."""
        if not self._check_root():
            return
            
        print(f"{Fore.YELLOW}[!] Tüm engelleme ve aktif savunma kuralları sıfırlanıyor...{Style.RESET_ALL}")
        self.unblock_all()
        
        # iptables kurallarını tamamen temizle (dsips spesifik)
        subprocess.run(['iptables', '-D', 'INPUT', '-m', 'set', '--match-set', self.SET_NAME, 'src', '-j', 'DROP'], shell=False, capture_output=True)
        subprocess.run(['iptables', '-D', 'FORWARD', '-m', 'set', '--match-set', self.SET_NAME, 'src', '-j', 'DROP'], shell=False, capture_output=True)
        subprocess.run(['ipset', 'flush', self.SET_NAME], shell=False, capture_output=True)
        print(f"{Fore.GREEN}[+] Aktif savunma iptables temizliği tamamlandı.{Style.RESET_ALL}")

    def get_blocked_hosts(self) -> dict:
        """Şu anda izole edilmiş ve engellenmiş cihazları döner."""
        with self.lock:
            return {'ips': list(self.blocked_ips), 'macs': list(self.blocked_macs)}
            
    def stop(self):
        """Bloklayıcı thread'leri durdurur."""
        self.running = False

    def _arp_poison_thread(self):
        """
        Banlanmış cihazları ağdan izole etmek için sürekli sahte ARP paketleri gönderir.
        
        v5 Profesyonel İzolasyon Mantığı:
        - Kurbana: "Gateway MAC adresi BENİM MAC'im" der → kurbanın trafiği Kali'ye gelir → iptables DROP
        - Gateway'e: "Kurbanın MAC adresi BENİM MAC'im" der → gateway'den kurbana gelen trafik Kali'ye gelir → iptables DROP
        - Her iki yönde de tam izolasyon sağlanır
        - Kurbanın IP adresini bilmesi ZORUNLU (pdst alanı)
        """
        try:
            from scapy.all import ARP, Ether, sendp, get_if_hwaddr
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        except ImportError:
            print(f"{Fore.RED}[!] İzolasyon için scapy gerekli. Lütfen kurun.{Style.RESET_ALL}")
            return

        print(f"{Fore.GREEN}[+] ARP İzolasyon thread'i aktif - banlanmış cihazları ağdan koparacak{Style.RESET_ALL}")
        
        while self.running:
            try:
                my_mac = get_if_hwaddr(self.interface)
            except Exception:
                my_mac = "02:00:00:00:00:00"

            if not self.gateway_ip:
                self._get_gateway_info()
                time.sleep(2)
                continue
                
            if not self.blocked_macs and not self.intercepted_macs:
                time.sleep(1)
                continue
                
            try:
                with self.lock:
                    # Hem tam izolasyon (Drop) hem de Intercept listesindeki cihazları zehirle
                    macs_to_poison = list(self.blocked_macs | self.intercepted_macs)
                    ip_mac_snapshot = dict(self.ip_mac_map)
                    
                for target_mac in macs_to_poison:
                    try:
                        if not target_mac or target_mac == "ff:ff:ff:ff:ff:ff":
                            continue
                            
                        # Kurbanın IP adresini bul (ARP poisoning için ZORUNLU)
                        victim_ip = ip_mac_snapshot.get(target_mac)
                        if not victim_ip:
                            # IP'yi çözümlemeyi dene
                            victim_ip = self._resolve_ip_for_mac(target_mac)
                            if not victim_ip:
                                continue  # IP bulamadıysak ARP zehirlemesi yapamayız
                        
                        # ═══════════════════════════════════════════
                        # PAKET 1: KURBANI ZEHİRLE
                        # Kurbana söyle: "Gateway'in MAC adresi benim (Kali) MAC adresim"
                        # Böylece kurban internete çıkmaya çalıştığında paketler Kali'ye gelir
                        # Kali'deki iptables DROP kuralı bu paketleri çöpe atar
                        # ═══════════════════════════════════════════
                        poison_victim = Ether(dst=target_mac) / ARP(
                            op=2,          # ARP Reply
                            pdst=victim_ip,    # Kurbanın IP'si (paketi kimin alacağı)
                            hwdst=target_mac,  # Kurbanın MAC'i
                            psrc=self.gateway_ip,  # "Ben gateway'im" diye yalan söylüyoruz
                            hwsrc=my_mac       # Kendi MAC'imizi gateway'inmiş gibi gösteriyoruz
                        )
                        sendp(poison_victim, iface=self.interface, verbose=False)
                        
                        # ═══════════════════════════════════════════
                        # PAKET 2: GATEWAY'İ (MODEMİ) ZEHİRLE
                        # Gateway'e söyle: "Kurbanın MAC adresi benim (Kali) MAC adresim"
                        # Böylece dışarıdan kurbana gelen paketler de Kali'ye gelir ve DROP edilir
                        # ═══════════════════════════════════════════
                        if self.gateway_mac:
                            poison_gateway = Ether(dst=self.gateway_mac) / ARP(
                                op=2,              # ARP Reply
                                pdst=self.gateway_ip,  # Gateway'in IP'si (paketi kimin alacağı)
                                hwdst=self.gateway_mac, # Gateway'in MAC'i
                                psrc=victim_ip,    # "Ben kurbanım" diye yalan söylüyoruz
                                hwsrc=my_mac       # Kendi MAC'imizi kurbanınmış gibi gösteriyoruz
                            )
                            sendp(poison_gateway, iface=self.interface, verbose=False)
                        
                        # ═══════════════════════════════════════════
                        # PAKET 3: BROADCAST ARP (Ağdaki herkese duyur)
                        # Tüm ağa: "Gateway'in MAC'i benim" diye broadcast ARP at
                        # Bu, kurbanın ARP cache timeout'unu sıfırlar
                        # ═══════════════════════════════════════════
                        # broadcast_poison = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        #     op=2,
                        #     pdst=victim_ip,
                        #     hwdst="ff:ff:ff:ff:ff:ff",
                        #     psrc=self.gateway_ip,
                        #     hwsrc=my_mac
                        # )
                        # sendp(broadcast_poison, iface=self.interface, verbose=False)
                        
                    except Exception:
                        pass
            except Exception:
                pass
                
            # ARP iyileşmesini önlemek için yüksek frekansta (0.3s) saldır
            time.sleep(0.3)
