# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

import socket
import ipaddress
import subprocess
import threading
import time
import ipaddress
from scapy.all import srp, ARP, Ether
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from colorama import Fore, Style
from utils.vendor import VendorLookup

class NetworkScanner:
    """
    Scapy kullanarak ağdaki IP ve MAC adreslerini keşfeden tarayıcı sınıfı.
    """
    def __init__(self, db, interface='eth0'):
        self.db = db
        self.interface = interface
        self.running = False
        self.scan_thread = None

    def get_subnet(self):
        """Arayüzün bağlı olduğu alt ağı (CIDR) bulur."""
        try:
            # ip -o -f inet addr show dev wlan0 | awk '{print $4}'
            cmd = f"ip -o -f inet addr show dev {self.interface} | awk '{{print $4}}'"
            out = subprocess.getoutput(cmd).strip()
            if out and "does not exist" not in out:
                return str(ipaddress.IPv4Network(out, strict=False))
        except Exception as e:
            print(f"{Fore.RED}[!] Subnet bulunamadı: {e}{Style.RESET_ALL}")
        return None

    def scan_once(self):
        """Ağı bir kez tarar ve bulunan cihazları veritabanına kaydeder."""
        subnet = self.get_subnet()
        if not subnet:
            print(f"{Fore.YELLOW}[!] Tarama başarısız: {self.interface} için alt ağ bulunamadı. Lütfen IP adresi aldığınızdan emin olun.{Style.RESET_ALL}")
            return []

        print(f"{Fore.CYAN}[*] {subnet} ağında ARP taraması yapılıyor (Arayüz: {self.interface})...{Style.RESET_ALL}")
        
        arp_request = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp_request
        
        try:
            result = srp(packet, timeout=2, iface=self.interface, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                
                # Marka tespiti
                vendor = VendorLookup.get_vendor(mac)
                
                # Hostname tespiti
                hostname = "Bilinmiyor"
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    pass
                    
                # TTL ve OS tespiti (ICMP ile ping atıp dönen paketin TTL'sine bakarak)
                os_type = "Bilinmiyor"
                try:
                    from scapy.all import IP as ScapyIP, ICMP, sr1
                    from utils.os_fingerprint import OSFingerprint
                    ping_pkt = ScapyIP(dst=ip)/ICMP()
                    # Çok kısa timeout ki taramayı yavaşlatmasın
                    resp = sr1(ping_pkt, timeout=0.5, verbose=0)
                    if resp and resp.haslayer(ScapyIP):
                        ttl = resp[ScapyIP].ttl
                        os_type = OSFingerprint.from_ttl(ttl)
                except Exception:
                    pass
                
                devices.append({'ip': ip, 'mac': mac, 'vendor': vendor, 'hostname': hostname, 'os_type': os_type})
                # Veritabanını güncelle (yeni kolonlarla)
                self.db.update_ip_mac(ip, mac, vendor=vendor, hostname=hostname, os_type=os_type)
                
            print(f"{Fore.GREEN}[+] Tarama tamamlandı: {len(devices)} cihaz bulundu.{Style.RESET_ALL}")
            return devices
        except PermissionError:
            print(f"{Fore.RED}[!] Yetki hatası: Ağ taraması için root (sudo) yetkisi gerekiyor!{Style.RESET_ALL}")
            return []
        except Exception as e:
            print(f"{Fore.RED}[!] Tarama hatası: {e}{Style.RESET_ALL}")
            return []

    def _scan_loop(self, interval):
        """Arka planda periyodik tarama yapan döngü."""
        while self.running:
            self.scan_once()
            # Kesilebilir uyku
            for _ in range(interval):
                if not self.running:
                    break
                time.sleep(1)

    def start_periodic(self, interval=60):
        """Periyodik taramayı başlatır."""
        if not self.running:
            self.running = True
            self.scan_thread = threading.Thread(target=self._scan_loop, args=(interval,), daemon=True)
            self.scan_thread.start()
            print(f"{Fore.GREEN}[*] Periyodik ağ tarayıcı başlatıldı (Aralık: {interval}s).{Style.RESET_ALL}")

    def stop(self):
        """Periyodik taramayı durdurur."""
        self.running = False
        if self.scan_thread:
            self.scan_thread.join(timeout=2)
            print(f"{Fore.YELLOW}[*] Periyodik ağ tarayıcı durduruldu.{Style.RESET_ALL}")
