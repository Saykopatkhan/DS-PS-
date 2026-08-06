# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Decoy Traffic Generator (Beyaz Gürültü Üretici)
Ağ dinleyen saldırganları (Sniffer) yanıltmak için sahte DNS ve HTTP trafiği oluşturur.
"""
import threading
import time
import random
import urllib.request
from scapy.all import IP, UDP, DNS, DNSQR, send

class DecoyTrafficGenerator:
    def __init__(self):
        self.running = False
        self.thread = None
        
        # Sahte DNS hedefleri (gerçek olmayan veya gürültü yaratacak siteler)
        self.fake_domains = [
            "banka-giris-sistemi-internal.local",
            "sirket-veritabani.local",
            "ik-maas-listeleri.com",
            "gizli-proje-x.net",
            "admin-portal-v2.org",
            "test-db-sunucusu.local"
        ]
        
        # Sahte HTTP istek hedefleri (Zararsız IP'lere rastgele GET)
        self.fake_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "9.9.9.9",
            "208.67.222.222",
            "192.168.1.100", # Ağda var olup olmadığı belirsiz bir IP
            "10.0.0.55"
        ]

    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._generate_noise, daemon=True)
            self.thread.start()
            print("[+] Decoy Traffic (Beyaz Gürültü) motoru başlatıldı.")

    def stop(self):
        self.running = False
        print("[-] Decoy Traffic (Beyaz Gürültü) motoru durduruldu.")

    def _generate_noise(self):
        while self.running:
            try:
                # Rastgele bekleme süresi (1 ile 5 saniye arası)
                time.sleep(random.uniform(1.0, 5.0))
                
                action = random.choice(['dns', 'http'])
                
                if action == 'dns':
                    # Sahte DNS sorgusu yolla
                    domain = random.choice(self.fake_domains)
                    dns_req = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
                    send(dns_req, verbose=False)
                    
                elif action == 'http':
                    # Sahte HTTP isteği yolla (Hata alsa da paket ağa çıkar)
                    target_ip = random.choice(self.fake_ips)
                    try:
                        req = urllib.request.Request(f"http://{target_ip}/admin_login.php", headers={'User-Agent': 'Mozilla/5.0'})
                        urllib.request.urlopen(req, timeout=0.5)
                    except Exception:
                        pass # İstek başarısız olsa da paket sniffers tarafından görülür
                        
            except Exception:
                pass
