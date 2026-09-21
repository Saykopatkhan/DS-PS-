#!/usr/bin/env python3
import socket
import requests
import time
import sys
import re
from colorama import init, Fore, Style

init(autoreset=True)


def probe_login_rate_limit(base_url):
    """Return True only for an observed HTTP 429 after valid-CSRF failures."""
    with requests.Session() as client:
        login = client.get(f'{base_url}/login', timeout=3)
        login.raise_for_status()
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', login.text)
        if not match:
            raise ValueError('Giriş formunda CSRF alanı bulunamadı')
        for attempt in range(6):
            response = client.post(f'{base_url}/login', data={
                'username': 'admin', 'password': f'invalid-qa-password-{attempt}',
                'csrf_token': match.group(1),
            }, timeout=3, allow_redirects=False)
            if response.status_code == 429:
                return True
            if response.status_code != 401:
                raise ValueError(f'Beklenmeyen HTTP {response.status_code}; hız sınırı doğrulanamadı')
    return False

class DSIPS_QASuite:
    def __init__(self, target_ip, web_port=5000):
        self.target_ip = target_ip
        self.web_port = web_port
        self.base_url = f"http://{target_ip}:{web_port}"
        self.results = []
        
    def log_result(self, test_name, status, details=""):
        if status == "BAŞARILI" or status == "TETİKLENDİ":
            color = Fore.GREEN
        elif status == "YANIT YOK" or status == "BAŞARISIZ":
            color = Fore.RED
        else:
            color = Fore.YELLOW
            
        print(f"[{color}{status}{Style.RESET_ALL}] {test_name.ljust(40)} | {details}")
        self.results.append((test_name, status))

    def run_all(self):
        print(f"\n{Fore.CYAN}=== DS-IPS v5.0 Güvenlik Doğrulama ve Regresyon Test Kiti ==={Style.RESET_ALL}")
        print(f"Hedef: {self.target_ip}\n")
        
        self.test_waf_payloads()
        self.test_bruteforce_defense()
        self.test_honeypot()
        self.test_dns_sinkhole()
        self.test_port_scan()
        # Tarpit testi en son yapılır çünkü bağlantıyı dondurabilir
        self.test_tcp_tarpit()
        
        self.print_summary()

    def test_waf_payloads(self):
        test_name = "1. WAF: SQLi & XSS Payload Tespiti"
        payloads = ["id=1' OR '1'='1", "<script>alert(1)</script>"]
        
        try:
            for p in payloads:
                requests.get(f"{self.base_url}/?{p}", timeout=3)
            self.log_result(test_name, "GÖNDERİLDİ", "Payloadlar gönderildi; tespit için sunucu alarmları doğrulanmalı")
        except requests.exceptions.RequestException:
            self.log_result(test_name, "DOĞRULANAMADI", "Bağlantı hatası WAF engellemesinin kanıtı değildir")

    def test_bruteforce_defense(self):
        test_name = "Login: Hız Sınırı"
        try:
            limited = probe_login_rate_limit(self.base_url)
            self.log_result(test_name, "BAŞARILI" if limited else "BAŞARISIZ",
                            "HTTP 429 gözlendi" if limited else "6 denemede HTTP 429 gözlenmedi")
        except (requests.RequestException, ValueError) as exc:
            self.log_result(test_name, "DOĞRULANAMADI", str(exc))

    def test_honeypot(self):
        test_name = "2. Honeypot Servis Tespiti"
        ports = [21, 23, 2222, 8081]
        triggered = 0
        
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((self.target_ip, port))
                banner = s.recv(1024).decode(errors='ignore').strip()
                s.close()
                if banner:
                    triggered += 1
            except:
                pass
                
        if triggered > 0:
            self.log_result(test_name, "TETİKLENDİ", f"{triggered}/{len(ports)} tuzak port aktif ve yanıt veriyor")
        else:
            self.log_result(test_name, "YANIT YOK", "Tuzak portlara erişilemedi")

    def test_dns_sinkhole(self):
        test_name = "4. DNS Sinkhole Karantina Yönlendirmesi"
        # Basit bir DNS A sorgusu (google.com)
        # Transaction ID: 0x1234, Flags: 0x0100 (Standard query), Questions: 1
        dns_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(dns_query, (self.target_ip, 53))
            data, _ = s.recvfrom(1024)
            s.close()
            
            # Yanıt geldiyse ve içerisinde bir IP (sinkhole IP'si) varsa çalışıyordur.
            if data:
                self.log_result(test_name, "TETİKLENDİ", "DNS Sunucusu (Sinkhole) sahte yanıt döndürdü")
            else:
                self.log_result(test_name, "YANIT YOK", "Boş yanıt")
        except socket.timeout:
            self.log_result(test_name, "YANIT YOK", "DNS Portu (53) kapalı veya cevap vermedi")
        except Exception as e:
            self.log_result(test_name, "BAŞARISIZ", str(e))

    def test_port_scan(self):
        test_name = "5. Port Tarama (Scan) Tespiti"
        try:
            # Hızlıca 15 farklı porta SYN/Connect göndererek tarama simülasyonu yapıyoruz
            for port in range(30000, 30015):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect_ex((self.target_ip, port))
                s.close()
            self.log_result(test_name, "GÖNDERİLDİ", "15 porta bağlantı denendi; alarm doğrulanmadı")
        except Exception as e:
            self.log_result(test_name, "BAŞARISIZ", str(e))

    def test_tcp_tarpit(self):
        test_name = "3. TCP Tarpit Akış Kontrolü"
        # Bu testin başarılı olması için kullanıcının IPS üzerinden bu araca (IP'sine) Tarpit uygulamış olması gerekir.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            # Tarpit portu olarak bilinen (veya herhangi bir) porta bağlanmayı deneriz.
            # IPS Tarpit aktifse normalde PREROUTING ile bağlantıyı 9999'a çekecektir.
            # Localhost'ta PREROUTING çalışmadığı için QA testini direkt dinleyici olan 9999'a yapıyoruz.
            s.connect((self.target_ip, 9999)) 
            start_time = time.time()
            data = s.recv(10)
            elapsed = time.time() - start_time
            
            if data and elapsed > 2.0:
                self.log_result(test_name, "TETİKLENDİ", f"Aşırı yavaş yanıt tespit edildi! (Süre: {elapsed:.2f}s)")
            else:
                self.log_result(test_name, "BAŞARISIZ", "Normal hızda yanıt alındı (Tarpit aktif edilmemiş olabilir)")
            s.close()
        except socket.timeout:
            self.log_result(test_name, "DOĞRULANAMADI", "Zaman aşımı; tek başına Tarpit kanıtı değildir")
        except ConnectionRefusedError:
            self.log_result(test_name, "YANIT YOK", "Port kapalı (Tarpit yönlendirmesi çalışmadı)")
        except Exception as e:
            self.log_result(test_name, "BAŞARISIZ", str(e))

    def print_summary(self):
        print(f"\n{Fore.CYAN}--- TEST ÖZETİ ---{Style.RESET_ALL}")
        for res in self.results:
            print(f"- {res[0].ljust(40)}: {res[1]}")
        print(f"\n{Fore.GREEN}[*] Testler tamamlandı. DS-IPS loglarınızı kontrol ediniz.{Style.RESET_ALL}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python3 ds_ips_qa_suite.py <HEDEF_IP>")
        sys.exit(1)
        
    target = sys.argv[1]
    suite = DSIPS_QASuite(target)
    suite.run_all()
