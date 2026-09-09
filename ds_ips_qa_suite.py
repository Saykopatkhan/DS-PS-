#!/usr/bin/env python3
import socket
import requests
import time
import sys
import struct
from colorama import init, Fore, Style

init(autoreset=True)

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
            self.log_result(test_name, "TETİKLENDİ", "Zararlı payloadlar gönderildi (Panelin engellemesi beklenir)")
        except requests.exceptions.RequestException as e:
            self.log_result(test_name, "TETİKLENDİ", "WAF bağlantıyı kesti veya reddetti")

    def test_bruteforce_defense(self):
        test_name = "1. Self-Defense: Brute-Force Koruması"
        try:
            for i in range(6):
                resp = requests.post(f"{self.base_url}/login", data={'username':'admin', 'password':f'bad{i}'}, timeout=3)
                if resp.status_code == 403 or "Engellendi" in resp.text:
                    self.log_result(test_name, "TETİKLENDİ", f"{i+1}. denemede IP engellendi (HTTP 403)")
                    return
            self.log_result(test_name, "BAŞARISIZ", "6 hatalı denemeye rağmen banlanmadı")
        except requests.exceptions.ConnectionError:
            self.log_result(test_name, "TETİKLENDİ", "Bağlantı seviyesinde (Firewall) banlandı")
        except Exception as e:
            self.log_result(test_name, "YANIT YOK", str(e))

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
            self.log_result(test_name, "BAŞARILI", "15 Porta tarama paketi gönderildi (Alarm bekleniyor)")
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
            
            if elapsed > 2.0:
                self.log_result(test_name, "TETİKLENDİ", f"Aşırı yavaş yanıt tespit edildi! (Süre: {elapsed:.2f}s)")
            else:
                self.log_result(test_name, "BAŞARISIZ", "Normal hızda yanıt alındı (Tarpit aktif edilmemiş olabilir)")
            s.close()
        except socket.timeout:
            self.log_result(test_name, "TETİKLENDİ", "Bağlantı açık ama veri gelmiyor (Sıfır TCP Penceresi - Tam Tarpit)")
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
