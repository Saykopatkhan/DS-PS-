#!/usr/bin/env python3
# ========================================================================
# DS-IPS (Premium SOC Edition) v5.0 - Security Validation & BAS Auditor
# ========================================================================
import argparse
import socket
import time
import sys
import requests
from colorama import init, Fore, Style

try:
    from scapy.all import IP, TCP, ARP, Ether, send, sendp, conf
except ImportError:
    print("Scapy eksik. Yüklemek için: pip install scapy")
    sys.exit(1)

try:
    import dns.message
    import dns.query
except ImportError:
    print("dnspython eksik. Yüklemek için: pip install dnspython")
    sys.exit(1)

init(autoreset=True)

class DSIpsAuditor:
    def __init__(self, target, interface, verbose, delay, self_test=False):
        self.target = target
        self.interface = interface
        self.verbose = verbose
        self.delay = delay
        self.is_whitelisted = (target == "127.0.0.1" or self_test)
        self.base_url = f"http://{self.target}:5000"
        self.results = []

    def log(self, msg, level="INFO"):
        if self.verbose:
            if level == "INFO":
                print(f"[*] {msg}")
            elif level == "WARN":
                print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
            elif level == "ERROR":
                print(f"{Fore.RED}[X] {msg}{Style.RESET_ALL}")
            elif level == "SUCCESS":
                print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

    def report_result(self, module, expected, observed, status, latency):
        if status == "PASSED":
            color = Fore.GREEN
        elif status == "FAILED":
            color = Fore.RED
        else:
            color = Fore.YELLOW
            
        self.results.append({
            "module": module,
            "expected": expected,
            "observed": observed,
            "status": f"{color}{status}{Style.RESET_ALL}",
            "latency": latency
        })

    def run_tests(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print("DS-IPS (Premium SOC) v5.0 - BAS Otonom Denetim Başlıyor")
        print(f"Hedef: {self.target} | Arayüz: {self.interface} | Gecikme: {self.delay}s")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        self.test_waf_and_self_defense()
        time.sleep(self.delay)
        
        self.test_honeypot()
        time.sleep(self.delay)
        
        self.test_tcp_tarpit()
        time.sleep(self.delay)
        
        self.test_dns_sinkhole()
        time.sleep(self.delay)
        
        self.test_l4_stealth_scan()
        time.sleep(self.delay)
        
        self.test_anti_mitm()
        time.sleep(self.delay)
        
        self.test_whitelist()
        
        self.print_final_report()

    def test_waf_and_self_defense(self):
        from ds_ips_qa_suite import probe_login_rate_limit
        start_time = time.time()
        try:
            limited = probe_login_rate_limit(self.base_url)
            self.report_result("1. Login Rate Limit", "HTTP 429",
                               "HTTP 429 observed" if limited else "No rate limit observed",
                               "PASSED" if limited else "FAILED",
                               f"{(time.time() - start_time) * 1000:.1f}ms")
        except (requests.RequestException, ValueError) as exc:
            self.report_result("1. Login Rate Limit", "HTTP 429", str(exc), "INCONCLUSIVE", "N/A")

    def test_honeypot(self):
        self.log("\nModül 2: Honeypot & Deception testi başlatılıyor...")
        module = "2. Honeypot & Deception"
        ports = {21: "FTP", 23: "Telnet", 2222: "SSH", 8081: "Web"}
        success_count = 0
        start_time = time.time()

        for port, service in ports.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((self.target, port))
                if port != 8081:
                    banner = s.recv(1024).decode(errors='ignore').strip()
                    self.log(f"Port {port} ({service}) Banner: {banner[:30]}...", "SUCCESS")
                    if banner:
                        success_count += 1
                else:
                    s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    banner = s.recv(1024).decode(errors='ignore')
                    if "Admin" in banner or "HTTP" in banner:
                        success_count += 1
                        self.log(f"Port {port} (Web) Sahte Portal Yanıtı Alındı", "SUCCESS")
                s.close()
            except Exception as e:
                self.log(f"Port {port} ({service}) erişilemedi: {e}", "WARN")

        latency = f"{(time.time() - start_time)*1000:.1f}ms"
        if success_count > 0:
            self.report_result(module, "Sahte Banner/Portal Yanıtı", f"{success_count}/{len(ports)} Port Aktif", "PASSED", latency)
        else:
            self.report_result(module, "Sahte Banner/Portal Yanıtı", "Portlar kapalı veya yanıt yok", "FAILED", latency)

    def test_tcp_tarpit(self):
        self.log("\nModül 3: TCP Tarpit Akış Darboğazı testi başlatılıyor...")
        module = "3. TCP Tarpit Analizi"
        start_time = time.time()
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, 9999)) # Direkt Tarpit portu
            self.log("Tarpit soketine bağlanıldı, veri bekleniyor...")
            
            # Tarpit 1-2 byte veriyi aşırı yavaş gönderir
            data = s.recv(10)
            elapsed = time.time() - start_time
            
            if data and elapsed >= 2.0:
                self.log(f"Aşırı yavaş veri akışı tespit edildi ({elapsed:.2f} saniye). Tarpit aktif!", "SUCCESS")
                self.report_result(module, "Zero-Window / Aşırı Gecikme", f"Gecikme: {elapsed:.2f}s", "PASSED", f"{elapsed*1000:.1f}ms")
            elif self.is_whitelisted:
                self.log(f"Test hedeflenen IP ({self.target}) beyaz listede olduğu için Tarpit tetiklenmedi (Hızlı koptu).", "SUCCESS")
                self.report_result(module, "Zero-Window / Aşırı Gecikme", "Bağlantı Reddildi (Beyaz Liste Koruması)", "INCONCLUSIVE", f"{elapsed*1000:.1f}ms")
            else:
                self.report_result(module, "Zero-Window / Aşırı Gecikme", "Bağlantı anında koptu veya çok hızlı", "FAILED", f"{elapsed*1000:.1f}ms")
            s.close()
        except socket.timeout:
            self.log("Soket zaman aşımına uğradı (Tam Tarpit - Zero Window)", "SUCCESS")
            self.report_result(module, "Zero-Window / Aşırı Gecikme", "Timeout; Tarpit doğrulanamadı", "INCONCLUSIVE", "5000+ms")
        except Exception as e:
            self.report_result(module, "Zero-Window / Aşırı Gecikme", f"Hata: {e}", "FAILED", "0ms")

    def test_dns_sinkhole(self):
        self.log("\nModül 4: DNS Sinkhole & LLMNR testi başlatılıyor...")
        module = "4. DNS Sinkhole (UDP 53)"
        start_time = time.time()
        domain = "malware.com"
        
        try:
            query = dns.message.make_query(domain, dns.rdatatype.A)
            response = dns.query.udp(query, self.target, timeout=3, port=53)
            if response.answer:
                sinkhole_ip = response.answer[0][0].address
                self.log(f"Zararlı DNS sorgusu yönlendirildi: {domain} -> {sinkhole_ip}", "SUCCESS")
                
                # HTTP Kontrolü
                try:
                    r = requests.get(f"http://{self.target}:8099/", timeout=3)
                    if "Karantina" in r.text or "DS-IPS" in r.text:
                        self.log("8099 Karantina sayfası doğrulandı.", "SUCCESS")
                        latency = f"{(time.time() - start_time)*1000:.1f}ms"
                        self.report_result(module, "Sinkhole IP + Karantina HTML", f"{sinkhole_ip} + HTML Başarılı", "PASSED", latency)
                        return
                except:
                    pass
                
                latency = f"{(time.time() - start_time)*1000:.1f}ms"
                self.report_result(module, "Sinkhole IP + Karantina HTML", "Sadece DNS Yanıtı Alındı (HTTP Hatalı)", "INCONCLUSIVE", latency)
            else:
                self.report_result(module, "Sinkhole IP + Karantina HTML", "Boş DNS Yanıtı", "FAILED", "0ms")
        except Exception as e:
            self.log(f"DNS Hatası: {e}", "WARN")
            self.report_result(module, "Sinkhole IP + Karantina HTML", "DNS Portu Kapalı veya Cevapsız", "FAILED", "0ms")

    def test_l4_stealth_scan(self):
        self.log("\nModül 5: L4 Stealth Port Tarama testi başlatılıyor...")
        module = "5. L4 Stealth Scan Tespiti"
        start_time = time.time()
        
        try:
            self.log("Parçalanmış SYN, FIN, NULL paketleri gönderiliyor...")
            conf.verb = 0
            # Rastgele 5 port'a SYN
            for port in range(30020, 30025):
                pkt = IP(dst=self.target)/TCP(dport=port, flags="S")
                send(pkt, verbose=False)
            # FIN paketi
            pkt_fin = IP(dst=self.target)/TCP(dport=30025, flags="F")
            send(pkt_fin, verbose=False)
            # NULL paketi
            pkt_null = IP(dst=self.target)/TCP(dport=30026, flags="")
            send(pkt_null, verbose=False)
            
            latency = f"{(time.time() - start_time)*1000:.1f}ms"
            self.report_result(module, "Tarama Alarmı Tetiklenmesi", "Paketler Enjekte Edildi; alarm doğrulanmadı", "SENT", latency)
        except Exception as e:
            self.report_result(module, "Tarama Alarmı Tetiklenmesi", f"Enjeksiyon Hatası: {e}", "FAILED", "0ms")

    def test_anti_mitm(self):
        self.log("\nModül 6: Anti-MITM & L2 İzolasyon testi başlatılıyor...")
        module = "6. Anti-MITM (ARP) Healing"
        start_time = time.time()
        
        try:
            self.log("Ağa sahte Gratuitous ARP pakedi yayınlanıyor...")
            # Kendi IP'miz gateway'miş gibi yayın yapıyoruz
            fake_arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.1", hwsrc="00:11:22:33:44:55")
            sendp(fake_arp, iface=self.interface, verbose=False)
            
            # Not: Tam iyileştirme paketini yakalamak için asenkron dinleme gerekir (sniff).
            # Bu otomasyonda sadece pakedin basılabildiğini teyit edip PASSED dönüyoruz.
            latency = f"{(time.time() - start_time)*1000:.1f}ms"
            self.report_result(module, "ARP İyileştirme Paketleri (Healing)", "Sahte ARP Yayınlandı; iyileştirme doğrulanmadı", "SENT", latency)
        except Exception as e:
            self.report_result(module, "ARP İyileştirme Paketleri (Healing)", f"L2 Enjeksiyon Hatası: {e}", "FAILED", "0ms")

    def test_whitelist(self):
        self.log("\nModül 7: Whitelist ve Anti-Self-DoS testi başlatılıyor...")
        module = "7. Whitelist & Anti-Self-DoS"
        start_time = time.time()
        
        try:
            self.log("127.0.0.1 (Localhost) üzerinden kritik hedeflere istek atılıyor...")
            # Beyaz listedeki bir adresten istek geldiğinde IPS onu engellememelidir.
            # DS-IPS 127.0.0.1'i otomatik beyaz listeye alır.
            r = requests.get(f"http://{self.target}:5000/", timeout=3)
            
            if r.status_code == 200:
                self.log("Erişim devam ediyor, sistem kendi kendini banlamadı.", "SUCCESS")
                latency = f"{(time.time() - start_time)*1000:.1f}ms"
                self.report_result(module, "Erişimin Kesilmemesi", "Sistem Erişilebilir Durumda", "PASSED", latency)
            else:
                self.report_result(module, "Erişimin Kesilmemesi", f"Beklenmedik HTTP Yanıtı: {r.status_code}", "FAILED", f"{(time.time() - start_time)*1000:.1f}ms")
        except Exception as e:
            self.report_result(module, "Erişimin Kesilmemesi", f"Self-DoS Tetiklendi! Sistem Kendini Banladı: {e}", "FAILED", "0ms")

    def print_final_report(self):
        print(f"\n{Fore.CYAN}{'='*100}")
        print(f"| {'Modül Adı'.ljust(30)} | {'Beklenen Davranış'.ljust(30)} | {'Durum'.ljust(15)} | {'Gecikme (ms)'.ljust(15)} |")
        print(f"{'-'*100}")
        
        for res in self.results:
            print(f"| {res['module'].ljust(30)} | {res['expected'].ljust(30)} | {res['status'].ljust(24)} | {res['latency'].ljust(15)} |")
            
        print(f"{'='*100}{Style.RESET_ALL}\n")
        print("[*] DS-IPS SOC Doğrulama (Auditor) Raporu Tamamlandı.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DS-IPS v5.0 SOC Security Auditor")
    parser.add_argument("--target", required=True, help="Hedef DS-IPS IP adresi")
    parser.add_argument("--interface", required=True, help="Ağ arayüzü (ör. wlan0, eth0)")
    parser.add_argument("--verbose", action="store_true", help="Detaylı log çıktısı")
    parser.add_argument("--delay", type=float, default=1.0, help="Testler arası bekleme süresi (sn)")
    parser.add_argument("--self-test", action="store_true", help="Target is localhost/whitelisted IP (Changes PASS criteria)")
    args = parser.parse_args()

    auditor = DSIpsAuditor(args.target, args.interface, args.verbose, args.delay, args.self_test)
    auditor.run_tests()
