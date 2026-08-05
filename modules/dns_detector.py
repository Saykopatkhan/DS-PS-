"""
DNS Tunneling ve Veri Sızdırma (Exfiltration) tespit modülü.
"""
import time
from collections import defaultdict
from scapy.all import DNS, DNSQR, IP
from core.database import Database
from utils.sound import SoundAlert

class DNSDetector:
    def __init__(self, db: Database, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        
        self.query_count = defaultdict(int)
        self.domain_length = defaultdict(list)
        self.detection_window = 10.0
        self.query_threshold = 100  # 10 saniyede 100 DNS sorgusu (DNS Flood)
        self.max_subdomain_len = 50 # Çok uzun subdomainler genelde tunneling işaretidir
        self.last_reset = time.time()

    def analyze(self, packet):
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                qname = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                
                self.query_count[src_ip] += 1
                
                # Exfiltration (Tunneling) kontrolü: Domainin sub-kısmı aşırı uzun mu?
                if qname:
                    # DNS Sinkhole Kontrolü
                    bad_domains = ['malware.com.', 'phishing.net.', 'hacker.io.']
                    if any(bad in qname for bad in bad_domains):
                        self._trigger_sinkhole(src_ip, qname, packet)
                        return # Spoof yaptık, devam etme
                        
                    parts = qname.split('.')
                    if len(parts) > 2:
                        subdomain = parts[0]
                        if len(subdomain) > self.max_subdomain_len:
                            self._detect_tunneling(src_ip, qname)
                
                self._check_flood(src_ip)
                
        self._reset_window()

    def _trigger_sinkhole(self, src_ip, domain, packet):
        # Sahte DNS cevabı oluştur (Sinkhole)
        from scapy.all import IP, UDP, DNSRR, sendp, Ether
        import socket, fcntl, struct
        
        # Local IP'yi al (Web panel IP'si)
        sinkhole_ip = '127.0.0.1'
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sinkhole_ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', bytes('eth0', 'utf-8')))[20:24])
        except:
            pass

        # DNS cevabını hazırla
        ip = packet.getlayer(IP)
        udp = packet.getlayer(UDP)
        dns = packet.getlayer(DNS)
        
        spoofed_pkt = Ether(dst=packet[Ether].src, src=packet[Ether].dst)/\
                      IP(dst=ip.src, src=ip.dst)/\
                      UDP(dport=udp.sport, sport=udp.dport)/\
                      DNS(id=dns.id, qr=1, aa=1, qd=dns.qd, \
                      an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata=sinkhole_ip))
                      
        sendp(spoofed_pkt, verbose=False)
        
        self.db.add_alert(
            alert_type='DNS Sinkhole (Zararlı Site Engeli)',
            src_ip=src_ip, src_mac='N/A',
            dst_ip='N/A', dst_mac='N/A',
            description=f'Kaynak {src_ip} zararlı siteye girmeye çalıştı: {domain}. Yönlendirme yapıldı.',
            severity='high'
        )
        SoundAlert.alert_attack("DNS Sinkhole")

    def _detect_tunneling(self, src_ip, domain):
        self.db.add_alert(
            alert_type='DNS Tunneling / Exfiltration',
            src_ip=src_ip, src_mac='N/A',
            dst_ip='N/A', dst_mac='N/A',
            description=f'Kaynak {src_ip} anormal uzunlukta DNS sorgusu yaptı: {domain}',
            severity='critical'
        )
        SoundAlert.alert_attack("DNS Tünelleme")
        # Otomatik Ban YOK (if self.blocker and self.auto_ban kaldırıldı, plan gereği)

    def _check_flood(self, src_ip):
        if self.query_count[src_ip] > self.query_threshold:
            self.db.add_alert(
                alert_type='DNS Flood',
                src_ip=src_ip, src_mac='N/A',
                dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {src_ip} {self.detection_window}s içinde {self.query_count[src_ip]} DNS sorgusu yaptı',
                severity='high'
            )
            SoundAlert.alert_attack("DNS Flood")
            self.query_count[src_ip] = 0 # Tekrar etmemesi için sıfırla

    def _reset_window(self):
        if time.time() - self.last_reset > self.detection_window:
            self.query_count.clear()
            self.last_reset = time.time()
