# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
DNS Tunneling ve Veri Sızdırma (Exfiltration) tespit modülü.
"""
import time
from collections import defaultdict
from scapy.all import DNS, DNSQR, IP, Ether
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
                
                # Sitenin sonundaki noktayı temizle (Örn: youtube.com. -> youtube.com)
                clean_domain = qname.rstrip('.')
                
                self.query_count[src_ip] += 1
                
                # Yeni özellik: Cihazın girdiği siteyi Traffic Monitor için veritabanına kaydet
                src_mac = packet.getlayer(Ether).src if packet.haslayer(Ether) else 'N/A'
                if clean_domain:
                    self.db.add_dns_log(src_ip, src_mac, clean_domain, record_type='DNS')
                
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
                
        # -------------------------------------------------------------
        # YENİ EKLENTİ: HTTP Host Header ve TLS SNI (HTTPS) Tespiti
        # DNS Önbelleğini veya Güvenli DNS'i (DoH) aşmak için doğrudan paketten okur.
        # -------------------------------------------------------------
        from scapy.all import TCP, Raw
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            if packet[TCP].dport == 80 or packet[TCP].dport == 443:
                src_ip = packet[IP].src
                src_mac = packet.getlayer(Ether).src if packet.haslayer(Ether) else 'N/A'
                try:
                    payload = packet[Raw].load
                    # HTTP Host Header kontrolü
                    if packet[TCP].dport == 80:
                        if payload.startswith(b"GET ") or payload.startswith(b"POST "):
                            lines = payload.split(b"\r\n")
                            for line in lines:
                                if line.lower().startswith(b"host:"):
                                    domain = line.split(b":", 1)[1].strip().decode('utf-8', errors='ignore')
                                    if domain:
                                        self.db.add_dns_log(src_ip, src_mac, domain, record_type='HTTP')
                                    return
                    # TLS SNI (HTTPS) kontrolü
                    elif packet[TCP].dport == 443:
                        # Client Hello paketi mi? (TLS Handshake 0x16, Type 0x01)
                        if len(payload) > 40 and payload[0] == 0x16 and payload[5] == 0x01:
                            import re
                            # Çok hızlı ve kaba bir TLS SNI ayıklayıcı (Regex heuristic)
                            strings = re.findall(rb'[a-z0-9.-]+\.[a-z]{2,6}', payload.lower())
                            for s in strings:
                                s_str = s.decode('utf-8', errors='ignore')
                                # Çöp verileri engellemek için sadece bilindik uzantıları kabul et
                                if s_str.endswith(('.com', '.net', '.org', '.tr', '.io', '.co', '.dev', '.info', '.gov', '.edu')):
                                    self.db.add_dns_log(src_ip, src_mac, s_str, record_type='HTTPS')
                                    return
                except Exception:
                    pass
        # -------------------------------------------------------------                
        # LLMNR Poisoning (Responder) Tespiti
        from scapy.all import UDP
        if packet.haslayer(UDP) and packet.haslayer(IP):
            if packet[UDP].sport == 5355 or packet[UDP].dport == 5355:
                src_ip = packet[IP].src
                # Eğer LLMNR cevabı ise (qr=1) genelde zehirlemedir
                if packet.haslayer(DNS) and packet[DNS].qr == 1:
                    self.db.add_alert(
                        alert_type='LLMNR Poisoning / MitM',
                        src_ip=src_ip, src_mac='N/A',
                        dst_ip=packet[IP].dst, dst_mac='N/A',
                        description=f'Kaynak {src_ip} sahte LLMNR (Responder) cevabı gönderiyor!',
                        severity='critical'
                    )
                    SoundAlert.alert_attack("LLMNR Zehirlenmesi")
                    if self.blocker and self.auto_ban:
                        self.blocker.block_ip(src_ip)
                
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
