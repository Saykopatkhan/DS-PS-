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
from scapy.all import DNS, DNSQR, DNSRR, IP, Ether, TCP, UDP, Raw, sendp
from core.database import Database
from utils.sound import SoundAlert


class DNSDetector:
    def __init__(self, db: Database, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.query_count = defaultdict(int)
        self.detection_window = 10.0
        self.query_threshold = 100
        self.max_subdomain_len = 50
        self.last_reset = time.time()
        self.dns_sinkhole = None

    def analyze(self, packet):
        self._reset_window()
        if not packet.haslayer(IP):
            return
        src_ip = packet[IP].src
        src_mac = packet[Ether].src if packet.haslayer(Ether) else 'N/A'
        if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet[DNS].qr == 0:
            raw_name = packet[DNSQR].qname
            qname = raw_name.decode('ascii', errors='ignore') if isinstance(raw_name, bytes) else str(raw_name)
            domain = qname.rstrip('.').lower()
            if len(self.query_count) >= 10000 and src_ip not in self.query_count:
                self.query_count.pop(next(iter(self.query_count)))
            self.query_count[src_ip] += 1
            if domain:
                self.db.add_dns_log(src_ip, src_mac, domain, record_type='DNS')
                blocked = self.dns_sinkhole.is_blocked(domain) if self.dns_sinkhole else False
                if blocked:
                    self._trigger_sinkhole(src_ip, domain, packet)
                if len(domain.split('.')) > 2 and len(domain.split('.')[0]) > self.max_subdomain_len:
                    self._detect_tunneling(src_ip, domain)
            self._check_flood(src_ip)
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            port = packet[TCP].dport
            payload = bytes(packet[Raw].load)
            domain = None
            if port == 80:
                # Read only request headers, never arbitrary response/body text.
                first_line = payload.split(b'\r\n', 1)[0]
                if first_line.split(b' ', 1)[0] in {b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'OPTIONS', b'PATCH', b'CONNECT'}:
                    for line in payload.split(b'\r\n\r\n', 1)[0].split(b'\r\n')[1:]:
                        if line.lower().startswith(b'host:'):
                            domain = line.split(b':', 1)[1].strip().decode('ascii', errors='ignore')
                            break
            elif port == 443:
                domain = self._tls_sni(payload)
            if domain:
                self.db.add_dns_log(src_ip, src_mac, domain, record_type='HTTP' if port == 80 else 'HTTPS')

    @staticmethod
    def _tls_sni(payload):
        """Extract SNI from one complete TLS ClientHello, with bounds checks.

        Fragmented hellos are left to stream reassembly rather than guessed from
        random strings in encrypted/binary records.
        """
        try:
            if len(payload) < 9 or payload[0] != 22 or payload[5] != 1:
                return None
            record_end = 5 + int.from_bytes(payload[3:5], 'big')
            hello_end = 9 + int.from_bytes(payload[6:9], 'big')
            if record_end > len(payload) or hello_end > record_end:
                return None
            data = payload[9:hello_end]
            if len(data) < 35:
                return None
            offset = 35 + data[34]
            if offset + 2 > len(data):
                return None
            offset += 2 + int.from_bytes(data[offset:offset + 2], 'big')
            if offset >= len(data):
                return None
            offset += 1 + data[offset]
            if offset + 2 > len(data):
                return None
            end = offset + 2 + int.from_bytes(data[offset:offset + 2], 'big')
            offset += 2
            if end > len(data):
                return None
            while offset + 4 <= end:
                kind = int.from_bytes(data[offset:offset + 2], 'big')
                length = int.from_bytes(data[offset + 2:offset + 4], 'big')
                offset += 4
                extension = data[offset:offset + length]
                if offset + length > end:
                    return None
                offset += length
                if kind != 0 or len(extension) < 5:
                    continue
                list_end = 2 + int.from_bytes(extension[:2], 'big')
                cursor = 2
                if list_end != len(extension):
                    return None
                while cursor + 3 <= list_end:
                    name_type = extension[cursor]
                    name_len = int.from_bytes(extension[cursor + 1:cursor + 3], 'big')
                    cursor += 3
                    if cursor + name_len > list_end:
                        return None
                    name = extension[cursor:cursor + name_len]
                    cursor += name_len
                    if name_type == 0:
                        return name.decode('ascii').lower()
        except (IndexError, UnicodeError, TypeError, ValueError):
            return None
        return None

    def _trigger_sinkhole(self, src_ip, domain, packet):
        redirected = False
        active = self.auto_ban and self.blocker and not getattr(self.blocker, 'dry_run', False)
        portal = self.dns_sinkhole
        if (active and portal and not portal.dry_run and packet.haslayer(UDP)
                and packet.haslayer(Ether) and packet[DNSQR].qtype == 1):
            import ipaddress
            try:
                target = ipaddress.ip_address(portal.sinkhole_ip)
                if target.version == 4 and not target.is_loopback and not target.is_unspecified:
                    reply = (Ether(dst=packet[Ether].src, src=packet[Ether].dst)
                             / IP(dst=src_ip, src=packet[IP].dst)
                             / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
                             / DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                   an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=str(target))))
                    sendp(reply, verbose=False, iface=getattr(portal, 'interface', None))
                    redirected = True
            except (OSError, ValueError):
                pass
        self.db.add_alert(
            alert_type='DNS Sinkhole (Zararlı Site Engeli)', src_ip=src_ip, src_mac='N/A',
            dst_ip='N/A', dst_mac='N/A',
            description=f'Kaynak {src_ip} engel listesindeki alanı sorguladı: {domain}. '
                        + ('Yönlendirme yapıldı.' if redirected else 'Pasif tespit; yönlendirme yapılmadı.'),
            severity='high')
        SoundAlert.alert_attack('DNS Sinkhole')

    def _detect_tunneling(self, src_ip, domain):
        self.db.add_alert(
            alert_type='DNS Tunneling / Exfiltration', src_ip=src_ip, src_mac='N/A',
            dst_ip='N/A', dst_mac='N/A',
            description=f'Kaynak {src_ip} anormal uzunlukta DNS sorgusu yaptı: {domain}', severity='critical')
        SoundAlert.alert_attack('DNS Tünelleme')

    def _check_flood(self, src_ip):
        if self.query_count[src_ip] > self.query_threshold:
            self.db.add_alert(
                alert_type='DNS Flood', src_ip=src_ip, src_mac='N/A', dst_ip='N/A', dst_mac='N/A',
                description=f'Kaynak {src_ip} {self.detection_window}s içinde {self.query_count[src_ip]} DNS sorgusu yaptı',
                severity='high')
            SoundAlert.alert_attack('DNS Flood')
            self.query_count[src_ip] = 0

    def _reset_window(self):
        now = time.time()
        if now - self.last_reset > self.detection_window:
            self.query_count.clear()
            self.last_reset = now
