# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Command and Control (C2) Beaconing Detector Modülü.
İç ağdaki bir cihazın, dışarıdaki bir komuta kontrol sunucusuna
düzenli aralıklarla (örneğin her 30 saniyede bir) sinyal gönderip
göndermediğini Zaman Serisi (Time-Series) analiziyle tespit eder.
"""

import time
from collections import defaultdict
import statistics
import ipaddress
from scapy.all import IP, TCP, UDP

class C2BeaconingDetector:
    def __init__(self, db, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        
        self.whitelist = [
            ipaddress.ip_network(n) for n in [
                '172.217.0.0/16', '142.250.0.0/15', '142.251.0.0/16', '173.194.0.0/16', '74.125.0.0/16', '216.58.0.0/16',
                '34.0.0.0/8', '35.0.0.0/8',
                '140.82.112.0/20', '185.199.108.0/22',
                '13.0.0.0/8', '20.0.0.0/8', '40.0.0.0/8', '52.0.0.0/8', '104.208.0.0/13',
                '104.16.0.0/12', '1.1.1.0/24',
                '54.0.0.0/8',
                '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12', '127.0.0.0/8',
                '8.8.8.8/32', '8.8.4.4/32', '1.1.1.1/32', '1.0.0.1/32'
            ]
        ]
        
        # Bağlantı zamanları: {(src, dst, dport): [timestamp1, timestamp2, ...]}
        self.conn_times = defaultdict(list)
        
        # Temizlik için son çalışma zamanı
        self.last_cleanup = time.time()
        
    def analyze(self, packet):
        if packet.haslayer(IP):
            # Yalnızca TCP veya UDP paketlerini incele
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                try:
                    src_addr = ipaddress.ip_address(src_ip)
                    dst_addr = ipaddress.ip_address(dst_ip)
                    if any(src_addr in net for net in self.whitelist) or any(dst_addr in net for net in self.whitelist):
                        return
                except ValueError:
                    pass
                
                if packet.haslayer(TCP):
                    dport = packet[TCP].dport
                else:
                    dport = packet[UDP].dport
                    
                key = (src_ip, dst_ip, dport)
                now = time.time()
                
                # Hafıza şişmesini önlemek için 60 saniyede bir eski verileri temizle
                if now - self.last_cleanup > 60:
                    self._cleanup(now)
                    
                times = self.conn_times[key]
                
                # Aynı saniye içindeki paket yığınlarını (burst/stream) tek bir olay say
                if not times or (now - times[-1] >= 1.0):
                    times.append(now)
                
                # İstatistiksel analiz için en az 5 bağlantı olayına ihtiyacımız var
                if len(times) >= 5:
                    # Bağlantılar arasındaki bekleme sürelerini hesapla (Inter-Arrival Time)
                    intervals = [times[i] - times[i-1] for i in range(1, len(times))]
                    
                    mean_interval = statistics.mean(intervals)
                    
                    # Eğer ortalama bekleme süresi 5 saniyeden büyük, 10 dakikadan küçükse (Tipik Beacon)
                    if 5.0 <= mean_interval <= 600.0:
                        stdev = statistics.stdev(intervals)
                        
                        # Standart sapma ortalamanın %20'sinden küçükse (Çok düzenli bir sinyal, örn: Jitter düşük)
                        if stdev < (mean_interval * 0.20):
                            self.db.add_alert(
                                alert_type='C2 Beaconing (Time-Series)',
                                src_ip=src_ip, src_mac=packet.src if hasattr(packet, 'src') else 'N/A',
                                dst_ip=dst_ip, dst_mac=packet.dst if hasattr(packet, 'dst') else 'N/A',
                                description=f'Düzenli dış bağlantı (C2 Beacon) saptandı! Hedef: {dst_ip}:{dport}, Aralık: ~{mean_interval:.1f}sn (Sapma: {stdev:.1f}sn)',
                                severity='critical'
                            )
                            if self.blocker and self.auto_ban:
                                self.blocker.block_ip(dst_ip)
                            
                            # Alarm spamını önlemek için geçmişi temizle
                            self.conn_times[key] = []
                            
                    # Liste boyutunu sabit tut
                    if len(self.conn_times[key]) > 8:
                        self.conn_times[key].pop(0)
                        
    def _cleanup(self, now):
        """10 dakikadan eski verileri hafızadan temizler."""
        keys_to_delete = []
        for k, v in self.conn_times.items():
            if v and (now - v[-1]) > 600:
                keys_to_delete.append(k)
        for k in keys_to_delete:
            del self.conn_times[k]
        self.last_cleanup = now
