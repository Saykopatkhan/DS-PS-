# ========================================================================
# DS-IPS (Premium SOC Edition)
# Kullanıcı Davranış Analizi (UEBA - User and Entity Behavior Analytics)
# ========================================================================

from scapy.all import IP, TCP, UDP
from collections import defaultdict
import time
import threading

class UEBADetector:
    """
    Ağdaki cihazların hangi portlara bağlandığını öğrenerek profil çıkarır.
    Öğrenme aşamasından sonra bir cihaz daha önce hiç gitmediği kritik bir porta
    (Örn: 22 SSH, 3389 RDP) gitmeye çalışırsa Anomali (Davranış Sapması) alarmı verir.
    """
    def __init__(self, db, blocker=None, auto_ban=False):
        self._lock = threading.RLock()
        self.last_seen = {}
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        
        # Her IP'nin bağlandığı portları tutar
        self.learned_ports = defaultdict(set)
        # Her IP'nin yaptığı toplam bağlantı sayısını tutar (Öğrenme süreci için)
        self.connection_counts = defaultdict(int)
        
        # Öğrenme Modu Paketi Eşiği (İlk X paket normal sayılır ve profile eklenir)
        self.learning_threshold = 50
        
        # Sadece bu hassas portlarda sapma olursa alarm verilir
        self.sensitive_ports = {
            22: 'SSH (Uzaktan Erişim)',
            23: 'Telnet (Şifresiz Erişim)',
            3389: 'RDP (Uzak Masaüstü)',
            445: 'SMB (Dosya Paylaşımı)',
            1433: 'MSSQL (Veritabanı)',
            3306: 'MySQL (Veritabanı)',
            21: 'FTP (Dosya Transferi)'
        }
        
        # Bir IP için aynı alarmı sürekli vermemek için cooldown mekanizması
        self.last_alarm_time = defaultdict(float)

    def get_profiles(self):
        with self._lock:
            return {ip: {'learned_ports': sorted(ports), 'total_connections': self.connection_counts[ip],
                         'learning': self.connection_counts[ip] <= self.learning_threshold}
                    for ip, ports in self.learned_ports.items()}

    def analyze(self, packet):
        with self._lock:
            self._analyze(packet)

    def _analyze(self, packet):
        """TCP ve UDP paketlerini analiz edip port profili çıkarır."""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_port = None
            proto = ""
            
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                proto = "TCP"
            elif packet.haslayer(UDP):
                dst_port = packet[UDP].dport
                proto = "UDP"
                
            if dst_port:
                # Use connection starts; ACK/data packets must not exhaust learning.
                if proto == 'TCP' and not (int(packet[TCP].flags) & 2 and not int(packet[TCP].flags) & 16):
                    return
                if src_ip not in self.last_seen and len(self.last_seen) >= 10000:
                    oldest = min(self.last_seen, key=self.last_seen.get)
                    self.last_seen.pop(oldest, None)
                    self.learned_ports.pop(oldest, None)
                    self.connection_counts.pop(oldest, None)
                    self.last_alarm_time.pop(oldest, None)
                self.last_seen[src_ip] = time.time()
                # Toplam bağlantı sayısını artır
                self.connection_counts[src_ip] += 1
                
                # Eğer cihaz hala Öğrenme Modundaysa (Learning Phase)
                if self.connection_counts[src_ip] <= self.learning_threshold:
                    self.learned_ports[src_ip].add(dst_port)
                else:
                    # Öğrenme Modu bitti. Bu port daha önce görülmüş mü?
                    if dst_port not in self.learned_ports[src_ip]:
                        # Yeni bir port. Peki bu port HASSAS (Kritik) bir port mu?
                        if dst_port in self.sensitive_ports:
                            current_time = time.time()
                            # Aynı cihaz için her 10 saniyede en fazla 1 alarm ver
                            if current_time - self.last_alarm_time[src_ip] > 10:
                                self._trigger_ueba_alarm(src_ip, dst_port, proto, packet)
                                self.last_alarm_time[src_ip] = current_time
                                
                        # Portu profile ekle (sürekli alarm vermesin)
                        if dst_port not in self.sensitive_ports or current_time - self.last_alarm_time[src_ip] == 0:
                            self.learned_ports[src_ip].add(dst_port)

    def _trigger_ueba_alarm(self, src_ip, dst_port, proto, packet):
        dst_ip = packet[IP].dst
        port_desc = self.sensitive_ports[dst_port]
        desc = f"Davranış Sapması (UEBA): Cihaz daha önce hiç kullanmadığı KRİTİK bir porta ({proto} {dst_port} - {port_desc}) erişmeye çalışıyor!"
        
        self.db.add_alert(
            alert_type='UEBA Anomaly (Davranış Sapması)',
            src_ip=src_ip, src_mac='N/A',
            dst_ip=dst_ip, dst_mac='N/A',
            description=desc,
            severity='high'
        )
        
        if self.blocker and self.auto_ban:
            self.blocker.block_ip(src_ip)
