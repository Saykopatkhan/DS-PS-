# ========================================================================
# DS-IPS (Premium SOC Edition)
# Otonom Zafiyet Tarayıcı (Auto-Vuln Scanner)
# ========================================================================

import threading
import subprocess
import ipaddress

class VulnScanner:
    """
    Ağa yeni katılan cihazları algıladığında arkaplanda Nmap zafiyet taraması yapar.
    Açık kritik portlar bulunursa sisteme alarm düşer.
    """
    def __init__(self, db, dry_run=False):
        self.db = db
        self.dry_run = dry_run
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(2)
        self._threads = set()
        # Daha önce taradığımız cihazları hafızada tutalım ki sürekli taramasın
        self.scanned_ips = set()
        
        # Tehlikeli ve kritik kabul edilen açık portlar
        self.critical_ports = {
            '21': 'FTP (Şifresiz Dosya Transferi)',
            '22': 'SSH (Uzaktan Erişim)',
            '23': 'Telnet (Şifresiz Uzaktan Erişim)',
            '3389': 'RDP (Uzak Masaüstü)',
            '445': 'SMB (Dosya Paylaşımı / WannaCry Zafiyeti)',
            '1433': 'MSSQL (Veritabanı)',
            '3306': 'MySQL (Veritabanı)'
        }

    def scan_ip_async(self, ip, mac='N/A'):
        if self.dry_run or self._stop_event.is_set():
            return False
        try:
            address = ipaddress.IPv4Address(ip)
        except (ValueError, TypeError):
            return False
        if address.is_loopback or address.is_multicast or address.is_unspecified or str(address) == '255.255.255.255':
            return False
        ip = str(address)
        with self._lock:
            if ip in self.scanned_ips or not self._slots.acquire(blocking=False):
                return False
            if len(self.scanned_ips) >= 10000:
                self.scanned_ips.pop()
            self.scanned_ips.add(ip)
            thread = threading.Thread(target=self._scan_worker, args=(ip, mac), daemon=True)
            self._threads.add(thread)
            thread.start()
        return True

    def _scan_worker(self, ip, mac):
        try:
            self._run_nmap_scan(ip, mac)
        finally:
            with self._lock:
                self._threads.discard(threading.current_thread())
            self._slots.release()

    def start(self):
        self._stop_event.clear()

    def stop(self):
        self._stop_event.set()
        with self._lock:
            threads = list(self._threads)
        for thread in threads:
            thread.join(timeout=1)

    def _run_nmap_scan(self, ip, mac):
        """Python socket ile hızlı port taraması yapar (Nmap yetki sorunu yaşamamak için)."""
        try:
            import socket
            ip = str(ipaddress.IPv4Address(ip))
            if self.dry_run or self._stop_event.is_set():
                return
                
            open_ports = []
            
            # En çok kullanılan kritik 100 portu (hızlı tarama) veya en azından belirlediğimiz kritik portları tara
            target_ports = list(self.critical_ports.keys())
            # Biraz daha genel portlar ekleyelim
            common_ports = ['80', '443', '8080', '8443', '53', '25', '110', '143', '993', '995', '5000', '3306', '5432', '21', '22', '23', '3389', '445', '1433']
            for p in common_ports:
                if p not in target_ports:
                    target_ports.append(p)
            
            for port_str in target_ports:
                port = int(port_str)
                if self._stop_event.is_set():
                    return
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.settimeout(0.3)
                    result = client.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port_str)

                    
            # Kritik portlardan herhangi biri açık mı?
            found_criticals = []
            for port in open_ports:
                if port in self.critical_ports:
                    found_criticals.append(f"Port {port} ({self.critical_ports[port]})")
                    
            if found_criticals:
                desc = "Port Taraması: İncelenmesi gereken ağ servisleri bulundu (zafiyet doğrulanmadı).\n"
                desc += "Açık Kapılar: " + ", ".join(found_criticals)
                
                self.db.add_alert(
                    alert_type='Port Scanner (Açık Servisler)',
                    src_ip=ip, src_mac=mac,
                    dst_ip='System', dst_mac='N/A',
                    description=desc,
                    severity='warning'
                )
            else:
                desc = "Port Taraması: Seçili portlarda bağlantı kontrolü tamamlandı; zafiyet analizi yapılmadı."
                if open_ports:
                    desc += f" (Açık Portlar: {', '.join(open_ports)})"
                else:
                    desc += " (Seçili portlara bağlantı kurulamadı; kapalı veya filtrelenmiş olabilir)"
                    
                self.db.add_alert(
                    alert_type='Port Scanner (Tamamlandı)',
                    src_ip=ip, src_mac=mac,
                    dst_ip='System', dst_mac='N/A',
                    description=desc,
                    severity='info'
                )
        except subprocess.TimeoutExpired:
            # Tarama çok uzun sürdüyse iptal et (ağı yormamak için)
            pass
        except Exception as e:
            print(f"Vuln Scanner Error: {e}")
