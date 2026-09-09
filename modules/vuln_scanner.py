# ========================================================================
# DS-IPS (Premium SOC Edition)
# Otonom Zafiyet Tarayıcı (Auto-Vuln Scanner)
# ========================================================================

import threading
import subprocess
import time

class VulnScanner:
    """
    Ağa yeni katılan cihazları algıladığında arkaplanda Nmap zafiyet taraması yapar.
    Açık kritik portlar bulunursa sisteme alarm düşer.
    """
    def __init__(self, db):
        self.db = db
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

    def scan_ip_async(self, ip, mac):
        """IP adresini arkaplanda thread olarak tarar."""
        if ip in self.scanned_ips or ip == 'N/A' or ip == '127.0.0.1':
            return
            
        self.scanned_ips.add(ip)
        thread = threading.Thread(target=self._run_nmap_scan, args=(ip, mac))
        thread.daemon = True
        thread.start()

    def _run_nmap_scan(self, ip, mac):
        """Python socket ile hızlı port taraması yapar (Nmap yetki sorunu yaşamamak için)."""
        try:
            import re
            import socket
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                print(f"Vuln Scanner Warning: Invalid IP format {ip}")
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
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)  # Hızlı timeout
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port_str)
                s.close()

                    
            # Kritik portlardan herhangi biri açık mı?
            found_criticals = []
            for port in open_ports:
                if port in self.critical_ports:
                    found_criticals.append(f"Port {port} ({self.critical_ports[port]})")
                    
            if found_criticals:
                desc = "Otonom Tarama: Cihazda KRİTİK açık portlar tespit edildi!\n"
                desc += "Açık Kapılar: " + ", ".join(found_criticals)
                
                self.db.add_alert(
                    alert_type='Auto-Vuln Scanner (Zafiyet)',
                    src_ip=ip, src_mac=mac,
                    dst_ip='System', dst_mac='N/A',
                    description=desc,
                    severity='high'
                )
            else:
                desc = "Otonom Tarama: Cihaz tarandı, kritik bir zafiyet bulunamadı."
                if open_ports:
                    desc += f" (Açık Portlar: {', '.join(open_ports)})"
                else:
                    desc += " (Tüm portlar kapalı/güvenli)"
                    
                self.db.add_alert(
                    alert_type='Auto-Vuln Scanner (Güvenli)',
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
