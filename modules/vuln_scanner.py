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
        """Asıl Nmap taramasını yapan gizli fonksiyon."""
        try:
            # -F: Hızlı tarama (Top 100 port), --open: Sadece açıkları göster
            cmd = f"nmap -F --open -n -T4 {ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            output = result.stdout
            open_ports = []
            
            # Nmap çıktısını analiz et
            for line in output.split('\n'):
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0].strip()
                    open_ports.append(port)
                    
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
