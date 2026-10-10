# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Ağ Geçidi Modu (Gateway Mode) - Meşru IPS Satır İçi Koruma Yapılandırması.
Kali'yi ağ geçidi olarak yapılandırarak tüm trafiğin IPS üzerinden geçmesini sağlar.
Bu modül ARP Spoofing YAPMAZ - sadece Linux çekirdek yönlendirme ayarlarını yapar.

2 Mod:
  A) Manuel Mod: IP Forwarding + NAT Masquerading (cihazlarda elle gateway ayarı gerekir)
  B) Otomatik DHCP Modu: dnsmasq ile DHCP sunucusu çalıştırır, ağa bağlanan tüm cihazlara
     otomatik olarak Kali'nin IP'sini gateway olarak verir. Modemde DHCP kapatılmalıdır.
"""

import subprocess
import threading
import logging
import os
import time
import ipaddress
import tempfile
import re

from colorama import Fore, Style

logger = logging.getLogger("DSIPS_GatewayMode")

DNSMASQ_CONF_PATH = '/tmp/dsips_dnsmasq.conf'
DNSMASQ_PID_PATH = '/tmp/dsips_dnsmasq.pid'
DNSMASQ_LEASE_PATH = '/tmp/dsips_dnsmasq.leases'


class GatewayMode:
    def __init__(self, interface=None, db=None, dry_run=False):
        self.interface = interface or 'eth0'
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', self.interface):
            raise ValueError('Geçersiz ağ arayüzü')
        self.dry_run = dry_run
        self._owned_rules = []
        self._original_forwarding = None
        self._dhcp_dir = None
        self._lock = threading.RLock()
        self.db = db
        self.active = False
        self.dhcp_active = False
        self.local_ip = None
        self.subnet_mask = None
        self.network_prefix = None
        self.gateway_ip = None
        self.dhcp_process = None
        self._detect_network()

    def _detect_network(self):
        """Ağ arayüzü bilgilerini tespit eder."""
        try:
            result = subprocess.run(['ip', '-4', 'addr', 'show', self.interface], 
                                    capture_output=True, text=True)
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('inet '):
                    parts = line.split()
                    cidr = parts[1]  # örn: 192.168.1.50/24
                    self.local_ip = cidr.split('/')[0]
                    try:
                        net = ipaddress.IPv4Network(cidr, strict=False)
                        self.subnet_mask = str(net.netmask)
                        self.network_prefix = str(net.network_address)
                    except Exception:
                        self.subnet_mask = '255.255.255.0'
                    break
        except Exception:
            pass
        
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if 'default via' in line:
                    parts = line.split()
                    idx = parts.index('via') + 1
                    self.gateway_ip = parts[idx]
                    break
        except Exception:
            pass

    def enable(self):
        """Enable forwarding and remember exactly which state this instance owns."""
        if self.dry_run:
            return False
        with self._lock:
            if self.active:
                return True
            try:
                result = subprocess.run(['sysctl', '-n', 'net.ipv4.ip_forward'], capture_output=True, text=True, check=True, timeout=5)
                self._original_forwarding = result.stdout.strip()
                if self._original_forwarding not in {'0', '1'}:
                    raise ValueError('IP forwarding durumu okunamadı')
                subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], capture_output=True, check=True, timeout=5)
                rules = [
                    (['-t', 'nat'], ['POSTROUTING', '-o', self.interface, '-m', 'comment', '--comment', 'dsips-gateway', '-j', 'MASQUERADE']),
                    ([], ['FORWARD', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-m', 'comment', '--comment', 'dsips-gateway', '-j', 'ACCEPT']),
                    ([], ['FORWARD', '-i', self.interface, '-m', 'comment', '--comment', 'dsips-gateway', '-j', 'ACCEPT']),
                ]
                for table, rule in rules:
                    result = subprocess.run(['iptables', *table, '-C', *rule], capture_output=True, timeout=5)
                    if result.returncode == 1:
                        subprocess.run(['iptables', *table, '-A', *rule], capture_output=True, check=True, timeout=5)
                        self._owned_rules.append((table, rule))
                    elif result.returncode != 0:
                        raise subprocess.CalledProcessError(result.returncode, result.args)
                self.active = True
                return True
            except Exception:
                logger.exception('Ağ geçidi modu etkinleştirilemedi')
                self.disable()
                return False

    def disable(self):
        if self.dry_run:
            return False
        with self._lock:
            success = self.stop_dhcp()
            for table, rule in list(reversed(self._owned_rules)):
                try:
                    subprocess.run(['iptables', *table, '-D', *rule], capture_output=True, check=True, timeout=5)
                    self._owned_rules.remove((table, rule))
                except Exception:
                    success = False
                    logger.exception('Gateway firewall cleanup failed')
            if self._original_forwarding is not None:
                try:
                    subprocess.run(['sysctl', '-w', f'net.ipv4.ip_forward={self._original_forwarding}'], capture_output=True, check=True, timeout=5)
                    self._original_forwarding = None
                except Exception:
                    success = False
                    logger.exception('Unable to restore IP forwarding')
            if success:
                self.active = False
            return success

    # =============================================
    # DHCP Sunucusu (dnsmasq) - Otomatik Gateway
    # =============================================
    def _generate_dhcp_range(self):
        """Select one contiguous range in the detected subnet, excluding gateways."""
        if not self.local_ip or not self.subnet_mask:
            return None, None
        try:
            net = ipaddress.IPv4Network(f"{self.local_ip}/{self.subnet_mask}", strict=False)
            if net.prefixlen >= 31:
                return None, None
            low, high = int(net.network_address) + 1, int(net.broadcast_address) - 1
            excluded = sorted({int(ipaddress.IPv4Address(ip)) for ip in (self.local_ip, self.gateway_ip) if ip and ipaddress.IPv4Address(ip) in net})
            segments = []
            for boundary in excluded + [high + 1]:
                if low < boundary:
                    segments.append((low, boundary - 1))
                low = boundary + 1
            if not segments:
                return None, None
            start, end = max(segments, key=lambda pair: pair[1] - pair[0])
            start = max(start, end - 49)
            return str(ipaddress.IPv4Address(start)), str(ipaddress.IPv4Address(end))
        except ValueError:
            return None, None

    def start_dhcp(self):
        """dnsmasq ile DHCP sunucusu başlatır. 
        Ağa bağlanan cihazlara otomatik olarak Kali'yi gateway olarak verir.
        
        ÖNEMLİ: Modemde/router'da DHCP sunucusunun kapatılması önerilir,
        aksi halde çift DHCP çakışması yaşanabilir.
        """
        if self.dry_run or not self.active:
            return False
        if self.dhcp_active:
            print(f"{Fore.YELLOW}[!] DHCP sunucusu zaten çalışıyor.{Style.RESET_ALL}")
            return True
        
        if not self.local_ip:
            print(f"{Fore.RED}[!] Ağ IP adresi bulunamadı. DHCP başlatılamaz.{Style.RESET_ALL}")
            return False
        
        dhcp_start, dhcp_end = self._generate_dhcp_range()
        if not dhcp_start:
            print(f"{Fore.RED}[!] DHCP aralığı hesaplanamadı.{Style.RESET_ALL}")
            return False
        
        if self._dhcp_dir is None:
            self._dhcp_dir = tempfile.TemporaryDirectory(prefix='dsips-dhcp-')
        conf_path = os.path.join(self._dhcp_dir.name, 'dnsmasq.conf')
        pid_path = os.path.join(self._dhcp_dir.name, 'dnsmasq.pid')
        lease_path = os.path.join(self._dhcp_dir.name, 'dnsmasq.leases')

        # DNS olarak Google + Cloudflare kullan
        dns_servers = '8.8.8.8,1.1.1.1'
        
        # dnsmasq yapılandırma dosyası oluştur
        conf = f"""# DS-IPS Otomatik DHCP Sunucusu (dnsmasq)
# Bu dosya DS-IPS tarafından otomatik oluşturulmuştur.
# Modemde/router'da DHCP'yi kapatmanız önerilir.

interface={self.interface}
bind-interfaces

# DHCP aralığı ve kira süresi (2 saat)
dhcp-range={dhcp_start},{dhcp_end},{self.subnet_mask or '255.255.255.0'},2h

# Gateway olarak Kali'nin IP'sini ver (TÜM TRAFİK IPS ÜZERİNDEN GEÇER)
dhcp-option=3,{self.local_ip}

# DNS sunucuları
dhcp-option=6,{dns_servers}

# Lease dosyası
dhcp-leasefile={lease_path}

# PID dosyası
pid-file={pid_path}

# Sadece DHCP, DNS proxy değil
port=0

# Log
log-dhcp
log-facility=-
"""
        
        try:
            with open(conf_path, 'w') as f:
                f.write(conf)
            
            # dnsmasq'ı başlat
            self.dhcp_process = subprocess.Popen(
                ['dnsmasq', '-C', conf_path, '--no-daemon'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            time.sleep(0.5)
            
            if self.dhcp_process.poll() is not None:
                print(f"{Fore.RED}[!] dnsmasq başlatılamadı. Muhtemelen port çakışması var.{Style.RESET_ALL}")
                return False
            
            self.dhcp_active = True
            print(f"{Fore.GREEN}[+] 📡 DHCP Sunucusu AKTİF!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}    Aralık: {dhcp_start} - {dhcp_end}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}    Gateway: {self.local_ip} (Kali IPS){Style.RESET_ALL}")
            print(f"{Fore.GREEN}    DNS: {dns_servers}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[⚠️] Modemde DHCP'yi kapatmanız önerilir (çift DHCP çakışmasını önlemek için).{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[ℹ️] Cihazlarınız Wi-Fi'dan çıkıp tekrar bağlandığında otomatik olarak IPS üzerinden geçecek.{Style.RESET_ALL}")
            
            if self.db:
                self.db.add_alert(
                    alert_type="📡 DHCP Sunucusu Başlatıldı",
                    src_ip=self.local_ip or 'N/A', src_mac='N/A',
                    dst_ip='N/A', dst_mac='N/A',
                    description=f"DHCP otomatik gateway aktif. Aralık: {dhcp_start}-{dhcp_end}. Cihazlar Wi-Fi'a tekrar bağlandığında IPS koruması altına girer.",
                    severity='info'
                )
            
            return True
        except FileNotFoundError:
            print(f"{Fore.RED}[!] dnsmasq bulunamadı. Kurulum: sudo apt install dnsmasq{Style.RESET_ALL}")
            return False
        except Exception as e:
            logger.error(f"[!] DHCP sunucusu başlatılamadı: {e}")
            print(f"{Fore.RED}[!] DHCP hatası: {e}{Style.RESET_ALL}")
            return False

    def stop_dhcp(self):
        """Stop only the child process started by this instance."""
        try:
            if self.dhcp_process and self.dhcp_process.poll() is None:
                self.dhcp_process.terminate()
                try:
                    self.dhcp_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.dhcp_process.kill()
                    self.dhcp_process.wait(timeout=3)
            self.dhcp_process = None
            self.dhcp_active = False
            if self._dhcp_dir is not None:
                self._dhcp_dir.cleanup()
                self._dhcp_dir = None
            return True
        except Exception:
            logger.exception('DHCP durdurma hatası')
            return False

    def get_connected_devices(self):
        """DHCP lease dosyasından bağlı cihazları okur."""
        devices = []
        try:
            lease_path = os.path.join(self._dhcp_dir.name, 'dnsmasq.leases') if self._dhcp_dir else None
            if lease_path and os.path.exists(lease_path):
                with open(lease_path, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            devices.append({
                                'expire': parts[0],
                                'mac': parts[1],
                                'ip': parts[2],
                                'hostname': parts[3] if parts[3] != '*' else 'Bilinmiyor'
                            })
        except Exception:
            pass
        return devices

    def get_status(self):
        """Ağ geçidi modu durumunu döner."""
        try:
            result = subprocess.run(['sysctl', 'net.ipv4.ip_forward'], capture_output=True, text=True)
            forwarding = result.returncode == 0 and result.stdout.partition('=')[2].strip() == '1'
        except Exception:
            forwarding = False
        
        dhcp_start, dhcp_end = self._generate_dhcp_range()
        
        return {
            'active': self.active and forwarding,
            'dhcp_active': self.dhcp_active,
            'local_ip': self.local_ip,
            'gateway_ip': self.gateway_ip,
            'interface': self.interface,
            'ip_forwarding': forwarding,
            'dhcp_range': f'{dhcp_start} - {dhcp_end}' if dhcp_start else 'N/A',
            'connected_devices': self.get_connected_devices() if self.dhcp_active else [],
            'instructions': {
                'tr': f'Cihazlarınızın ağ ayarlarında Gateway (Ağ Geçidi) adresini {self.local_ip} olarak ayarlayın.',
                'iphone': f'Ayarlar → Wi-Fi → (i) → Yönlendirici/Router → {self.local_ip}',
                'android': f'Ayarlar → Wi-Fi → Ağı Düzenle → Gelişmiş → Gateway → {self.local_ip}',
                'windows': f'Ağ Ayarları → IPv4 → Varsayılan Ağ Geçidi → {self.local_ip}',
                'mac': f'Sistem Tercihleri → Ağ → Gelişmiş → TCP/IP → Yönlendirici → {self.local_ip}',
                'auto': 'DHCP sunucusu aktifleştirildiğinde cihazlar Wi-Fi\'dan çıkıp tekrar bağlandığında otomatik olarak IPS koruması altına girer.'
            }
        }
