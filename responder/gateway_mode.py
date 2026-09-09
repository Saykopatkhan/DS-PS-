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
import signal
import ipaddress

from colorama import Fore, Style

logger = logging.getLogger("DSIPS_GatewayMode")

DNSMASQ_CONF_PATH = '/tmp/dsips_dnsmasq.conf'
DNSMASQ_PID_PATH = '/tmp/dsips_dnsmasq.pid'
DNSMASQ_LEASE_PATH = '/tmp/dsips_dnsmasq.leases'


class GatewayMode:
    def __init__(self, interface=None, db=None):
        self.interface = interface or 'eth0'
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
        """Ağ geçidi modunu etkinleştirir (IP Forwarding + NAT Masquerading)."""
        try:
            # 1. IP Forwarding aç
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                          capture_output=True, check=True)
            
            # 2. NAT Masquerading kur
            check = subprocess.run(
                ['iptables', '-t', 'nat', '-C', 'POSTROUTING', '-o', self.interface, '-j', 'MASQUERADE'],
                capture_output=True
            )
            if check.returncode != 0:
                subprocess.run(
                    ['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', self.interface, '-j', 'MASQUERADE'],
                    check=True, capture_output=True
                )
            
            # 3. FORWARD zincirinde bağlantı izleme
            check2 = subprocess.run(
                ['iptables', '-C', 'FORWARD', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
                capture_output=True
            )
            if check2.returncode != 0:
                subprocess.run(
                    ['iptables', '-A', 'FORWARD', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
                    check=True, capture_output=True
                )
            
            # 4. FORWARD zincirinde gelen trafiği kabul et
            check3 = subprocess.run(
                ['iptables', '-C', 'FORWARD', '-i', self.interface, '-j', 'ACCEPT'],
                capture_output=True
            )
            if check3.returncode != 0:
                subprocess.run(
                    ['iptables', '-A', 'FORWARD', '-i', self.interface, '-j', 'ACCEPT'],
                    check=True, capture_output=True
                )
            
            self.active = True
            print(f"{Fore.GREEN}[+] 🌐 Ağ Geçidi Modu AKTİF - IP Forwarding + NAT Masquerading kuruldu.{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[ℹ️] Kali Gateway IP: {self.local_ip}{Style.RESET_ALL}")
            
            if self.db:
                self.db.add_alert(
                    alert_type="🌐 Ağ Geçidi Modu Etkinleştirildi",
                    src_ip=self.local_ip or 'N/A', src_mac='N/A',
                    dst_ip='N/A', dst_mac='N/A',
                    description=f"IPS Ağ Geçidi Modu aktif. Gateway: {self.local_ip}",
                    severity='info'
                )
            
            return True
        except Exception as e:
            logger.error(f"[!] Ağ geçidi modu etkinleştirilemedi: {e}")
            print(f"{Fore.RED}[!] Ağ Geçidi Modu hatası: {e}{Style.RESET_ALL}")
            return False

    def disable(self):
        """Ağ geçidi modunu devre dışı bırakır."""
        try:
            # Önce DHCP'yi kapat
            if self.dhcp_active:
                self.stop_dhcp()
            
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], 
                          capture_output=True)
            subprocess.run(
                ['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-o', self.interface, '-j', 'MASQUERADE'],
                capture_output=True
            )
            self.active = False
            print(f"{Fore.YELLOW}[-] Ağ Geçidi Modu devre dışı bırakıldı.{Style.RESET_ALL}")
            return True
        except Exception as e:
            logger.error(f"[!] Ağ geçidi kapatma hatası: {e}")
            return False

    # =============================================
    # DHCP Sunucusu (dnsmasq) - Otomatik Gateway
    # =============================================
    def _generate_dhcp_range(self):
        """Ağ alt ağına göre DHCP dağıtım aralığı hesaplar.
        Kali IP'si ve gerçek gateway IP'si aralık dışında bırakılır."""
        if not self.local_ip:
            return None, None
        try:
            net = ipaddress.IPv4Network(f"{self.local_ip}/24", strict=False)
            hosts = list(net.hosts())
            
            # Kali IP ve gateway IP'yi çıkar
            exclude = set()
            if self.local_ip:
                exclude.add(ipaddress.IPv4Address(self.local_ip))
            if self.gateway_ip:
                exclude.add(ipaddress.IPv4Address(self.gateway_ip))
            
            available = [h for h in hosts if h not in exclude]
            if len(available) < 10:
                return None, None
            
            # Aralığı ortadan başlat (çakışma riski düşük)
            mid = len(available) // 2
            start = available[mid]
            end = available[min(mid + 50, len(available) - 1)]
            return str(start), str(end)
        except Exception:
            return None, None

    def start_dhcp(self):
        """dnsmasq ile DHCP sunucusu başlatır. 
        Ağa bağlanan cihazlara otomatik olarak Kali'yi gateway olarak verir.
        
        ÖNEMLİ: Modemde/router'da DHCP sunucusunun kapatılması önerilir,
        aksi halde çift DHCP çakışması yaşanabilir.
        """
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
dhcp-leasefile={DNSMASQ_LEASE_PATH}

# PID dosyası
pid-file={DNSMASQ_PID_PATH}

# Sadece DHCP, DNS proxy değil
port=0

# Log
log-dhcp
log-facility=/tmp/dsips_dnsmasq.log
"""
        
        try:
            with open(DNSMASQ_CONF_PATH, 'w') as f:
                f.write(conf)
            
            # Varsa eski dnsmasq DS-IPS sürecini öldür
            self._kill_existing_dnsmasq()
            
            # dnsmasq'ı başlat
            self.dhcp_process = subprocess.Popen(
                ['dnsmasq', '-C', DNSMASQ_CONF_PATH, '--no-daemon'],
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
        """DHCP sunucusunu durdurur."""
        try:
            if self.dhcp_process and self.dhcp_process.poll() is None:
                self.dhcp_process.terminate()
                self.dhcp_process.wait(timeout=3)
            
            self._kill_existing_dnsmasq()
            
            # Geçici dosyaları temizle
            for f in [DNSMASQ_CONF_PATH, DNSMASQ_PID_PATH]:
                try:
                    os.remove(f)
                except FileNotFoundError:
                    pass
            
            self.dhcp_active = False
            print(f"{Fore.YELLOW}[-] 📡 DHCP Sunucusu durduruldu.{Style.RESET_ALL}")
            return True
        except Exception as e:
            logger.error(f"[!] DHCP durdurma hatası: {e}")
            return False

    def _kill_existing_dnsmasq(self):
        """DS-IPS'e ait dnsmasq süreçlerini öldürür."""
        try:
            if os.path.exists(DNSMASQ_PID_PATH):
                with open(DNSMASQ_PID_PATH, 'r') as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.3)
        except (ProcessLookupError, ValueError, FileNotFoundError):
            pass
        # Fallback: tüm dsips config kullanan dnsmasq'ları öldür
        subprocess.run(['pkill', '-f', DNSMASQ_CONF_PATH], capture_output=True)

    def get_connected_devices(self):
        """DHCP lease dosyasından bağlı cihazları okur."""
        devices = []
        try:
            if os.path.exists(DNSMASQ_LEASE_PATH):
                with open(DNSMASQ_LEASE_PATH, 'r') as f:
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
            forwarding = '1' in result.stdout
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
