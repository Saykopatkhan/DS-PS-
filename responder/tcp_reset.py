# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
TCP RST Injection (Aktif Oturum Koparma) Modülü v2.0
Gerçek aktif TCP oturumlarını tespit edip RST paketleri ile koparır.
- ss (socket statistics) ile aktif bağlantı keşfi
- conntrack ile bağlantı durumu izleme
- Çift yönlü RST enjeksiyonu
"""

import subprocess
import logging
import re

logger = logging.getLogger("DSIPS_TCPReset")

class TCPResetEngine:
    def __init__(self, interface=None, db=None):
        self.interface = interface
        self.db = db
        self._scapy_available = False
        try:
            from scapy.all import IP, TCP, send
            self._scapy_available = True
        except ImportError:
            logger.warning("[!] Scapy bulunamadı. TCP RST devre dışı.")

    def _find_active_sessions(self, target_ip):
        """
        ss (socket statistics) ve conntrack kullanarak hedef IP ile olan
        tüm aktif TCP oturumlarını bulur.
        Returns: [(local_ip, local_port, remote_ip, remote_port), ...]
        """
        sessions = []
        
        # Yöntem 1: ss komutu ile aktif TCP bağlantılarını bul
        try:
            result = subprocess.run(
                ['ss', '-tnp', 'state', 'established'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if target_ip in line:
                    # ss çıktı formatı: ESTAB 0 0 local_ip:port peer_ip:port
                    parts = line.split()
                    if len(parts) >= 5:
                        try:
                            local = parts[3]
                            remote = parts[4]
                            local_ip, local_port = local.rsplit(':', 1)
                            remote_ip, remote_port = remote.rsplit(':', 1)
                            # IPv6 mapped IPv4 temizle
                            local_ip = local_ip.replace('::ffff:', '').strip('[]')
                            remote_ip = remote_ip.replace('::ffff:', '').strip('[]')
                            if target_ip in remote_ip or target_ip in local_ip:
                                sessions.append((local_ip, int(local_port), remote_ip, int(remote_port)))
                        except (ValueError, IndexError):
                            continue
        except Exception as e:
            logger.debug(f"ss sorgusu hatası: {e}")

        # Yöntem 2: conntrack ile NAT/FORWARD edilen bağlantıları da bul
        try:
            result = subprocess.run(
                ['conntrack', '-L', '-p', 'tcp', '--state', 'ESTABLISHED'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if target_ip in line:
                    # conntrack formatı: tcp 6 431999 ESTABLISHED src=X dst=Y sport=A dport=B ...
                    src_match = re.search(r'src=(\S+)', line)
                    dst_match = re.search(r'dst=(\S+)', line)
                    sport_match = re.search(r'sport=(\d+)', line)
                    dport_match = re.search(r'dport=(\d+)', line)
                    if all([src_match, dst_match, sport_match, dport_match]):
                        src = src_match.group(1)
                        dst = dst_match.group(1)
                        sport = int(sport_match.group(1))
                        dport = int(dport_match.group(1))
                        if target_ip == src or target_ip == dst:
                            sess = (dst, dport, src, sport) if target_ip == src else (src, sport, dst, dport)
                            if sess not in sessions:
                                sessions.append(sess)
        except FileNotFoundError:
            pass  # conntrack yüklü değilse atla
        except Exception as e:
            logger.debug(f"conntrack sorgusu hatası: {e}")

        # Oturum bulunamadıysa yaygın portlara fallback
        if not sessions:
            common_ports = [22, 23, 25, 53, 80, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 4444, 5555]
            for p in common_ports:
                sessions.append(('0.0.0.0', p, target_ip, p))
            logger.info(f"[*] {target_ip} için aktif oturum bulunamadı, yaygın portlara RST gönderiliyor.")
        else:
            logger.info(f"[+] {target_ip} ile {len(sessions)} aktif TCP oturumu bulundu.")

        return sessions

    def kill_session(self, src_ip, dst_ip=None, src_port=None, dst_port=None):
        """
        Saldırgan IP ile olan tüm aktif TCP oturumlarını RST injection ile koparır.
        """
        if not self._scapy_available:
            logger.error("[!] Scapy yüklü değil, RST gönderilemez.")
            return False
            
        try:
            from scapy.all import IP, TCP, send
            import random
            
            # Aktif oturumları bul
            sessions = self._find_active_sessions(src_ip)
            
            count = 0
            for local_ip, local_port, remote_ip, remote_port in sessions:
                try:
                    # Birden fazla SEQ numarası ile gönder (doğru SEQ yakalamak için)
                    for seq_offset in range(0, 2_000_000_000, 500_000_000):
                        seq = seq_offset + random.randint(0, 500_000_000)
                        
                        # Saldırgana RST gönder
                        pkt_to_attacker = IP(dst=remote_ip) / TCP(
                            sport=local_port, dport=remote_port,
                            flags="R", seq=seq
                        )
                        send(pkt_to_attacker, verbose=False, iface=self.interface)
                        
                        # Kurbana (lokal tarafa) da RST gönder
                        if local_ip and local_ip != '0.0.0.0':
                            pkt_to_local = IP(dst=local_ip) / TCP(
                                sport=remote_port, dport=local_port,
                                flags="R", seq=seq
                            )
                            send(pkt_to_local, verbose=False, iface=self.interface)
                    
                    count += 1
                except Exception as e:
                    logger.debug(f"RST gönderme hatası ({remote_ip}:{remote_port}): {e}")
                    continue
            
            # conntrack ile bağlantı kaydını da sil
            try:
                subprocess.run(
                    ['conntrack', '-D', '-s', src_ip],
                    capture_output=True, timeout=5
                )
            except Exception:
                pass

            logger.info(f"[⚡] IP {src_ip} - {count} TCP oturumu RST ile koparıldı.")
            
            if self.db:
                self.db.add_alert(
                    alert_type="⚡ TCP RST Active Session Killer",
                    src_ip=src_ip, src_mac="N/A", dst_ip="N/A", dst_mac="N/A",
                    description=f"Saldırgan {src_ip} cihazının {count} aktif TCP oturumu RST paketleri ile koparıldı.",
                    severity="critical"
                )
            return True
        except Exception as e:
            logger.error(f"[!] TCP RST injection hatası: {e}")
            return False
