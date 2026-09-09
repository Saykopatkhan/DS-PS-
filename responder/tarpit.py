# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
TCP Tarpit (Kaynak Tüketim Tuzağı) Modülü.
Saldırganların tarama ve DoS isteklerini aşırı yavaş yanıtlayarak
bağlantı ve thread kaynaklarını kilitler.
"""

import socket
import threading
import subprocess
import time
import logging
import ipaddress

logger = logging.getLogger("DSIPS_Tarpit")

MAX_TARPIT_IPS = 100
MAX_CONNECTIONS = 500

class TCPTarpit:
    def __init__(self, port=9999, db=None, blocker=None):
        self.port = port
        self.db = db
        self.blocker = blocker
        self.running = False
        self.server_socket = None
        self.trapped_ips = set()
        self.total_trapped_connections = 0
        self.lock = threading.Lock()

    def start(self):
        """Tarpit dinleme soketini ve arka plan thread'ini başlatır."""
        self.running = True
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(100)
            
            t = threading.Thread(target=self._listen_loop, daemon=True)
            t.start()
            logger.info(f"[+] TCP Tarpit daemon port {self.port} üzerinde aktif.")
        except Exception as e:
            logger.error(f"[!] TCP Tarpit başlatılamadı: {e}")

    def _listen_loop(self):
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                conn, addr = self.server_socket.accept()
                ip = addr[0]
                
                with self.lock:
                    if self.total_trapped_connections >= MAX_CONNECTIONS:
                        conn.close()
                        continue
                    
                    self.trapped_ips.add(ip)
                    self.total_trapped_connections += 1
                
                # Her istemciyi ayrı bir kilitçi thread'de yavaşlat
                t = threading.Thread(target=self._tarpit_client, args=(conn, ip), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.debug(f"Tarpit listen error: {e}")
                break

    def _tarpit_client(self, conn, ip):
        """Saldırgan bağlantısını açıp aşırı yavaş veri göndererek soketini kilitler."""
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
            # QA testi ve gerçek tarpit senaryosu için ilk byte'ı göndermeden önce mutlaka beklet!
            time.sleep(2)
            # Pencere boyutunu en aza indir (Zero-Window Trap)
            while self.running:
                # 3 saniyede 1 tek bayt gönder (Mobil Keep-Alive kandırmacası)
                conn.send(b"\x00")
                time.sleep(3)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def tarpit_ip(self, ip):
        """Saldırgan IP adresinin tüm TCP trafiğini Tarpit portuna (9999) yönlendirir.
        Hem direkt saldırılarda (PREROUTING) hem de ağ geçidi modunda (FORWARD) çalışır."""
        
        # Whitelist Kontrolü
        if ip in {'127.0.0.1', '0.0.0.0', '::1'} or (self.blocker and ip in self.blocker.whitelist):
            logger.warning(f"[!] Whitelist ihlali girişimi: {ip} Tarpit'e ALINAMAZ!")
            return False
            
        with self.lock:
            if len(self.trapped_ips) >= MAX_TARPIT_IPS:
                logger.warning(f"[!] Tarpit havuzu dolu ({MAX_TARPIT_IPS}). Yeni IP {ip} eklenemiyor (Conntrack DoS Koruması).")
                return False

        try:
            # Command Injection önlemi için geçerli bir IP mi kontrol et
            ipaddress.ip_address(ip)
            rules_added = 0
            
            # Kural 1: PREROUTING - Saldırganın TCP trafiğini tarpit portuna yönlendir
            check_cmd = ["iptables", "-t", "nat", "-C", "PREROUTING", "-p", "tcp", "-s", ip, "-j", "REDIRECT", "--to-ports", str(self.port)]
            res = subprocess.run(check_cmd, capture_output=True)
            if res.returncode != 0:
                cmd = ["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-s", ip, "-j", "REDIRECT", "--to-ports", str(self.port)]
                subprocess.run(cmd, check=True, capture_output=True)
                rules_added += 1
            
            # Kural 2: FORWARD zincirinde saldırganın çıkış trafiğini engelle (Gateway Modu)
            check_cmd2 = ["iptables", "-C", "FORWARD", "-s", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]
            res2 = subprocess.run(check_cmd2, capture_output=True)
            if res2.returncode != 0:
                cmd2 = ["iptables", "-I", "FORWARD", "-s", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]
                subprocess.run(cmd2, check=True, capture_output=True)
                rules_added += 1
            
            logger.info(f"[+] IP {ip} Tarpit tuzağına aktarıldı (Port {self.port}, {rules_added} kural eklendi).")
            with self.lock:
                self.trapped_ips.add(ip)
            if self.db:
                self.db.add_alert(
                    alert_type="🪤 Tarpit Kaynak Tuzağı Uygulandı",
                    src_ip=ip, src_mac="N/A", dst_ip="N/A", dst_mac="N/A",
                    description=f"Saldırgan IP {ip} TCP Tarpit tuzağına aktarıldı. Tüm TCP bağlantıları kilitleniyor.",
                    severity="high"
                )
            return True
        except Exception as e:
            logger.error(f"[!] Tarpit yönlendirme hatası ({ip}): {e}")
        return False

    def untarpit_ip(self, ip):
        """IP üzerindeki Tarpit yönlendirmesini kaldırır (tüm zincirlerden)."""
        try:
            ipaddress.ip_address(ip) # Validate IP
            # PREROUTING kuralını kaldır
            subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-s", ip, "-j", "REDIRECT", "--to-ports", str(self.port)],
                         capture_output=True)
            # FORWARD kuralını kaldır
            subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"],
                         capture_output=True)
            with self.lock:
                self.trapped_ips.discard(ip)
            logger.info(f"[-] IP {ip} Tarpit tuzağından çıkarıldı.")
            return True
        except Exception as e:
            logger.error(f"[!] Untarpit hatası ({ip}): {e}")
        return False

    def get_stats(self):
        with self.lock:
            return {
                "active_tarpit_ips": list(self.trapped_ips),
                "total_trapped_connections": self.total_trapped_connections,
                "tarpit_count": len(self.trapped_ips)
            }

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
