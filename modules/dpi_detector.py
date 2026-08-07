# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Deep Packet Inspection (DPI) Modülü.
Ağdan geçen şifresiz TCP paketlerinin veri kısımlarını (Raw Payload) inceler.
Tersine bağlantı (Reverse Shell) veya komut satırı izlerini yakalar.
"""
import base64
import urllib.parse
import re
import yara
from scapy.all import IP, TCP, Raw

class DPIDetector:
    def __init__(self, db, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        
        # Sızma testlerinde ve Reverse Shell'lerde sık görülen komut satırı imzaları
        self.signatures = [
            "cmd.exe",
            "powershell",
            "/bin/bash",
            "/bin/sh",
            "NCat",
            "uid=0(root)",
            "whoami"
        ]
        
        # YARA Kuralları (Malware / Webshell Tespiti)
        yara_rules = """
        rule Webshell_PHP {
            strings:
                $php1 = "<?php"
                $eval = "eval($_"
                $exec = "shell_exec("
                $system = "system("
            condition:
                $php1 and ($eval or $exec or $system)
        }
        rule Ransomware_WannaCry {
            strings:
                $s1 = "WNcry@2ol7"
                $s2 = "WanaCrypt0r"
            condition:
                any of them
        }
        """
        try:
            self.yara_compiled = yara.compile(source=yara_rules)
        except Exception as e:
            print(f"YARA derleme hatası: {e}")
            self.yara_compiled = None

    def analyze(self, packet):
        """TCP paketlerinin payload (veri) kısımlarını derinlemesine inceler."""
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            try:
                # 1. YARA Taraması
                if self.yara_compiled:
                    matches = self.yara_compiled.match(data=packet[Raw].load)
                    if matches:
                        rule_name = matches[0].rule
                        self._trigger_alert(packet, src_ip, dst_ip, f"YARA Kuralı Eşleşti: Zararlı yazılım izi bulundu! ({rule_name})")
                        return

                # Byte dizisini string'e dönüştür (hataları yoksay)
                original_payload = packet[Raw].load.decode('utf-8', errors='ignore')
                payload = original_payload.lower()
                
                # De-Obfuscation Motoru
                # 1. URL Decode (%20 -> boşluk, vb.)
                payload = urllib.parse.unquote(payload)
                
                # 2. Base64 Decode
                # Payload içinde geçen Base64 benzeri metinleri çöz ve incelemeye dahil et
                b64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', original_payload)
                for b64 in b64_matches:
                    try:
                        decoded = base64.b64decode(b64).decode('utf-8', errors='ignore').lower()
                        payload += " " + decoded
                    except Exception:
                        pass
                
                for sig in self.signatures:
                    if sig.lower() in payload:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        
                        self.db.add_alert(
                            alert_type='DPI: Reverse Shell / Malicious Payload',
                            src_ip=src_ip, src_mac='N/A', dst_ip=dst_ip, dst_mac='N/A',
                            description=f'Kaynak {src_ip} paketinde şüpheli metin (İmza: {sig}) tespit edildi!',
                            severity='critical'
                        )
                        if self.blocker and self.auto_ban:
                            self.blocker.block_ip(src_ip)
                        # Aynı paket için birden fazla alarm vermemek için döngüden çık
                        break
                        
            except Exception:
                pass
