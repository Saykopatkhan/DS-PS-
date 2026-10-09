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
try:
    import yara
except ImportError:
    yara = None
from scapy.all import IP, TCP, Raw

class DPIDetector:
    def __init__(self, db, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        
        # A program name in documentation or a download is not a shell session.
        self.shell_prompt = re.compile(r'(?:^|\n)[^\r\n]{0,80}[$#>]\s*(?:id|whoami)\s*\r?\n')
        self.shell_identity = re.compile(r'\buid=\d+\([^\r\n)]+\)\s+gid=\d+\([^\r\n)]+\)')
        
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
            self.yara_compiled = yara.compile(source=yara_rules) if yara else None
        except Exception as e:
            print(f"YARA derleme hatası: {e}")
            self.yara_compiled = None

    def _trigger_alert(self, packet, src_ip, dst_ip, description):
        self.db.add_alert(
            alert_type='DPI: YARA Match',
            src_ip=src_ip, src_mac=packet.src if hasattr(packet, 'src') else 'N/A',
            dst_ip=dst_ip, dst_mac=packet.dst if hasattr(packet, 'dst') else 'N/A',
            description=description,
            severity='warning'
        )
        # A content match cannot establish whether a transfer is authorized.

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
                original_payload = bytes(packet[Raw].load)[:65536].decode('utf-8', errors='ignore')
                payload = original_payload.lower()
                
                # De-Obfuscation Motoru
                # 1. URL Decode (%20 -> boşluk, vb.)
                payload = urllib.parse.unquote(original_payload).lower()
                
                # 2. Base64 Decode
                # Payload içinde geçen Base64 benzeri metinleri çöz ve incelemeye dahil et
                b64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', original_payload)
                for b64 in b64_matches[:32]:
                    try:
                        decoded = base64.b64decode(b64, validate=True).decode('utf-8').lower()
                        payload += " " + decoded
                    except Exception:
                        pass
                
                if self.shell_prompt.search(payload) and self.shell_identity.search(payload):
                    self.db.add_alert(
                        alert_type='DPI: Shell Session Indicators',
                        src_ip=src_ip, src_mac='N/A', dst_ip=dst_ip, dst_mac='N/A',
                        description='Şifresiz içerikte komut istemi ve kullanıcı kimliği çıktısı birlikte gözlendi. Yetkisiz oturum olduğuna dair ek doğrulama gerekli.',
                        severity='warning'
                    )
                        
            except Exception:
                pass
