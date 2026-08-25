import asyncio
import time
import socket
import struct
from collections import deque
import subprocess
import json

class FastSniffer:
    """
    Tshark tabanlı (C-backend) yüksek performanslı paket yakalayıcı.
    pypcap kurulamadığı ortamlarda sıfıra yakın gecikmeyle çalışır.
    """
    def __init__(self, interface='eth0', filter_str=None):
        self.interface = interface
        self.filter_str = filter_str
        self.callbacks = []
        self.running = False
        
        # State for detection logic
        self.gateway_mac = None
        self.gateway_ip = None
        
        # O(1) Sliding windows for flood detection
        self.syn_window = {}
        self.udp_window = {}
        self.icmp_window = {}
        
        self.SYN_LIMIT = 100
        self.UDP_LIMIT = 500
        self.ICMP_LIMIT = 50
        self.HONEYPOT_PORTS = {2222, 8080, 445}

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def _trigger_alert(self, alert_type, source_ip, details):
        event = {
            'type': alert_type,
            'source_ip': source_ip,
            'details': details,
            'timestamp': time.time()
        }
        for cb in self.callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def analyze_packet(self, packet_data):
        """tshark JSON çıktısını analiz eder."""
        try:
            layers = packet_data.get('_source', {}).get('layers', {})
            now = time.time()

            # 1. DAI - ARP Spoofing Tespiti & Cihaz Keşfi
            if 'arp' in layers:
                arp = layers['arp']
                if arp.get('arp.opcode') in ['1', '2']: # Request or Reply
                    sender_ip = arp.get('arp.src.proto_ipv4')
                    sender_mac = arp.get('arp.src.hw_mac')
                    
                    if sender_ip and sender_mac:
                        # Cihaz Keşfi Sinyali (Web paneli için)
                        self._trigger_alert('DEVICE_DISCOVERED', sender_ip, sender_mac)
                    
                    if self.gateway_ip and sender_ip == self.gateway_ip:
                        if self.gateway_mac and sender_mac != self.gateway_mac:
                            self._trigger_alert('ARP_SPOOF', sender_ip, f"Sahte Gateway MAC: {sender_mac}")
                return

            if 'ip' not in layers:
                return
                
            src_ip = layers['ip'].get('ip.src')
            if not src_ip:
                return

            # TCP (SYN Flood & Honeypot)
            if 'tcp' in layers:
                tcp = layers['tcp']
                flags = int(tcp.get('tcp.flags', '0'), 16)
                dst_port = int(tcp.get('tcp.dstport', '0'))
                
                # SYN flag set, ACK not set (0x02)
                if (flags & 0x02) and not (flags & 0x10):
                    if src_ip not in self.syn_window:
                        self.syn_window[src_ip] = deque()
                    self.syn_window[src_ip].append(now)
                    while self.syn_window[src_ip] and self.syn_window[src_ip][0] < now - 1.0:
                        self.syn_window[src_ip].popleft()
                        
                    if len(self.syn_window[src_ip]) > self.SYN_LIMIT:
                        self._trigger_alert('SYN_FLOOD', src_ip, f"1 saniyede {len(self.syn_window[src_ip])} SYN")
                        
                    if dst_port in self.HONEYPOT_PORTS:
                        self._trigger_alert('HONEYPOT_HIT', src_ip, f"Honeypot Porta Erişim: {dst_port}")
                        
            # UDP Flood
            elif 'udp' in layers:
                if src_ip not in self.udp_window:
                    self.udp_window[src_ip] = deque()
                self.udp_window[src_ip].append(now)
                while self.udp_window[src_ip] and self.udp_window[src_ip][0] < now - 1.0:
                    self.udp_window[src_ip].popleft()
                if len(self.udp_window[src_ip]) > self.UDP_LIMIT:
                    self._trigger_alert('UDP_FLOOD', src_ip, f"1 saniyede {len(self.udp_window[src_ip])} UDP")

            # ICMP Flood
            elif 'icmp' in layers:
                if src_ip not in self.icmp_window:
                    self.icmp_window[src_ip] = deque()
                self.icmp_window[src_ip].append(now)
                while self.icmp_window[src_ip] and self.icmp_window[src_ip][0] < now - 1.0:
                    self.icmp_window[src_ip].popleft()
                if len(self.icmp_window[src_ip]) > self.ICMP_LIMIT:
                    self._trigger_alert('ICMP_FLOOD', src_ip, f"1 saniyede {len(self.icmp_window[src_ip])} Ping")
                    
        except Exception as e:
            pass

    def _capture_loop(self):
        cmd = ['tshark', '-i', self.interface, '-l', '-T', 'ek']
        if self.filter_str:
            cmd.extend(['-f', self.filter_str])
            
        print(f"[*] FastSniffer (tshark-backend) {self.interface} üzerinde dinliyor...")
        
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            for line in iter(self.process.stdout.readline, ''):
                if not self.running:
                    break
                line = line.strip()
                if not line or line.startswith('{"index"'): 
                    continue
                    
                try:
                    packet_data = json.loads(line)
                    self.analyze_packet(packet_data)
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"[!] Sniffer Hatası: {e}")
        finally:
            if hasattr(self, 'process'):
                self.process.terminate()

    def start(self):
        self.running = True
        import threading
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if hasattr(self, 'process'):
            self.process.terminate()
