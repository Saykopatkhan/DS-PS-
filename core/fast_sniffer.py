import time
from collections import deque
import subprocess
import json
import threading

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
        self.process = None
        self.thread = None
        self._lifecycle_lock = threading.RLock()
        self._last_prune = 0.0
        
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
        self.HONEYPOT_PORTS = {2222, 8081, 445}
        self.honeypot_ips = set()
        self._last_alert = {}

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def _trigger_alert(self, alert_type, source_ip, details):
        if alert_type != 'DEVICE_DISCOVERED':
            now = time.monotonic()
            key = (alert_type, source_ip)
            if now - self._last_alert.get(key, float('-inf')) < 10:
                return
            if len(self._last_alert) >= 10000:
                self._last_alert.clear()
            self._last_alert[key] = now
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
            layers = packet_data.get('_source', {}).get('layers', packet_data.get('layers', {}))
            # -T ek uses arp_arp_src_proto_ipv4 rather than JSON's
            # arp.src.proto_ipv4 and puts layers directly at the top level.
            normalized = {}
            for protocol, fields in layers.items():
                if not isinstance(fields, dict):
                    continue
                normalized[protocol] = {}
                for key, value in fields.items():
                    name = key[len(protocol) + 1:] if key.startswith(protocol + '_') else key
                    name = name.replace('_', '.')
                    if name == 'arp.src.proto.ipv4':
                        name = 'arp.src.proto_ipv4'
                    elif name == 'arp.src.hw.mac':
                        name = 'arp.src.hw_mac'
                    normalized[protocol][name] = value[0] if isinstance(value, list) and value else value
            layers = normalized
            now = time.monotonic()
            if now - self._last_prune > 5:
                for window in (self.syn_window, self.udp_window, self.icmp_window):
                    for address in list(window):
                        if not window[address] or window[address][-1] < now - 1:
                            del window[address]
                self._last_prune = now

            # 1. DAI - ARP Spoofing Tespiti & Cihaz Keşfi
            if 'arp' in layers:
                arp = layers['arp']
                if str(arp.get('arp.opcode')) in ['1', '2']: # Request or Reply
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
                flags_value = tcp.get('tcp.flags', '0')
                flags = int(flags_value, 16) if isinstance(flags_value, str) else int(flags_value)
                dst_port = int(tcp.get('tcp.dstport', '0'))
                
                # SYN flag set, ACK not set (0x02)
                if (flags & 0x02) and not (flags & 0x10):
                    if src_ip not in self.syn_window:
                        self.syn_window[src_ip] = deque(maxlen=max(self.SYN_LIMIT, self.UDP_LIMIT, self.ICMP_LIMIT) + 1)
                    self.syn_window[src_ip].append(now)
                    while self.syn_window[src_ip] and self.syn_window[src_ip][0] < now - 1.0:
                        self.syn_window[src_ip].popleft()
                        
                    if len(self.syn_window[src_ip]) > self.SYN_LIMIT:
                        self._trigger_alert('SYN_FLOOD', src_ip, f"1 saniyede {len(self.syn_window[src_ip])} SYN")
                        
                    if dst_port in self.HONEYPOT_PORTS and layers['ip'].get('ip.dst') in self.honeypot_ips:
                        self._trigger_alert('HONEYPOT_HIT', src_ip, f"Honeypot Porta Erişim: {dst_port}")
                        
            # UDP Flood
            elif 'udp' in layers:
                if src_ip not in self.udp_window:
                    self.udp_window[src_ip] = deque(maxlen=max(self.SYN_LIMIT, self.UDP_LIMIT, self.ICMP_LIMIT) + 1)
                self.udp_window[src_ip].append(now)
                while self.udp_window[src_ip] and self.udp_window[src_ip][0] < now - 1.0:
                    self.udp_window[src_ip].popleft()
                if len(self.udp_window[src_ip]) > self.UDP_LIMIT:
                    self._trigger_alert('UDP_FLOOD', src_ip, f"1 saniyede {len(self.udp_window[src_ip])} UDP")

            # ICMP Flood
            elif 'icmp' in layers:
                if src_ip not in self.icmp_window:
                    self.icmp_window[src_ip] = deque(maxlen=max(self.SYN_LIMIT, self.UDP_LIMIT, self.ICMP_LIMIT) + 1)
                self.icmp_window[src_ip].append(now)
                while self.icmp_window[src_ip] and self.icmp_window[src_ip][0] < now - 1.0:
                    self.icmp_window[src_ip].popleft()
                if len(self.icmp_window[src_ip]) > self.ICMP_LIMIT:
                    self._trigger_alert('ICMP_FLOOD', src_ip, f"1 saniyede {len(self.icmp_window[src_ip])} Ping")
                    
        except Exception:
            pass

    def _capture_loop(self):
        cmd = ['tshark', '-i', self.interface, '-l', '-T', 'ek']
        if self.filter_str:
            cmd.extend(['-f', self.filter_str])
            
        print(f"[*] FastSniffer (tshark-backend) {self.interface} üzerinde dinliyor...")
        
        try:
            with self._lifecycle_lock:
                if not self.running:
                    return
                self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                process = self.process
            for line in iter(process.stdout.readline, ''):
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
            with self._lifecycle_lock:
                process = self.process
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                    if process.stdout:
                        process.stdout.close()
                    self.process = None
                self.running = False

    def start(self):
        with self._lifecycle_lock:
            if self.running or (self.thread and self.thread.is_alive()):
                return
            self.running = True
            self.thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.thread.start()

    def stop(self):
        with self._lifecycle_lock:
            self.running = False
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=3)
