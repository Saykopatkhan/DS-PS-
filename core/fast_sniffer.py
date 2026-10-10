import time
from collections import deque, OrderedDict
import ipaddress
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
        self.packet_count = 0
        self.last_packet_at = None
        self.last_error = None
        self.process = None
        self.thread = None
        self._lifecycle_lock = threading.RLock()
        self._last_prune = 0.0
        
        # State for detection logic
        self.gateway_mac = None
        self.gateway_ip = None
        
        # O(1) Sliding windows for flood detection
        self.syn_window = OrderedDict()
        self.udp_window = OrderedDict()
        self.icmp_window = OrderedDict()
        self._syn_flows = OrderedDict()
        self.MAX_TRACKED = 4096
        
        self.SYN_LIMIT = 100
        self.UDP_LIMIT = 500
        self.ICMP_LIMIT = 50
        self.HONEYPOT_PORTS = {2222, 8081, 445}
        self.honeypot_ips = set()
        self._last_alert = OrderedDict()

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def _trigger_alert(self, alert_type, source_ip, details, destination_ip=None):
        if alert_type != 'DEVICE_DISCOVERED':
            now = time.monotonic()
            key = (alert_type, source_ip, destination_ip)
            if now - self._last_alert.get(key, float('-inf')) < 10:
                return
            self._last_alert[key] = now
            self._last_alert.move_to_end(key)
            while len(self._last_alert) > self.MAX_TRACKED:
                self._last_alert.popitem(last=False)
        event = {
            'type': alert_type,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'severity': 'medium',
            'details': details,
            'timestamp': time.time()
        }
        for cb in self.callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def _rate(self, table, key, now, limit):
        if key not in table:
            if len(table) >= self.MAX_TRACKED:
                table.popitem(last=False)
            table[key] = deque(maxlen=limit + 1)
        table.move_to_end(key)
        samples = table[key]
        while samples and samples[0] < now - 1:
            samples.popleft()
        samples.append(now)
        return len(samples)

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
            if layers:
                self.packet_count += 1
                self.last_packet_at = time.time()
            now = time.monotonic()
            if now - self._last_prune > 5:
                for window in (self.syn_window, self.udp_window, self.icmp_window):
                    for address in list(window):
                        if not window[address] or window[address][-1] < now - 1:
                            del window[address]
                self._last_prune = now
            while self._syn_flows and next(iter(self._syn_flows.values())) < now - 1:
                self._syn_flows.popitem(last=False)

            # 1. DAI - ARP Spoofing Tespiti & Cihaz Keşfi
            if 'arp' in layers:
                arp = layers['arp']
                if str(arp.get('arp.opcode')) in ['1', '2']: # Request or Reply
                    sender_ip = str(ipaddress.IPv4Address(arp.get('arp.src.proto_ipv4')))
                    sender_mac = str(arp.get('arp.src.hw_mac', '')).lower()
                    if sender_ip == '0.0.0.0' or not sender_mac:
                        return
                    
                    if sender_ip and sender_mac:
                        # Cihaz Keşfi Sinyali (Web paneli için)
                        self._trigger_alert('DEVICE_DISCOVERED', sender_ip, sender_mac)
                    
                    if self.gateway_ip and sender_ip == self.gateway_ip:
                        if self.gateway_mac and sender_mac != self.gateway_mac.lower():
                            self._trigger_alert('ARP_SPOOF', sender_ip, f"Gateway MAC değişimi gözlendi: {sender_mac}; IP sahibinin kimliği doğrulanmadı.")
                return

            if 'ip' not in layers:
                return
                
            src_ip = layers['ip'].get('ip.src')
            if not src_ip:
                return
            dst_ip = layers['ip'].get('ip.dst')
            key = (src_ip, dst_ip)

            # TCP (SYN Flood & Honeypot)
            if 'tcp' in layers:
                tcp = layers['tcp']
                flags_value = tcp.get('tcp.flags', '0')
                flags = int(flags_value, 16) if isinstance(flags_value, str) else int(flags_value)
                dst_port = int(tcp.get('tcp.dstport', '0'))
                
                # SYN flag set, ACK not set (0x02)
                if (flags & 0x02) and not (flags & 0x10):
                    sequence = tcp.get('tcp.seq.raw')
                    source_port = tcp.get('tcp.srcport')
                    if sequence is not None and source_port is not None:
                        flow = (src_ip, dst_ip, source_port, dst_port, sequence)
                        if flow in self._syn_flows:
                            return
                        self._syn_flows[flow] = now
                        if len(self._syn_flows) > self.MAX_TRACKED:
                            self._syn_flows.popitem(last=False)
                    count = self._rate(self.syn_window, key, now, self.SYN_LIMIT)
                    if count > self.SYN_LIMIT:
                        self._trigger_alert('SYN_FLOOD', src_ip, f"Aynı hedefe 1 saniyede en az {count} SYN; hız anomalisi, saldırı doğrulanmadı.", dst_ip)
                        
                    if dst_port in self.HONEYPOT_PORTS and layers['ip'].get('ip.dst') in self.honeypot_ips:
                        self._trigger_alert('HONEYPOT_HIT', src_ip, f"Tuzak portuna SYN gözlendi: {dst_port}; bağlantı henüz doğrulanmadı.", dst_ip)
                        
            # UDP Flood
            elif 'udp' in layers:
                count = self._rate(self.udp_window, key, now, self.UDP_LIMIT)
                if count > self.UDP_LIMIT:
                    self._trigger_alert('UDP_FLOOD', src_ip, f"Aynı hedefe 1 saniyede en az {count} UDP; hız anomalisi, saldırı doğrulanmadı.", dst_ip)

            # ICMP Flood
            elif 'icmp' in layers and str(layers['icmp'].get('icmp.type')) == '8':
                count = self._rate(self.icmp_window, key, now, self.ICMP_LIMIT)
                if count > self.ICMP_LIMIT:
                    self._trigger_alert('ICMP_FLOOD', src_ip, f"Aynı hedefe 1 saniyede en az {count} echo isteği; hız anomalisi.", dst_ip)
                    
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
            self.last_error = str(e)[:200]
            print(f"[!] Sniffer Hatası: {e}")
        finally:
            with self._lifecycle_lock:
                if self.running and self.last_error is None:
                    self.last_error = 'tshark paket akışı beklenmedik şekilde kapandı'
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
            self.last_error = None
            self.thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.thread.start()

    def stop(self):
        with self._lifecycle_lock:
            self.running = False
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=3)
