# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Port Scan tespit modülü (SYN, FIN, XMAS, NULL, UDP).
"""
import time
from collections import defaultdict, deque
from scapy.all import DHCP, DNS, TCP, UDP, IP
import psutil
from core.database import Database
import threading

class ScanDetector:
    """Detect bursts of distinct ports for one source/destination pair."""

    def __init__(self, db: Database, blocker=None, auto_ban=False, auto_vuln_scan_cb=None):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.auto_vuln_scan_cb = auto_vuln_scan_cb
        self.syn_count = defaultdict(dict)
        self.fin_count = defaultdict(dict)
        self.xmas_count = defaultdict(dict)
        self.null_count = defaultdict(dict)
        self.udp_count = defaultdict(dict)
        self.connection_timestamps = defaultdict(lambda: deque(maxlen=2001))
        self.scan_threshold = 15
        self.time_window = 5.0
        self.last_cleanup = time.time()
        self.last_flood_alert = {}
        self._alerted_scans = {}
        self._udp_flows = {}
        self._scan_slots = threading.BoundedSemaphore(2)
        self.local_ips = self._get_local_ips()

    def _get_local_ips(self):
        ips = {'127.0.0.1'}
        try:
            for snics in psutil.net_if_addrs().values():
                for snic in snics:
                    if snic.family == 2:
                        ips.add(snic.address)
        except Exception:
            pass
        return ips

    def analyze(self, packet):
        now = time.time()
        self._cleanup(now)
        if not packet.haslayer(IP):
            return
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        pair = (src_ip, dst_ip)
        if packet.haslayer(UDP):
            udp = packet[UDP]
            flow = (src_ip, dst_ip, udp.sport, udp.dport)
            reverse = (dst_ip, src_ip, udp.dport, udp.sport)
            if reverse in self._udp_flows and now - self._udp_flows[reverse] < self.time_window:
                return
            if len(self._udp_flows) >= 10000 and flow not in self._udp_flows:
                self._udp_flows.pop(next(iter(self._udp_flows)))
            self._udp_flows[flow] = now
            if src_ip in self.local_ips:
                return
            if ((packet.haslayer(DNS) and ({udp.sport, udp.dport} & {53, 5353}))
                    or (packet.haslayer(DHCP) and ({udp.sport, udp.dport} & {67, 68}))):
                return
            self._record('udp', pair, udp.dport, now)
            self._check_flood(pair, 'UDP', now)
            return
        if src_ip in self.local_ips or not packet.haslayer(TCP):
            return
        flags = int(packet[TCP].flags)
        # ECN negotiation can add ECE/CWR to a valid SYN.
        kind = 'syn' if flags & 2 and not flags & (16 | 4 | 1) else {
            0x01: 'fin', 0x29: 'xmas', 0x00: 'null'
        }.get(flags)
        if kind:
            self._record(kind, pair, packet[TCP].dport, now)
        if kind == 'syn':
            self._check_flood(pair, 'SYN', now)

    def _record(self, kind, pair, port, now):
        table = getattr(self, kind + '_count')
        if pair not in table and len(table) >= 10000:
            table.pop(next(iter(table)))
        ports = table[pair]
        for old_port in list(ports):
            if now - ports[old_port] >= self.time_window:
                del ports[old_port]
        if port not in ports and len(ports) >= max(64, self.scan_threshold + 1):
            ports.pop(next(iter(ports)))
        ports[port] = now
        alert_key = (kind, pair)
        if len(ports) <= self.scan_threshold or now - self._alerted_scans.get(alert_key, float('-inf')) < self.time_window:
            return
        self._alerted_scans[alert_key] = now
        src_ip, dst_ip = pair
        self.db.add_alert(
            alert_type=kind.upper() + ' Scan',
            src_ip=src_ip, src_mac='N/A', dst_ip=dst_ip, dst_mac='N/A',
            description=f'Kaynak {src_ip}, hedef {dst_ip}: {self.time_window:g}s içinde '
                        f'{len(ports)} farklı {kind.upper()} hedef portu (örnek: {sorted(ports)[:10]}).',
            severity='warning' if kind == 'udp' else 'high'
        )
        # UDP reply streams can resemble scans when only one direction is visible.
        if kind != 'udp' and self.blocker and self.auto_ban:
            self.blocker.block_ip(src_ip)
        if kind in {'syn', 'xmas'}:
            self._schedule_scan(src_ip)

    def _check_flood(self, pair, proto, now):
        key = (pair, proto)
        if key not in self.connection_timestamps and len(self.connection_timestamps) >= 10000:
            self.connection_timestamps.pop(next(iter(self.connection_timestamps)))
        recent = self.connection_timestamps[key]
        while recent and now - recent[0] >= 1.0:
            recent.popleft()
        recent.append(now)
        if len(recent) > 2000 and now - self.last_flood_alert.get(key, float('-inf')) >= 5.0:
            src_ip, dst_ip = pair
            self.db.add_alert(
                alert_type='SYN/UDP Flood (DoS)',
                src_ip=src_ip, src_mac='N/A', dst_ip=dst_ip, dst_mac='N/A',
                description=f'Kaynak {src_ip}, hedef {dst_ip}: saniyede en az {len(recent)} {proto} paketi.',
                severity='warning' if proto == 'UDP' else 'high'
            )
            self.last_flood_alert[key] = now
            if proto == 'SYN' and self.blocker and self.auto_ban:
                self.blocker.block_ip(src_ip)

    def _schedule_scan(self, src_ip):
        if not self.auto_vuln_scan_cb or getattr(self.blocker, 'dry_run', False):
            return
        if not self._scan_slots.acquire(blocking=False):
            return
        def run():
            try:
                self.auto_vuln_scan_cb(src_ip)
            finally:
                self._scan_slots.release()
        threading.Thread(target=run, daemon=True).start()

    def _cleanup(self, now=None):
        now = time.time() if now is None else now
        if now - self.last_cleanup < 1.0:
            return
        # Expire individual observations: fixed resets lose scans across a boundary.
        for kind in ('syn', 'fin', 'xmas', 'null', 'udp'):
            table = getattr(self, kind + '_count')
            for pair, ports in list(table.items()):
                for port in list(ports):
                    if now - ports[port] >= self.time_window:
                        del ports[port]
                if not ports:
                    del table[pair]
        for key, recent in list(self.connection_timestamps.items()):
            while recent and now - recent[0] >= 1.0:
                recent.popleft()
            if not recent:
                del self.connection_timestamps[key]
        self._alerted_scans = {key: ts for key, ts in self._alerted_scans.items() if now - ts < self.time_window}
        self.last_flood_alert = {key: ts for key, ts in self.last_flood_alert.items() if now - ts < 5.0}
        self._udp_flows = {key: ts for key, ts in self._udp_flows.items() if now - ts < self.time_window}
        self.last_cleanup = now

    def get_stats(self) -> dict:
        return {kind + '_scans': len(getattr(self, kind + '_count'))
                for kind in ('syn', 'fin', 'xmas', 'null', 'udp')}
