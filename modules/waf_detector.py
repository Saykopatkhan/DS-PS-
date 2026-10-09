# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

"""
Web Application Firewall (WAF) Modülü.
Dizin Kaba Kuvveti (Directory Bruteforce) ve L7 DoS saldırılarını tespit eder.
"""
import re
import time
from collections import defaultdict, deque
from scapy.all import IP, TCP, Raw


class WAFDetector:
    """Passive HTTP/1 observations; complete headers must fit in one packet."""

    REQUEST = re.compile(rb'^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) ([^\s]+) HTTP/1\.[01]\r?\n')
    RESPONSE = re.compile(rb'^HTTP/1\.[01] ([0-9]{3})(?: |\r?\n)')

    def __init__(self, db, blocker=None, auto_ban=False):
        self.db = db
        self.blocker = blocker
        self.auto_ban = auto_ban
        self.http_requests = defaultdict(list)
        self.http_404_errors = defaultdict(list)
        self.time_window = 10.0
        self.bruteforce_threshold = 30
        self.l7_dos_threshold = 100
        self.last_cleanup = time.time()
        self._segments = {}
        self._pending = {}
        self._correlation_lost = {}
        self._last_alert = {}

    def analyze(self, packet):
        now = time.time()
        self._cleanup(now)
        if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
            return
        tcp = packet[TCP]
        if tcp.dport not in {80, 8080} and tcp.sport not in {80, 8080}:
            return
        src, dst = packet[IP].src, packet[IP].dst
        payload = bytes(packet[Raw].load)
        request = self.REQUEST.match(payload) if tcp.dport in {80, 8080} else None
        response = self.RESPONSE.match(payload) if tcp.sport in {80, 8080} else None
        if not request and not response:
            return
        flow = (src, dst, tcp.sport, tcp.dport)
        # Mirrored capture duplicates and retransmissions are one observation.
        segment = (flow, tcp.seq, len(payload), payload[:128])
        if segment in self._segments and now - self._segments[segment] < self.time_window:
            return
        self._bounded_insert(self._segments, segment, now)
        if request:
            if flow in self._correlation_lost:
                self._correlation_lost[flow] = now
            else:
                if flow not in self._pending:
                    self._bounded_insert(self._pending, flow, deque(maxlen=64))
                pending = self._pending[flow]
                # Stop correlation for this busy flow until it becomes idle.
                if len(pending) == pending.maxlen:
                    self._pending.pop(flow)
                    self._bounded_insert(self._correlation_lost, flow, now)
                else:
                    pending.append((now, request[2][:4096]))
            pair = (src, dst)
            if pair not in self.http_requests:
                self._bounded_insert(self.http_requests, pair, [])
            self.http_requests[pair].append(now)
            self._check_l7_dos(pair, now)
        elif response:
            reverse = (dst, src, tcp.dport, tcp.sport)
            pending = self._pending.get(reverse)
            if not pending or int(response[1]) < 200:
                return
            started, path = pending.popleft()
            if not pending:
                self._pending.pop(reverse, None)
            if response[1] == b'404' and now - started < self.time_window:
                pair = (dst, src)
                if pair not in self.http_404_errors:
                    self._bounded_insert(self.http_404_errors, pair, [])
                self.http_404_errors[pair].append((now, path))
                self._check_bruteforce(pair, now)

    @staticmethod
    def _bounded_insert(table, key, value):
        if key not in table and len(table) >= 10000:
            table.pop(next(iter(table)))
        table[key] = value

    def _check_l7_dos(self, pair, now):
        recent = [timestamp for timestamp in self.http_requests[pair]
                  if now - timestamp < self.time_window]
        # The alert only needs threshold+1 evidence, not an unbounded packet log.
        self.http_requests[pair] = recent[-(self.l7_dos_threshold + 1):]
        if len(recent) > self.l7_dos_threshold:
            self._alert('Web L7 DoS / Flood', pair, now,
                        f'{self.time_window:g}s içinde en az {len(recent)} HTTP isteği. '
                        'Yoğun meşru istemci/proxy trafiği olabilir.')

    def _check_bruteforce(self, pair, now):
        recent = [(timestamp, path) for timestamp, path in self.http_404_errors[pair]
                  if now - timestamp < self.time_window]
        # Keep one timestamp per path; a missing asset retry is not a directory scan.
        paths = {path: timestamp for timestamp, path in recent}
        self.http_404_errors[pair] = [(timestamp, path) for path, timestamp in paths.items()][-(self.bruteforce_threshold + 1):]
        if len(paths) > self.bruteforce_threshold:
            self._alert('Web Dir-Bruteforce', pair, now,
                        f'{self.time_window:g}s içinde en az {len(paths)} farklı istek yolu için '
                        'eşleştirilmiş 404 yanıtı; olası dizin taraması.')

    def _alert(self, kind, pair, now, description):
        key = (kind, pair)
        if now - self._last_alert.get(key, float('-inf')) < self.time_window:
            return
        self._bounded_insert(self._last_alert, key, now)
        self.db.add_alert(alert_type=kind, src_ip=pair[0], src_mac='N/A',
                          dst_ip=pair[1], dst_mac='N/A', description=description,
                          severity='warning')
        # Rate/404 heuristics cannot distinguish shared proxies or authorized jobs.

    def _cleanup(self, now=None):
        now = time.time() if now is None else now
        if now - self.last_cleanup < self.time_window:
            return
        for pair, timestamps in list(self.http_requests.items()):
            recent = [timestamp for timestamp in timestamps if now - timestamp < self.time_window]
            if recent:
                self.http_requests[pair] = recent
            else:
                del self.http_requests[pair]
        for pair, errors in list(self.http_404_errors.items()):
            recent = [(timestamp, path) for timestamp, path in errors if now - timestamp < self.time_window]
            if recent:
                self.http_404_errors[pair] = recent
            else:
                del self.http_404_errors[pair]
        self._segments = {key: ts for key, ts in self._segments.items() if now - ts < self.time_window}
        self._correlation_lost = {key: ts for key, ts in self._correlation_lost.items() if now - ts < self.time_window}
        self._last_alert = {key: ts for key, ts in self._last_alert.items() if now - ts < self.time_window}
        for flow, pending in list(self._pending.items()):
            while pending and now - pending[0][0] >= self.time_window:
                pending.popleft()
            if not pending:
                del self._pending[flow]
        self.last_cleanup = now
