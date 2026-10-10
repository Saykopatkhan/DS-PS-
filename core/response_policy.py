"""Correlate local observations before considering a reversible firewall response.

Packet source addresses and severity labels alone never authorize a block.
Incidents and response outcomes survive a process restart; scores are bounded
per evidence family so duplicate sensors cannot manufacture corroboration.
"""

import ipaddress
import json
import logging
import threading
import time


class ResponsePolicy:
    WINDOW_SECONDS = 300
    SCORE_THRESHOLD = 80

    def __init__(self, db, blocker=None, *, mode='ids', dry_run=False,
                 enabled=False, clock=None):
        self.db = db
        self.blocker = blocker
        self.mode = mode
        self.dry_run = dry_run
        self.enabled = enabled
        self.clock = clock or time.time
        self._lock = threading.RLock()
        with db.lock:
            db.conn.executescript('''
                CREATE TABLE IF NOT EXISTS security_incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    alert_count INTEGER NOT NULL DEFAULT 0,
                    last_alert_id INTEGER,
                    score INTEGER NOT NULL DEFAULT 0,
                    signals TEXT NOT NULL DEFAULT '{}',
                    decision TEXT NOT NULL DEFAULT 'observe',
                    reason TEXT NOT NULL DEFAULT 'insufficient_evidence'
                );
                CREATE INDEX IF NOT EXISTS incidents_source_id
                    ON security_incidents(source_ip, id DESC);
                CREATE TABLE IF NOT EXISTS response_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL UNIQUE,
                    source_ip TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    outcome TEXT NOT NULL,
                    reason TEXT NOT NULL
                );
            ''')
            db.conn.commit()

    @staticmethod
    def _signal(alert):
        kind = str(alert.get('alert_type', '')).casefold()
        # A claimed ARP/DHCP identity can belong to the victim. It must not
        # contribute to a source-IP response, even if another sensor sees it.
        if any(word in kind for word in ('arp', 'dhcp', 'mac spoof', 'geo-ip', 'port scanner', 'auto-vuln scanner')):
            return 'unattributed', 0, False
        verified = alert.get('source_verified') is True
        if kind == 'ssh_brute_force':
            return 'authentication', 50, verified
        if 'honeypot' in kind:
            return 'honeypot', 35 if verified else 10, verified
        if 'flood' in kind or 'ddos' in kind or 'dos' in kind:
            return 'traffic_rate', 10, False
        if 'scan' in kind or 'tarama' in kind or 'dir-bruteforce' in kind:
            return 'reconnaissance', 20, False
        if any(word in kind for word in ('injection', 'command_inj', 'traversal', 'xss', 'dpi:')):
            return 'web_payload', 25, False
        if 'c&c' in kind or 'sinkhole' in kind:
            return 'threat_intelligence', 25, False
        if 'dns' in kind:
            return 'dns_anomaly', 15, False
        if 'beacon' in kind or 'ueba' in kind:
            return 'behavior', 15, False
        return 'observation', 0, False

    def status(self):
        return {
            'enabled': bool(self.enabled), 'mode': self.mode,
            'dry_run': bool(self.dry_run),
            'window_seconds': self.WINDOW_SECONDS,
            'score_threshold': self.SCORE_THRESHOLD,
            'minimum_families': 2,
            'requires_verified_source': True,
            'automatic_action': 'temporary_ip_block',
        }

    def _decision(self, source, signals, score, monitoring):
        if self.blocker and self.blocker.is_protected_ip(source):
            return 'observe', 'protected_address'
        if ipaddress.ip_address(source).version != 4:
            return 'observe', 'ipv6_response_unsupported'
        evidence = [s for s in signals.values() if s['weight'] > 0]
        if (len(evidence) < 2 or score < self.SCORE_THRESHOLD
                or not any(s['verified'] for s in evidence)):
            return 'observe', 'insufficient_evidence'
        if not self.enabled:
            return 'review', 'automatic_response_disabled'
        if self.mode != 'ips' or self.dry_run or not self.blocker:
            return 'review', 'passive_mode'
        if not monitoring:
            return 'review', 'monitoring_stopped'
        if self.db.is_banned(ip=source):
            return 'observe', 'already_blocked'
        return 'block', 'corroborated_verified_source'

    def observe(self, alert, *, monitoring=False):
        try:
            address = ipaddress.ip_address(alert.get('source_ip'))
        except (ValueError, TypeError):
            return None
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            return None
        source = str(address)
        now = self.clock()
        family, weight, verified = self._signal(alert)
        # Serialize decision + reservation. Firewall work does not hold db.lock.
        with self._lock:
            with self.db.lock:
                row = self.db.conn.execute(
                    'SELECT * FROM security_incidents WHERE source_ip=? ORDER BY id DESC LIMIT 1',
                    (source,),
                ).fetchone()
                if row is None or not 0 <= now - row['first_seen'] < self.WINDOW_SECONDS:
                    cursor = self.db.conn.execute(
                        'INSERT INTO security_incidents (source_ip, first_seen, last_seen) VALUES (?, ?, ?)',
                        (source, now, now),
                    )
                    incident_id, signals = cursor.lastrowid, {}
                else:
                    incident_id, signals = row['id'], json.loads(row['signals'])
                previous = signals.get(family, {'weight': 0, 'verified': False, 'count': 0})
                signals[family] = {
                    'weight': max(previous['weight'], weight),
                    'verified': previous['verified'] or verified,
                    'count': previous['count'] + 1,
                }
                score = min(100, sum(s['weight'] for s in signals.values()))
                action = self.db.conn.execute(
                    'SELECT outcome, reason FROM response_actions WHERE incident_id=?', (incident_id,),
                ).fetchone()
                decision, reason = ((action['outcome'], action['reason']) if action else
                                    self._decision(source, signals, score, monitoring))
                self.db.conn.execute('''
                    UPDATE security_incidents SET last_seen=?, alert_count=alert_count+1,
                        last_alert_id=?, score=?, signals=?, decision=?, reason=? WHERE id=?
                ''', (now, alert.get('id'), score, json.dumps(signals), decision, reason, incident_id))
                if decision == 'block' and not action:
                    # A crash after reservation remains visible as pending; a
                    # restart cannot silently execute the same response twice.
                    self.db.conn.execute('''
                        INSERT INTO response_actions (incident_id, source_ip, created_at, outcome, reason)
                        VALUES (?, ?, ?, 'pending', ?)
                    ''', (incident_id, source, now, reason))
                    self.db.conn.execute(
                        "UPDATE security_incidents SET decision='pending' WHERE id=?", (incident_id,),
                    )
                self.db.conn.commit()
            if decision == 'block' and not action:
                try:
                    applied = self.blocker.block_ip(
                        source, reason=f'Correlated incident #{incident_id}: {", ".join(sorted(signals))}',
                        severity='high',
                    ) is True
                    decision, reason = ('blocked', 'corroborated_verified_source') if applied else ('failed', 'firewall_not_applied')
                except Exception:
                    logging.exception('Incident %s response failed', incident_id)
                    decision, reason = 'failed', 'firewall_error'
                with self.db.lock:
                    self.db.conn.execute(
                        'UPDATE response_actions SET outcome=?, reason=? WHERE incident_id=?',
                        (decision, reason, incident_id),
                    )
                    self.db.conn.execute(
                        'UPDATE security_incidents SET decision=?, reason=? WHERE id=?',
                        (decision, reason, incident_id),
                    )
                    self.db.conn.commit()
            return {'incident_id': incident_id, 'score': score, 'families': sorted(signals),
                    'decision': decision, 'reason': reason}

    def get_incidents(self, limit=50):
        limit = max(1, min(int(limit), 1000))
        with self.db.lock:
            rows = self.db.conn.execute(
                'SELECT * FROM security_incidents ORDER BY last_seen DESC, id DESC LIMIT ?', (limit,),
            ).fetchall()
        now = self.clock()
        result = []
        for row in rows:
            item = dict(row)
            item['signals'] = json.loads(item['signals'])
            item['active'] = 0 <= now - item['first_seen'] < self.WINDOW_SECONDS
            result.append(item)
        return result
