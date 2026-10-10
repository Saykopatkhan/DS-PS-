# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

import subprocess
import threading
import time
import os
import re
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from colorama import Fore, Style
from core.database import Database


class Blocker:
    """Apply validated firewall changes with explicit startup and bounded bans."""
    SET_NAME = "dsips_blacklist"

    def __init__(self, db: Database, auto_unban_time=3600, interface='eth0',
                 dry_run=False, active_defense_mgr=None, autostart=False):
        self.db = db
        self.active_defense_mgr = active_defense_mgr
        self.auto_unban_time = auto_unban_time
        self.interface = interface
        self.dry_run = dry_run
        self.blocked_ips = set()
        self.blocked_macs = set()
        self.intercepted_macs = set()
        self.ip_mac_map = {}
        self.mac_ip_map = {}
        self.lock = threading.RLock()
        self.gateway_ip = self.gateway_mac = None
        self.running = False
        self.arp_thread = self.expiry_thread = None
        self._stop_event = threading.Event()
        self._expires = {}
        self._rate_rules = {}
        self.BAN_DURATIONS = {'critical': 86400, 'high': 3600, 'medium': 600, 'low': 300}
        self.whitelist = {'127.0.0.1', '::1', '0.0.0.0'}
        self._load_config()
        try:
            import scapy.all as scapy_module
            self._scapy_available = hasattr(scapy_module, 'sendp')
        except ImportError:
            self._scapy_available = False
        if autostart:
            self.start()

    def start(self):
        with self.lock:
            if self.running:
                return True
            if not self.dry_run and not self._check_root():
                return False
            self._stop_event.clear()
            if not self.dry_run:
                self._get_gateway_info()
                if self.gateway_ip:
                    self.whitelist.add(self.gateway_ip)
                try:
                    from scapy.all import get_if_addr
                    self.whitelist.add(get_if_addr(self.interface))
                except Exception:
                    pass
                if not self._init_ipset():
                    return False
                self._load_active_bans()
            self.running = True
            if not self.dry_run:
                self.expiry_thread = threading.Thread(target=self._expiry_loop, daemon=True)
                self.expiry_thread.start()
                if self._scapy_available:
                    self.arp_thread = threading.Thread(target=self._arp_poison_thread, daemon=True)
                    self.arp_thread.start()
            return True

    def _check_root(self):
        return hasattr(os, 'geteuid') and os.geteuid() == 0

    def _load_config(self):
        import json
        try:
            with open('/etc/dsips/config.json') as stream:
                cfg = json.load(stream)
            if not isinstance(cfg, dict):
                return
            entries = cfg.get('whitelisted_ips', [])
            if not isinstance(entries, list):
                entries = []
            for entry in entries:
                try:
                    if not isinstance(entry, str):
                        raise ValueError('Address must be a string')
                    # Keep valid entries even if another item is malformed.
                    parsed = (ipaddress.ip_network(entry, strict=False) if '/' in entry
                              else ipaddress.ip_address(entry))
                    self.whitelist.add(str(parsed))
                except (ValueError, TypeError):
                    logging.warning('Invalid allowlist entry ignored: %r', entry)
            for key, severity in [('block_critical', 'critical'), ('block_high', 'high'), ('block_ddos', 'medium')]:
                value = cfg.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                    self.BAN_DURATIONS[severity] = value
            self.dry_run = self.dry_run or cfg.get('dry_run') is True
        except (OSError, ValueError, TypeError):
            pass

    def get_ban_duration(self, severity='medium'):
        return self.BAN_DURATIONS.get(str(severity).lower(), self.auto_unban_time)

    def is_protected_ip(self, ip):
        """Return whether an address is infrastructure or in the IP/CIDR allowlist."""
        address = ipaddress.ip_address(ip)
        if (address.is_loopback or address.is_unspecified or address.is_multicast
                or str(address) == '255.255.255.255'):
            return True
        for entry in tuple(self.whitelist):
            try:
                if address in ipaddress.ip_network(entry, strict=False):
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def _validate_ip(self, ip, protected=False):
        address = ipaddress.IPv4Address(ip)
        value = str(address)
        if protected and self.is_protected_ip(value):
            raise ValueError(f"Korumalı IP engellenemez: {value}")
        return value

    def _validate_mac(self, mac, protected=False):
        if not isinstance(mac, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
            raise ValueError('Geçersiz MAC adresi')
        mac = mac.lower()
        if protected and (mac == self.gateway_mac or mac == '00:00:00:00:00:00' or int(mac[:2], 16) & 1):
            raise ValueError('Korumalı MAC adresi')
        return mac

    def _run(self, command):
        return subprocess.run(command, capture_output=True, check=True, timeout=5)

    def _ensure_rule(self, rule, insert=True):
        result = subprocess.run(['iptables', '-C', *rule], capture_output=True, timeout=5)
        if result.returncode == 0:
            return False
        if result.returncode != 1:
            raise subprocess.CalledProcessError(result.returncode, result.args, stderr=result.stderr)
        self._run(['iptables', '-I' if insert else '-A', *rule])
        return True

    def _delete_rule(self, rule):
        result = subprocess.run(['iptables', '-C', *rule], capture_output=True, timeout=5)
        if result.returncode == 1:
            return
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, result.args, stderr=result.stderr)
        self._run(['iptables', '-D', *rule])

    def _mac_rules(self, mac):
        return [[chain, '-m', 'mac', '--mac-source', mac, '-m', 'comment', '--comment', 'dsips-block', '-j', 'DROP'] for chain in ('INPUT', 'FORWARD')]

    def _init_ipset(self):
        try:
            self._run(['ipset', 'create', self.SET_NAME, 'hash:ip', 'timeout', '0', '-exist'])
            for chain in ('INPUT', 'FORWARD'):
                self._ensure_rule([chain, '-m', 'set', '--match-set', self.SET_NAME, 'src', '-j', 'DROP'])
            return True
        except (OSError, subprocess.SubprocessError):
            logging.exception('Firewall initialization failed')
            return False

    def _load_active_bans(self):
        active, stale = {}, []
        for ban in self.db.get_active_bans():
            ip, mac = ban.get('ip_address'), ban.get('mac_address')
            validated = False
            try:
                ip = self._validate_ip(ip) if ip else None
                mac = self._validate_mac(mac) if mac else None
                validated = True
                if not ip and not mac:
                    self.db.remove_ban_by_id(ban['id'])
                    continue
                expiry = ban.get('expires_at')
                now = datetime.now(timezone.utc)
                if expiry:
                    deadline = datetime.fromisoformat(expiry)
                else:
                    # Old rows without expires_at must not gain a fresh full
                    # lifetime on every service restart.
                    created = datetime.fromisoformat(ban['ban_time'])
                    deadline = created + timedelta(seconds=self.auto_unban_time)
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=timezone.utc)
                remaining = int((deadline - now).total_seconds())
                protected = bool(ip and self.is_protected_ip(ip))
                try:
                    if mac:
                        self._validate_mac(mac, protected=True)
                except ValueError:
                    protected = True
                if protected or remaining <= 0 or str(ban.get('reason', '')).startswith('[DRY RUN]'):
                    stale.append((ban['id'], ip, mac))
                else:
                    target = (ip, mac)
                    active[target] = max(active.get(target, 0), remaining)
            except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
                logging.exception('Unable to restore ban for %s/%s', ip, mac)
                if validated and ban.get('id') is not None:
                    # Corrupt timestamps cannot create an unbounded kernel ban.
                    stale.append((ban['id'], ip, mac))
        active_ips = {ip for ip, _ in active if ip}
        active_macs = {mac for _, mac in active if mac}
        for ban_id, ip, mac in stale:
            try:
                # An expired historical row must not cancel a newer valid ban.
                if ip and ip not in active_ips:
                    self._run(['ipset', 'del', self.SET_NAME, ip, '-exist'])
                if mac and mac not in active_macs:
                    for rule in self._mac_rules(mac):
                        self._delete_rule(rule)
                self.db.remove_ban_by_id(ban_id)
            except (OSError, subprocess.SubprocessError):
                logging.exception('Unable to clean up expired ban %s', ban_id)
                # Keep stale rules owned even when the firewall is temporarily
                # unavailable. The expiry worker will retry after startup.
                if ip:
                    self.blocked_ips.add(ip)
                if mac:
                    self.blocked_macs.add(mac)
                self._expires[(ip, mac)] = time.monotonic()
        # Restore longest overlapping IP timeouts last; shorter duplicates must
        # never shorten the effective lifetime of a later valid ban.
        for (ip, mac), remaining in sorted(active.items(), key=lambda item: item[1]):
            try:
                self._apply_ban(ip, mac, remaining)
            except (ValueError, OSError, subprocess.SubprocessError):
                logging.exception('Unable to restore ban for %s/%s', ip, mac)

    def _apply_ban(self, ip, mac, duration):
        if isinstance(duration, bool) or not isinstance(duration, int) or duration <= 0:
            raise ValueError('Ban süresi pozitif bir tam sayı olmalı')
        previous_ip_expiry = max((deadline for target, deadline in self._expires.items()
                                  if ip and target[0] == ip), default=None)
        added = []
        ip_applied = False
        try:
            if ip:
                self._run(['ipset', 'add', self.SET_NAME, ip, 'timeout', str(max(1, int(duration))), '-exist'])
                ip_applied = True
            if mac:
                for rule in self._mac_rules(mac):
                    if self._ensure_rule(rule):
                        added.append(rule)
        except Exception as error:
            pending_ip = pending_mac = None
            for rule in reversed(added):
                try:
                    self._delete_rule(rule)
                except (OSError, subprocess.SubprocessError):
                    pending_mac = mac
                    logging.exception('Firewall rollback failed')
            if ip and (ip_applied or isinstance(error, subprocess.TimeoutExpired)):
                try:
                    if previous_ip_expiry is None:
                        self._run(['ipset', 'del', self.SET_NAME, ip, '-exist'])
                    else:
                        remaining = max(1, int(previous_ip_expiry - time.monotonic()) + 1)
                        self._run(['ipset', 'add', self.SET_NAME, ip, 'timeout', str(remaining), '-exist'])
                except (OSError, subprocess.SubprocessError):
                    if previous_ip_expiry is None:
                        pending_ip = ip
                    logging.exception('IP set rollback failed')
            if pending_ip or pending_mac:
                # A failed rollback still owns rules. Retain them for the
                # expiry worker/cleanup path instead of silently orphaning them.
                if pending_ip:
                    self.blocked_ips.add(pending_ip)
                if pending_mac:
                    self.blocked_macs.add(pending_mac)
                self._expires[(pending_ip, pending_mac)] = time.monotonic()
            raise
        if ip:
            self.blocked_ips.add(ip)
        if mac:
            self.blocked_macs.add(mac)
        if ip and mac:
            self.ip_mac_map[mac] = ip
            self.mac_ip_map[ip] = mac
        self._expires[(ip, mac)] = time.monotonic() + duration

    def block_ip(self, ip, reason='Otomatik tespit', severity='medium'):
        ip = self._validate_ip(ip, protected=True)
        if self.dry_run or not self.running:
            return False
        with self.lock:
            if self.dry_run or not self.running or ip in self.blocked_ips:
                return False
            try:
                duration = self.get_ban_duration(severity)
                # A source IP can share its observed MAC with many other hosts
                # behind a router. An IP decision must remain IP scoped.
                self._apply_ban(ip, None, duration)
                try:
                    self.db.add_ban(ip, None, reason, duration=duration)
                except Exception:
                    self._remove_ban(ip, None)
                    raise
                self._record_defense('block_ip', ip, None, reason)
                return True
            except Exception:
                logging.exception('IP engelleme başarısız: %s', ip)
                return False

    def block_mac(self, mac, reason='Otomatik tespit', severity='medium'):
        mac = self._validate_mac(mac, protected=True)
        if self.dry_run or not self.running:
            return False
        with self.lock:
            if self.dry_run or not self.running or mac in self.blocked_macs:
                return False
            try:
                ip = self._resolve_ip_for_mac(mac)
                ip = self._validate_ip(ip, protected=True) if ip else None
                duration = self.get_ban_duration(severity)
                self._apply_ban(None, mac, duration)
                try:
                    self.db.add_ban(None, mac, reason, duration=duration)
                except Exception:
                    self._remove_ban(None, mac)
                    raise
                self._record_defense('block_mac', None, mac, reason)
                return True
            except Exception:
                logging.exception('MAC engelleme başarısız: %s', mac)
                return False

    def _record_defense(self, module, ip, mac, reason):
        if self.active_defense_mgr:
            try:
                self.active_defense_mgr.add_rule(module, target_ip=ip, target_mac=mac,
                                                 parameters={'reason': reason})
            except Exception:
                # The durable ban and its expiry already exist. A secondary UI
                # ledger failure must not misreport the firewall result.
                logging.exception('Unable to record active defense metadata')

    def _remove_ban(self, ip, mac):
        if self.dry_run or not self._check_root():
            return False
        with self.lock:
            try:
                target = (ip, mac)
                others = [item for item in self._expires if item != target]
                remove_ip = ip and not any(item[0] == ip for item in others)
                remove_mac = mac and not any(item[1] == mac for item in others)
                if remove_ip:
                    self._run(['ipset', 'del', self.SET_NAME, ip, '-exist'])
                if remove_mac:
                    for rule in self._mac_rules(mac):
                        self._delete_rule(rule)
                for ban in self.db.get_active_bans():
                    saved_mac = ban.get('mac_address')
                    saved_mac = saved_mac.lower() if saved_mac else None
                    if (ban.get('ip_address') or None, saved_mac) == target:
                        self.db.remove_ban_by_id(ban['id'])
                if remove_ip:
                    self.blocked_ips.discard(ip)
                if remove_mac:
                    self.blocked_macs.discard(mac)
                    self.intercepted_macs.discard(mac)
                self._expires.pop(target, None)
                if self.active_defense_mgr:
                    try:
                        if remove_ip:
                            for module in ('block_ip', 'block_mac'):
                                self.active_defense_mgr.remove_rule_by_target(module, ip)
                        if remove_mac:
                            self.active_defense_mgr.remove_rule_by_target('block_mac', target_mac=mac)
                    except Exception:
                        logging.exception('Unable to remove active defense metadata')
                if remove_mac:
                    self._restore_arp(ip or self.ip_mac_map.get(mac), mac)
                if self.db.socketio:
                    try:
                        self.db.socketio.emit('ban_update', {'action': 'removed', 'ip': ip, 'mac': mac}, namespace='/')
                    except Exception:
                        logging.exception('Unable to publish ban removal')
                return True
            except Exception:
                logging.exception('Ban removal failed: %s/%s', ip, mac)
                return False

    def unblock_ip(self, ip):
        ip = self._validate_ip(ip)
        with self.lock:
            targets = [target for target in self._expires if target[0] == ip]
            if not targets:
                targets = [(ip, None)]
            return all([self._remove_ban(*target) for target in targets])

    def unblock_mac(self, mac):
        mac = self._validate_mac(mac)
        with self.lock:
            targets = [target for target in self._expires if target[1] == mac]
            if not targets:
                targets = [(None, mac)]
            return all([self._remove_ban(*target) for target in targets])

    def expire_bans(self):
        """Reconcile expired and newly protected targets under the policy lock."""
        removed = 0
        with self.lock:
            now = time.monotonic()
            for (ip, mac), deadline in list(self._expires.items()):
                if deadline <= now or (ip and self.is_protected_ip(ip)):
                    removed += bool(self._remove_ban(ip, mac))
        return removed

    def _expiry_loop(self):
        while not self._stop_event.wait(1):
            self.expire_bans()

    def _restore_arp(self, ip, mac):
        if self.dry_run or not all((ip, mac, self.gateway_ip, self.gateway_mac, self._scapy_available)):
            return
        try:
            from scapy.all import ARP, Ether, sendp
            sendp(Ether(dst=mac)/ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac), iface=self.interface, count=3, verbose=False)
            sendp(Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=mac), iface=self.interface, count=3, verbose=False)
        except Exception:
            logging.exception('ARP restore failed')

    def intercept_ip(self, ip):
        ip = self._validate_ip(ip, protected=True)
        if self.dry_run or not self.running:
            return False
        mac = self._resolve_mac_for_ip(ip)
        if not mac:
            return False
        mac = self._validate_mac(mac, protected=True)
        with self.lock:
            self.intercepted_macs.add(mac)
        return True

    def stop_intercept_ip(self, ip):
        ip = self._validate_ip(ip)
        if self.dry_run:
            return False
        with self.lock:
            mac = self.mac_ip_map.get(ip)
            self.intercepted_macs.discard(mac)
            if mac not in self.blocked_macs:
                self._restore_arp(ip, mac)
        return True

    def _limit_rules(self, ip, rate):
        rules = []
        for chain, direction in [('FORWARD', '-d'), ('FORWARD', '-s'), ('INPUT', '-s')]:
            base = [chain, direction, ip, '-m', 'comment', '--comment', 'dsips-rate']
            name = f'ds_{int(ipaddress.IPv4Address(ip)):08x}_{chain[0]}{direction[1]}'
            rules.append(base + ['-m', 'hashlimit', '--hashlimit-above', rate,
                                 '--hashlimit-mode', 'srcip' if direction == '-s' else 'dstip',
                                 '--hashlimit-name', name, '-j', 'DROP'])
        return rules

    def rate_limit_ip(self, ip, rate='1/s'):
        ip = self._validate_ip(ip, protected=True)
        if not re.fullmatch(r'[1-9][0-9]*(?:/(?:s|sec|second|m|min|minute|h|hour|d|day))?', rate):
            raise ValueError('Geçersiz hız sınırı')
        if self.dry_run or not self.running:
            return False
        with self.lock:
            if self.dry_run or not self.running or ip in self._rate_rules:
                return False
            added = []
            try:
                # Only excess traffic terminates here. Traffic below the limit
                # must still pass the existing firewall's authorization rules.
                for rule in reversed(self._limit_rules(ip, rate)):
                    if self._ensure_rule(rule):
                        added.append(rule)
                self._rate_rules[ip] = rate
                if self.active_defense_mgr:
                    try:
                        self.active_defense_mgr.add_rule('rate_limit', target_ip=ip, parameters={'rate': rate})
                    except Exception:
                        logging.exception('Unable to record rate-limit metadata')
                return True
            except Exception:
                cleanup_failed = False
                for rule in reversed(added):
                    try:
                        self._delete_rule(rule)
                    except Exception:
                        cleanup_failed = True
                        logging.exception('Rate-limit rollback failed')
                if cleanup_failed:
                    self._rate_rules[ip] = rate
                return False

    def unrate_limit_ip(self, ip, rate='1/s'):
        ip = self._validate_ip(ip)
        if self.dry_run or not self._check_root():
            return False
        with self.lock:
            try:
                rate = self._rate_rules.get(ip, rate)
                for rule in self._limit_rules(ip, rate):
                    self._delete_rule(rule)
                self._rate_rules.pop(ip, None)
                if self.active_defense_mgr:
                    try:
                        self.active_defense_mgr.remove_rule_by_target('rate_limit', ip)
                    except Exception:
                        logging.exception('Unable to remove rate-limit metadata')
                self.stop_intercept_ip(ip)
                return True
            except Exception:
                logging.exception('Rate-limit removal failed')
                return False

    def kill_session_hardware(self, ip):
        ip = self._validate_ip(ip, protected=True)
        if self.dry_run or not self.running:
            return False
        added = []
        success = True
        try:
            for direction in ('-s', '-d'):
                rule = ['FORWARD', '-p', 'tcp', direction, ip, '-m', 'comment', '--comment', 'dsips-rst', '-j', 'REJECT', '--reject-with', 'tcp-reset']
                if self._ensure_rule(rule):
                    added.append(rule)
            self._stop_event.wait(2)
        except Exception:
            logging.exception('TCP reset rules failed')
            success = False
        finally:
            for rule in reversed(added):
                try:
                    self._delete_rule(rule)
                except Exception:
                    logging.exception('TCP reset cleanup failed')
                    success = False
        return success

    def unblock_all(self):
        with self.lock:
            ips, macs = tuple(self.blocked_ips), tuple(self.blocked_macs)
        success = True
        for ip in ips:
            success = self.unblock_ip(ip) and success
        for mac in macs:
            if mac in self.blocked_macs:
                success = self.unblock_mac(mac) and success
        return success

    def cleanup_all(self):
        if self.dry_run or not self._check_root():
            return False
        success = self.unblock_all()
        for ip in tuple(self._rate_rules):
            success = self.unrate_limit_ip(ip) and success
        for mac in tuple(self.intercepted_macs):
            ip = self.ip_mac_map.get(mac)
            if ip:
                self.stop_intercept_ip(ip)
        # Keep the empty set and its hooks available for subsequent bans.
        return success

    def get_blocked_hosts(self):
        with self.lock:
            return {'ips': sorted(self.blocked_ips), 'macs': sorted(self.blocked_macs)}

    def stop(self):
        with self.lock:
            self.running = False
            self._stop_event.set()
        for thread in (self.arp_thread, self.expiry_thread):
            if thread and thread is not threading.current_thread():
                thread.join(timeout=4)
        if not self.dry_run:
            self.cleanup_all()
        with self.lock:
            for mac in self.blocked_macs | self.intercepted_macs:
                self._restore_arp(self.ip_mac_map.get(mac), mac)
            self.intercepted_macs.clear()

    def _get_gateway_info(self):
        """Ağ geçidi IP ve MAC adresini tespit eder."""
        if not self._scapy_available:
            # Fallback: ip route ile gateway bul
            try:
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if 'default via' in line:
                        parts = line.split()
                        idx = parts.index('via') + 1
                        self.gateway_ip = parts[idx]
                        break
            except Exception:
                pass
            return
            
        try:
            from scapy.all import conf, getmacbyip
            gw = conf.route.route("0.0.0.0")[2]
            if gw and gw != '0.0.0.0':
                self.gateway_ip = gw
                self.gateway_mac = None if self.dry_run else getmacbyip(gw)
                self.whitelist.add(self.gateway_ip)
                if self.gateway_mac:
                    print(f"{Fore.GREEN}[+] Gateway tespit edildi: {self.gateway_ip} ({self.gateway_mac}){Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] Gateway IP bulundu ({gw}) ama MAC alınamadı{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Gateway IP bulunamadı{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Gateway tespiti hatası: {e}{Style.RESET_ALL}")

    def _resolve_ip_for_mac(self, mac_address):
        """Bir MAC adresi için IP adresini çözümler."""
        # 1. Önce kendi eşleştirme tablomuzdan bak
        with self.lock:
            if mac_address in self.ip_mac_map:
                return self.ip_mac_map[mac_address]
        
        # 2. Veritabanındaki ip_mac_records tablosundan bak
        try:
            with self.db.lock:
                self.db.cursor.execute(
                    'SELECT ip_address FROM ip_mac_records WHERE mac_address = ? ORDER BY last_seen DESC LIMIT 1',
                    (mac_address,)
                )
                row = self.db.cursor.fetchone()
                if row:
                    ip = row['ip_address'] if isinstance(row, dict) else row[0]
                    with self.lock:
                        self.ip_mac_map[mac_address] = ip
                        self.mac_ip_map[ip] = mac_address
                    return ip
        except Exception:
            pass
        
        # 3. ARP taramasıyla bul
        if not self.dry_run and self._scapy_available and self.gateway_ip:
            try:
                from scapy.all import ARP, Ether, srp
                # Ağdaki tüm cihazları tara
                network = '.'.join(self.gateway_ip.split('.')[:3]) + '.0/24'
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), 
                           iface=self.interface, timeout=3, verbose=False)
                for _, rcv in ans:
                    if rcv.hwsrc.lower() == mac_address.lower():
                        ip = rcv.psrc
                        with self.lock:
                            self.ip_mac_map[mac_address] = ip
                            self.mac_ip_map[ip] = mac_address
                        return ip
            except Exception:
                pass
        
        return None

    def _resolve_mac_for_ip(self, ip_address):
        """Bir IP adresi için ağa anında ARP atarak MAC adresini bulur."""
        # 1. Önce eşleştirme tablosu
        with self.lock:
            if ip_address in self.mac_ip_map:
                return self.mac_ip_map[ip_address]
                
        # 2. Veritabanına bak (Geçmiş cihaz kayıtları)
        if hasattr(self, 'db') and self.db:
            try:
                with self.db.lock:
                    self.db.cursor.execute(
                        'SELECT mac_address FROM ip_mac_records WHERE ip_address = ? ORDER BY last_seen DESC LIMIT 1',
                        (ip_address,)
                    )
                    row = self.db.cursor.fetchone()
                    if row:
                        mac = row['mac_address'] if isinstance(row, dict) else row[0]
                        with self.lock:
                            self.mac_ip_map[ip_address] = mac
                            self.ip_mac_map[mac] = ip_address
                        return mac
            except Exception:
                pass
        
        # 3. Aktif ARP sorgusu
        if not self.dry_run and self._scapy_available:
            try:
                from scapy.all import ARP, Ether, srp
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), 
                           iface=self.interface, timeout=2, verbose=False)
                for _, rcv in ans:
                    mac = rcv.hwsrc
                    with self.lock:
                        self.mac_ip_map[ip_address] = mac
                        self.ip_mac_map[mac] = ip_address
                    return mac
            except Exception:
                pass
        return None

    def _arp_poison_thread(self):
        """
        Banlanmış cihazları ağdan izole etmek için sürekli sahte ARP paketleri gönderir.
        
        v5 Profesyonel İzolasyon Mantığı:
        - Kurbana: "Gateway MAC adresi BENİM MAC'im" der → kurbanın trafiği Kali'ye gelir → iptables DROP
        - Gateway'e: "Kurbanın MAC adresi BENİM MAC'im" der → gateway'den kurbana gelen trafik Kali'ye gelir → iptables DROP
        - Her iki yönde de tam izolasyon sağlanır
        - Kurbanın IP adresini bilmesi ZORUNLU (pdst alanı)
        """
        try:
            from scapy.all import ARP, Ether, sendp, get_if_hwaddr
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        except ImportError:
            print(f"{Fore.RED}[!] İzolasyon için scapy gerekli. Lütfen kurun.{Style.RESET_ALL}")
            return

        print(f"{Fore.GREEN}[+] ARP İzolasyon thread'i aktif - banlanmış cihazları ağdan koparacak{Style.RESET_ALL}")
        
        while self.running:
            try:
                my_mac = get_if_hwaddr(self.interface)
            except Exception:
                my_mac = "02:00:00:00:00:00"

            if not self.gateway_ip:
                self._get_gateway_info()
                self._stop_event.wait(2)
                continue
                
            if not self.blocked_macs and not self.intercepted_macs:
                self._stop_event.wait(1)
                continue
                
            try:
                with self.lock:
                    # Hem tam izolasyon (Drop) hem de Intercept listesindeki cihazları zehirle
                    macs_to_poison = list(self.blocked_macs | self.intercepted_macs)
                    ip_mac_snapshot = dict(self.ip_mac_map)
                    
                for target_mac in macs_to_poison:
                    try:
                        if not self.running or target_mac == self.gateway_mac or not target_mac or target_mac == "ff:ff:ff:ff:ff:ff":
                            continue
                            
                        # Kurbanın IP adresini bul (ARP poisoning için ZORUNLU)
                        victim_ip = ip_mac_snapshot.get(target_mac)
                        if not victim_ip:
                            # IP'yi çözümlemeyi dene
                            victim_ip = self._resolve_ip_for_mac(target_mac)
                            if not victim_ip:
                                continue  # IP bulamadıysak ARP zehirlemesi yapamayız
                        
                        # ═══════════════════════════════════════════
                        # PAKET 1: KURBANI ZEHİRLE
                        # Kurbana söyle: "Gateway'in MAC adresi benim (Kali) MAC adresim"
                        # Böylece kurban internete çıkmaya çalıştığında paketler Kali'ye gelir
                        # Kali'deki iptables DROP kuralı bu paketleri çöpe atar
                        # ═══════════════════════════════════════════
                        if victim_ip in self.whitelist:
                            continue
                        poison_victim = Ether(dst=target_mac) / ARP(
                            op=2,          # ARP Reply
                            pdst=victim_ip,    # Kurbanın IP'si (paketi kimin alacağı)
                            hwdst=target_mac,  # Kurbanın MAC'i
                            psrc=self.gateway_ip,  # "Ben gateway'im" diye yalan söylüyoruz
                            hwsrc=my_mac       # Kendi MAC'imizi gateway'inmiş gibi gösteriyoruz
                        )
                        sendp(poison_victim, iface=self.interface, verbose=False)
                        
                        # ═══════════════════════════════════════════
                        # PAKET 2: GATEWAY'İ (MODEMİ) ZEHİRLE
                        # Gateway'e söyle: "Kurbanın MAC adresi benim (Kali) MAC adresim"
                        # Böylece dışarıdan kurbana gelen paketler de Kali'ye gelir ve DROP edilir
                        # ═══════════════════════════════════════════
                        if self.gateway_mac:
                            poison_gateway = Ether(dst=self.gateway_mac) / ARP(
                                op=2,              # ARP Reply
                                pdst=self.gateway_ip,  # Gateway'in IP'si (paketi kimin alacağı)
                                hwdst=self.gateway_mac, # Gateway'in MAC'i
                                psrc=victim_ip,    # "Ben kurbanım" diye yalan söylüyoruz
                                hwsrc=my_mac       # Kendi MAC'imizi kurbanınmış gibi gösteriyoruz
                            )
                            sendp(poison_gateway, iface=self.interface, verbose=False)
                        
                        # ═══════════════════════════════════════════
                        # PAKET 3: BROADCAST ARP (Ağdaki herkese duyur)
                        # Tüm ağa: "Gateway'in MAC'i benim" diye broadcast ARP at
                        # Bu, kurbanın ARP cache timeout'unu sıfırlar
                        # ═══════════════════════════════════════════
                        # broadcast_poison = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        #     op=2,
                        #     pdst=victim_ip,
                        #     hwdst="ff:ff:ff:ff:ff:ff",
                        #     psrc=self.gateway_ip,
                        #     hwsrc=my_mac
                        # )
                        # sendp(broadcast_poison, iface=self.interface, verbose=False)
                        
                    except Exception:
                        pass
            except Exception:
                pass
                
            # ARP iyileşmesini önlemek için yüksek frekansta (0.3s) saldır
            self._stop_event.wait(0.3)
