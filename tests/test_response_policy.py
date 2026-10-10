"""Firewall policy regressions; every operating-system effect is mocked."""
import json
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, mock_open

import pytest

from core.database import Database
from responder.blocker import Blocker
from responder.tarpit import TCPTarpit


@pytest.fixture
def blocker(monkeypatch):
    monkeypatch.setattr(Blocker, '_load_config', lambda self: None)
    database = Database(':memory:')
    instance = Blocker(database)
    instance.running = True
    instance._scapy_available = False
    monkeypatch.setattr(instance, '_check_root', lambda: True)
    monkeypatch.setattr(instance, '_resolve_ip_for_mac', lambda mac: '192.0.2.20')
    calls = []

    def command(arguments, **kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 1 if '-C' in arguments else 0,
                                           stdout='', stderr='')

    monkeypatch.setattr('responder.blocker.subprocess.run', command)
    instance.test_commands = calls
    yield instance
    database.close()


def test_ip_ban_does_not_expand_to_router_mac(blocker, monkeypatch):
    resolve = Mock(side_effect=AssertionError('IP bans must not resolve or block MACs'))
    monkeypatch.setattr(blocker, '_resolve_mac_for_ip', resolve)
    assert blocker.block_ip('192.0.2.20') is True
    resolve.assert_not_called()
    assert blocker.get_blocked_hosts() == {'ips': ['192.0.2.20'], 'macs': []}
    assert blocker.db.get_active_bans()[0]['mac_address'] is None
    assert all(command[0] == 'ipset' for command in blocker.test_commands)


@pytest.mark.parametrize('method, target', [('block_ip', '192.0.2.20'),
                                           ('block_mac', '02:00:00:00:00:20'),
                                           ('rate_limit_ip', '192.0.2.20')])
def test_waiting_response_cannot_add_rules_after_shutdown(blocker, method, target):
    entered = threading.Event()
    owner = threading.current_thread()
    underlying = threading.RLock()

    class ObservedLock:
        def __enter__(self):
            if threading.current_thread() is not owner:
                entered.set()
            underlying.acquire()

        def __exit__(self, *args):
            underlying.release()

    blocker.lock = ObservedLock()
    result = []
    with blocker.lock:
        worker = threading.Thread(target=lambda: result.append(getattr(blocker, method)(target)))
        worker.start()
        assert entered.wait(2)
        blocker.stop()
    worker.join(2)
    assert not worker.is_alive()
    assert result == [False]
    assert blocker.test_commands == []
    assert blocker.db.get_active_bans() == []


def test_ip_release_does_not_release_independent_mac_ban(blocker):
    ip, mac = '192.0.2.20', '02:00:00:00:00:20'
    blocker.mac_ip_map[ip] = mac
    blocker.ip_mac_map[mac] = ip
    assert blocker.block_ip(ip)
    assert blocker.block_mac(mac)
    assert blocker.unblock_ip(ip)
    assert blocker.get_blocked_hosts() == {'ips': [], 'macs': [mac]}
    assert (None, mac) in blocker._expires
    assert len(blocker.db.get_active_bans()) == 1
    assert blocker.db.get_active_bans()[0]['mac_address'] == mac


def test_allowlist_accepts_cidr_and_keeps_valid_entries_after_invalid(monkeypatch):
    config = {'whitelisted_ips': ['bad', '198.51.100.0/24', '192.0.2.20', False],
              'block_high': 321, 'dry_run': True}
    monkeypatch.setattr('builtins.open', mock_open(read_data=json.dumps(config)))
    database = Database(':memory:')
    instance = Blocker(database)
    try:
        assert instance.is_protected_ip('198.51.100.99')
        assert instance.is_protected_ip('192.0.2.20')
        assert not instance.is_protected_ip('198.51.101.99')
        assert instance.get_ban_duration('high') == 321
        assert instance.dry_run is True
    finally:
        database.close()


def test_allowlist_applies_to_block_rate_limit_and_tarpit(blocker):
    blocker.whitelist.add('198.51.100.0/24')
    for action in (blocker.block_ip, blocker.rate_limit_ip):
        with pytest.raises(ValueError):
            action('198.51.100.15')
    tarpit = TCPTarpit(blocker=blocker)
    tarpit.running = True
    assert tarpit.tarpit_ip('198.51.100.15') is False
    assert tarpit.tarpit_ip('255.255.255.255') is False
    assert blocker.test_commands == []


def test_database_failure_rolls_back_ban(blocker, monkeypatch):
    monkeypatch.setattr(blocker.db, 'add_ban', Mock(side_effect=RuntimeError('disk full')))
    assert blocker.block_ip('192.0.2.20') is False
    assert blocker.get_blocked_hosts() == {'ips': [], 'macs': []}
    assert blocker._expires == {}
    assert any(command[:2] == ['ipset', 'del'] for command in blocker.test_commands)


def test_secondary_metadata_failure_keeps_truthful_firewall_result(blocker):
    blocker.active_defense_mgr = Mock()
    blocker.active_defense_mgr.add_rule.side_effect = RuntimeError('ledger unavailable')
    blocker.active_defense_mgr.remove_rule_by_target.side_effect = RuntimeError('ledger unavailable')
    assert blocker.block_ip('192.0.2.20') is True
    assert len(blocker.db.get_active_bans()) == 1
    assert blocker.unblock_ip('192.0.2.20') is True
    assert blocker.db.get_active_bans() == []


def test_new_allowlist_entry_releases_live_ban(blocker):
    assert blocker.block_ip('192.0.2.20')
    blocker.whitelist.add('192.0.2.0/24')
    assert blocker.expire_bans() == 1
    assert blocker.get_blocked_hosts() == {'ips': [], 'macs': []}
    assert blocker.db.get_active_bans() == []


def test_expiry_releases_only_elapsed_bans(blocker):
    assert blocker.block_ip('192.0.2.20')
    assert blocker.block_ip('192.0.2.21')
    blocker._expires[('192.0.2.20', None)] = time.monotonic() - 1
    assert blocker.expire_bans() == 1
    assert blocker.get_blocked_hosts()['ips'] == ['192.0.2.21']
    assert [ban['ip_address'] for ban in blocker.db.get_active_bans()] == ['192.0.2.21']


def save_ban(database, ip, mac=None, *, expires, created=None):
    database.add_ban(ip, mac, 'Test history', duration=3600)
    with database.lock:
        ban_id = database.cursor.execute('SELECT MAX(id) FROM banned_hosts').fetchone()[0]
        database.cursor.execute('UPDATE banned_hosts SET expires_at=? WHERE id=?', (expires, ban_id))
        if created is not None:
            database.cursor.execute('UPDATE banned_hosts SET ban_time=? WHERE id=?', (created, ban_id))
        database.conn.commit()
    return ban_id


def test_restart_handles_aware_timestamp_without_refreshing_lifetime(blocker):
    expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
    save_ban(blocker.db, '192.0.2.20', expires=expiry.isoformat())
    blocker._load_active_bans()
    remaining = blocker._expires[('192.0.2.20', None)] - time.monotonic()
    assert 290 <= remaining <= 300


def test_restart_does_not_extend_legacy_ban(blocker):
    created = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')
    save_ban(blocker.db, '192.0.2.20', expires=None, created=created)
    blocker._load_active_bans()
    assert blocker.db.get_active_bans() == []
    assert blocker.get_blocked_hosts()['ips'] == []
    assert any(command[:2] == ['ipset', 'del'] for command in blocker.test_commands)


def test_stale_duplicate_does_not_cancel_newer_ban(blocker):
    now = datetime.now(timezone.utc)
    save_ban(blocker.db, '192.0.2.20', expires=(now - timedelta(minutes=1)).isoformat())
    current_id = save_ban(blocker.db, '192.0.2.20', expires=(now + timedelta(minutes=5)).isoformat())
    blocker._load_active_bans()
    assert [ban['id'] for ban in blocker.db.get_active_bans()] == [current_id]
    assert blocker.get_blocked_hosts()['ips'] == ['192.0.2.20']
    assert not any(command[:2] == ['ipset', 'del'] for command in blocker.test_commands)


def test_shorter_duplicate_does_not_shorten_restored_ban(blocker):
    now = datetime.now(timezone.utc)
    save_ban(blocker.db, '192.0.2.20', expires=(now + timedelta(minutes=10)).isoformat())
    save_ban(blocker.db, '192.0.2.20', expires=(now + timedelta(minutes=2)).isoformat())
    blocker._load_active_bans()
    assert blocker._expires[('192.0.2.20', None)] - time.monotonic() > 590


@pytest.mark.parametrize('expiry', ['malformed', None])
def test_corrupt_or_protected_restored_ban_is_removed(blocker, expiry):
    blocker.whitelist.add('192.0.2.0/24')
    save_ban(blocker.db, '192.0.2.20', expires=expiry)
    blocker._load_active_bans()
    assert blocker.db.get_active_bans() == []
    assert blocker._expires == {}
    assert all(command[:2] != ['ipset', 'add'] for command in blocker.test_commands)


def test_overlapping_legacy_expiry_preserves_other_live_rule(blocker):
    ip, mac = '192.0.2.20', '02:00:00:00:00:20'
    blocker._apply_ban(ip, mac, 60)
    blocker.db.add_ban(ip, mac, 'Old paired scope', duration=60)
    blocker._apply_ban(ip, None, 600)
    blocker.db.add_ban(ip, None, 'IP scope', duration=600)
    blocker._expires[(ip, mac)] = time.monotonic() - 1
    blocker.test_commands.clear()
    assert blocker.expire_bans() == 1
    assert blocker.get_blocked_hosts() == {'ips': [ip], 'macs': []}
    assert len(blocker.db.get_active_bans()) == 1
    assert blocker.db.get_active_bans()[0]['mac_address'] is None
    assert not any(command[:2] == ['ipset', 'del'] for command in blocker.test_commands)


def test_tarpit_failed_rollback_remains_visible_and_retryable(monkeypatch):
    tarpit = TCPTarpit()
    tarpit.running = True

    def fail_after_first_rule(command, **kwargs):
        if '-C' in command:
            return subprocess.CompletedProcess(command, 1)
        if '-D' in command or 'FORWARD' in command:
            raise subprocess.CalledProcessError(2, command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr('responder.tarpit.subprocess.run', fail_after_first_rule)
    assert tarpit.tarpit_ip('192.0.2.20') is False
    assert tarpit.get_stats()['cleanup_pending_ips'] == ['192.0.2.20']
    assert tarpit.tarpit_ip('192.0.2.20') is False
    monkeypatch.setattr('responder.tarpit.subprocess.run', lambda command, **kwargs: subprocess.CompletedProcess(command, 0))
    assert tarpit.untarpit_ip('192.0.2.20') is True
    assert tarpit.get_stats()['cleanup_pending_ips'] == []
    assert tarpit.trapped_ips == set()


def test_tarpit_removal_tolerates_rule_already_deleted(monkeypatch):
    tarpit = TCPTarpit()
    tarpit.trapped_ips.add('192.0.2.20')
    tarpit._owned_rules['192.0.2.20'] = tarpit._rules('192.0.2.20')
    command = Mock(side_effect=lambda args, **kwargs: subprocess.CompletedProcess(args, 1))
    monkeypatch.setattr('responder.tarpit.subprocess.run', command)
    assert tarpit.untarpit_ip('192.0.2.20') is True
    assert not tarpit.trapped_ips
    assert all('-C' in call.args[0] for call in command.call_args_list)


def test_failed_rate_limit_rollback_can_be_retried(blocker, monkeypatch):
    ensure = Mock(side_effect=[True, subprocess.CalledProcessError(2, ['iptables'])])
    monkeypatch.setattr(blocker, '_ensure_rule', ensure)
    monkeypatch.setattr(blocker, '_delete_rule', Mock(side_effect=OSError('busy')))
    assert blocker.rate_limit_ip('192.0.2.20') is False
    assert blocker._rate_rules == {'192.0.2.20': '1/s'}
    monkeypatch.setattr(blocker, '_delete_rule', Mock())
    assert blocker.unrate_limit_ip('192.0.2.20') is True
    assert blocker._rate_rules == {}


def test_failed_ban_rollback_is_retried_by_expiry_worker(blocker, monkeypatch):
    mac = '02:00:00:00:00:20'
    monkeypatch.setattr(blocker, '_ensure_rule', Mock(side_effect=[True, OSError('busy')]))
    monkeypatch.setattr(blocker, '_delete_rule', Mock(side_effect=OSError('busy')))
    assert blocker.block_mac(mac) is False
    assert blocker.get_blocked_hosts()['macs'] == [mac]
    assert blocker.db.get_active_bans() == []
    monkeypatch.setattr(blocker, '_delete_rule', Mock())
    assert blocker.expire_bans() == 1
    assert blocker.get_blocked_hosts()['macs'] == []


def test_failed_startup_expiry_cleanup_remains_retryable(blocker, monkeypatch):
    ip, mac = '192.0.2.20', '02:00:00:00:00:20'
    now = datetime.now(timezone.utc)
    save_ban(blocker.db, ip, mac, expires=(now - timedelta(minutes=1)).isoformat())
    active_id = save_ban(blocker.db, ip, expires=(now + timedelta(minutes=5)).isoformat())
    monkeypatch.setattr(blocker, '_delete_rule', Mock(side_effect=OSError('busy')))
    blocker._load_active_bans()
    assert (ip, mac) in blocker._expires
    assert (ip, None) in blocker._expires
    monkeypatch.setattr(blocker, '_delete_rule', Mock())
    blocker.test_commands.clear()
    assert blocker.expire_bans() == 1
    assert blocker.get_blocked_hosts() == {'ips': [ip], 'macs': []}
    assert [ban['id'] for ban in blocker.db.get_active_bans()] == [active_id]
    assert not any(command[:2] == ['ipset', 'del'] for command in blocker.test_commands)
