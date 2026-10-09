import asyncio
import subprocess
from unittest.mock import AsyncMock, Mock

import pytest
from core.database import Database
from responder.blocker import Blocker
from responder.gateway_mode import GatewayMode
from responder.tarpit import TCPTarpit
from responder.tcp_reset import TCPResetEngine


@pytest.fixture
def offline_blocker(monkeypatch):
    monkeypatch.setattr(Blocker, '_load_config', lambda self: None)
    db = Database(':memory:')
    blocker = Blocker(db)
    blocker.running = True
    blocker._scapy_available = False
    monkeypatch.setattr(blocker, '_check_root', lambda: True)
    monkeypatch.setattr(blocker, '_resolve_mac_for_ip', lambda ip: '02:00:00:00:00:01')
    yield blocker
    db.close()


def firewall_fake(command, **kwargs):
    return subprocess.CompletedProcess(command, 1 if '-C' in command else 0, stdout='', stderr='')


def test_construction_and_dry_run_never_mutate(monkeypatch):
    monkeypatch.setattr(Blocker, '_load_config', lambda self: None)
    run = Mock(side_effect=AssertionError('No firewall command expected'))
    monkeypatch.setattr('responder.blocker.subprocess.run', run)
    db = Database(':memory:')
    blocker = Blocker(db, dry_run=True)
    assert blocker.start()
    assert blocker.block_ip('192.0.2.1') is False
    assert blocker.block_mac('02:00:00:00:00:01') is False
    assert blocker.unblock_ip('192.0.2.1') is False
    assert blocker.unblock_mac('02:00:00:00:00:01') is False
    assert blocker.rate_limit_ip('192.0.2.1') is False
    assert blocker.unrate_limit_ip('192.0.2.1') is False
    assert blocker.kill_session_hardware('192.0.2.1') is False
    assert blocker.cleanup_all() is False
    assert db.get_active_bans() == []
    blocker.stop()
    run.assert_not_called()
    db.close()


def test_block_success_is_boolean_persists_expiry_and_unblocks(monkeypatch, offline_blocker):
    monkeypatch.setattr('responder.blocker.subprocess.run', firewall_fake)
    blocker = offline_blocker
    assert blocker.block_ip('192.0.2.1') is True
    assert blocker.db.get_active_bans()[0]['expires_at']
    assert blocker.block_ip('192.0.2.1') is False
    assert blocker.unblock_ip('192.0.2.1') is True
    assert blocker.get_blocked_hosts() == {'ips': [], 'macs': []}
    assert blocker.db.get_active_bans() == []
    assert blocker._expires == {}


def test_failed_firewall_never_claims_success(monkeypatch, offline_blocker):
    def failed(command, **kwargs):
        raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr('responder.blocker.subprocess.run', failed)
    assert offline_blocker.block_ip('192.0.2.1') is False
    assert offline_blocker.db.get_active_bans() == []
    assert offline_blocker.get_blocked_hosts() == {'ips': [], 'macs': []}


def test_protected_mac_resolution_cannot_bypass_whitelist(monkeypatch, offline_blocker):
    monkeypatch.setattr(offline_blocker, '_resolve_ip_for_mac', lambda mac: '127.0.0.1')
    run = Mock()
    monkeypatch.setattr('responder.blocker.subprocess.run', run)
    assert offline_blocker.block_mac('02:00:00:00:00:01') is False
    run.assert_not_called()
    for value in ('--help', '999.0.0.1', '::1'):
        with pytest.raises(ValueError):
            offline_blocker.block_ip(value)


def test_rate_limit_never_bypasses_existing_firewall_policy(monkeypatch, offline_blocker):
    calls = []
    def command(args, **kwargs):
        calls.append(args)
        return firewall_fake(args, **kwargs)
    monkeypatch.setattr('responder.blocker.subprocess.run', command)
    assert offline_blocker.rate_limit_ip('192.0.2.1')
    input_inserts = [cmd for cmd in calls if cmd[:3] == ['iptables', '-I', 'INPUT']]
    assert len(input_inserts) == 1
    assert input_inserts[0][-1] == 'DROP'
    assert '--hashlimit-above' in input_inserts[0]
    assert not any('ACCEPT' in cmd for cmd in calls)


def test_gateway_only_removes_owned_rules_restores_original_forwarding(monkeypatch):
    monkeypatch.setattr(GatewayMode, '_detect_network', lambda self: None)
    calls = []
    def command(args, **kwargs):
        calls.append(args)
        if args[:2] == ['sysctl', '-n']:
            return subprocess.CompletedProcess(args, 0, stdout='1\n')
        if '-C' in args:
            # Existing NAT belongs to prior setup and must remain untouched.
            return subprocess.CompletedProcess(args, 0 if 'POSTROUTING' in args else 1)
        return subprocess.CompletedProcess(args, 0)
    monkeypatch.setattr('responder.gateway_mode.subprocess.run', command)
    gateway = GatewayMode()
    assert gateway.enable()
    assert gateway.disable()
    deleted = [cmd for cmd in calls if '-D' in cmd]
    assert len(deleted) == 2
    assert all('FORWARD' in cmd for cmd in deleted)
    assert calls[-1] == ['sysctl', '-w', 'net.ipv4.ip_forward=1']


def test_gateway_range_is_contiguous_and_uses_real_subnet(monkeypatch):
    monkeypatch.setattr(GatewayMode, '_detect_network', lambda self: None)
    gateway = GatewayMode()
    gateway.local_ip = '192.0.2.5'
    gateway.gateway_ip = '192.0.2.10'
    gateway.subnet_mask = '255.255.255.240'
    start, end = gateway._generate_dhcp_range()
    import ipaddress
    values = range(int(ipaddress.ip_address(start)), int(ipaddress.ip_address(end)) + 1)
    assert int(ipaddress.ip_address(gateway.local_ip)) not in values
    assert int(ipaddress.ip_address(gateway.gateway_ip)) not in values
    assert ipaddress.ip_address(end) in ipaddress.ip_network('192.0.2.0/28')


def test_tarpit_releases_live_connection_slot():
    tarpit = TCPTarpit()
    connection = Mock()
    tarpit.active_connections.add(connection)
    tarpit._stop_event.set()
    tarpit._tarpit_client(connection, '192.0.2.1')
    assert not tarpit.active_connections
    connection.close.assert_called_once()


def test_tcp_sessions_require_exact_endpoint_and_do_not_fabricate(monkeypatch):
    outputs = ['0 0 192.0.2.1:80 192.0.2.10:8000\n0 0 192.0.2.1:443 192.0.2.2:4000', '']
    monkeypatch.setattr('responder.tcp_reset.subprocess.run', lambda args, **kwargs: Mock(stdout=outputs.pop(0)))
    engine = TCPResetEngine(dry_run=True)
    assert engine._find_active_sessions('192.0.2.2') == [('192.0.2.1', 443, '192.0.2.2', 4000)]
    monkeypatch.setattr('responder.tcp_reset.subprocess.run', lambda *args, **kwargs: Mock(stdout=''))
    assert engine._find_active_sessions('192.0.2.2') == []


def test_telegram_rejects_untrusted_chat_before_action():
    pytest.importorskip('telegram')
    from responder.telegram_bot import TelegramBot
    bot = TelegramBot.__new__(TelegramBot)
    bot.chat_id = '1234'
    bot.blocker = Mock()
    query = Mock(answer=AsyncMock(), data='ban:192.0.2.1')
    update = Mock(effective_chat=Mock(id=9999), callback_query=query)
    asyncio.run(bot.button_callback(update, None))
    bot.blocker.block_ip.assert_not_called()
    query.answer.assert_awaited_once_with('Yetkisiz işlem', show_alert=True)
