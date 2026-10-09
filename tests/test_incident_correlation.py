"""Response decisions use local observations and a mocked firewall only."""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest

from core.database import Database
from core.response_policy import ResponsePolicy


@pytest.fixture
def policy(tmp_path):
    db = Database(tmp_path / 'incidents.db')
    blocker = Mock()
    blocker.is_protected_ip.return_value = False
    blocker.block_ip.return_value = True
    engine = ResponsePolicy(db, blocker, mode='ips', enabled=True, clock=lambda: 1000)
    yield engine
    db.close()


def event(kind, *, verified=False, source='192.0.2.20'):
    return {'id': 1, 'source_ip': source, 'alert_type': kind,
            'severity': 'critical', 'source_verified': verified}


def corroborate(policy, **kwargs):
    policy.observe(event('SSH_BRUTE_FORCE', verified=True), **kwargs)
    return policy.observe(event('Deep Honeypot Sızma (SSH)', verified=True), **kwargs)


def test_repeated_family_cannot_manufacture_independent_evidence(policy):
    for _ in range(100):
        result = policy.observe(event('SSH_BRUTE_FORCE', verified=True), monitoring=True)
    assert result['score'] == 50
    assert result['reason'] == 'insufficient_evidence'
    row = policy.get_incidents()[0]
    assert row['alert_count'] == 100
    assert row['signals']['authentication']['count'] == 100
    policy.blocker.block_ip.assert_not_called()


def test_packet_only_score_never_authorizes_response(policy):
    for kind in ('SYN Scan', 'UDP_FLOOD', 'DNS Tunneling / Exfiltration',
                 'DPI: YARA Match', 'C2 Beaconing (Time-Series)', 'Zararlı C&C Sunucu Bağlantısı'):
        result = policy.observe(event(kind), monitoring=True)
    assert result['score'] == 100
    assert result['decision'] == 'observe'
    policy.blocker.block_ip.assert_not_called()


@pytest.mark.parametrize('kind', ['ARP Spoofing', 'DHCP Rogue Server',
                                 'MAC Spoofing (Anti-Evasion)', 'Port Scanner (Açık Servisler)'])
def test_claimed_victims_and_own_inventory_never_add_response_evidence(policy, kind):
    result = policy.observe(event(kind, verified=True), monitoring=True)
    assert result['score'] == 0
    assert policy.get_incidents()[0]['signals']['unattributed']['verified'] is False
    policy.blocker.block_ip.assert_not_called()


@pytest.mark.parametrize('setting, value, reason', [
    ('enabled', False, 'automatic_response_disabled'),
    ('mode', 'ids', 'passive_mode'),
    ('dry_run', True, 'passive_mode'),
])
def test_mode_guards_preserve_reviewable_incident_without_firewall(policy, setting, value, reason):
    setattr(policy, setting, value)
    result = corroborate(policy, monitoring=True)
    assert result['decision'] == 'review'
    assert result['reason'] == reason
    assert policy.get_incidents()[0]['score'] == 85
    policy.blocker.block_ip.assert_not_called()


def test_stopped_monitoring_and_protected_addresses_do_not_block(policy):
    assert corroborate(policy)['reason'] == 'monitoring_stopped'
    policy.blocker.is_protected_ip.return_value = True
    assert corroborate(policy, monitoring=True)['reason'] == 'protected_address'
    policy.blocker.block_ip.assert_not_called()


def test_correlated_response_is_journaled_once_across_concurrency_and_restart(policy):
    result = corroborate(policy, monitoring=True)
    assert result['decision'] == 'blocked'
    policy.blocker.block_ip.assert_called_once()
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: policy.observe(event('SYN_FLOOD'), monitoring=True), range(12)))
    assert all(row['decision'] == 'blocked' for row in results)
    policy.blocker.block_ip.assert_called_once()
    restarted = ResponsePolicy(policy.db, policy.blocker, mode='ips', enabled=True, clock=lambda: 1001)
    assert restarted.observe(event('SSH_BRUTE_FORCE', verified=True), monitoring=True)['decision'] == 'blocked'
    policy.blocker.block_ip.assert_called_once()
    rows = policy.db.conn.execute('SELECT * FROM response_actions').fetchall()
    assert len(rows) == 1 and rows[0]['outcome'] == 'blocked'


@pytest.mark.parametrize('failure, reason', [(False, 'firewall_not_applied'), (OSError('unavailable'), 'firewall_error')])
def test_failed_firewall_is_visible_and_does_not_retry_per_packet(policy, failure, reason):
    if isinstance(failure, Exception):
        policy.blocker.block_ip.side_effect = failure
    else:
        policy.blocker.block_ip.return_value = failure
    result = corroborate(policy, monitoring=True)
    assert result['decision'] == 'failed'
    assert result['reason'] == reason
    corroborate(policy, monitoring=True)
    policy.blocker.block_ip.assert_called_once()
    assert policy.get_incidents()[0]['decision'] == 'failed'


def test_pending_reservation_is_durable_before_firewall_and_is_not_retried(policy):
    def interrupted(*args, **kwargs):
        assert policy.get_incidents()[0]['decision'] == 'pending'
        raise KeyboardInterrupt
    policy.blocker.block_ip.side_effect = interrupted
    with pytest.raises(KeyboardInterrupt):
        corroborate(policy, monitoring=True)
    restarted = ResponsePolicy(policy.db, policy.blocker, mode='ips', enabled=True, clock=lambda: 1001)
    assert restarted.observe(event('SYN Scan'), monitoring=True)['decision'] == 'pending'
    policy.blocker.block_ip.assert_called_once()


def test_evidence_expires_at_window_boundary(policy):
    first = policy.observe(event('SSH_BRUTE_FORCE', verified=True), monitoring=True)
    policy.clock = lambda: 1000 + policy.WINDOW_SECONDS
    second = policy.observe(event('Deep Honeypot Sızma (SSH)', verified=True), monitoring=True)
    assert first['incident_id'] != second['incident_id']
    assert second['score'] == 35
    assert [row['active'] for row in policy.get_incidents()] == [True, False]
    policy.blocker.block_ip.assert_not_called()


@pytest.mark.parametrize('source', [None, 'N/A', '127.0.0.1', '0.0.0.0', '224.0.0.1'])
def test_non_host_sources_do_not_create_incidents(policy, source):
    assert policy.observe(event('SSH_BRUTE_FORCE', source=source, verified=True), monitoring=True) is None
    assert policy.get_incidents() == []


def test_ipv6_remains_visible_without_unsupported_firewall_action(policy):
    result = policy.observe(event('SSH_BRUTE_FORCE', source='2001:db8::1', verified=True), monitoring=True)
    assert result['reason'] == 'ipv6_response_unsupported'
    assert policy.get_incidents()[0]['source_ip'] == '2001:db8::1'
    policy.blocker.block_ip.assert_not_called()


def test_retiring_stale_ban_does_not_retire_later_duplicate(policy):
    policy.db.add_ban('192.0.2.20', None, 'old')
    policy.db.add_ban('192.0.2.20', None, 'current')
    old = policy.db.get_active_bans()[0]
    assert policy.db.remove_ban_by_id(old['id'])
    assert not policy.db.remove_ban_by_id(old['id'])
    assert [ban['reason'] for ban in policy.db.get_active_bans()] == ['current']
