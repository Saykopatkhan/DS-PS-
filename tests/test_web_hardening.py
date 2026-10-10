"""Offline HTTP regressions for bounded alerts and honest defense status."""

from unittest.mock import MagicMock

import pytest

from test_web_security import login, panel as panel
from web.app import IPSWebApp


def test_public_canary_is_unverified_and_suppresses_repeat_alerts(panel):
    client = panel.app.test_client()
    panel.sniffer_running = True
    for _ in range(3):
        assert client.get('/sirket_sifreleri.pdf').status_code == 403
    alerts = panel.db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]['severity'] == 'medium'
    panel.legacy_sniffer.dump_pcap.assert_not_called()
    assert panel.notifier.send_alert.call_count == 1

    # A different canary remains observable; the same one becomes observable
    # again after its suppression window without retaining unlimited sources.
    assert client.get('/banka_bilgileri.xlsx').status_code == 403
    panel._canary_alert_times[('127.0.0.1', 'sirket_sifreleri.pdf')] -= 301
    assert client.get('/sirket_sifreleri.pdf').status_code == 403
    assert panel.db.get_total_alert_count() == 3


def test_public_canary_source_cache_is_bounded(panel):
    panel._canary_alert_times = {(str(index), 'canary'): 1 for index in range(2048)}
    panel.app.test_client().get('/sirket_sifreleri.pdf')
    assert len(panel._canary_alert_times) == 2048
    assert ('0', 'canary') not in panel._canary_alert_times


@pytest.mark.parametrize('failure', [False, OSError('firewall unavailable')])
def test_unban_preserves_failed_rule_and_reports_incomplete_cleanup(panel, failure):
    panel.blocker = MagicMock()
    panel.blocker.unblock_ip.return_value = True
    panel.blocker.unrate_limit_ip.return_value = True
    panel.tarpit.untarpit_ip.return_value = False
    if isinstance(failure, Exception):
        panel.tarpit.untarpit_ip.side_effect = failure
    panel.dns_sinkhole.remove_quarantine_redirect.return_value = True
    target = '192.0.2.10'
    for module in ('tarpit', 'quarantine'):
        panel.active_defense_mgr.add_rule(module, target_ip=target)
    client = panel.app.test_client()
    csrf = login(panel, client)
    result = client.post('/api/unban', json={'ip': target}, headers={'X-CSRF-Token': csrf})
    assert result.status_code == 503
    assert result.json['success'] is False
    assert result.json['remaining_modules'] == ['tarpit']
    assert [row['module'] for row in panel.active_defense_mgr.get_all_rules()] == ['tarpit']
    panel.dns_sinkhole.remove_quarantine_redirect.assert_called_once_with(target)
    panel.blocker.unrate_limit_ip.assert_called_once_with(target)

    panel.tarpit.untarpit_ip.side_effect = None
    panel.tarpit.untarpit_ip.return_value = True
    retry = client.post('/api/unban', json={'ip': target}, headers={'X-CSRF-Token': csrf})
    assert retry.status_code == 200
    assert panel.active_defense_mgr.get_all_rules() == []


def test_fast_alerts_retain_severity_and_destination_without_direct_ban(panel):
    panel.mode = 'ips'
    panel.blocker = MagicMock()
    panel.response_policy = MagicMock()
    panel.response_policy.observe.return_value = None
    panel._handle_fast_sniffer_event({
        'type': 'SYN_FLOOD', 'source_ip': '192.0.2.10',
        'destination_ip': '192.0.2.20', 'details': 'Rate anomaly', 'severity': 'medium',
    })
    alert = panel.db.get_alerts()[0]
    assert alert['severity'] == 'medium'
    assert alert['destination_ip'] == '192.0.2.20'
    panel.blocker.block_ip.assert_not_called()
    panel.response_policy.observe.assert_called_once()


def test_response_policy_read_apis_require_auth_and_bound_limits(panel):
    client = panel.app.test_client()
    for path in ('/api/incidents', '/api/response-policy'):
        assert client.get(path).status_code == 401
    login(panel, client)
    dashboard = client.get('/')
    assert dashboard.status_code == 200
    assert b'id="incident-table-body"' in dashboard.data
    panel.response_policy = MagicMock()
    panel.response_policy.get_incidents.return_value = [{'id': 1, 'status': 'advisory'}]
    panel.response_policy.status.return_value = {'enabled': False}
    assert client.get('/api/incidents?limit=20').json == [{'id': 1, 'status': 'advisory'}]
    panel.response_policy.get_incidents.assert_called_once_with(limit=20)
    assert client.get('/api/incidents?limit=1000000').status_code == 400
    assert client.get('/api/response-policy').json == {'enabled': False}


def test_alert_callback_attaches_policy_decision(panel):
    panel.response_policy = MagicMock()
    decision = {'action': 'advisory', 'reason': 'insufficient evidence'}
    panel.response_policy.observe.return_value = decision
    alert = {'id': 1, 'alert_type': 'Observation', 'description': 'Test', 'severity': 'medium'}
    panel._handle_alert(alert)
    panel.response_policy.observe.assert_called_once_with(alert, monitoring=False)
    assert alert['response'] == decision
    panel.notifier.send_alert.assert_called_once()


def test_ips_constructor_cannot_bypass_policy_or_scan_sources(panel, tmp_path):
    from modules.honeypot import Honeypot

    active_panel = IPSWebApp(mode='ips', db_path=str(tmp_path / 'ips.db'))
    try:
        assert Honeypot.call_args.kwargs['auto_ban'] is False
        assert active_panel.scan_detector.auto_vuln_scan_cb is None
        active_panel.vuln_scanner.scan_ip_async.assert_not_called()
    finally:
        active_panel.close()


def test_manual_ban_validates_both_targets_before_applying_either(panel):
    panel.blocker = MagicMock()
    panel.blocker._validate_mac.side_effect = ValueError('Korumalı MAC engellenemez')
    client = panel.app.test_client()
    csrf = login(panel, client)
    result = client.post('/api/ban', json={'ip': '192.0.2.10', 'mac': 'ff:ff:ff:ff:ff:ff'},
                         headers={'X-CSRF-Token': csrf})
    assert result.status_code == 400
    assert result.json['applied'] == {}
    panel.blocker.block_ip.assert_not_called()
    panel.blocker.block_mac.assert_not_called()


@pytest.mark.parametrize('failure', [False, OSError('firewall failure')])
def test_partial_manual_ban_reports_applied_and_pending_targets(panel, failure):
    panel.blocker = MagicMock()
    panel.blocker.block_ip.return_value = True
    panel.blocker.block_mac.return_value = failure
    if isinstance(failure, Exception):
        panel.blocker.block_mac.side_effect = failure
    client = panel.app.test_client()
    csrf = login(panel, client)
    result = client.post('/api/ban', json={'ip': '192.0.2.10', 'mac': '02:00:00:00:00:10'},
                         headers={'X-CSRF-Token': csrf})
    assert result.status_code in (500, 503)
    assert result.json['success'] is False
    assert result.json['applied'] == {'ip': '192.0.2.10'}
    assert result.json['pending'] == {'mac': '02:00:00:00:00:10'}
