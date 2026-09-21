"""HTTP and Socket.IO regressions; networking and firewall components are mocked."""
import importlib
import re
from unittest.mock import MagicMock

import pytest

from web.app import IPSWebApp


@pytest.fixture
def panel(tmp_path, monkeypatch):
    monkeypatch.setenv('DS_IPS_USER', 'test-admin')
    monkeypatch.setenv('DS_IPS_PASSWORD', 'pássword with spaces ')
    monkeypatch.setenv('DS_IPS_SECRET_KEY', 'test-only-secret')
    components = [
        ('core.fast_sniffer', 'FastSniffer'), ('core.sniffer', 'PacketSniffer'),
        ('core.scanner', 'NetworkScanner'), ('responder.blocker', 'Blocker'),
        ('responder.notifier', 'Notifier'), ('responder.tarpit', 'TCPTarpit'),
        ('responder.tcp_reset', 'TCPResetEngine'), ('responder.gateway_mode', 'GatewayMode'),
        ('modules.dns_sinkhole', 'DNSSinkhole'), ('modules.honeypot', 'Honeypot'),
        ('modules.ssh_honeypot', 'SSHHoneypot'), ('modules.decoy_traffic', 'DecoyTrafficGenerator'),
        ('modules.arp_detector', 'ARPDetector'), ('modules.scan_detector', 'ScanDetector'),
        ('modules.wifi_detector', 'WiFiDetector'), ('modules.dns_detector', 'DNSDetector'),
        ('modules.dhcp_detector', 'DHCPDetector'), ('modules.threat_intel', 'ThreatIntelDetector'),
        ('modules.anti_evasion', 'AntiEvasionDetector'), ('modules.waf_detector', 'WAFDetector'),
        ('modules.dpi_detector', 'DPIDetector'), ('modules.c2_detector', 'C2BeaconingDetector'),
        ('modules.ueba_detector', 'UEBADetector'), ('modules.vuln_scanner', 'VulnScanner'),
    ]
    web = importlib.import_module('web.app')
    for module_name, name in components:
        component = MagicMock(name=name)
        component.get_stats.return_value = {}
        component.get_profiles.return_value = {}
        component.sent_count = 0
        component.dry_run = False
        component.blocklist = []
        component.start.return_value = True
        constructor = MagicMock(return_value=component)
        monkeypatch.setattr(importlib.import_module(module_name), name, constructor)
        if hasattr(web, name):
            monkeypatch.setattr(web, name, constructor)
    panel = IPSWebApp(db_path=str(tmp_path / 'web.db'))
    panel.app.config['TESTING'] = True
    panel.pcap_dir = str(tmp_path / 'pcaps')
    yield panel
    panel.close()


def login(panel, client):
    response = client.get('/login')
    token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()
    response = client.post('/login', data={'username': panel.admin_user,
                                         'password': panel.admin_pass, 'csrf_token': token})
    assert response.status_code == 302
    with client.session_transaction() as session:
        return session['csrf_token']


def test_constructor_does_not_start_active_services(panel):
    for name in ('sniffer', 'legacy_sniffer', 'tarpit', 'dns_sinkhole', 'honeypot',
                 'ssh_honeypot', 'decoy_generator', 'threat_intel'):
        getattr(panel, name).start.assert_not_called()
    assert panel.active_defense_mgr.db_path == panel.db.db_path


def test_cleanup_preserves_metadata_when_firewall_removal_fails(panel):
    panel.mode = 'ips'
    panel.tarpit.trapped_ips = {'192.0.2.10'}
    panel.tarpit.untarpit_ip.return_value = False
    panel.dns_sinkhole.quarantined_ips = set()
    panel.active_defense_mgr.add_rule('tarpit', target_ip='192.0.2.10')
    assert panel._cleanup_defenses() is False
    assert panel.active_defense_mgr.get_all_rules()[0]['target_ip'] == '192.0.2.10'
    panel.tarpit.untarpit_ip.return_value = True
    assert panel._cleanup_defenses() is True
    assert panel.active_defense_mgr.get_all_rules() == []


def test_port_scan_results_use_current_detector_alert_name(panel):
    panel.db.add_alert('Port Scanner (Açık Servisler)', '192.0.2.10', None, None, None,
                       'Port 22 (SSH)', 'warning')
    client = panel.app.test_client()
    login(panel, client)
    assert client.get('/api/vuln_scans').json[0]['source_ip'] == '192.0.2.10'


def test_proxy_and_secure_cookie_environment_flags(panel, monkeypatch, tmp_path):
    monkeypatch.setenv('DS_IPS_TRUST_PROXY', 'true')
    monkeypatch.setenv('DS_IPS_COOKIE_SECURE', 'true')
    proxy_panel = IPSWebApp(db_path=str(tmp_path / 'proxy.db'))
    try:
        assert proxy_panel.app.config['SESSION_COOKIE_SECURE'] is True
        client = proxy_panel.app.test_client()
        response = client.get('/login', base_url='https://localhost')
        assert 'Secure;' in response.headers['Set-Cookie']
        token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()
        response = client.post('/login', base_url='https://localhost',
                               data={'username': 'wrong', 'password': 'wrong', 'csrf_token': token},
                               headers={'X-Forwarded-For': '198.51.100.10', 'X-Forwarded-Proto': 'https'})
        assert response.status_code == 401
        assert '198.51.100.10' in proxy_panel.failed_attempts
    finally:
        proxy_panel.close()


def test_auth_and_csrf_cover_login_api_and_logout(panel):
    client = panel.app.test_client()
    assert client.get('/api/alerts').status_code == 401
    assert client.post('/login', data={'username': panel.admin_user, 'password': panel.admin_pass}).status_code == 403
    token = login(panel, client)
    assert client.post('/api/settings', json={}, headers={'X-Requested-With': 'XMLHttpRequest'}).status_code == 403
    assert client.post('/api/settings', json={}, headers={'X-CSRF-Token': token}).status_code == 200
    assert client.get('/logout').status_code == 405
    assert client.post('/logout', headers={'X-CSRF-Token': token}).status_code == 302
    assert client.get('/api/alerts').status_code == 401


def test_socket_requires_matching_live_session_and_logout_revokes(panel):
    client = panel.app.test_client()
    csrf = login(panel, client)
    token = client.get('/api/ws_token').json['token']
    other = panel.app.test_client()
    login(panel, other)
    for auth, browser in [(None, client), ({'token': []}, client), ([], client),
                          ({'token': token}, other), ({'token': token}, panel.app.test_client())]:
        socket = panel.socketio.test_client(panel.app, flask_test_client=browser, auth=auth)
        assert not socket.is_connected()
    socket = panel.socketio.test_client(panel.app, flask_test_client=client, auth={'token': token})
    assert socket.is_connected()
    client.post('/logout', headers={'X-CSRF-Token': csrf})
    assert not socket.is_connected()


@pytest.mark.parametrize('url,payload', [('/api/ban', {'ip': ['invalid']}),
    ('/api/ban', {'mac': 'invalid'}), ('/api/unban', {}),
    ('/api/scan_ip', {'ip': '127.0.0.1;id'}), ('/api/active_defense', {'ip': 'invalid'}),
    ('/api/settings', {'telegram_token': []}), ('/api/dns_sinkhole/blocklist', {'domains': {}}),
    ('/api/dns_sinkhole/blocklist', {'domains': ['https://evil.invalid/']}),
    ('/api/active_defense/save', {'module': 'tarpit', 'target_ip': 'bad'}),
    ('/api/control', {'action': 'start', 'interface': 'eth0;id'})])
def test_invalid_api_inputs_do_not_reach_components(panel, url, payload):
    client = panel.app.test_client()
    csrf = login(panel, client)
    response = client.post(url, json=payload, headers={'X-CSRF-Token': csrf})
    assert response.status_code == 400, response.data
    panel.vuln_scanner.scan_ip_async.assert_not_called()


@pytest.mark.parametrize('payload', [[], None, 'text', 3])
def test_json_api_requires_object(panel, payload):
    import json
    client = panel.app.test_client()
    csrf = login(panel, client)
    response = client.post('/api/control', data=json.dumps(payload), content_type='application/json',
                           headers={'X-CSRF-Token': csrf})
    assert response.status_code == 400


def test_limits_pcap_access_and_device_alias(panel):
    client = panel.app.test_client()
    assert client.get('/static/pcaps/alert_1.pcap').status_code == 302
    assert client.get('/api/pcaps/alert_1.pcap').status_code == 401
    login(panel, client)
    for limit in ('-1', '0', '1000000', 'oops'):
        assert client.get('/api/alerts?limit=' + limit).status_code == 400
    assert client.get('/api/devices').json == client.get('/api/records').json
    assert client.get('/api/pcaps/not-a-capture').status_code == 400


def test_passive_monitoring_and_start_failure_cleanup(panel):
    panel._start_monitoring()
    assert panel.sniffer_running
    panel.honeypot.start.assert_not_called()
    panel.scanner.start_periodic.assert_not_called()
    panel._stop_monitoring()
    assert not panel.sniffer_running
    client = panel.app.test_client()
    csrf = login(panel, client)
    panel.legacy_sniffer.start.side_effect = OSError('cannot capture')
    result = client.post('/api/control', json={'action': 'start'}, headers={'X-CSRF-Token': csrf})
    assert result.status_code == 503
    assert not panel.sniffer_running
    assert panel.sniffer.stop.called


def test_dns_blocklist_real_newlines_and_partial_settings(panel):
    client = panel.app.test_client()
    csrf = login(panel, client)
    headers = {'X-CSRF-Token': csrf}
    response = client.post('/api/dns_sinkhole/blocklist', json={'domains': 'EXAMPLE.COM\nexample.net\nexample.com'}, headers=headers)
    assert response.status_code == 200
    panel.dns_sinkhole.update_blocklist.assert_called_once_with(['example.com', 'example.net'])
    panel.db.set_setting('telegram_token', '123:old')
    assert client.post('/api/settings', json={'telegram_chat_id': '-123'}, headers=headers).status_code == 200
    assert panel.db.get_setting('telegram_token') == '123:old'
    assert client.post('/api/settings', json={'telegram_chat_id': ''}, headers=headers).status_code == 200
    assert panel.db.get_setting('telegram_chat_id') == ''


def test_pdf_handles_turkish_unicode_and_newest_rows(tmp_path):
    from web.report_gen import generate_pdf_report
    path = tmp_path / 'report.pdf'
    rows = [{'timestamp': '2026-09-19', 'alert_type': 'Şüpheli İstanbul 🔒',
             'source_ip': '10.0.0.1', 'severity': 'Yüksek'}]
    generate_pdf_report(rows, path)
    assert path.read_bytes().startswith(b'%PDF-')
