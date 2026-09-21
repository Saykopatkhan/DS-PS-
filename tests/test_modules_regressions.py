"""Detection regressions use synthetic packets only; nothing is transmitted."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scapy.all import ARP, DNS, DNSQR, Ether, IP, Raw, TCP, UDP

from modules.arp_detector import ARPDetector
from modules.c2_detector import C2BeaconingDetector
from modules.dns_detector import DNSDetector
from modules.dns_sinkhole import DNSSinkhole
from modules.hids_engine import HIDSEngine
from modules.ueba_detector import UEBADetector
from modules.vuln_scanner import VulnScanner


@pytest.fixture(autouse=True)
def silence_alarms(monkeypatch):
    monkeypatch.setattr('utils.sound.SoundAlert.alert_attack', Mock())


def dns_packet(qr=0, qtype='A'):
    return (Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') /
            IP(src='192.0.2.10', dst='192.0.2.1') / UDP(sport=12345, dport=53) /
            DNS(qr=qr, qd=DNSQR(qname='malware.com', qtype=qtype)))


@pytest.mark.parametrize('dry_run, auto_ban', [(False, False), (True, True)])
def test_dns_passive_and_dry_run_never_forge_packets(monkeypatch, dry_run, auto_ban):
    transmit = Mock(side_effect=AssertionError('Packet transmission is forbidden'))
    monkeypatch.setattr('modules.dns_detector.sendp', transmit)
    detector = DNSDetector(Mock(), SimpleNamespace(dry_run=dry_run), auto_ban=auto_ban)
    detector.dns_sinkhole = SimpleNamespace(dry_run=False, sinkhole_ip='192.0.2.2', is_blocked=lambda name: True)
    detector.analyze(dns_packet())
    detector.db.add_alert.assert_called_once()
    transmit.assert_not_called()


def test_dns_response_does_not_inflate_query_statistics():
    detector = DNSDetector(Mock())
    detector.analyze(dns_packet(qr=1))
    assert not detector.query_count
    detector.db.add_dns_log.assert_not_called()


def client_hello(name):
    host = name.encode('ascii')
    entry = b'\x00' + len(host).to_bytes(2, 'big') + host
    names = len(entry).to_bytes(2, 'big') + entry
    extension = b'\x00\x00' + len(names).to_bytes(2, 'big') + names
    hello = b'\x03\x03' + b'x' * 32 + b'\x00\x00\x02\x13\x01\x01\x00' + len(extension).to_bytes(2, 'big') + extension
    handshake = b'\x01' + len(hello).to_bytes(3, 'big') + hello
    return b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake


def test_tls_sni_extracts_valid_name_and_rejects_every_truncation():
    payload = client_hello('example.technology')
    assert DNSDetector._tls_sni(payload) == 'example.technology'
    for length in range(len(payload)):
        assert DNSDetector._tls_sni(payload[:length]) is None
    assert DNSDetector._tls_sni(b'random encrypted example.com data') is None


def test_http_response_body_is_not_a_host_header():
    detector = DNSDetector(Mock())
    detector.analyze(IP(src='192.0.2.1') / TCP(dport=80) / Raw(b'HTTP/1.1 200 OK\r\n\r\nHost: not-a-request.invalid'))
    detector.db.add_dns_log.assert_not_called()


def test_sinkhole_domains_match_labels_and_persist_atomically(tmp_path):
    portal = DNSSinkhole(dry_run=True)
    portal.blocklist_path = str(tmp_path / 'domains.json')
    assert portal.update_blocklist(['EXAMPLE.org.', 'example.org'])
    assert portal.blocklist == ['example.org']
    assert portal.is_blocked('sub.example.org.')
    assert not portal.is_blocked('notexample.org')
    assert not portal.is_blocked('example.org.safe.test')
    assert not portal.update_blocklist(['https://example.org/'])
    assert portal.blocklist == ['example.org']


@pytest.mark.parametrize('qtype', ['AAAA', 'MX', 'TXT', 'NS'])
def test_sinkhole_does_not_return_a_record_for_other_question_types(qtype):
    portal = DNSSinkhole(dry_run=True, sinkhole_ip='192.0.2.2')
    portal.blocklist = ['example.org']
    query = DNS(id=1234, qd=DNSQR(qname='example.org', qtype=qtype))
    reply = DNS(portal._dns_response(bytes(query), '192.0.2.10'))
    assert reply.id == 1234
    assert reply.ancount == 0


def test_sinkhole_refuses_unrelated_domains_and_ignores_replies():
    portal = DNSSinkhole(dry_run=True, sinkhole_ip='192.0.2.2')
    portal.blocklist = ['blocked.invalid']
    query = DNS(qd=DNSQR(qname='safe.invalid'))
    assert DNS(portal._dns_response(bytes(query), '192.0.2.10')).rcode == 5
    query.qr = 1
    assert portal._dns_response(bytes(query), '192.0.2.10') is None
    assert portal._dns_response(b'bad', '192.0.2.10') is None


def test_sinkhole_dry_run_and_invalid_ip_never_run_firewall(monkeypatch):
    execute = Mock(side_effect=AssertionError('Firewall mutation forbidden'))
    monkeypatch.setattr('modules.dns_sinkhole.subprocess.run', execute)
    portal = DNSSinkhole(dry_run=True)
    assert not portal.redirect_to_quarantine('192.0.2.10')
    assert not portal.quarantined_ips
    portal.dry_run = False
    assert not portal.redirect_to_quarantine('192.0.2.10; false')
    execute.assert_not_called()


def test_arp_passive_detection_does_not_send_healing(monkeypatch):
    monkeypatch.setattr(ARPDetector, '_get_local_macs', lambda self: [])
    monkeypatch.setattr(ARPDetector, '_get_local_ips', lambda self: [])
    transmit = Mock(side_effect=AssertionError('No healing in IDS'))
    monkeypatch.setattr('scapy.all.sendp', transmit)
    detector = ARPDetector(Mock())
    for mac in ['02:00:00:00:00:01', '02:00:00:00:00:02']:
        detector.analyze(Ether(src=mac) / ARP(op=2, psrc='192.0.2.1', pdst='192.0.2.2', hwsrc=mac))
    assert detector.db.add_alert.call_args.kwargs['alert_type'] == 'ARP Spoofing'
    transmit.assert_not_called()


def test_c2_detects_regular_connections_from_private_lan(monkeypatch):
    detector = C2BeaconingDetector(Mock())
    packet = IP(src='192.168.1.10', dst='9.9.9.9') / TCP(dport=4444, flags='S')
    for timestamp in [1000, 1030, 1060, 1090, 1120]:
        monkeypatch.setattr('modules.c2_detector.time.time', lambda: timestamp)
        detector.analyze(packet)
    detector.db.add_alert.assert_called_once()


def test_hids_normal_browser_is_not_command_injection():
    detector = HIDSEngine()
    events = []
    detector.register_callback(events.append)
    detector._analyze_web_log('192.0.2.10 - - [date] "GET / HTTP/1.1" 200 50 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"')
    assert not events


@pytest.mark.parametrize('path, expected', [
    ('/?q=UNION%20SELECT%20password', 'SQL_INJECTION'),
    ('/?q=%3Cscript%3Ealert(1)', 'XSS_REFLECTED'),
    ('/?file=../../etc/passwd', 'LFI_DIR_TRAVERSAL'),
    ('/?cmd=%3B%20curl%20example.org', 'RCE_COMMAND_INJ'),
])
def test_hids_decodes_request_signatures(path, expected):
    detector = HIDSEngine()
    events = []
    detector.register_callback(events.append)
    detector._analyze_web_log(f'192.0.2.10 - - [date] "GET {path} HTTP/1.1" 200 50 "-" "Browser"')
    assert events[0]['type'] == expected


def test_ueba_counts_connections_not_payload_packets():
    detector = UEBADetector(Mock())
    for _ in range(60):
        detector.analyze(IP(src='192.0.2.10') / TCP(dport=80, flags='A'))
    assert detector.get_profiles() == {}
    detector.analyze(IP(src='192.0.2.10') / TCP(dport=443, flags='S'))
    assert detector.get_profiles()['192.0.2.10']['total_connections'] == 1


def test_vulnerability_scan_dry_run_and_malformed_targets_do_not_connect(monkeypatch):
    connect = Mock(side_effect=AssertionError('No network in test'))
    monkeypatch.setattr('socket.socket', connect)
    assert VulnScanner(Mock(), dry_run=True).scan_ip_async('192.0.2.1') is False
    scanner = VulnScanner(Mock())
    assert scanner.scan_ip_async('127.0.0.1') is False
    assert scanner.scan_ip_async('--help') is False
    connect.assert_not_called()
