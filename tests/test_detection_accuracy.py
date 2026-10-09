"""Accuracy regressions use in-memory packet fixtures; no packets are transmitted."""
from hashlib import sha256
from unittest.mock import Mock

import pytest
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, Dot11, Dot11Beacon, Dot11Elt, Ether, IP, Raw, TCP, UDP

from modules.anti_evasion import AntiEvasionDetector
from modules.arp_detector import ARPDetector
from modules.c2_detector import C2BeaconingDetector
from modules.dhcp_detector import DHCPDetector
from modules.dns_detector import DNSDetector
from modules.dpi_detector import DPIDetector
from modules.scan_detector import ScanDetector
from modules.ueba_detector import UEBADetector
from modules.waf_detector import WAFDetector
from modules.wifi_detector import WiFiDetector


@pytest.fixture(autouse=True)
def passive_fixtures(monkeypatch):
    monkeypatch.setattr('utils.sound.SoundAlert.alert_attack', Mock())
    monkeypatch.setattr('scapy.all.sendp', Mock(side_effect=AssertionError('No transmission')))
    monkeypatch.setattr('scapy.all.send', Mock(side_effect=AssertionError('No transmission')))
    monkeypatch.setattr(ARPDetector, '_get_local_macs', lambda self: [])
    monkeypatch.setattr(ARPDetector, '_get_local_ips', lambda self: [])
    monkeypatch.setattr(ScanDetector, '_get_local_ips', lambda self: set())


@pytest.fixture
def clock(monkeypatch):
    value = [1000.0]
    monkeypatch.setattr('time.time', lambda: value[0])
    return value


def scan_packet(port, dst='192.0.2.20', flags='S'):
    return IP(src='192.0.2.10', dst=dst) / TCP(sport=40000, dport=port, flags=flags)


@pytest.mark.parametrize('flags', ['S', 'F', 'FPU', ''])
def test_scan_does_not_merge_unrelated_destinations(flags, clock):
    detector = ScanDetector(Mock())
    for index in range(16):
        detector.analyze(scan_packet(1000 + index, f'192.0.2.{20 + index}', flags))
    detector.db.add_alert.assert_not_called()


@pytest.mark.parametrize('flags', ['S', 'SEC', 'F', 'FPU', ''])
def test_scan_rolling_window_crosses_cleanup_boundary(flags, clock):
    detector = ScanDetector(Mock())
    clock[0] = 1004.9
    for port in range(1000, 1008):
        detector.analyze(scan_packet(port, flags=flags))
    clock[0] = 1005.1
    for port in range(1008, 1016):
        detector.analyze(scan_packet(port, flags=flags))
    detector.db.add_alert.assert_called_once()
    assert detector.db.add_alert.call_args.kwargs['dst_ip'] == '192.0.2.20'


def test_scan_old_ports_expire(clock):
    detector = ScanDetector(Mock())
    for port in range(1000, 1008):
        detector.analyze(scan_packet(port))
    clock[0] += 6
    for port in range(1008, 1016):
        detector.analyze(scan_packet(port))
    detector.db.add_alert.assert_not_called()


def test_udp_responses_to_observed_requests_are_not_scans(clock):
    detector = ScanDetector(Mock())
    detector.local_ips = {'192.0.2.10'}
    for port in range(40000, 40020):
        detector.analyze(IP(src='192.0.2.10', dst='192.0.2.20') / UDP(sport=port, dport=3478))
        detector.analyze(IP(src='192.0.2.20', dst='192.0.2.10') / UDP(sport=3478, dport=port))
    detector.db.add_alert.assert_not_called()


def test_c2_ignores_periodic_ack_stream(clock):
    detector = C2BeaconingDetector(Mock())
    for index in range(8):
        clock[0] = 1000 + index * 30
        detector.analyze(IP(src='10.0.0.2', dst='9.9.9.9') / TCP(dport=443, flags='A'))
    detector.db.add_alert.assert_not_called()
    assert not detector.conn_times


def test_c2_timing_is_advisory_and_protocols_are_separate(clock):
    blocker = Mock()
    detector = C2BeaconingDetector(Mock(), blocker, auto_ban=True)
    for index in range(6):
        clock[0] = 1000 + index * 30
        transport = TCP(dport=443, flags='S') if index % 2 == 0 else UDP(dport=443)
        detector.analyze(IP(src='10.0.0.2', dst='9.9.9.9') / transport)
    detector.db.add_alert.assert_not_called()
    for index in range(3, 5):
        clock[0] = 1000 + index * 60
        detector.analyze(IP(src='10.0.0.2', dst='9.9.9.9') / TCP(dport=443, flags='S'))
    detector.db.add_alert.assert_called_once()
    assert detector.db.add_alert.call_args.kwargs['severity'] == 'warning'
    blocker.block_ip.assert_not_called()


def dns_packet(label):
    return IP(src='192.0.2.10', dst='192.0.2.1') / UDP(dport=53) / DNS(qd=DNSQR(qname=f'{label}.example.invalid'))


def test_long_cdn_label_and_retries_do_not_prove_tunneling(clock):
    detector = DNSDetector(Mock())
    label = sha256(b'cdn-asset').hexdigest()[:56]
    for _ in range(20):
        detector.analyze(dns_packet(label))
    detector.db.add_alert.assert_not_called()


def test_dns_tunnel_candidate_requires_distinct_high_entropy_labels(clock):
    detector = DNSDetector(Mock())
    for index in range(12):
        detector.analyze(dns_packet(f'{index:02d}' + 'a' * 54))
    detector.db.add_alert.assert_not_called()
    for index in range(12):
        detector.analyze(dns_packet(sha256(str(index).encode()).hexdigest()[:56]))
    detector.db.add_alert.assert_called_once()
    assert detector.db.add_alert.call_args.kwargs['severity'] == 'warning'


def test_dns_candidate_evidence_expires(clock):
    detector = DNSDetector(Mock())
    for index in range(9):
        detector.analyze(dns_packet(sha256(str(index).encode()).hexdigest()[:56]))
    clock[0] += 11
    detector.analyze(dns_packet(sha256(b'last').hexdigest()[:56]))
    detector.db.add_alert.assert_not_called()


def arp_packet(mac):
    return Ether(src=mac) / ARP(op=2, psrc='192.0.2.1', pdst='192.0.2.10', hwsrc=mac)


def test_arp_conflict_does_not_block_claimed_victim_or_forge_healing(clock):
    blocker = Mock(dry_run=False)
    detector = ARPDetector(Mock(), blocker, auto_ban=True)
    detector.analyze(arp_packet('02:00:00:00:00:01'))
    detector.analyze(arp_packet('02:00:00:00:00:02'))
    detector.db.add_alert.assert_called_once()
    assert detector.db.add_alert.call_args.kwargs['severity'] == 'warning'
    blocker.block_ip.assert_not_called()
    blocker.block_mac.assert_not_called()


def test_arp_stale_binding_allows_dhcp_reassignment(clock):
    detector = ARPDetector(Mock())
    detector.analyze(arp_packet('02:00:00:00:00:01'))
    clock[0] += detector.binding_ttl + 1
    detector.analyze(arp_packet('02:00:00:00:00:02'))
    detector.db.add_alert.assert_not_called()


def test_many_legitimate_devices_are_not_mac_evasion(clock):
    detector = AntiEvasionDetector(Mock())
    for index in range(20):
        detector.analyze(Ether(src=f'02:00:00:00:00:{index:02x}') / IP(src=f'192.0.2.{index + 1}'))
    detector.db.add_alert.assert_not_called()


def test_mac_rotation_is_correlated_to_one_ip(clock):
    detector = AntiEvasionDetector(Mock())
    for index in range(10):
        detector.analyze(Ether(src=f'02:00:00:00:00:{index:02x}') / IP(src='192.0.2.10'))
    detector.db.add_alert.assert_called_once()
    assert detector.db.add_alert.call_args.kwargs['src_ip'] == '192.0.2.10'


@pytest.mark.parametrize('text', [b'Learn powershell and cmd.exe', b'GET /docs/whoami HTTP/1.1\r\n\r\n', b'HTTP/1.1 200 OK\r\n\r\n/bin/bash and /bin/sh are shells'])
def test_dpi_program_names_are_not_reverse_shell_evidence(text):
    detector = DPIDetector(Mock(), Mock(), auto_ban=True)
    detector.yara_compiled = None
    detector.analyze(IP(src='192.0.2.10', dst='192.0.2.20') / TCP(dport=80) / Raw(text))
    detector.db.add_alert.assert_not_called()
    detector.blocker.block_ip.assert_not_called()


def test_dpi_shell_session_evidence_is_advisory():
    detector = DPIDetector(Mock(), Mock(), auto_ban=True)
    detector.yara_compiled = None
    detector.analyze(IP(src='192.0.2.10', dst='192.0.2.20') / TCP(dport=4444) /
                     Raw(b'user@host:~$ id\r\nuid=1000(user) gid=1000(user)\r\n'))
    detector.db.add_alert.assert_called_once()
    detector.blocker.block_ip.assert_not_called()


def dhcp_discover(xid=1):
    return Ether(src='02:00:00:00:00:01') / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(sport=68, dport=67) / BOOTP(xid=xid) / DHCP(options=[('message-type', 1), 'end'])


def test_dhcp_retries_are_not_distinct_allocation_requests(clock):
    detector = DHCPDetector(Mock())
    for _ in range(150):
        detector.analyze(dhcp_discover())
    assert detector.total_discovers == 1
    detector.db.add_alert.assert_not_called()


def test_dhcp_starvation_threshold_is_per_second(clock):
    detector = DHCPDetector(Mock())
    for index in range(100):
        detector.analyze(dhcp_discover(index))
    detector.db.add_alert.assert_not_called()
    detector.analyze(dhcp_discover(100))
    detector.db.add_alert.assert_called_once()


def test_approved_dhcp_server_via_relay_is_not_rogue(clock):
    detector = DHCPDetector(Mock())
    detector.legit_dhcp = '192.0.2.1'
    packet = Ether(src='02:00:00:00:00:02') / IP(src='192.0.2.2') / UDP(sport=67, dport=68) / BOOTP(op=2) / DHCP(options=[('message-type', 2), ('server_id', '192.0.2.1'), 'end'])
    detector.analyze(packet)
    detector.db.add_alert.assert_not_called()


def beacon(ssid, bssid):
    return Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid) / Dot11Beacon() / Dot11Elt(ID=0, info=ssid.encode())


def test_dense_wifi_and_mesh_are_not_beacon_flood_or_evil_twin(clock):
    detector = WiFiDetector(Mock())
    for index in range(60):
        detector.analyze(beacon(f'network-{index}', f'02:00:00:00:00:{index:02x}'))
        detector.analyze(beacon('company-mesh', f'02:00:00:00:01:{index:02x}'))
    detector.db.add_alert.assert_not_called()
    assert detector.get_stats()['evil_twin_ssids'] == 0


def test_wifi_inventory_identifies_unapproved_ap(clock):
    detector = WiFiDetector(Mock())
    detector.trusted_bssids = {'company': {'02:00:00:00:00:01', '02:00:00:00:00:02'}}
    for index in range(1, 4):
        detector.analyze(beacon('company', f'02:00:00:00:00:{index:02x}'))
    detector.db.add_alert.assert_called_once()
    assert detector.get_stats()['evil_twin_ssids'] == 1


def test_ueba_retransmits_and_udp_stream_do_not_exhaust_learning(clock):
    detector = UEBADetector(Mock())
    tcp = IP(src='192.0.2.10', dst='192.0.2.20') / TCP(sport=40000, dport=443, flags='S', seq=100)
    udp = IP(src='192.0.2.11', dst='192.0.2.20') / UDP(sport=40000, dport=443)
    for _ in range(100):
        detector.analyze(tcp)
        detector.analyze(udp)
    assert detector.get_profiles()['192.0.2.10']['total_connections'] == 1
    assert detector.get_profiles()['192.0.2.11']['total_connections'] == 1


def test_ueba_novel_sensitive_service_is_advisory_and_not_trusted(clock):
    detector = UEBADetector(Mock(), Mock(), auto_ban=True)
    detector.learning_threshold = 1
    detector.analyze(IP(src='192.0.2.10', dst='192.0.2.20') / TCP(dport=443, flags='S'))
    detector.analyze(IP(src='192.0.2.10', dst='192.0.2.20') / TCP(dport=22, flags='S'))
    detector.db.add_alert.assert_called_once()
    assert 22 not in detector.get_profiles()['192.0.2.10']['learned_ports']
    detector.blocker.block_ip.assert_not_called()


def http_request(index=0, path='/missing', dst='192.0.2.20'):
    return IP(src='192.0.2.10', dst=dst) / TCP(sport=40000 + index, dport=80, seq=index * 1000) / Raw(f'GET {path} HTTP/1.1\r\nHost: example.invalid\r\n\r\n'.encode())


def http_response(index=0):
    return IP(src='192.0.2.20', dst='192.0.2.10') / TCP(sport=80, dport=40000 + index, seq=index * 1000) / Raw(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')


def test_waf_retransmits_and_separate_servers_do_not_inflate_rate(clock):
    detector = WAFDetector(Mock())
    detector.l7_dos_threshold = 2
    for _ in range(20):
        detector.analyze(http_request())
    for index in range(1, 10):
        detector.analyze(http_request(index, dst=f'192.0.2.{20 + index}'))
    detector.db.add_alert.assert_not_called()


def test_waf_same_missing_asset_and_unmatched_404_are_not_directory_scan(clock):
    detector = WAFDetector(Mock())
    detector.bruteforce_threshold = 2
    for index in range(10):
        detector.analyze(http_response(index))
    for index in range(10, 20):
        detector.analyze(http_request(index))
        detector.analyze(http_response(index))
    detector.db.add_alert.assert_not_called()


def test_waf_correlates_distinct_missing_paths_to_client_and_server(clock):
    detector = WAFDetector(Mock(), Mock(), auto_ban=True)
    detector.bruteforce_threshold = 2
    for index in range(3):
        detector.analyze(http_request(index, f'/missing-{index}'))
        detector.analyze(http_response(index))
    detector.db.add_alert.assert_called_once()
    alert = detector.db.add_alert.call_args.kwargs
    assert (alert['src_ip'], alert['dst_ip']) == ('192.0.2.10', '192.0.2.20')
    detector.blocker.block_ip.assert_not_called()


def test_waf_pipelining_overflow_keeps_rate_detection_but_discards_correlation(clock):
    detector = WAFDetector(Mock())
    detector.bruteforce_threshold = 2
    for index in range(105):
        request = http_request(0, f'/missing-{index}')
        request[TCP].seq = index * 1000
        detector.analyze(request)
    assert detector.db.add_alert.call_args.kwargs['alert_type'] == 'Web L7 DoS / Flood'
    detector.db.add_alert.reset_mock()
    for index in range(5):
        response = http_response(0)
        response[TCP].seq = index * 1000
        detector.analyze(response)
    detector.db.add_alert.assert_not_called()


def test_wifi_many_ssids_from_one_bssid_is_an_advisory_anomaly(clock):
    detector = WiFiDetector(Mock())
    for index in range(60):
        detector.analyze(beacon(f'network-{index}', '02:00:00:00:00:01'))
    detector.db.add_alert.assert_called_once()
    assert detector.db.add_alert.call_args.kwargs['alert_type'] == 'Beacon Flood'


def test_wifi_deauth_does_not_block_unauthenticated_sender_identity(clock):
    detector = WiFiDetector(Mock(), Mock(), auto_ban=True)
    for index in range(11):
        detector.analyze(Dot11(type=0, subtype=12, SC=index << 4,
                              addr1='02:00:00:00:00:02', addr2='02:00:00:00:00:01'))
    detector.db.add_alert.assert_called_once()
    detector.blocker.block_mac.assert_not_called()


def test_ueba_profiles_tcp_and_udp_services_separately(clock):
    detector = UEBADetector(Mock())
    detector.learning_threshold = 1
    detector.analyze(IP(src='192.0.2.10', dst='192.0.2.20') / UDP(dport=22))
    detector.analyze(IP(src='192.0.2.10', dst='192.0.2.20') / TCP(dport=22, flags='S'))
    detector.db.add_alert.assert_called_once()


def test_c2_publicly_addressed_clients_and_resolver_ip_other_services_are_observed(clock):
    detector = C2BeaconingDetector(Mock())
    for index in range(5):
        clock[0] = 1000 + index * 30
        detector.analyze(IP(src='9.9.9.10', dst='1.1.1.1') / TCP(dport=443, flags='S'))
    detector.db.add_alert.assert_called_once()
    assert detector.db.add_alert.call_args.kwargs['src_ip'] == '9.9.9.10'


@pytest.mark.parametrize('port', [53, 123, 1900])
def test_c2_port_number_alone_does_not_exempt_unknown_udp(clock, port):
    detector = C2BeaconingDetector(Mock())
    for index in range(5):
        clock[0] = 1000 + index * 30
        detector.analyze(IP(src='192.0.2.10', dst='9.9.9.9') / UDP(dport=port) / Raw(b'abc'))
    detector.db.add_alert.assert_called_once()


def test_c2_leaves_decoded_dns_to_dedicated_detector(clock):
    detector = C2BeaconingDetector(Mock())
    for index in range(5):
        clock[0] = 1000 + index * 30
        detector.analyze(IP(src='192.0.2.10', dst='9.9.9.9') / UDP(dport=53) /
                         DNS(qd=DNSQR(qname='example.invalid')))
    detector.db.add_alert.assert_not_called()


def test_dhcp_unassigned_client_does_not_create_shared_na_inventory_row(clock, monkeypatch):
    detector = DHCPDetector(Mock())
    monkeypatch.setattr('utils.os_fingerprint.OSFingerprint.from_dhcp_options', lambda values: 'Linux')
    packet = dhcp_discover()
    packet[DHCP].options = [('message-type', 1), ('param_req_list', [1, 3, 6]), 'end']
    detector.analyze(packet)
    detector.db.update_ip_mac.assert_not_called()


def test_udp_known_source_port_does_not_exempt_unclassified_packets(clock):
    detector = ScanDetector(Mock())
    for port in range(40000, 40016):
        detector.analyze(IP(src='192.0.2.10', dst='192.0.2.20') /
                         UDP(sport=53, dport=port) / Raw(b'abc'))
    detector.db.add_alert.assert_called_once()
    assert detector.db.add_alert.call_args.kwargs['alert_type'] == 'UDP Scan'


def test_udp_decoded_dns_responses_do_not_trigger_port_scan(clock):
    detector = ScanDetector(Mock())
    for port in range(40000, 40016):
        detector.analyze(IP(src='192.0.2.10', dst='192.0.2.20') /
                         UDP(sport=53, dport=port) / DNS(qr=1, qd=DNSQR(qname='example.invalid')))
    detector.db.add_alert.assert_not_called()
