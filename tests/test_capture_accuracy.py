"""Passive JSON/log inputs only: no capture subprocess or packet transmission."""

import pytest

from core.fast_sniffer import FastSniffer
from modules.hids_engine import HIDSEngine


def tcp_packet(source='192.0.2.10', destination='192.0.2.20', sequence=100, port=40000):
    return {'layers': {'ip': {'ip_ip_src': source, 'ip_ip_dst': destination},
                       'tcp': {'tcp_tcp_flags': '0x0002', 'tcp_tcp_dstport': '443',
                               'tcp_tcp_srcport': str(port), 'tcp_tcp_seq_raw': str(sequence)}}}


@pytest.fixture
def capture(monkeypatch):
    monkeypatch.setattr('core.fast_sniffer.time.monotonic', lambda: 100)
    sniffer = FastSniffer()
    sniffer.SYN_LIMIT = 3
    events = []
    sniffer.register_callback(events.append)
    return sniffer, events


def test_syn_retransmissions_and_unrelated_targets_are_not_a_flood(capture):
    sniffer, events = capture
    for _ in range(20):
        sniffer.analyze_packet(tcp_packet())
    assert not events
    for index in range(1, 10):
        sniffer.analyze_packet(tcp_packet(destination=f'192.0.2.{index}', sequence=index))
    assert not events
    assert len(sniffer.syn_window[('192.0.2.10', '192.0.2.20')]) == 1


def test_distinct_syn_rate_is_advisory_throttled_and_target_specific(capture):
    sniffer, events = capture
    for index in range(20):
        sniffer.analyze_packet(tcp_packet(sequence=index, port=40000 + index))
    assert len(events) == 1
    assert events[0]['type'] == 'SYN_FLOOD'
    assert events[0]['severity'] == 'medium'
    assert events[0]['destination_ip'] == '192.0.2.20'


def test_capture_state_is_bounded_and_expired_windows_do_not_accumulate(capture, monkeypatch):
    sniffer, events = capture
    sniffer.MAX_TRACKED = 4
    for index in range(10):
        sniffer.analyze_packet(tcp_packet(source=f'192.0.2.{index + 1}'))
    assert len(sniffer.syn_window) == 4
    assert len(sniffer._syn_flows) == 4
    monkeypatch.setattr('core.fast_sniffer.time.monotonic', lambda: 110)
    sniffer.analyze_packet(tcp_packet())
    assert len(sniffer.syn_window) == 1
    assert not events


def test_icmp_echo_replies_are_not_attributed_as_ping_flood(capture):
    sniffer, events = capture
    sniffer.ICMP_LIMIT = 2
    packet = {'layers': {'ip': {'ip_ip_src': '192.0.2.1', 'ip_ip_dst': '192.0.2.2'},
                         'icmp': {'icmp_icmp_type': '0'}}}
    for _ in range(10):
        sniffer.analyze_packet(packet)
    assert not events
    packet['layers']['icmp']['icmp_icmp_type'] = '8'
    for _ in range(3):
        sniffer.analyze_packet(packet)
    assert events[0]['type'] == 'ICMP_FLOOD'


def test_arp_probe_and_mac_case_do_not_create_spoof_alert(capture):
    sniffer, events = capture
    sniffer.gateway_ip = '192.0.2.1'
    sniffer.gateway_mac = '02:AB:00:00:00:01'
    packet = {'layers': {'arp': {'arp_arp_opcode': '2', 'arp_arp_src_proto_ipv4': '0.0.0.0',
                                'arp_arp_src_hw_mac': '02:ab:00:00:00:01'}}}
    sniffer.analyze_packet(packet)
    assert not events
    packet['layers']['arp']['arp_arp_src_proto_ipv4'] = sniffer.gateway_ip
    sniffer.analyze_packet(packet)
    assert [event['type'] for event in events] == ['DEVICE_DISCOVERED']


def auth_line(address='192.0.2.20', username='tester'):
    return f'Oct 9 12:00:00 host sshd[123]: Failed password for {username} from {address} port 40000 ssh2'


def test_hids_counts_actual_failures_not_disconnects_or_username_addresses():
    engine = HIDSEngine()
    events = []
    engine.register_callback(events.append)
    for _ in range(10):
        engine._analyze_auth_log('host sshd[123]: Connection closed by authenticating user 192.0.2.1 192.0.2.20 port 40000 [preauth]')
        engine._analyze_auth_log('host app[123]: Failed password for guest from 192.0.2.1 port 40000 ssh2')
    assert not events
    for _ in range(5):
        engine._analyze_auth_log(auth_line(username='192.0.2.99'))
    assert len(events) == 1
    assert events[0]['source_ip'] == '192.0.2.20'
    assert events[0]['source_verified'] is True


def test_hids_ipv6_failures_cooldown_and_state_bound(monkeypatch):
    now = [100]
    monkeypatch.setattr('modules.hids_engine.time.monotonic', lambda: now[0])
    engine = HIDSEngine()
    engine.MAX_SOURCES = 3
    events = []
    engine.register_callback(events.append)
    for _ in range(20):
        engine._analyze_auth_log(auth_line(address='2001:db8::20'))
    assert len(events) == 1
    now[0] += 61
    for _ in range(5):
        engine._analyze_auth_log(auth_line(address='2001:db8::20'))
    assert len(events) == 2
    for index in range(10):
        engine._analyze_auth_log(auth_line(address=f'192.0.2.{index + 1}'))
    assert len(engine.ssh_failures) == 3


def test_scanner_name_in_url_or_referrer_does_not_identify_user_agent():
    engine = HIDSEngine()
    events = []
    engine.register_callback(events.append)
    engine._analyze_web_log('192.0.2.20 - - [date] "GET /docs/nmap HTTP/1.1" 200 50 "https://example.org/sqlmap" "Browser"')
    assert not events
    engine._analyze_web_log('192.0.2.20 - - [date] "GET / HTTP/1.1" 200 50 "-" "nmap"')
    assert events[0]['type'] == 'SCANNER_USER_AGENT'


@pytest.mark.parametrize('target', ['/docs/curl', '/docs/python', '/selectfrom/options', '/?page=1=1'])
def test_hids_common_documentation_names_and_numeric_values_are_not_injections(target):
    engine = HIDSEngine()
    events = []
    engine.register_callback(events.append)
    engine._analyze_web_log(f'192.0.2.20 - - [date] "GET {target} HTTP/1.1" 200 50 "-" "Browser"')
    assert not events


def test_pcap_evidence_is_private_and_failed_write_preserves_previous_file(tmp_path, monkeypatch):
    from core.sniffer import PacketSniffer
    from scapy.all import IP, UDP, rdpcap

    sniffer = PacketSniffer()
    sniffer._packet_handler(IP(src='192.0.2.1', dst='192.0.2.2') / UDP())
    target = tmp_path / 'evidence.pcap'
    assert sniffer.dump_pcap(target)
    assert target.stat().st_mode & 0o777 == 0o600
    assert len(rdpcap(str(target))) == 1
    original = target.read_bytes()

    def fail_write(path, packets):
        with open(path, 'wb') as stream:
            stream.write(b'incomplete')
        raise OSError('storage unavailable')

    monkeypatch.setattr('core.sniffer.wrpcap', fail_write)
    assert not sniffer.dump_pcap(target)
    assert target.read_bytes() == original
    assert list(tmp_path.iterdir()) == [target]
