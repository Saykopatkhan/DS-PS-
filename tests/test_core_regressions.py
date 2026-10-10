import asyncio
import sqlite3
import threading
from unittest.mock import Mock

from core.database import Database
from core.event_bus import EventBus
from core.fast_sniffer import FastSniffer
from core.scanner import NetworkScanner


def test_partial_database_migration(tmp_path):
    path = tmp_path / 'legacy.db'
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE ip_mac_records (id INTEGER PRIMARY KEY, ip_address TEXT, mac_address TEXT, vendor TEXT, first_seen TIMESTAMP, last_seen TIMESTAMP, status TEXT, UNIQUE(ip_address, mac_address))')
    db = Database(path)
    try:
        db.update_ip_mac('192.0.2.1', '02:00:00:00:00:01', hostname='host', os_type='Linux')
        assert db.get_ip_mac_records()[0]['hostname'] == 'host'
        assert 'threat_score' in db.get_ip_mac_records()[0]
    finally:
        db.close()


def test_alert_returns_id_orders_ties_and_callback_updates_payload():
    db = Database(':memory:')
    db.socketio = Mock()
    db.set_alert_callback(lambda alert: alert.update(pcap_file='capture.pcap'))
    first = db.add_alert('scan', '192.0.2.1', None, None, None, 'first', 'high')
    second = db.add_alert('scan', '192.0.2.1', None, None, None, 'second', 'high')
    assert first < second
    assert db.get_alerts()[0]['id'] == second
    assert db.socketio.emit.call_args.args[1]['pcap_file'] == 'capture.pcap'
    db.close()


def test_remove_ban_does_not_modify_inactive_history():
    db = Database(':memory:')
    db.add_ban('192.0.2.1', '02:00:00:00:00:01', 'old')
    db.remove_ban(mac='02:00:00:00:00:01')
    with db.lock:
        db.conn.execute("UPDATE banned_hosts SET unban_time = '2000-01-01' WHERE is_active = 0")
        db.conn.commit()
    db.add_ban('192.0.2.2', '02:00:00:00:00:02', 'new', duration=30)
    db.remove_ban(ip='192.0.2.2', mac='02:00:00:00:00:01')
    assert db.conn.execute('SELECT unban_time FROM banned_hosts WHERE id=1').fetchone()[0] == '2000-01-01'
    assert not db.get_active_bans()
    db.close()


def test_dns_listener_runs_outside_database_lock():
    db = Database(':memory:')
    completed = []
    def emit(*args, **kwargs):
        thread = threading.Thread(target=lambda: completed.append(db.get_total_alert_count()))
        thread.start()
        thread.join(timeout=1)
        assert not thread.is_alive()
    db.socketio = Mock(emit=emit)
    db.add_dns_log('192.0.2.1', None, 'example.org')
    assert completed == [0]
    db.close()


def test_event_bus_awaits_async_handlers_and_stops_idle():
    async def scenario():
        bus = EventBus()
        received = []
        async def handler(value):
            await asyncio.sleep(0)
            received.append(value)
        bus.subscribe('event', handler)
        task = asyncio.create_task(bus.run())
        await bus.publish('event', 1)
        await asyncio.wait_for(bus._queue.join(), timeout=1)
        assert received == [1]
        bus.stop()
        await asyncio.wait_for(task, timeout=1)
        assert not bus.running
    asyncio.run(scenario())


def test_fast_sniffer_understands_actual_ek_layers():
    sniffer = FastSniffer()
    sniffer.honeypot_ips = {'192.0.2.10'}
    events = []
    sniffer.register_callback(events.append)
    sniffer.analyze_packet({'layers': {'arp': {'arp_arp_opcode': '2', 'arp_arp_src_proto_ipv4': '192.0.2.1', 'arp_arp_src_hw_mac': '02:00:00:00:00:01'}}})
    sniffer.analyze_packet({'layers': {'ip': {'ip_ip_src': ['192.0.2.2'], 'ip_ip_dst': '192.0.2.10'}, 'tcp': {'tcp_tcp_flags': '0x0002', 'tcp_tcp_dstport': '2222'}}})
    assert [event['type'] for event in events] == ['DEVICE_DISCOVERED', 'HONEYPOT_HIT']


def test_remote_smb_is_not_a_honeypot_and_flood_alerts_are_throttled():
    sniffer = FastSniffer()
    events = []
    sniffer.register_callback(events.append)
    packet = {'layers': {'ip': {'ip_ip_src': '192.0.2.2', 'ip_ip_dst': '192.0.2.3'},
                         'tcp': {'tcp_tcp_flags': '0x0002', 'tcp_tcp_dstport': '445'}}}
    for _ in range(200):
        sniffer.analyze_packet(packet)
    assert [event['type'] for event in events] == ['SYN_FLOOD']


def test_scanner_uses_argv_and_handles_multiple_addresses(monkeypatch):
    run = Mock(return_value=Mock(stdout='2: eth0 inet 192.0.2.3/24 scope global eth0\n2: eth0 inet 10.0.0.1/8 scope global secondary eth0\n'))
    monkeypatch.setattr('core.scanner.subprocess.run', run)
    scanner = NetworkScanner(Mock(), interface='eth0; false')
    assert scanner.get_subnet() == '192.0.2.0/24'
    assert run.call_args.args[0][-1] == 'eth0; false'
    scanner.target = '198.51.100.2/24'
    assert scanner.get_subnet() == '198.51.100.0/24'
