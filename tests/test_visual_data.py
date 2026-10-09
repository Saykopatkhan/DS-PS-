"""Dashboard capture and inventory contracts without starting network services."""
from unittest.mock import Mock

from core.database import Database
from core.fast_sniffer import FastSniffer
from core.sniffer import PacketSniffer
from test_web_security import panel as panel


def test_inventory_preserves_shared_mac_and_latest_ip_binding():
    db = Database(':memory:')
    try:
        db.update_ip_mac('192.0.2.10', '02:00:00:00:00:01')
        db.update_ip_mac('192.0.2.11', '02:00:00:00:00:01')
        db.update_ip_mac('192.0.2.12', 'N/A')
        db.update_ip_mac('192.0.2.13', 'N/A')
        db.update_ip_mac('192.0.2.10', '02:00:00:00:00:02')
        records = db.get_ip_mac_records()
        assert len(records) == 4
        assert records[0]['ip_address'] == '192.0.2.10'
        assert records[0]['mac_address'] == '02:00:00:00:00:02'
        assert len(db.get_ip_mac_records(limit=2)) == 2
        assert db.get_ip_mac_records(limit=0) == []
    finally:
        db.close()


def test_scapy_counts_all_packets_even_if_a_detector_fails():
    sniffer = PacketSniffer()
    callback = Mock(side_effect=ValueError('detector failed'))
    healthy = Mock()
    sniffer.register_callback(callback)
    sniffer.register_callback(healthy)
    sniffer._packet_handler(object())
    assert sniffer.packet_count == 1
    assert sniffer.last_packet_at is not None
    healthy.assert_called_once()


def test_fast_capture_counts_non_alert_traffic():
    sniffer = FastSniffer()
    sniffer.analyze_packet({'index': {}})
    assert sniffer.packet_count == 0
    sniffer.analyze_packet({'layers': {'ip': {'ip_ip_src': '192.0.2.1', 'ip_ip_dst': '192.0.2.2'}}})
    assert sniffer.packet_count == 1
    assert sniffer.last_packet_at is not None


def test_dead_capture_is_not_reported_active_and_can_restart(panel):
    panel.sniffer_running = True
    panel.sniffer.running = False
    panel.legacy_sniffer.running = False
    panel.sniffer.last_error = 'tshark unavailable'
    stats = panel._get_stats()
    assert stats['monitoring_requested'] is True
    assert stats['sniffer_running'] is False
    assert stats['capture']['tshark']['error'] == 'tshark unavailable'
    panel._start_monitoring()
    panel.sniffer.start.assert_called_once()
    panel.legacy_sniffer.start.assert_called_once()


def test_partial_capture_remains_visible_and_reports_packet_count(panel):
    panel.sniffer_running = True
    panel.sniffer.running = False
    panel.legacy_sniffer.running = True
    panel.legacy_sniffer.packet_count = 12
    panel.legacy_sniffer.last_packet_at = 1000.0
    stats = panel._get_stats()
    assert stats['sniffer_running'] is True
    assert stats['capture']['scapy']['packets'] == 12
    assert stats['capture']['scapy']['last_packet_at'] == 1000.0
