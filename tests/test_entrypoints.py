"""Offline regressions for configuration and optional service lifecycle."""

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from services import RuntimeServices, env_bool
from web_main import build_parser


@pytest.mark.parametrize("value, expected", [("true", True), ("1", True), ("false", False), ("0", False)])
def test_environment_boolean(monkeypatch, value, expected):
    monkeypatch.setenv("DSIPS_TEST_BOOL", value)
    assert env_bool("DSIPS_TEST_BOOL") is expected


def test_environment_boolean_rejects_typo(monkeypatch):
    monkeypatch.setenv("DSIPS_TEST_BOOL", "treu")
    with pytest.raises(ValueError):
        env_bool("DSIPS_TEST_BOOL")


@pytest.mark.parametrize("arguments", [["--port", "0"], ["--port", "65536"], ["--unban-time", "-1"]])
def test_cli_rejects_invalid_values(arguments):
    with pytest.raises(SystemExit) as result:
        build_parser().parse_args(arguments)
    assert result.value.code == 2


def test_optional_services_preserve_severity():
    webapp = SimpleNamespace(db=MagicMock(), _handle_alert=MagicMock())
    service = RuntimeServices(webapp)
    service._hids_alert({"type": "SQL_INJECTION", "source_ip": "192.0.2.1", "details": "payload", "severity": "critical"})
    assert webapp.db.add_alert.call_args.kwargs["severity"] == "critical"


@pytest.mark.parametrize('autostart, fail', [(False, False), (True, False), (True, True)])
def test_web_autostart_lifecycle(monkeypatch, autostart, fail):
    import web_main
    import web.app

    panel = MagicMock()
    services = MagicMock()
    monkeypatch.setattr(web_main, 'load_dotenv', lambda *_: None)
    monkeypatch.setattr(web.app, 'IPSWebApp', MagicMock(return_value=panel))
    monkeypatch.setattr(web_main, 'RuntimeServices', MagicMock(return_value=services))
    monkeypatch.setattr(web_main.os, 'geteuid', lambda: 0)
    monkeypatch.setenv('DS_IPS_DRY_RUN', 'false')
    arguments = ['--mode', 'ips', '--interface', 'test0'] + (['--autostart'] if autostart else [])
    if fail:
        panel._start_monitoring.side_effect = RuntimeError('capture failed')
        with pytest.raises(RuntimeError, match='capture failed'):
            web_main.main(arguments)
        panel.run.assert_not_called()
    else:
        web_main.main(arguments)
        panel.run.assert_called_once()
    assert panel._start_monitoring.call_count == int(autostart)
    services.start.assert_called_once()
    services.stop.assert_called_once()
    panel.close.assert_called_once()


def test_services_loop_lives_until_stop_and_restores_callback(monkeypatch):
    from modules import hids_engine

    started = threading.Event()
    cancelled = threading.Event()

    class HIDS:
        def register_callback(self, callback):
            self.callback = callback

        async def run(self):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        def stop(self):
            pass

    monkeypatch.setattr(hids_engine, "HIDSEngine", HIDS)
    webapp = SimpleNamespace(db=MagicMock(), _handle_alert=MagicMock())
    services = RuntimeServices(webapp)
    try:
        services.start()
        assert started.wait(timeout=2)
        assert services.thread.is_alive()
        first_thread = services.thread
        services.start()
        assert services.thread is first_thread
    finally:
        services.stop()
    assert not services.thread.is_alive()
    assert cancelled.is_set()
    assert webapp.db.set_alert_callback.call_args.args == (webapp._handle_alert,)


def test_disabled_services_do_not_start_threads():
    services = RuntimeServices(MagicMock(), hids_enabled=False, telegram_enabled=False)
    services.start()
    assert services.thread is None
    services.stop()


def test_console_alert_listing_uses_database_schema(monkeypatch):
    from main import SOCConsole

    console_app = SOCConsole.__new__(SOCConsole)
    console_app.db = MagicMock()
    console_app.db.get_alerts.return_value = [{
        "timestamp": "2026-09-19 10:00:00", "alert_type": "Test",
        "source_ip": "192.0.2.1", "source_mac": None, "description": "Test alarmı",
    }]
    output = MagicMock()
    monkeypatch.setattr("main.console", output)
    console_app.list_alerts()
    console_app.db.get_alerts.assert_called_once_with(limit=15)
    output.print.assert_called_once()


def test_qa_rate_limit_probe_does_not_confuse_csrf_denial_with_ban(monkeypatch):
    from ds_ips_qa_suite import probe_login_rate_limit
    client = MagicMock()
    client.get.return_value.text = '<input name="csrf_token" value="test-token">'
    client.post.return_value.status_code = 403
    monkeypatch.setattr('ds_ips_qa_suite.requests.Session', lambda: client)
    client.__enter__.return_value = client
    with pytest.raises(ValueError, match='403'):
        probe_login_rate_limit('http://example.invalid')
    assert client.post.call_args.kwargs['data']['csrf_token'] == 'test-token'


def test_qa_rate_limit_probe_accepts_only_observed_429(monkeypatch):
    from ds_ips_qa_suite import probe_login_rate_limit
    client = MagicMock()
    client.get.return_value.text = '<input name="csrf_token" value="test-token">'
    client.post.side_effect = [SimpleNamespace(status_code=401)] * 5 + [SimpleNamespace(status_code=429)]
    monkeypatch.setattr('ds_ips_qa_suite.requests.Session', lambda: client)
    client.__enter__.return_value = client
    assert probe_login_rate_limit('http://example.invalid') is True
