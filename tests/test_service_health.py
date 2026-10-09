"""Service startup/health regressions; no log followers or network connections."""

import asyncio
import json
import logging
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from services import RuntimeServices
from test_web_security import login, panel as panel


def wait_for_state(services, name, state):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if services.status()['services'][name]['state'] == state:
            return
        time.sleep(0.005)
    assert services.status()['services'][name]['state'] == state


@pytest.mark.parametrize('during_constructor', [True, False])
def test_initialization_failure_is_reported_to_caller_and_cleans_up(monkeypatch, during_constructor):
    from modules import hids_engine

    class BrokenHIDS:
        def __init__(self):
            if during_constructor:
                raise ValueError('private credential detail')

        def register_callback(self, callback):
            pass

        async def run(self):
            raise ValueError('private credential detail')

        def stop(self):
            pass

    monkeypatch.setattr(hids_engine, 'HIDSEngine', BrokenHIDS)
    webapp = SimpleNamespace(db=MagicMock(), _handle_alert=MagicMock())
    services = RuntimeServices(webapp)
    with pytest.raises(RuntimeError, match='could not start') as error:
        services.start()
    assert isinstance(error.value.__cause__, ValueError)
    assert not services.thread.is_alive()
    assert services.status()['services']['hids'] == {'state': 'failed', 'error': 'ValueError'}
    assert 'private credential detail' not in json.dumps(services.status())
    assert webapp.db.set_alert_callback.call_args.args == (webapp._handle_alert,)


def test_runtime_task_failure_is_logged_and_visible(monkeypatch, caplog):
    from modules import hids_engine

    class FailingHIDS:
        def register_callback(self, callback):
            pass

        async def run(self):
            self.fail = asyncio.Event()
            await self.fail.wait()
            raise OSError('reader failed')

        def stop(self):
            pass

    engine = FailingHIDS()
    monkeypatch.setattr(hids_engine, 'HIDSEngine', lambda: engine)
    services = RuntimeServices(SimpleNamespace(db=MagicMock(), _handle_alert=MagicMock()))
    try:
        with caplog.at_level(logging.ERROR, logger='services'):
            services.start()
            assert services.status()['services']['hids']['state'] == 'running'
            services.loop.call_soon_threadsafe(engine.fail.set)
            wait_for_state(services, 'hids', 'failed')
        assert services.thread.is_alive()
        assert services.status()['services']['hids']['error'] == 'OSError'
        assert 'hids background task failed' in caplog.text
    finally:
        services.stop()


def test_absent_optional_logs_leave_hids_idle_without_failing_web(monkeypatch, tmp_path):
    from modules import hids_engine

    engine = hids_engine.HIDSEngine()
    engine.LOG_FILES = {'auth_log': str(tmp_path / 'absent.log')}
    monkeypatch.setattr(hids_engine, 'HIDSEngine', lambda: engine)
    services = RuntimeServices(SimpleNamespace(db=MagicMock(), _handle_alert=MagicMock()))
    try:
        services.start()
        wait_for_state(services, 'hids', 'idle')
        assert services.status()['running'] is True
        assert services.status()['services']['event_bus']['state'] == 'running'
    finally:
        services.stop()


def test_health_api_requires_auth_and_reports_configured_services(panel):
    client = panel.app.test_client()
    assert client.get('/api/service-health').status_code == 401
    services = RuntimeServices(panel, hids_enabled=False, telegram_enabled=False)
    services.start()
    login(panel, client)
    result = client.get('/api/service-health')
    assert result.status_code == 200
    assert result.json == services.status()
    assert result.json['services']['hids']['state'] == 'disabled'


@pytest.mark.parametrize('healthy_reader', [False, True])
def test_real_hids_reader_failure_is_failed_or_degraded(monkeypatch, tmp_path, healthy_reader, caplog):
    from modules import hids_engine

    bad_path = tmp_path / 'unreadable.log'
    good_path = tmp_path / 'readable.log'
    bad_path.touch()
    good_path.touch()

    class Process:
        returncode = None

        def __init__(self):
            self.stdout = self

        async def readline(self):
            await asyncio.Event().wait()

        def terminate(self):
            self.returncode = 0

        async def wait(self):
            return self.returncode

    process = Process()

    async def spawn(*args, **kwargs):
        if args[-1] == str(bad_path):
            raise OSError('reader startup failed')
        return process

    engine = hids_engine.HIDSEngine()
    engine.LOG_FILES = {'bad': str(bad_path)}
    if healthy_reader:
        engine.LOG_FILES['good'] = str(good_path)
    monkeypatch.setattr(hids_engine, 'HIDSEngine', lambda: engine)
    monkeypatch.setattr(hids_engine.asyncio, 'create_subprocess_exec', spawn)
    services = RuntimeServices(SimpleNamespace(db=MagicMock(), _handle_alert=MagicMock()))
    try:
        with caplog.at_level(logging.ERROR):
            if healthy_reader:
                services.start()
                wait_for_state(services, 'hids', 'degraded')
            else:
                with pytest.raises(RuntimeError, match='could not start'):
                    services.start()
                assert services.status()['services']['hids']['state'] == 'failed'
        assert services.status()['services']['hids']['readers']['bad']['state'] == 'failed'
        assert 'HIDS reader failed: bad' in caplog.text
    finally:
        services.stop()
    if healthy_reader:
        assert process.returncode == 0


def test_telegram_suppressed_adapter_error_is_not_reported_running(monkeypatch):
    import sys

    class Bot:
        def __init__(self, *args):
            self.app = SimpleNamespace(running=False, updater=SimpleNamespace(running=False))

        async def start_polling(self):
            pass  # Legacy adapter swallowed its initialization exception.

        async def stop(self):
            pass

    monkeypatch.setitem(sys.modules, 'responder.telegram_bot', SimpleNamespace(TelegramBot=Bot))
    monkeypatch.setenv('BOT_TOKEN', 'test-token')
    monkeypatch.setenv('CHAT_ID', '1')
    services = RuntimeServices(SimpleNamespace(db=MagicMock(), _handle_alert=MagicMock(), blocker=None),
                               hids_enabled=False, telegram_enabled=True)
    with pytest.raises(RuntimeError, match='could not start'):
        services.start()
    assert services.status()['services']['telegram']['state'] == 'failed'
    assert not services.thread.is_alive()
