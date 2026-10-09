"""Shared, explicitly started optional services for CLI and WSGI entrypoints."""

import asyncio
import concurrent.futures
import logging
import os
import threading

logger = logging.getLogger(__name__)


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name}: expected true/false, got {value!r}")


class RuntimeServices:
    """Keep asyncio services alive in one owned loop and stop before the database."""

    def __init__(self, webapp, hids_enabled=True, telegram_enabled=False):
        self.webapp = webapp
        self.hids_enabled = hids_enabled
        self.telegram_enabled = telegram_enabled
        self.thread = None
        self.loop = None
        self.event_bus = None
        self._stop_event = None
        self._serve_task = None
        self.hids = None
        self._ready = threading.Event()
        self._stopping = threading.Event()
        self._startup_error = None
        self._health_lock = threading.Lock()
        self._health = {}
        self.webapp.runtime_services = self
        self._reset_health()

    def _reset_health(self):
        with self._health_lock:
            self._health = {
                'event_bus': {'state': 'stopped' if self.hids_enabled or self.telegram_enabled else 'disabled'},
                'hids': {'state': 'stopped' if self.hids_enabled else 'disabled'},
                'telegram': {'state': 'stopped' if self.telegram_enabled else 'disabled'},
            }

    def _set_health(self, name, state, error=None):
        with self._health_lock:
            # Public health must not expose credentials or paths from exceptions.
            self._health[name] = {'state': state}
            if error is not None:
                self._health[name]['error'] = type(error).__name__

    def status(self):
        with self._health_lock:
            health = {name: dict(value) for name, value in self._health.items()}
        readers = getattr(self.hids, 'reader_health', None)
        if isinstance(readers, dict):
            health['hids']['readers'] = {name: dict(value) for name, value in readers.items()}
            if health['hids']['state'] == 'running' and any(
                    value['state'] == 'failed' for value in readers.values()):
                health['hids']['state'] = 'degraded'
        return {'running': bool(self.thread and self.thread.is_alive()), 'services': health}

    def _task_finished(self, name, task):
        if task.cancelled():
            with self._health_lock:
                if self._health[name]['state'] != 'failed':
                    self._health[name] = {'state': 'stopped'}
            return
        error = task.exception()
        if error is not None:
            self._set_health(name, 'failed', error)
            logger.error('%s background task failed', name,
                         exc_info=(type(error), error, error.__traceback__))
            if not self._ready.is_set():
                self._startup_error = error
        else:
            # HIDS can finish normally when none of its optional logs exist.
            self._set_health(name, 'stopped' if self._stopping.is_set() else 'idle')

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        if not self.hids_enabled and not self.telegram_enabled:
            return
        self._ready.clear()
        self._stopping.clear()
        self._startup_error = None
        self.hids = None
        self._reset_health()
        self.thread = threading.Thread(target=self._run, name="dsips-services", daemon=True)
        self.thread.start()
        if not self._ready.wait(timeout=5):
            self.stop()
            raise RuntimeError("Background service event loop did not start")
        if self._startup_error is not None:
            self.stop()
            raise RuntimeError('Background services could not start') from self._startup_error

    def _run(self):
        try:
            asyncio.run(self._serve())
        except asyncio.CancelledError:
            if not self._ready.is_set():
                self._startup_error = RuntimeError('Background service startup cancelled')
        except Exception as error:
            self._set_health('runtime', 'failed', error)
            if not self._ready.is_set():
                self._startup_error = error
            logger.exception("Background services failed")
        finally:
            self.loop = None
            self._serve_task = None
            self._ready.set()

    async def _serve(self):
        from core.event_bus import EventBus

        self.loop = asyncio.get_running_loop()
        self._serve_task = asyncio.current_task()
        self._stop_event = asyncio.Event()
        self.event_bus = EventBus()
        tasks = {'event_bus': asyncio.create_task(self.event_bus.run())}
        bot = None
        hids = None
        try:
            self.webapp.db.set_alert_callback(self._handle_alert)
            if self.hids_enabled:
                from modules.hids_engine import HIDSEngine

                self._set_health('hids', 'starting')
                try:
                    hids = HIDSEngine()
                    self.hids = hids
                    hids.register_callback(self._hids_alert)
                    tasks['hids'] = asyncio.create_task(hids.run())
                except Exception as error:
                    self._set_health('hids', 'failed', error)
                    raise
            for name, task in tasks.items():
                self._set_health(name, 'running')
                task.add_done_callback(lambda completed, service=name: self._task_finished(service, completed))
            if self.telegram_enabled:
                token = os.environ.get("BOT_TOKEN")
                chat_id = os.environ.get("CHAT_ID")
                if not token or not chat_id:
                    self._set_health('telegram', 'unconfigured')
                    logger.warning("Telegram requires BOT_TOKEN and CHAT_ID")
                else:
                    try:
                        from responder.telegram_bot import TelegramBot

                        bot = TelegramBot(token, chat_id, self.event_bus, self.webapp.blocker)
                        await asyncio.wait_for(bot.start_polling(), timeout=3)
                        if not bot.app.running or not bot.app.updater.running:
                            raise RuntimeError('Telegram polling did not start')
                        self._set_health('telegram', 'running')
                    except Exception as error:
                        self._set_health('telegram', 'failed', error)
                        raise
            # Let newly created coroutines execute their initialization before
            # advertising readiness to the WSGI/CLI entrypoint.
            await asyncio.sleep(0)
            if hids is not None and isinstance(getattr(hids, 'ready', None), asyncio.Event):
                try:
                    await asyncio.wait_for(hids.ready.wait(), timeout=3)
                    available = [value for value in hids.reader_health.values()
                                 if value['state'] != 'unavailable']
                    if available and all(value['state'] == 'failed' for value in available):
                        raise RuntimeError('No HIDS log reader could start')
                except Exception as error:
                    self._set_health('hids', 'failed', error)
                    raise
            for task in tasks.values():
                if task.done() and not task.cancelled() and task.exception() is not None:
                    raise task.exception()
            if self._startup_error is not None:
                raise self._startup_error
            self._ready.set()
            if self._stopping.is_set():
                self._stop_event.set()
            await self._stop_event.wait()
        finally:
            self._stopping.set()
            self.webapp.db.set_alert_callback(self.webapp._handle_alert)
            if hids:
                try:
                    hids.stop()
                except Exception:
                    logger.exception('HIDS shutdown failed')
            if bot:
                try:
                    await asyncio.wait_for(bot.stop(), timeout=3)
                except Exception:
                    logger.exception("Telegram shutdown failed")
                with self._health_lock:
                    if self._health['telegram']['state'] == 'running':
                        self._health['telegram'] = {'state': 'stopped'}
            self.event_bus.stop()
            for task in tasks.values():
                task.cancel()
            await asyncio.gather(*tasks.values(), return_exceptions=True)

    def _hids_alert(self, event):
        self.webapp.db.add_alert(
            alert_type=event.get("type", "HIDS"),
            src_ip=event.get("source_ip"), src_mac=None, dst_ip=None, dst_mac=None,
            description=event.get("details", ""), severity=event.get("severity", "high"),
            source_verified=event.get("source_verified") is True,
        )

    def _handle_alert(self, alert):
        try:
            self.webapp._handle_alert(alert)
        finally:
            loop = self.loop
            if (self.telegram_enabled and loop and loop.is_running() and not self._stopping.is_set()
                    and self.event_bus and self.event_bus.running):
                event = {
                    "type": alert.get("alert_type", "HIDS"),
                    "source_ip": alert.get("source_ip"),
                    "details": alert.get("description", ""),
                    "severity": alert.get("severity", "high"),
                }
                coro = self.event_bus.publish("ALERT", event)
                try:
                    future = asyncio.run_coroutine_threadsafe(coro, loop)
                    future.add_done_callback(self._publish_done)
                except RuntimeError:
                    coro.close()

    @staticmethod
    def _publish_done(future):
        try:
            future.result()
        except concurrent.futures.CancelledError:
            pass
        except Exception:
            logger.exception("Could not publish Telegram event")

    def stop(self):
        self._stopping.set()
        loop = self.loop
        if loop and not loop.is_closed() and self._stop_event:
            try:
                loop.call_soon_threadsafe(self._stop_event.set)
                if not self._ready.is_set() and self._serve_task:
                    loop.call_soon_threadsafe(self._serve_task.cancel)
            except RuntimeError:
                pass
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                logger.warning("Background services have not finished shutting down")
