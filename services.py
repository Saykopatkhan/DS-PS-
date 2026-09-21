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
        self._ready = threading.Event()
        self._stopping = threading.Event()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        if not self.hids_enabled and not self.telegram_enabled:
            return
        self._ready.clear()
        self._stopping.clear()
        self.thread = threading.Thread(target=self._run, name="dsips-services", daemon=True)
        self.thread.start()
        if not self._ready.wait(timeout=5):
            self.stop()
            raise RuntimeError("Background service event loop did not start")

    def _run(self):
        try:
            asyncio.run(self._serve())
        except Exception:
            logger.exception("Background services failed")
        finally:
            self._ready.set()
            self.loop = None

    async def _serve(self):
        from core.event_bus import EventBus

        self.loop = asyncio.get_running_loop()
        self._stop_event = asyncio.Event()
        self.event_bus = EventBus()
        tasks = [asyncio.create_task(self.event_bus.run())]
        bot = None
        hids = None
        self.webapp.db.set_alert_callback(self._handle_alert)
        self._ready.set()
        try:
            if self.hids_enabled:
                from modules.hids_engine import HIDSEngine

                hids = HIDSEngine()
                hids.register_callback(self._hids_alert)
                tasks.append(asyncio.create_task(hids.run()))
            if self.telegram_enabled:
                token = os.environ.get("BOT_TOKEN")
                chat_id = os.environ.get("CHAT_ID")
                if not token or not chat_id:
                    logger.warning("Telegram requires BOT_TOKEN and CHAT_ID")
                else:
                    try:
                        from responder.telegram_bot import TelegramBot

                        bot = TelegramBot(token, chat_id, self.event_bus, self.webapp.blocker)
                        await bot.start_polling()
                    except Exception:
                        logger.exception("Optional Telegram service could not start")
            if self._stopping.is_set():
                self._stop_event.set()
            await self._stop_event.wait()
        finally:
            self.webapp.db.set_alert_callback(self.webapp._handle_alert)
            if hids:
                hids.stop()
            if bot:
                try:
                    await asyncio.wait_for(bot.stop(), timeout=3)
                except Exception:
                    logger.exception("Telegram shutdown failed")
            self.event_bus.stop()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def _hids_alert(self, event):
        self.webapp.db.add_alert(
            alert_type=event.get("type", "HIDS"),
            src_ip=event.get("source_ip"), src_mac=None, dst_ip=None, dst_mac=None,
            description=event.get("details", ""), severity=event.get("severity", "high"),
        )

    def _handle_alert(self, alert):
        try:
            self.webapp._handle_alert(alert)
        finally:
            loop = self.loop
            if self.telegram_enabled and loop and loop.is_running() and not self._stopping.is_set():
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
            except RuntimeError:
                pass
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                logger.warning("Background services have not finished shutting down")
