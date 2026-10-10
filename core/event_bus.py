import asyncio
import inspect
import logging
from typing import Callable, List, Dict, Any


class EventBus:
    """Dispatch events on one asyncio loop and shut down without a pending get()."""

    def __init__(self):
        self._queue = asyncio.Queue(maxsize=10000)
        self._handlers: Dict[str, List[Callable]] = {}
        self.running = False
        self._loop = None

    def subscribe(self, event_type: str, handler: Callable):
        handlers = self._handlers.setdefault(event_type, [])
        if handler not in handlers:
            handlers.append(handler)

    async def publish(self, event_type: str, data: Any):
        await self._queue.put({'type': event_type, 'data': data})

    async def run(self):
        if self.running:
            return
        self._loop = asyncio.get_running_loop()
        self.running = True
        try:
            while self.running:
                event = await self._queue.get()
                try:
                    if event is None:
                        break
                    for handler in tuple(self._handlers.get(event['type'], ())):
                        try:
                            result = handler(event['data'])
                            if inspect.isawaitable(result):
                                await result
                        except Exception:
                            logging.exception('Event handler failed: %s', event['type'])
                finally:
                    self._queue.task_done()
        finally:
            self.running = False
            self._loop = None

    def stop(self):
        def wake():
            # Keep running true until the sentinel is consumed: queued events are
            # drained and task_done remains balanced even when stop races a handler.
            try:
                self._queue.put_nowait(None)
            except asyncio.QueueFull:
                self.running = False
        if self._loop and self.running:
            self._loop.call_soon_threadsafe(wake)
