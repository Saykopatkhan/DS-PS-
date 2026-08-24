import asyncio
from typing import Callable, List, Dict, Any

class EventBus:
    """
    Tüm modüller (NIDS, HIDS vb.) arasındaki asenkron iletişimi sağlayan merkezi olay döngüsü.
    """
    def __init__(self):
        self._queue = asyncio.Queue()
        self._handlers: Dict[str, List[Callable]] = {}
        self.running = False

    def subscribe(self, event_type: str, handler: Callable):
        """Bir olay tipine abone olur."""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    async def publish(self, event_type: str, data: Any):
        """Bir olayı kuyruğa ekler."""
        await self._queue.put({'type': event_type, 'data': data})

    async def run(self):
        """Olay kuyruğunu işleyen ana döngü."""
        self.running = True
        print("[*] EventBus başlatıldı, olaylar dinleniyor...")
        while self.running:
            try:
                event = await self._queue.get()
                event_type = event['type']
                data = event['data']
                
                if event_type in self._handlers:
                    for handler in self._handlers[event_type]:
                        try:
                            # Handler async ise bekle, değilse direkt çalıştır
                            if asyncio.iscoroutinefunction(handler):
                                asyncio.create_task(handler(data))
                            else:
                                handler(data)
                        except Exception as e:
                            print(f"[!] Event handler hatası ({event_type}): {e}")
                            
                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[!] EventBus hatası: {e}")

    def stop(self):
        self.running = False
