# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

import requests
import threading
import html

class Notifier:
    """
    Kritik durumlarda Telegram veya Discord Webhook'una bildirim gönderir.
    """
    def __init__(self, telegram_token=None, telegram_chat_id=None, discord_webhook=None):
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.discord_webhook = discord_webhook
        self.sent_count = 0
        self.command_count = 0
        self._slots = threading.BoundedSemaphore(4)
        self._lock = threading.Lock()

    def send_alert(self, title, message, severity="high"):
        if not (self.telegram_token and self.telegram_chat_id or self.discord_webhook):
            return False
        if not self._slots.acquire(blocking=False):
            return False
        def _send():
            try:
                delivered = False
                if self.telegram_token and self.telegram_chat_id:
                    delivered = self._send_telegram(f"🚨 <b>{html.escape(str(title))}</b>\n\n{html.escape(str(message))}")
                if self.discord_webhook:
                    delivered = self._send_discord(str(title), str(message), 16711680 if severity == 'critical' else 16753920) or delivered
                if delivered:
                    with self._lock:
                        self.sent_count += 1
            finally:
                self._slots.release()
        threading.Thread(target=_send, daemon=True).start()
        return True

    def _send_telegram(self, text):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat_id,
                "text": text,
                "parse_mode": "HTML"
            }
            r = requests.post(url, json=payload, timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def _send_discord(self, title, message, color):
        try:
            payload = {
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": color
                }]
            }
            response = requests.post(self.discord_webhook, json=payload, timeout=5)
            return 200 <= response.status_code < 300
        except Exception:
            return False

