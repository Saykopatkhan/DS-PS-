import requests
import threading

class Notifier:
    """
    Kritik durumlarda Telegram veya Discord Webhook'una bildirim gönderir.
    """
    def __init__(self, telegram_token=None, telegram_chat_id=None, discord_webhook=None):
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.discord_webhook = discord_webhook

    def send_alert(self, title, message, severity="high"):
        def _send():
            if self.telegram_token and self.telegram_chat_id:
                self._send_telegram(f"🚨 <b>{title}</b>\n\n{message}")
                
            if self.discord_webhook:
                color = 16711680 if severity == "critical" else 16753920
                self._send_discord(title, message, color)
                
        threading.Thread(target=_send, daemon=True).start()

    def _send_telegram(self, text):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat_id,
                "text": text,
                "parse_mode": "HTML"
            }
            requests.post(url, json=payload, timeout=5)
        except Exception:
            pass

    def _send_discord(self, title, message, color):
        try:
            payload = {
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": color
                }]
            }
            requests.post(self.discord_webhook, json=payload, timeout=5)
        except Exception:
            pass
