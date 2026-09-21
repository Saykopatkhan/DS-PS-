import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
import ipaddress

class TelegramBot:
    """Asenkron Telegram Yönetim Ajanı."""
    def __init__(self, token, chat_id, event_bus, blocker):
        self.token = token
        self.chat_id = chat_id
        self.event_bus = event_bus
        self.blocker = blocker
        
        self.app = Application.builder().token(self.token).build()
        self.app.add_handler(CommandHandler("start", self.start))
        self.app.add_handler(CallbackQueryHandler(self.button_callback))
        
        # Olay kuyruğunu dinle
        self.event_bus.subscribe('ALERT', self._handle_alert)
        self.event_bus.subscribe('BAN', self._handle_ban)

    def _authorized(self, update):
        # Configured chat must be present on *every* control update. Matching
        # private chat IDs also binds the sender; group membership is trusted.
        return (self.chat_id is not None and update.effective_chat is not None
                and str(update.effective_chat.id) == str(self.chat_id))

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        await update.message.reply_text("🛡️ DS-IPS v5.0 Telegram Yönetim Ajanı Aktif.")

    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        if not self._authorized(update):
            await query.answer('Yetkisiz işlem', show_alert=True)
            return
        await query.answer()
        action, separator, ip = (query.data or '').partition(':')
        if not separator or action not in {'ban', 'unban'}:
            return
        try:
            ip = str(ipaddress.IPv4Address(ip))
        except ValueError:
            return
        
        if action == "ban":
            try:
                success = await asyncio.to_thread(self.blocker.block_ip, ip, reason="Telegram Bot üzerinden manuel engelleme")
            except ValueError:
                success = False
            msg = f"🔒 {ip} başarıyla engellendi!" if success else f"⚠️ {ip} zaten engellenmiş."
            await query.edit_message_text(text=query.message.text + f"\n\n👉 Sonuç: {msg}")
            
        elif action == "unban":
            success = await asyncio.to_thread(self.blocker.unblock_ip, ip)
            msg = f"🔓 {ip} engeli kaldırıldı!" if success else f"⚠️ {ip} engelli değildi."
            await query.edit_message_text(text=query.message.text + f"\n\n👉 Sonuç: {msg}")

    async def _handle_alert(self, event):
        """EventBus'tan gelen alarmları Telegram'a iletir."""
        if not self.chat_id:
            return
            
        try:
            source_ip = event.get('source_ip', 'Bilinmiyor')
            alert_type = event.get('alert_type', event.get('type', 'Bilinmiyor'))
            details = event.get('description', event.get('details', ''))
            
            keyboard = [
                [
                    InlineKeyboardButton("🔒 ipset ile Engelle", callback_data=f"ban:{source_ip}"),
                    InlineKeyboardButton("🔓 Engeli Kaldır", callback_data=f"unban:{source_ip}")
                ]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            message = f"🚨 *YENİ ALARM* 🚨\n\n*Tür:* {alert_type}\n*Kaynak IP:* `{source_ip}`\n*Detay:* {details}"
            
            await self.app.bot.send_message(
                chat_id=self.chat_id,
                text=message,
                reply_markup=reply_markup
            )
        except Exception as e:
            print(f"[!] Telegram Alert Gönderme Hatası: {e}")

    async def _handle_ban(self, event):
        if not self.chat_id:
            return
        try:
            ip = event.get('ip')
            reason = event.get('reason')
            message = f"🛑 *OTOMATİK ENGELLEME* 🛑\n\n*IP:* `{ip}`\n*Neden:* {reason}"
            await self.app.bot.send_message(chat_id=self.chat_id, text=message)
        except Exception:
            pass

    async def start_polling(self):
        """Asenkron olarak botu başlatır."""
        print("[*] Telegram Bot Polling başlatılıyor...")
        try:
            await self.app.initialize()
            await self.app.start()
            await self.app.updater.start_polling()
        except Exception as e:
            print(f"[!] Telegram Bot başlatılamadı: {e}")
            
    async def stop(self):
        # Stop each component independently even after partial initialization.
        for operation in (self.app.updater.stop, self.app.stop, self.app.shutdown):
            try:
                await operation()
            except RuntimeError:
                pass
