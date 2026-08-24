import argparse
import os
import sys
import asyncio
from colorama import init, Fore, Style
from dotenv import load_dotenv

# Yeni Asenkron Mimari Bileşenleri
from core.database import Database
from core.event_bus import EventBus
from core.fast_sniffer import FastSniffer
from modules.hids_engine import HIDSEngine
from responder.blocker import Blocker
from responder.telegram_bot import TelegramBot

# Flask/SocketIO entegrasyonunu asyncio içerisinde yönetebilmek için
import threading
from web.app import IPSWebApp

init(autoreset=True)
load_dotenv() # .env dosyasından token vb. çekmek için

def print_banner():
    banner = f"""
{Fore.YELLOW}
  ██████╗ ███████╗   ██╗██████╗ ███████╗
  ██╔══██╗██╔════╝   ██║██╔══██╗██╔════╝
  ██║  ██║███████╗█████║██████╔╝███████╗
  ██║  ██║╚════██║╚════╝██╔═══╝ ╚════██║
  ██████╔╝███████║   ██║██║     ███████║
  ╚═════╝ ╚══════╝   ╚═╝╚═╝     ╚══════╝
{Style.RESET_ALL}
{Fore.CYAN}       Next-Gen Hybrid IPS v5.0{Style.RESET_ALL}
{Fore.GREEN}       (Async, ipset, HIDS/WAF){Style.RESET_ALL}
    """
    print(banner)

async def main():
    parser = argparse.ArgumentParser(description='DS-IPS Next-Gen Hybrid')
    parser.add_argument('-i', '--interface', default='eth0', help='Dinlenecek ağ arayüzü')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Web panel portu')
    parser.add_argument('--host', default='0.0.0.0', help='Web panel host adresi')
    parser.add_argument('--db', default='ds_ips.db', help='Veritabanı dosyası')
    args = parser.parse_args()

    print_banner()

    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] UYARI: IPS modu ve ipset için root yetkisi gerekiyor!{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Lütfen 'sudo' ile çalıştırın.{Style.RESET_ALL}")

    # Core Bileşenleri Başlat
    db = Database(args.db)
    event_bus = EventBus()
    blocker = Blocker(db, interface=args.interface)
    
    # NIDS (Ağ Katmanı)
    sniffer = FastSniffer(interface=args.interface)
    sniffer.register_callback(lambda event: asyncio.create_task(event_bus.publish('ALERT', event)))
    
    # HIDS (Uygulama Katmanı)
    hids = HIDSEngine()
    hids.register_callback(lambda event: asyncio.create_task(event_bus.publish('ALERT', event)))
    
    # Telegram Bot
    bot_token = os.getenv("BOT_TOKEN")
    chat_id = os.getenv("CHAT_ID")
    telegram_bot = None
    if bot_token and chat_id:
        telegram_bot = TelegramBot(bot_token, chat_id, event_bus, blocker)
    
    # Flask Web Uygulaması (Farklı bir thread'de asenkron bloklamadan çalıştırıyoruz)
    webapp = IPSWebApp(
        interface=args.interface,
        mode='ips',
        db_path=args.db
    )
    
    def run_flask():
        webapp.run(host=args.host, port=args.port, debug=False)
        
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    # Sistemin Olay Döngüsünü ve Asenkron Görevleri Başlat
    tasks = []
    tasks.append(asyncio.create_task(event_bus.run()))
    tasks.append(asyncio.create_task(hids.run()))
    
    if telegram_bot:
        tasks.append(asyncio.create_task(telegram_bot.start_polling()))
        
    # Sniffer'ı arka planda başlat (kendi thread'i var)
    sniffer.start()

    print(f"{Fore.GREEN}[+] Sistem başarıyla başlatıldı. Çıkmak için Ctrl+C{Style.RESET_ALL}")
    
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n{Fore.YELLOW}[*] Kapatılıyor...{Style.RESET_ALL}")
        sniffer.stop()
        hids.stop()
        event_bus.stop()
        if telegram_bot:
            await telegram_bot.stop()
        db.close()
        print(f"{Fore.GREEN}[✓] Görüşmek üzere!{Style.RESET_ALL}")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
