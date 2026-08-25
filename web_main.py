# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

#!/usr/bin/env python3
"""
DS IPS Web Panel - Ana çalıştırma dosyası.
Flask + SocketIO tabanlı gerçek zamanlı dashboard.
"""
import argparse
import os
import sys
import threading
from colorama import init, Fore, Style

# Otomatik Aktif Arayüz Tespiti (Örn: wlan0, eth0)
# 'any' seçilerek hem localhost (lo) hem de dış ağ kartlarının aynı anda dinlenmesi sağlanır.
default_iface = 'any'

init(autoreset=True)


def print_banner():
    """Uygulama başlangıç banner'ını yazdırır."""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║  {Fore.GREEN}DS IPS - Ağ Saldırı Tespit & Önleme Web Paneli{Fore.CYAN}         ║
║  {Fore.GREEN}Intrusion Prevention System v1.0 - Dashboard{Fore.CYAN}           ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description='DS IPS Web Panel - Gerçek Zamanlı Dashboard')
    parser.add_argument('-i', '--interface', default=default_iface,
                        help=f'Ağ arayüzü (Varsayılan: {default_iface})')
    parser.add_argument('-m', '--mode', choices=['ids', 'ips'], default='ips',
                        help='Çalışma modu (ids: sadece tespit, ips: tespit + önleme)')
    parser.add_argument('--wifi', action='store_true',
                        help='WiFi saldırı tespiti (monitor mode gerektirir)')
    parser.add_argument('--db', default='ds_ips.db',
                        help='Veritabanı dosya yolu')
    parser.add_argument('--unban-time', type=int, default=3600,
                        help='Otomatik ban kaldırma süresi (saniye)')
    parser.add_argument('-p', '--port', type=int, default=5000,
                        help='Web panel portu')
    parser.add_argument('--host', default='0.0.0.0',
                        help='Web panel host adresi')
    parser.add_argument('--debug', action='store_true',
                        help='Debug modu')
    parser.add_argument('--dry-run', action='store_true',
                        help='Dry Run: Tespit yap ama engelleme yapma (test modu)')

    args = parser.parse_args()

    print_banner()

    if args.mode == 'ips' and os.geteuid() != 0:
        print(f"{Fore.RED}[!] UYARI: IPS modu için root yetkisi gerekiyor!{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Lütfen 'sudo' ile çalıştırın.{Style.RESET_ALL}")

    from web.app import IPSWebApp

    webapp = IPSWebApp(
        interface=args.interface,
        mode=args.mode,
        wifi_enabled=args.wifi,
        db_path=args.db,
        unban_time=args.unban_time,
        dry_run=args.dry_run
    )

    # --- Yeni v5.0 Eklentileri (Arka Plan Thread'leri) ---
    # HIDS/WAF Motoru (Log izleme - opsiyonel)
    try:
        from modules.hids_engine import HIDSEngine
        import asyncio
        hids = HIDSEngine()
        # HIDS alarmlarını veritabanına ve Socket.IO'ya köprüle
        def hids_alert_handler(event):
            import time
            try:
                webapp.db.add_alert(
                    ip=event.get('source_ip', 'Bilinmiyor'),
                    mac='N/A',
                    alert_type=event.get('type', 'HIDS'),
                    description=event.get('details', ''),
                    severity='Yüksek'
                )
                webapp.socketio.emit('new_alert', {
                    'id': int(time.time()),
                    'ip': event.get('source_ip'),
                    'type': event.get('type'),
                    'description': event.get('details'),
                    'severity': 'Yüksek',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }, namespace='/')
            except Exception:
                pass
        hids.register_callback(hids_alert_handler)
        
        def run_hids():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(hids.run())
        
        hids_thread = threading.Thread(target=run_hids, daemon=True)
        hids_thread.start()
        print(f"{Fore.GREEN}[+] HIDS/WAF Motoru arka planda başlatıldı (Log izleme aktif){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] HIDS Motoru yüklenemedi (opsiyonel): {e}{Style.RESET_ALL}")

    # Telegram Bot (opsiyonel - .env yoksa atlanır)
    try:
        from dotenv import load_dotenv
        load_dotenv()
        bot_token = os.getenv('BOT_TOKEN')
        chat_id = os.getenv('CHAT_ID')
        if bot_token and chat_id:
            from responder.telegram_bot import TelegramBot
            from core.event_bus import EventBus
            event_bus = EventBus()
            telegram_bot = TelegramBot(bot_token, chat_id, event_bus, webapp.blocker)
            
            def run_telegram():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(telegram_bot.start_polling())
            
            telegram_thread = threading.Thread(target=run_telegram, daemon=True)
            telegram_thread.start()
            print(f"{Fore.GREEN}[+] Telegram Bot başlatıldı (Uzaktan yönetim aktif){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[*] Telegram Bot: .env dosyasında BOT_TOKEN/CHAT_ID bulunamadı (opsiyonel){Style.RESET_ALL}")
    except ImportError:
        print(f"{Fore.YELLOW}[*] Telegram Bot: python-telegram-bot kütüphanesi kurulu değil (opsiyonel){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Telegram Bot yüklenemedi: {e}{Style.RESET_ALL}")
    # --- Yeni v5.0 Eklentileri Sonu ---

    try:
        webapp.run(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Kapatılıyor...{Style.RESET_ALL}")
        if webapp.sniffer_running:
            webapp.sniffer.stop()
        webapp.db.close()
        print(f"{Fore.GREEN}[✓] Görüşmek üzere!{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == '__main__':
    main()
