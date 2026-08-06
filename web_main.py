#!/usr/bin/env python3
"""
DS IPS Web Panel - Ana çalıştırma dosyası.
Flask + SocketIO tabanlı gerçek zamanlı dashboard.
"""
import argparse
import os
import sys
from colorama import init, Fore, Style

# Otomatik Aktif Arayüz Tespiti (Örn: wlan0, eth0)
try:
    from scapy.all import conf
    default_iface = conf.route.route("0.0.0.0")[3]
except Exception:
    default_iface = 'eth0'

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
        unban_time=args.unban_time
    )

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
