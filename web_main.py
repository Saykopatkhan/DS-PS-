#!/usr/bin/env python3
"""DS-IPS development dashboard entrypoint; production uses start_prod.sh."""

import argparse
import ipaddress
import os
import signal
from pathlib import Path

from dotenv import load_dotenv

from services import RuntimeServices, env_bool


def port_number(value):
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("Port 1–65535 arasında olmalıdır")
    return number


def positive_seconds(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Süre sıfırdan büyük olmalıdır")
    return number


def build_parser():
    parser = argparse.ArgumentParser(description="DS-IPS geliştirme web paneli")
    parser.add_argument("-i", "--interface", default=os.getenv("DS_IPS_INTERFACE", "any"))
    parser.add_argument("-m", "--mode", choices=["ids", "ips"], default=os.getenv("DS_IPS_MODE", "ids"))
    parser.add_argument("--wifi", action="store_true", default=env_bool("DS_IPS_WIFI"))
    parser.add_argument("--db", default=os.getenv("DS_IPS_DB", "ds_ips.db"))
    parser.add_argument("--target", type=lambda value: str(ipaddress.IPv4Network(value, strict=False)),
                        help="Elle/periyodik ARP taramasının IPv4 alt ağı")
    parser.add_argument("--unban-time", type=positive_seconds, default=os.getenv("DS_IPS_UNBAN_TIME", "3600"))
    parser.add_argument("-p", "--port", type=port_number, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--autostart", action="store_true", help="Panel açılırken izleme ve seçili modun servislerini başlat")
    parser.add_argument("--dry-run", action="store_true", default=env_bool("DS_IPS_DRY_RUN"))
    parser.add_argument("--reset-db", action="store_true", help="Cihaz ve alarm geçmişini temizle")
    parser.add_argument("--no-hids", action="store_true", default=not env_bool("DS_IPS_HIDS", True))
    return parser


def main(argv=None):
    load_dotenv(Path(__file__).resolve().parent / ".env")
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.mode not in {"ids", "ips"}:
        parser.error("DS_IPS_MODE ids veya ips olmalıdır")
    if args.mode == "ips" and not args.dry_run and os.geteuid() != 0:
        parser.error("IPS modu için root yetkisi gerekir; test için --dry-run kullanın")

    from web.app import IPSWebApp

    webapp = IPSWebApp(interface=args.interface, mode=args.mode,
                       wifi_enabled=args.wifi, db_path=args.db,
                       unban_time=args.unban_time, dry_run=args.dry_run)
    if args.target:
        webapp.scanner.target = args.target
    services = RuntimeServices(webapp, hids_enabled=not args.no_hids,
                               telegram_enabled=env_bool("DS_IPS_TELEGRAM"))

    def terminate(_signum, _frame):
        raise KeyboardInterrupt

    previous_sigterm = signal.signal(signal.SIGTERM, terminate)
    try:
        if args.reset_db:
            webapp.db.reset_database()
        services.start()
        if args.autostart:
            webapp._start_monitoring()
        webapp.run(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        pass
    finally:
        services.stop()
        webapp.close()
        signal.signal(signal.SIGTERM, previous_sigterm)


if __name__ == "__main__":
    main()
