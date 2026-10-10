"""Gunicorn entrypoint. Run one threaded worker; sensor state is process-local."""

import atexit
import os
from pathlib import Path

from dotenv import load_dotenv

from services import RuntimeServices, env_bool
from web.app import IPSWebApp

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

webapp = IPSWebApp(
    interface=os.environ.get("DS_IPS_INTERFACE", "any"),
    mode=os.environ.get("DS_IPS_MODE", "ids"),
    wifi_enabled=env_bool("DS_IPS_WIFI"),
    db_path=os.environ.get("DS_IPS_DB", str(BASE_DIR / "ds_ips.db")),
    unban_time=int(os.environ.get("DS_IPS_UNBAN_TIME", "3600")),
    dry_run=env_bool("DS_IPS_DRY_RUN"),
)
app = webapp.app

services = RuntimeServices(
    webapp, hids_enabled=env_bool("DS_IPS_HIDS", True),
    telegram_enabled=env_bool("DS_IPS_TELEGRAM"),
)
webapp.start_background_tasks()
services.start()
atexit.register(services.stop)
