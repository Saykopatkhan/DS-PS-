# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

import sys
sys.path.append('/home/kali/İndirilenler/ds_ips_project')
from web.app import IPSWebApp

webapp = IPSWebApp(interface='lo', mode='ids', wifi_enabled=False, db_path='test.db')
print(webapp.app.url_map)
