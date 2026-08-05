import sys
sys.path.append('/home/kali/İndirilenler/ds_ips_project')
from web.app import IPSWebApp

webapp = IPSWebApp(interface='lo', mode='ids', wifi_enabled=False, db_path='test.db')
print(webapp.app.url_map)
