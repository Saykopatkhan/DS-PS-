# ========================================================================
# DS-IPS (Premium SOC Edition)
# SIEM & Log Export Modülü
# ========================================================================

import json
import os
import threading
from datetime import datetime

class SIEMExporter:
    """
    Sistemdeki alarmları ElasticSearch, Splunk gibi SIEM sistemlerinin
    okuyabileceği standart JSON (veya Syslog) formatında dışa aktarır.
    """
    def __init__(self, log_file='data/siem_logs.json'):
        self.log_file = log_file
        # Ensure data directory exists
        self._lock = threading.Lock()

    def export_alert(self, alert_data):
        """
        Alarmı SIEM uyumlu JSON formatında dosyaya ekler.
        """
        siem_event = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event": {
                "dataset": "ds_ips.alerts",
                "kind": "alert",
                "type": alert_data.get('alert_type', 'Unknown'),
                "severity": alert_data.get('severity', 'info'),
                "action": "logged"
            },
            "source": {
                "ip": alert_data.get('source_ip', alert_data.get('src_ip', '')),
                "mac": alert_data.get('source_mac', alert_data.get('src_mac', ''))
            },
            "destination": {
                "ip": alert_data.get('destination_ip', alert_data.get('dst_ip', '')),
                "mac": alert_data.get('destination_mac', alert_data.get('dst_mac', ''))
            },
            "message": alert_data.get('description', '')
        }

        try:
            with self._lock:
                os.makedirs(os.path.dirname(os.path.abspath(self.log_file)), exist_ok=True)
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(siem_event) + "\n")
        except Exception as e:
            print(f"SIEM Export Error: {e}")

# Global instance for easy access
exporter = SIEMExporter()
