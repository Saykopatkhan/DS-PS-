# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from colorama import Fore, Style


class Database:
    """
    DS IPS sistemi için SQLite veritabanı yöneticisi.
    Thread-safe operasyonlar sağlar ve IP/MAC kayıtları, alarmlar ve yasaklı hostlar için tablolar içerir.
    """
    def __init__(self, db_path='ds_ips.db'):
        """
        Veritabanı yöneticisini başlatır.
        
        Args:
            db_path (str): Veritabanı dosyasının yolu. Varsayılan 'ds_ips.db'.
        """
        self.db_path = db_path
        self.lock = threading.RLock()
        self.socketio = None  # WebSocket referansı
        self.alert_callback = None  # Ek callback fonksiyonu
        
        # Connect to DB with thread safety
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        
        self._create_tables()

    def set_socketio(self, sio):
        """
        Flask-SocketIO referansını ayarlar.
        
        Args:
            sio: Flask-SocketIO instance.
        """
        self.socketio = sio

    def set_alert_callback(self, callback):
        """
        Alarm oluşturulduğunda çağrılacak ek callback fonksiyonunu ayarlar.
        
        Args:
            callback (function): Alarm verisi ile çağrılacak fonksiyon.
        """
        self.alert_callback = callback

    def _create_tables(self):
        """Gerekli tabloları oluşturur."""
        with self.lock:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_mac_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    mac_address TEXT,
                    vendor TEXT DEFAULT 'Bilinmiyor',
                    hostname TEXT DEFAULT 'Bilinmiyor',
                    os_type TEXT DEFAULT 'Bilinmiyor',
                    threat_score INTEGER DEFAULT 0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'normal',
                    UNIQUE(ip_address, mac_address)
                )
            ''')
            
            # Migrate each missing column independently; an existing vendor column
            # must not prevent newer columns from being added.
            columns = {row[1] for row in self.cursor.execute("PRAGMA table_info(ip_mac_records)")}
            for name, declaration in {
                'vendor': "TEXT DEFAULT 'Bilinmiyor'",
                'hostname': "TEXT DEFAULT 'Bilinmiyor'",
                'os_type': "TEXT DEFAULT 'Bilinmiyor'",
                'threat_score': 'INTEGER DEFAULT 0',
            }.items():
                if name not in columns:
                    self.cursor.execute(f"ALTER TABLE ip_mac_records ADD COLUMN {name} {declaration}")

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT,
                    source_ip TEXT,
                    source_mac TEXT,
                    destination_ip TEXT,
                    destination_mac TEXT,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    resolved INTEGER DEFAULT 0,
                    pcap_file TEXT DEFAULT NULL
                )
            ''')
            
            try:
                self.cursor.execute("ALTER TABLE alerts ADD COLUMN pcap_file TEXT DEFAULT NULL")
            except sqlite3.OperationalError:
                pass

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS active_bans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    mac_address TEXT,
                    reason TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self.conn.commit()

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS banned_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    mac_address TEXT,
                    ban_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    unban_time TIMESTAMP,
                    reason TEXT,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            columns = {row[1] for row in self.cursor.execute("PRAGMA table_info(banned_hosts)")}
            if 'expires_at' not in columns:
                self.cursor.execute("ALTER TABLE banned_hosts ADD COLUMN expires_at TIMESTAMP")

            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS dns_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    src_mac TEXT,
                    domain TEXT,
                    record_type TEXT DEFAULT 'DNS'
                )
            ''')
            self.conn.commit()

    def reset_database(self):
        """Sistem başlatıldığında önceki oturumdan kalan harita ve alarmları sıfırlar."""
        with self.lock:
            try:
                self.cursor.execute("DELETE FROM ip_mac_records")
                self.cursor.execute("DELETE FROM alerts")
                self.conn.commit()
                print(f"{Fore.GREEN}[+] Veritabanı temizlendi (Cihaz geçmişi ve alarmlar sıfırlandı).{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Veritabanı temizlenirken hata: {e}{Style.RESET_ALL}")

    def update_ip_mac(self, ip, mac, vendor='Bilinmiyor', hostname='Bilinmiyor', os_type='Bilinmiyor'):
        """IP ve MAC adresi eşleşmesini kaydeder veya günceller."""
        with self.lock:
            self.cursor.execute('''
                INSERT OR IGNORE INTO ip_mac_records (ip_address, mac_address)
                VALUES (?, ?)
            ''', (ip, mac))
            
            # Güncellenecek alanları belirle (sadece verilenler)
            # Eğer zaten bir değer varsa ve yeni değer 'Bilinmiyor' ise eskiyi ezme
            self.cursor.execute('SELECT vendor, hostname, os_type FROM ip_mac_records WHERE ip_address = ? AND mac_address = ?', (ip, mac))
            row = self.cursor.fetchone()
            
            if row:
                final_vendor = vendor if vendor != 'Bilinmiyor' else row['vendor']
                final_hostname = hostname if hostname != 'Bilinmiyor' else row['hostname']
                final_os = os_type if os_type != 'Bilinmiyor' else row['os_type']
            else:
                final_vendor = vendor
                final_hostname = hostname
                final_os = os_type
                
            self.cursor.execute('''
                UPDATE ip_mac_records 
                SET last_seen = CURRENT_TIMESTAMP,
                    vendor = ?,
                    hostname = ?,
                    os_type = ?
                WHERE ip_address = ? AND mac_address = ?
            ''', (final_vendor, final_hostname, final_os, ip, mac))
            self.conn.commit()

    def get_mac_for_ip(self, ip):
        """Verilen bir IP adresi için bilinen tüm MAC adreslerini getirir."""
        with self.lock:
            self.cursor.execute('SELECT mac_address FROM ip_mac_records WHERE ip_address = ?', (ip,))
            return [row['mac_address'] for row in self.cursor.fetchall()]

    def _get_mitre_mapping(self, alert_type):
        """Alarm türüne göre MITRE ATT&CK Taktik/Tekniğini döndürür."""
        alert_lower = alert_type.lower()
        if 'flood' in alert_lower or 'dos' in alert_lower:
            return 'T1498 (Network Denial of Service)'
        if 'dpi' in alert_lower or 'reverse shell' in alert_lower or 'payload' in alert_lower:
            return 'T1059 (Command and Scripting Interpreter)'
        if 'zehirlenme' in alert_lower or 'arp' in alert_lower or 'dns' in alert_lower or 'dhcp' in alert_lower or 'llmnr' in alert_lower:
            return 'T1557 (Adversary-in-the-Middle)'
        if 'beaconing' in alert_lower or 'c2' in alert_lower:
            return 'T1071 (Application Layer Protocol - C2)'
        if 'geo-ip' in alert_lower:
            return 'T1090 (Proxy) / Backdoor'
        if 'tarama' in alert_lower or 'scan' in alert_lower:
            return 'T1046 (Network Service Discovery)'
        if 'honeypot' in alert_lower or 'brute' in alert_lower:
            return 'T1110 (Brute Force)'
        return 'T1078 (Valid Accounts / Unknown)'

    def add_alert(self, alert_type, src_ip, src_mac, dst_ip, dst_mac, description, severity, pcap_file=None, **kwargs):
        """Yeni bir alarm ekler, konsola yazdırır ve WebSocket üzerinden gönderir."""
        mitre_tactic = self._get_mitre_mapping(alert_type)
        description = f"[{mitre_tactic}] {description}"
        
        with self.lock:
            self.cursor.execute('''
                INSERT INTO alerts (
                    alert_type, source_ip, source_mac, 
                    destination_ip, destination_mac, description, severity, pcap_file
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (alert_type, src_ip, src_mac, dst_ip, dst_mac, description, severity, pcap_file))
            
            alert_id = self.cursor.lastrowid
            # Tehdit skorunu artır
            if src_ip and src_ip != 'N/A':
                score_increase = 50 if severity.lower() == 'critical' else 25 if severity.lower() == 'high' else 10
                self.cursor.execute('''
                    UPDATE ip_mac_records
                    SET threat_score = MIN(threat_score + ?, 100)
                    WHERE ip_address = ?
                ''', (score_increase, src_ip))
                
            self.conn.commit()

        # Konsol çıktısı
        severity_lower = severity.lower()
        if severity_lower in ['critical', 'high']:
            color = Fore.RED
        elif severity_lower == 'medium':
            color = Fore.YELLOW
        elif severity_lower in ['low', 'info']:
            color = Fore.CYAN
        else:
            color = Fore.WHITE
            
        print(f"{color}[{severity.upper()}] {alert_type}: {description} (Src: {src_ip}/{src_mac} -> Dst: {dst_ip}/{dst_mac}){Style.RESET_ALL}")
        
        # WebSocket bildirimi
        alert_data = {
            'id': alert_id,
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            'alert_type': alert_type,
            'source_ip': src_ip,
            'source_mac': src_mac,
            'destination_ip': dst_ip,
            'destination_mac': dst_mac,
            'description': description,
            'severity': severity,
            'pcap_file': pcap_file
        }
        alert_data.update(kwargs)
        
        if self.alert_callback:
            try:
                self.alert_callback(alert_data)
            except Exception:
                pass
        if self.socketio:
            try:
                self.socketio.emit('new_alert', alert_data, namespace='/')
            except Exception:
                pass
        return alert_id

    def update_alert_pcap(self, alert_id, pcap_file):
        """Alarm tablosundaki bir alarmın pcap_file sütununu günceller."""
        with self.lock:
            self.cursor.execute('UPDATE alerts SET pcap_file = ? WHERE id = ?', (pcap_file, alert_id))
            self.conn.commit()

    def get_alerts(self, limit=50):
        """En son alarmları getirir."""
        with self.lock:
            self.cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC, id DESC LIMIT ?', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]

    def get_alert_counts(self):
        """Alarm türlerine ve severity'ye göre detaylı sayıları döner."""
        with self.lock:
            self.cursor.execute('SELECT alert_type, severity, COUNT(*) as count FROM alerts GROUP BY alert_type, severity')
            return [{'alert_type': row['alert_type'], 'severity': row['severity'].lower() if row['severity'] else 'info', 'count': row['count']} for row in self.cursor.fetchall()]

    def get_total_alert_count(self):
        """Toplam alarm sayısını döner."""
        with self.lock:
            self.cursor.execute('SELECT COUNT(*) FROM alerts')
            return self.cursor.fetchone()[0]

    def add_ban(self, ip, mac, reason, duration=None):
        """Bir IP veya MAC adresini yasaklılar listesine ekler."""
        with self.lock:
            self.cursor.execute('''
                INSERT INTO banned_hosts (ip_address, mac_address, reason, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (ip, mac, reason, (datetime.now(timezone.utc) + timedelta(seconds=duration)).strftime('%Y-%m-%d %H:%M:%S') if duration else None))
            self.conn.commit()
        
        if self.socketio:
            try:
                self.socketio.emit('ban_update', {
                    'action': 'added', 'ip': ip, 'mac': mac, 'reason': reason
                }, namespace='/')
            except Exception:
                pass

    def remove_ban(self, ip=None, mac=None):
        """Bir IP veya MAC adresinin yasağını kaldırır."""
        if not ip and not mac:
            return
            
        query = "UPDATE banned_hosts SET is_active = 0, unban_time = CURRENT_TIMESTAMP WHERE is_active = 1 AND "
        params = []
        conditions = []
        
        if ip:
            conditions.append("ip_address = ?")
            params.append(ip)
        if mac:
            conditions.append("mac_address = ?")
            params.append(mac)
            
        query += "(" + " OR ".join(conditions) + ")"
            
        with self.lock:
            self.cursor.execute(query, tuple(params))
            self.conn.commit()
        
        if self.socketio:
            try:
                self.socketio.emit('ban_update', {
                    'action': 'removed', 'ip': ip, 'mac': mac
                }, namespace='/')
            except Exception:
                pass

    def get_active_bans(self):
        """Aktif yasakları getirir."""
        with self.lock:
            self.cursor.execute('SELECT * FROM banned_hosts WHERE is_active = 1')
            return [dict(row) for row in self.cursor.fetchall()]

    def remove_ban_by_id(self, ban_id):
        """Retire one stale history row without touching a newer target ban."""
        with self.lock:
            self.cursor.execute('''
                UPDATE banned_hosts SET is_active=0, unban_time=CURRENT_TIMESTAMP
                WHERE id=? AND is_active=1
            ''', (ban_id,))
            changed = self.cursor.rowcount > 0
            self.conn.commit()
        return changed

    def get_active_ban_count(self):
        """Aktif yasak sayısını döner."""
        with self.lock:
            self.cursor.execute('SELECT COUNT(*) FROM banned_hosts WHERE is_active = 1')
            return self.cursor.fetchone()[0]

    def is_banned(self, ip=None, mac=None):
        """Bir IP veya MAC adresinin yasaklı olup olmadığını kontrol eder."""
        if not ip and not mac:
            return False
            
        query = "SELECT COUNT(*) FROM banned_hosts WHERE is_active = 1 AND ("
        params = []
        conditions = []
        
        if ip:
            conditions.append("ip_address = ?")
            params.append(ip)
        if mac:
            conditions.append("mac_address = ?")
            params.append(mac)
            
        query += " OR ".join(conditions) + ")"
            
        with self.lock:
            self.cursor.execute(query, tuple(params))
            count = self.cursor.fetchone()[0]
            return count > 0

    def get_ip_mac_records(self, limit=100):
        """Return the latest observed binding per IP, retaining shared-MAC peers."""
        if limit <= 0:
            return []
        with self.lock:
            self.cursor.execute('SELECT * FROM ip_mac_records ORDER BY last_seen DESC, id DESC')
            rows = [dict(row) for row in self.cursor.fetchall()]
        records = {}
        for row in rows:
            ip = row['ip_address']
            if not ip or ip == 'N/A' or ip in records:
                continue
            # A router MAC or an unknown MAC can describe multiple observed
            # peers. Grouping by MAC silently erased these IPs from the panel.
            records[ip] = row
            if len(records) >= limit:
                break
        return list(records.values())

    def get_setting(self, key, default=None):
        """Ayar değerini getirir."""
        with self.lock:
            self.cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
            row = self.cursor.fetchone()
            return row['value'] if row else default

    def set_setting(self, key, value):
        """Ayar değerini kaydeder veya günceller."""
        with self.lock:
            self.cursor.execute('''
                INSERT OR REPLACE INTO settings (key, value)
                VALUES (?, ?)
            ''', (key, value))
            self.conn.commit()

    def cleanup_old_dns_logs(self):
        """10 dakikadan eski DNS trafik geçmişini temizler."""
        with self.lock:
            # SQLite CURRENT_TIMESTAMP UTC kullanır, bu yüzden datetime.utcnow() kullanmalıyız.
            ten_mins_ago = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
            self.cursor.execute("DELETE FROM dns_logs WHERE timestamp < ?", (ten_mins_ago,))
            self.conn.commit()

    def add_dns_log(self, src_ip, src_mac, domain, record_type='DNS'):
        """Bir cihazın girdiği site/domain kaydını ekler."""
        self.cleanup_old_dns_logs() # Her eklemede eskiyi temizle
        with self.lock:
            self.cursor.execute('''
                INSERT INTO dns_logs (src_ip, src_mac, domain, record_type)
                VALUES (?, ?, ?, ?)
            ''', (src_ip, src_mac, domain, record_type))
            self.conn.commit()
            
        # Call external listeners after releasing the database lock.
        if self.socketio:
            log_data = {
                'timestamp': datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                'src_ip': src_ip, 'src_mac': src_mac,
                'domain': domain, 'record_type': record_type,
            }
            try:
                self.socketio.emit('new_dns_log', log_data)
            except Exception:
                pass

    def get_dns_logs(self, ip=None, limit=50):
        """Domain erişim geçmişini getirir (İsteğe bağlı IP filtreli)."""
        self.cleanup_old_dns_logs() # Her okumada da eskiyi temizle
        with self.lock:
            if ip:
                self.cursor.execute('SELECT * FROM dns_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT ?', (ip, limit))
            else:
                self.cursor.execute('SELECT * FROM dns_logs ORDER BY timestamp DESC, id DESC LIMIT ?', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]

    def close(self):
        """Veritabanı bağlantısını kapatır."""
        with self.lock:
            self.conn.close()
