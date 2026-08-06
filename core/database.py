import sqlite3
import threading
import time
from datetime import datetime
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
        self.lock = threading.Lock()
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
            
            # Eski veritabanı varsa kolonları ekle (hata verirse atla)
            try:
                self.cursor.execute("ALTER TABLE ip_mac_records ADD COLUMN vendor TEXT DEFAULT 'Bilinmiyor'")
                self.cursor.execute("ALTER TABLE ip_mac_records ADD COLUMN hostname TEXT DEFAULT 'Bilinmiyor'")
                self.cursor.execute("ALTER TABLE ip_mac_records ADD COLUMN os_type TEXT DEFAULT 'Bilinmiyor'")
                self.cursor.execute("ALTER TABLE ip_mac_records ADD COLUMN threat_score INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass

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
                    resolved INTEGER DEFAULT 0
                )
            ''')

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

    def add_alert(self, alert_type, src_ip, src_mac, dst_ip, dst_mac, description, severity):
        """Yeni bir alarm ekler, konsola yazdırır ve WebSocket üzerinden gönderir."""
        with self.lock:
            self.cursor.execute('''
                INSERT INTO alerts (
                    alert_type, source_ip, source_mac, 
                    destination_ip, destination_mac, description, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (alert_type, src_ip, src_mac, dst_ip, dst_mac, description, severity))
            
            # Tehdit skorunu artır
            if src_ip and src_ip != 'N/A':
                score_increase = 50 if severity.lower() == 'critical' else 25 if severity.lower() == 'high' else 10
                self.cursor.execute('''
                    UPDATE ip_mac_records
                    SET threat_score = MIN(threat_score + ?, 100)
                    WHERE ip_address = ?
                ''', (score_increase, src_ip))
                
            self.conn.commit()
            alert_id = self.cursor.lastrowid
            
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
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'alert_type': alert_type,
            'source_ip': src_ip,
            'source_mac': src_mac,
            'destination_ip': dst_ip,
            'destination_mac': dst_mac,
            'description': description,
            'severity': severity
        }
        
        if self.socketio:
            try:
                self.socketio.emit('new_alert', alert_data, namespace='/')
            except Exception:
                pass
        
        if self.alert_callback:
            try:
                self.alert_callback(alert_data)
            except Exception:
                pass

    def get_alerts(self, limit=50):
        """En son alarmları getirir."""
        with self.lock:
            self.cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]

    def get_alert_counts(self):
        """Alarm türlerine göre sayıları döner."""
        with self.lock:
            self.cursor.execute('SELECT alert_type, COUNT(*) as count FROM alerts GROUP BY alert_type')
            return {row['alert_type']: row['count'] for row in self.cursor.fetchall()}

    def get_total_alert_count(self):
        """Toplam alarm sayısını döner."""
        with self.lock:
            self.cursor.execute('SELECT COUNT(*) FROM alerts')
            return self.cursor.fetchone()[0]

    def add_ban(self, ip, mac, reason):
        """Bir IP veya MAC adresini yasaklılar listesine ekler."""
        with self.lock:
            self.cursor.execute('''
                INSERT INTO banned_hosts (ip_address, mac_address, reason)
                VALUES (?, ?, ?)
            ''', (ip, mac, reason))
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
            
        query += " OR ".join(conditions)
            
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
        """IP-MAC kayıtlarını getirir (MAC adresine göre gruplanmış ve N/A IP'ler elenmiş şekilde)."""
        with self.lock:
            self.cursor.execute('SELECT * FROM ip_mac_records ORDER BY last_seen DESC')
            rows = [dict(row) for row in self.cursor.fetchall()]
            
            # Aynı MAC adresine sahip birden fazla kayıt (Örn: N/A ve gerçek IP) varsa birleştir
            unique_macs = {}
            for r in rows:
                mac = r['mac_address']
                ip = r['ip_address']
                
                if mac not in unique_macs:
                    unique_macs[mac] = r
                else:
                    # Mevcut kayıt N/A ise ve yeni gelen geçerliyse ez
                    if unique_macs[mac]['ip_address'] == 'N/A' and ip != 'N/A':
                        unique_macs[mac]['ip_address'] = ip
                        
                    # Mevcut kaydın OS/Vendor/Hostname bilgisi "Bilinmiyor" ise ve yeni gelende varsa tamamla
                    for field in ['vendor', 'hostname', 'os_type']:
                        if unique_macs[mac].get(field, 'Bilinmiyor') == 'Bilinmiyor' and r.get(field, 'Bilinmiyor') != 'Bilinmiyor':
                            unique_macs[mac][field] = r[field]
                            
                    # Tehdit skorunu en yüksek olana ayarla
                    if r.get('threat_score', 0) > unique_macs[mac].get('threat_score', 0):
                        unique_macs[mac]['threat_score'] = r['threat_score']
                        
            result = list(unique_macs.values())
            # Yeniden sırala ve limite göre kes
            result.sort(key=lambda x: x.get('last_seen', ''), reverse=True)
            return result[:limit]

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

    def add_dns_log(self, src_ip, src_mac, domain, record_type='DNS'):
        """Bir cihazın girdiği site/domain kaydını ekler."""
        with self.lock:
            self.cursor.execute('''
                INSERT INTO dns_logs (src_ip, src_mac, domain, record_type)
                VALUES (?, ?, ?, ?)
            ''', (src_ip, src_mac, domain, record_type))
            self.conn.commit()
            
            # WebSocket ile ön yüze canlı olarak fırlat
            if self.socketio:
                log_data = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'src_ip': src_ip,
                    'src_mac': src_mac,
                    'domain': domain,
                    'record_type': record_type
                }
                self.socketio.emit('new_dns_log', log_data)
                
    def get_dns_logs(self, ip=None, limit=50):
        """Domain erişim geçmişini getirir (İsteğe bağlı IP filtreli)."""
        with self.lock:
            if ip:
                self.cursor.execute('SELECT * FROM dns_logs WHERE src_ip = ? ORDER BY timestamp DESC LIMIT ?', (ip, limit))
            else:
                self.cursor.execute('SELECT * FROM dns_logs ORDER BY timestamp DESC LIMIT ?', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]

    def close(self):
        """Veritabanı bağlantısını kapatır."""
        with self.lock:
            self.conn.close()
