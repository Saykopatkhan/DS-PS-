import sqlite3
import threading
import json
from datetime import datetime

class ActiveDefenseManager:
    """
    Manages active defense rules (Tarpit, TCP RST, Honeypot, DNS Sinkhole, Rate Limit).
    Persists them to a SQLite database.
    """
    def __init__(self, db_path='ds_ips.db'):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        with self.lock:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS active_defense_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT NOT NULL,
                    target_ip TEXT,
                    target_mac TEXT,
                    parameters TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self.conn.commit()

    def add_rule(self, module, target_ip=None, target_mac=None, parameters=None):
        if parameters is None:
            parameters = {}
        
        param_str = json.dumps(parameters)
        
        with self.lock:
            self.cursor.execute('''
                INSERT INTO active_defense_rules (module, target_ip, target_mac, parameters)
                VALUES (?, ?, ?, ?)
            ''', (module, target_ip, target_mac, param_str))
            self.conn.commit()
            return self.cursor.lastrowid

    def remove_rule(self, rule_id):
        with self.lock:
            self.cursor.execute('DELETE FROM active_defense_rules WHERE id = ?', (rule_id,))
            self.conn.commit()
            
    def remove_rule_by_target(self, module, target_ip):
        with self.lock:
            self.cursor.execute('DELETE FROM active_defense_rules WHERE module = ? AND target_ip = ?', (module, target_ip))
            self.conn.commit()

    def get_all_rules(self):
        with self.lock:
            self.cursor.execute('SELECT * FROM active_defense_rules ORDER BY created_at DESC')
            rows = self.cursor.fetchall()
            
            result = []
            for r in rows:
                rule = dict(r)
                try:
                    rule['parameters'] = json.loads(rule['parameters']) if rule['parameters'] else {}
                except json.JSONDecodeError:
                    rule['parameters'] = {}
                result.append(rule)
            return result
            
    def clear_all_rules(self):
        with self.lock:
            self.cursor.execute('DELETE FROM active_defense_rules')
            self.conn.commit()
