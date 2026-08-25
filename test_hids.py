import asyncio
import time
from core.database import Database
from responder.blocker import Blocker
from modules.hids_engine import HIDSEngine

def test_hids():
    print("=== HIDS Engine Testi Başlıyor ===")
    db = Database()
    blocker = Blocker(db, dry_run=True)
    hids = HIDSEngine()
    
    alerts = []
    hids.register_callback(lambda e: alerts.append(e))
    
    # 1. SQL Injection Testi
    print("[*] SQL Injection Testi (UNION SELECT)")
    hids._analyze_web_log('192.168.1.100 - - [10/Oct/2026] "GET /login?id=1 UNION SELECT password FROM users" 200')
    
    # 2. XSS Testi
    print("[*] XSS Testi (<script>)")
    hids._analyze_web_log('192.168.1.101 - - [10/Oct/2026] "GET /search?q=<script>alert(1)</script>" 200')
    
    # 3. HTTP DDoS Testi (100 istek simülasyonu)
    print("[*] HTTP DDoS Testi (100 Istek/Sn)")
    for _ in range(101):
        hids._analyze_web_log('192.168.1.102 - - [10/Oct/2026] "GET /" 200')
        
    # 4. Scanner Testi (Nmap)
    print("[*] Scanner Testi (Nmap User-Agent)")
    hids._analyze_web_log('192.168.1.103 - - [10/Oct/2026] "GET /" 404 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"')
    
    # Sonucları goster
    print("\n--- TEST SONUÇLARI ---")
    for a in alerts:
        print(f"🚨 ALARM: {a['type']} (Seviye: {a.get('severity', 'none')}) - IP: {a['source_ip']} - Detay: {a['details']}")
    print("==================================\n")

if __name__ == "__main__":
    test_hids()
