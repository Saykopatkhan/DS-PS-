#!/usr/bin/env python3
import sys
import os
import argparse
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import print as rprint
from rich.prompt import Prompt

from core.database import Database
from core.sniffer import PacketSniffer
from core.scanner import NetworkScanner
from responder.blocker import Blocker
from responder.notifier import Notifier

from modules.arp_detector import ARPDetector
from modules.scan_detector import ScanDetector
from modules.wifi_detector import WiFiDetector
from modules.dns_detector import DNSDetector
from modules.dhcp_detector import DHCPDetector
from modules.honeypot import Honeypot
from modules.threat_intel import ThreatIntelDetector
from modules.anti_evasion import AntiEvasionDetector

console = Console()

class SOCConsole:
    def __init__(self, interface='eth0', wifi_enabled=False):
        self.interface = interface
        self.wifi_enabled = wifi_enabled
        
        self.db = Database()
        
        # Blocker (Manuel ban için devrede, otomatik ban KAPALI)
        self.blocker = Blocker(self.db, interface=self.interface)
        
        # Notifier (Örnek kullanım, webhooklar boş)
        self.notifier = Notifier()
        
        # Detectors (Tümünde auto_ban = False)
        self.arp_detector = ARPDetector(self.db, self.blocker, auto_ban=False)
        self.scan_detector = ScanDetector(self.db, self.blocker, auto_ban=False)
        self.dns_detector = DNSDetector(self.db, self.blocker, auto_ban=False)
        self.dhcp_detector = DHCPDetector(self.db, self.blocker, auto_ban=False)
        
        if self.wifi_enabled:
            self.wifi_detector = WiFiDetector(self.db, self.blocker, auto_ban=False)
        else:
            self.wifi_detector = None
            
        self.honeypot = Honeypot(self.db, self.blocker, auto_ban=False)
        self.threat_intel = ThreatIntelDetector(self.db, self.blocker, auto_ban=False)
        self.anti_evasion = AntiEvasionDetector(self.db, self.blocker, auto_ban=False)
        
        # Sniffer
        self.sniffer = PacketSniffer(interface=self.interface)
        self.sniffer.register_callback(self.arp_detector.analyze)
        self.sniffer.register_callback(self.scan_detector.analyze)
        self.sniffer.register_callback(self.dns_detector.analyze)
        self.sniffer.register_callback(self.dhcp_detector.analyze)
        self.sniffer.register_callback(self.threat_intel.analyze)
        self.sniffer.register_callback(self.anti_evasion.analyze)
        if self.wifi_detector:
            self.sniffer.register_callback(self.wifi_detector.analyze)
            
        # Scanner
        self.scanner = NetworkScanner(self.db, interface=self.interface)

    def draw_header(self):
        console.clear()
        header = f"[bold cyan]🛡️  DS IPS - YENİ NESİL SOC KONSOLU[/bold cyan] | [yellow]Arayüz: {self.interface}[/yellow] | [red]Otomatik Ban: KAPALI[/red]"
        console.print(Panel(header, expand=False))

    def show_menu(self):
        table = Table(show_header=False, box=None)
        table.add_column("No", style="bold green")
        table.add_column("İşlem", style="bold white")
        
        table.add_row("1", "Sniffer ve Honeypot'u Başlat (Tüm Kalkanlar Aktif)")
        table.add_row("2", "Sistemi Durdur")
        table.add_row("3", "Ağı Tara (IP/MAC/Marka/Hostname)")
        table.add_row("4", "Cihaz Envanterini Listele")
        table.add_row("5", "Son Tehdit Alarmlarını Göster")
        table.add_row("6", "Aktif İzolasyonları Göster")
        table.add_row("7", "[red]Manuel Ağdan İzole Et (Ban)[/red]")
        table.add_row("8", "[yellow]İzolasyonu Kaldır (Unban)[/yellow]")
        table.add_row("9", "Çıkış")
        
        console.print(Panel(table, title="[bold blue]Operasyon Merkezi", expand=False))

    def start_systems(self):
        if not self.sniffer.running:
            self.sniffer.start()
            self.honeypot.start()
            console.print("[bold green]✔ Sniffer ve Honeypot (Port: 21, 23, 445) başlatıldı. Ağ izleniyor...[/bold green]")
        else:
            console.print("[bold yellow]⚠ Sistemler zaten aktif.[/bold yellow]")

    def stop_systems(self):
        if self.sniffer.running:
            self.sniffer.stop()
            self.honeypot.stop()
            console.print("[bold green]✔ Sniffer ve Honeypot durduruldu.[/bold green]")
        else:
            console.print("[bold yellow]⚠ Sistemler şu anda çalışmıyor.[/bold yellow]")

    def run_scanner(self):
        with console.status("[bold cyan]Ağ taranıyor (ARP Ping)... Lütfen bekleyin...[/bold cyan]", spinner="dots"):
            self.scanner.scan_once()

    def list_devices(self):
        records = self.db.get_ip_mac_records(limit=20)
        if not records:
            console.print("[bold yellow]Cihaz bulunamadı. Lütfen önce ağı tarayın (Seçenek 3).[/bold yellow]")
            return
            
        table = Table(title="Ağ Cihaz Envanteri (Son 20)", style="cyan")
        table.add_column("IP Adresi", style="green")
        table.add_column("MAC Adresi", style="magenta")
        table.add_column("Marka", style="blue")
        table.add_column("Hostname", style="white")
        table.add_column("Cihaz Tipi (OS)", style="bold cyan")
        table.add_column("Tehdit Skoru", style="bold red")
        
        for r in records:
            vendor = r.get('vendor', 'Bilinmiyor')
            hostname = r.get('hostname', 'Bilinmiyor')
            os_type = r.get('os_type', 'Bilinmiyor')
            score = r.get('threat_score', 0)
            
            # Skor renklendirme
            if score > 20:
                score_str = f"[bold red]{score}[/bold red]"
            elif score > 0:
                score_str = f"[bold yellow]{score}[/bold yellow]"
            else:
                score_str = f"[dim white]{score}[/dim white]"
                
            table.add_row(r['ip_address'], r['mac_address'], vendor, hostname, os_type, score_str)
            
        console.print(table)

    def list_alerts(self):
        alerts = self.db.get_recent_alerts(limit=15)
        if not alerts:
            console.print("[bold green]✔ Kayıtlı hiçbir tehdit veya alarm bulunamadı.[/bold green]")
            return
            
        table = Table(title="Son Tespit Edilen Tehditler", style="red")
        table.add_column("Tarih", style="dim")
        table.add_column("Saldırı Tipi", style="bold red")
        table.add_column("Kaynak", style="yellow")
        table.add_column("Açıklama", style="white")
        
        for a in alerts:
            src = f"{a['source_ip'] or 'N/A'}\n{a['source_mac'] or 'N/A'}"
            table.add_row(a['alert_time'], a['alert_type'], src, a['description'])
            
        console.print(table)

    def list_bans(self):
        bans = self.db.get_active_bans()
        if not bans:
            console.print("[bold green]✔ Şu anda aktif hiçbir izolasyon/engelleme yok.[/bold green]")
            return
            
        table = Table(title="Aktif İzolasyonlar (ARP Blackholing)", style="red")
        table.add_column("Tarih", style="dim")
        table.add_column("IP Adresi", style="red")
        table.add_column("MAC Adresi", style="red")
        table.add_column("Neden", style="white")
        
        for b in bans:
            table.add_row(b.get('ban_time',''), b.get('ip_address') or 'N/A', b.get('mac_address') or 'N/A', b.get('reason','-'))
            
        console.print(table)

    def manual_ban(self):
        console.print("[bold red]DİKKAT: Cihaz ağdan tamamen izole edilecektir![/bold red]")
        ip = Prompt.ask("Engellenecek IP (boş bırakabilirsiniz)").strip()
        mac = Prompt.ask("Engellenecek MAC (boş bırakabilirsiniz)").strip()
        
        if not ip and not mac:
            console.print("[bold yellow]İşlem iptal edildi.[/bold yellow]")
            return
            
        if ip:
            self.blocker.block_ip(ip, reason="SOC Konsol - Manuel Ban")
        elif mac:
            self.blocker.block_mac(mac, reason="SOC Konsol - Manuel Ban")

    def manual_unban(self):
        ip = Prompt.ask("İzolasyonu kaldırılacak IP").strip()
        mac = Prompt.ask("İzolasyonu kaldırılacak MAC").strip()
        
        if ip:
            self.blocker.unblock_ip(ip)
        if mac:
            self.blocker.unblock_mac(mac)

    def run(self):
        if os.geteuid() != 0:
            console.print("[bold red][!] UYARI: Ağ izolasyonu, Honeypot ve tarama için ROOT yetkisi (sudo) gerekiyor![/bold red]")
            
        while True:
            self.draw_header()
            self.show_menu()
            
            choice = Prompt.ask("[bold cyan]Komut (1-9)[/bold cyan]", choices=[str(i) for i in range(1, 10)])
            console.print()
            
            if choice == '1': self.start_systems()
            elif choice == '2': self.stop_systems()
            elif choice == '3': self.run_scanner()
            elif choice == '4': self.list_devices()
            elif choice == '5': self.list_alerts()
            elif choice == '6': self.list_bans()
            elif choice == '7': self.manual_ban()
            elif choice == '8': self.manual_unban()
            elif choice == '9':
                self.stop_systems()
                self.blocker.stop()
                self.db.close()
                console.print("[bold green]✔ Sistem kapatıldı. Güvenli günler.[/bold green]")
                sys.exit(0)
                
            Prompt.ask("\n[dim]Devam etmek için Enter'a basın...[/dim]")

def main():
    parser = argparse.ArgumentParser(description='DS IPS - SOC Konsolu')
    parser.add_argument('-i', '--interface', default='eth0', help='Ağ arayüzü (örn: wlan0)')
    parser.add_argument('--wifi', action='store_true', help='WiFi saldırılarını algıla')
    
    args = parser.parse_args()
    
    app = SOCConsole(interface=args.interface, wifi_enabled=args.wifi)
    try:
        app.run()
    except KeyboardInterrupt:
        app.stop_systems()
        app.blocker.stop()
        app.db.close()
        console.print("\n[bold green]✔ Sistem kapatıldı.[/bold green]")

if __name__ == "__main__":
    main()
