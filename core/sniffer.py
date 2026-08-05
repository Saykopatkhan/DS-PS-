import threading
import logging
from scapy.all import sniff, conf

class PacketSniffer:
    """
    Scapy tabanlı paket yakalayıcı (sniffer).
    Gelen paketleri yakalar ve kayıtlı callback fonksiyonlarına iletir.
    """
    def __init__(self, interface='eth0', filter_str=None):
        """
        Paket yakalayıcıyı başlatır.
        
        Args:
            interface (str): Dinlenecek ağ arayüzü. Varsayılan 'eth0'.
            filter_str (str, optional): BPF (Berkeley Packet Filter) filtresi.
        """
        self.interface = interface
        self.filter_str = filter_str
        self.callbacks = []
        self.running = False
        self.sniff_thread = None

    def register_callback(self, callback):
        """
        Paket işleyici callback fonksiyonunu kaydeder.
        
        Args:
            callback (function): Paketi işleyecek fonksiyon.
        """
        self.callbacks.append(callback)

    def _packet_handler(self, packet):
        """
        Yakalanan her paket için çağrılır ve kayıtlı callback'leri tetikler.
        
        Args:
            packet (scapy.packet.Packet): Yakalanan paket.
        """
        for callback in self.callbacks:
            try:
                callback(packet)
            except Exception as e:
                logging.error(f"Callback çalıştırılırken hata oluştu: {e}")

    def start(self):
        """
        Paket dinleme işlemini arka planda (daemon thread) başlatır.
        """
        self.running = True
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def _sniff_loop(self):
        """Gerçek paket yakalama döngüsü."""
        try:
            sniff(
                store=0,
                prn=self._packet_handler,
                iface=self.interface,
                filter=self.filter_str,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            logging.error(f"Sniffer hatası: {e}")
            self.running = False

    def stop(self):
        """
        Paket dinleme işlemini durdurur.
        """
        self.running = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2.0)
