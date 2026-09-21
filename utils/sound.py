# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

import subprocess
import threading

class SoundAlert:
    """
    Saldırı anında veya ban atıldığında espeak ile sesli uyarı verir.
    """
    _lock = threading.Lock()
    _last_play_time = float("-inf")
    _cooldown = 4.0  # Aynı anda üst üste ses gelmemesi için 4 saniye bekleme süresi

    @staticmethod
    def play(message, lang='tr'):
        """Sesli mesajı arka planda okur (Spam korumalı)."""
        import time
        current_time = time.monotonic()
        # Eğer son sesin üzerinden bekleme süresi (cooldown) geçmediyse sesi yut, konuşma.
        with SoundAlert._lock:
            if current_time - SoundAlert._last_play_time < SoundAlert._cooldown:
                return
            SoundAlert._last_play_time = current_time
        def _speak():
            try:
                # espeak komutunu kullanarak sesi üret
                # -v tr : Türkçe dili
                # -s 140 : Hız
                subprocess.run(['espeak', '-v', lang, '-s', '140', message], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL, timeout=15)
            except Exception:
                pass
        
        t = threading.Thread(target=_speak, daemon=True)
        t.start()

    @staticmethod
    def alert_attack(attack_name):
        SoundAlert.play(f"Saldırı! {attack_name} tespit edildi!")

    @staticmethod
    def alert_ban(ip):
        SoundAlert.play(f"Cihaz ağdan izole edildi. İp adresi: {ip}")
