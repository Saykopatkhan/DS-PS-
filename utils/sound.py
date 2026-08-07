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
    _last_play_time = 0
    _cooldown = 4.0  # Aynı anda üst üste ses gelmemesi için 4 saniye bekleme süresi

    @staticmethod
    def play(message, lang='tr'):
        """Sesli mesajı arka planda okur (Spam korumalı)."""
        import time
        current_time = time.time()
        # Eğer son sesin üzerinden bekleme süresi (cooldown) geçmediyse sesi yut, konuşma.
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
                               stderr=subprocess.DEVNULL)
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
