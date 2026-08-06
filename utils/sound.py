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
    @staticmethod
    def play(message, lang='tr'):
        """Sesli mesajı arka planda okur."""
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
