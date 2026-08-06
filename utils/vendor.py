# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

import requests
import re
from functools import lru_cache

class VendorLookup:
    """
    MAC adresinden cihaz üreticisini bulur.
    """
    COMMON_VENDORS = {
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi",
        "00:0c:29": "VMware",
        "00:1c:42": "Parallels",
        "00:15:5d": "Microsoft (Hyper-V)"
    }

    @staticmethod
    @lru_cache(maxsize=128)
    def get_vendor(mac_address: str) -> str:
        """MAC adresinden markayı çözer. Hızlı sonuç için önbellek (lru_cache) kullanır."""
        if not mac_address or mac_address == "N/A" or mac_address == "ff:ff:ff:ff:ff:ff":
            return "Bilinmiyor"

        # OUI (ilk 3 oktet) kontrolü
        prefix = mac_address.lower()[:8]
        if prefix in VendorLookup.COMMON_VENDORS:
            return VendorLookup.COMMON_VENDORS[prefix]

        try:
            # macvendors.co API'sine istek at (ücretsiz ve key gerektirmez)
            # Zaman aşımı kısa tutuldu ki taramayı yavaşlatmasın
            url = f"https://api.macvendors.com/{mac_address}"
            response = requests.get(url, timeout=1.5)
            if response.status_code == 200:
                vendor = response.text.strip()
                # Çok uzun marka isimlerini kısalt
                if len(vendor) > 20:
                    return vendor.split(' ')[0] + "..."
                return vendor
            else:
                return "Bilinmiyor"
        except requests.RequestException:
            return "Bilinmiyor"
