# ========================================================================
# DS-IPS (Premium SOC Edition)
# Bu proje Kadir Kırmacı'ya aittir. 
# Copyright (c) 2026 Kadir Kırmacı. All Rights Reserved.
# Ticari kullanımı ve tersine mühendislik yapılması kesinlikle yasaktır.
# ========================================================================

class OSFingerprint:
    """
    Pasif ve aktif ağ verilerinden işletim sistemi ve cihaz tipini (OS/Device) çıkaran sınıf.
    """
    
    @staticmethod
    def from_ttl(ttl: int) -> str:
        """
        TTL (Time To Live) değerine bakarak tahmini OS döndürür.
        """
        if not isinstance(ttl, int) or not 1 <= ttl <= 255:
            return "Bilinmiyor"
            
        # Standart başlangıç TTL değerlerine yakınlık
        if ttl <= 64:
            return "Linux / Mac / Android"
        elif ttl <= 128:
            return "Windows PC"
        elif ttl <= 255:
            return "Ağ Cihazı (Switch/Router vb.)"
            
        return "Bilinmiyor"

    @staticmethod
    def from_dhcp_options(options_list: list) -> str:
        """
        DHCP Option 55 (Parameter Request List) imzalarına bakarak nokta atışı OS/Cihaz döndürür.
        options_list: [1, 3, 6, 15, ...] şeklinde integer listesidir.
        """
        if not options_list:
            return "Bilinmiyor"
            
        # Option 55 listesini virgülle ayrılmış string'e çevir
        opt_str = ",".join(map(str, options_list))
        
        # En popüler imzalar
        signatures = {
            "1,121,3,6,15,114,119,252": "Apple (iOS/macOS)",
            "1,3,6,15,119,252": "Apple (iOS/macOS)",
            "1,3,6,15,119,95,252,44,46,47": "Apple (macOS)",
            "1,3,6,15,26,28,51,58,59,43": "Windows PC",
            "1,3,6,15,31,33,43,44,46,47,119,121,249,252": "Windows PC",
            "1,3,6,15,26,28,51,58,59,43,119": "Windows PC",
            "1,3,6,15,26,28,51,58,59,43,119,121,249,252": "Windows PC",
            "1,3,6,15,26,28,51,58,59,43,121,249,252": "Windows PC",
            "1,3,6,15,119,252,95,44,46": "Apple (macOS)",
            "1,3,6,28,15,51,58,59,43,119": "Windows",
            "1,3,6,12,15,28,42": "Linux / IoT",
            # Android genelde 33, 42, 121 (classless static route) vs ister
            "1,3,6,15,26,28,51,58,59,43,121,33": "Android",
            "1,3,6,15,26,28,51,58,59,43,119,121,33": "Android"
        }
        
        if opt_str in signatures:
            return signatures[opt_str]
            
        # Kaba tahmin (Tam eşleşme yoksa)
        options = set(options_list)
        if {121, 252, 119} <= options:
            return "Apple Cihaz (Tahmini)"
        if {26, 28, 51, 58} <= options:
            return "Windows (Tahmini)"
        if {33, 42} <= options:
            return "Android (Tahmini)"
            
        return "Bilinmiyor"
