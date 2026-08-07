#!/bin/bash

# ========================================================================
# DS-IPS (Premium SOC Edition) Otomatik Kurulum ve Yapılandırma Dosyası
# ========================================================================

# Terminal Renkleri
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}   🛡️ DS-IPS (Premium SOC Edition) Kurulumu   ${NC}"
echo -e "${CYAN}=================================================${NC}"

# 1. Root Yetkisi Kontrolü
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] HATA: Sistem ağ ayarlarını (IP Forwarding) değiştirebilmek için Root yetkisi gerekiyor.${NC}"
  echo -e "${YELLOW}Lütfen komutu şu şekilde çalıştırın:${NC} sudo ./install.sh"
  exit 1
fi
echo -e "${GREEN}[✔] Root yetkisi doğrulandı.${NC}"

# 2. Python Kütüphanelerini Kurma
echo -e "${GREEN}[+] Python kütüphaneleri (requirements.txt) yükleniyor...${NC}"
# Kali/Debian'da PEP668 korumasını aşmak için --break-system-packages kullanılır (opsiyonel)
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
echo -e "${GREEN}[✔] Bağımlılıklar kuruldu.${NC}"

# 3. IP Yönlendirmeyi (IP Forwarding) Açma
# Bu işlem, ARP Spoofing ve Anti-MITM modüllerinin çalışırken kurbanın internetini tamamen kesmemesi için şarttır.
echo -e "${GREEN}[+] IP Yönlendirmesi (IP Forwarding) aktif ediliyor...${NC}"
sysctl -w net.ipv4.ip_forward=1 > /dev/null
echo -e "${GREEN}[✔] Ağ yapılandırması tamamlandı.${NC}"

# 4. Çalıştırma İzinlerini Ayarlama
echo -e "${GREEN}[+] Dosya izinleri ayarlanıyor...${NC}"
chmod +x web_main.py
chmod +x install.sh

echo -e "${CYAN}=================================================${NC}"
echo -e "${GREEN}🚀 KURULUM BAŞARIYLA TAMAMLANDI!${NC}"
echo -e "${YELLOW}DS-IPS sistemini hemen başlatmak için şu komutu çalıştırabilirsiniz:${NC}"
echo -e "${CYAN}sudo python3 web_main.py${NC}"
echo -e "${CYAN}=================================================${NC}"
