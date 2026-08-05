<h1 align="center">🛡️ DS-IPS (Intrusion Prevention System) - Premium SOC Edition</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.6-00e5ff.svg?style=for-the-badge&logo=appveyor" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.x-blue.svg?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-Proprietary-red.svg?style=for-the-badge&logo=law" alt="License">
  <img src="https://img.shields.io/badge/Security-Military_Grade-success.svg?style=for-the-badge&logo=security" alt="Security">
</p>

<p align="center">
  <strong>Gelişmiş Ağ Saldırı Tespit ve Önleme Sistemi & Siber Güvenlik Operasyon Merkezi (SOC)</strong><br>
  Telif Hakkı (c) 2026 - Kadir Kırmacı
</p>

---

## 🌟 Proje Özeti
**DS-IPS**, yerel ağınızda (LAN) ve kablosuz ağınızda (Wi-Fi) meydana gelebilecek siber saldırıları, anormallikleri ve keşif (tarama) girişimlerini gerçek zamanlı olarak **tespit eden (IDS)** ve saldırganı ağdan tamamen **izole eden (IPS)** profesyonel bir güvenlik yazılımıdır. 

Proje, yalnızca ağ paketlerini yakalamakla kalmaz, aynı zamanda sistem yöneticilerine **Premium Glassmorphism** tasarımlı, canlı bir Ağ Haritası (Live Topology) sunarak tüm ağı saniyeler içinde görselleştirir.

---

## 🚀 Neler Yapabilir? (Temel Özellikler)

### 1. 🔍 Gelişmiş Saldırı Tespiti (IDS - Intrusion Detection)
- **ARP Spoofing / Zehirlenmesi:** Ağdaki cihazların kimliğine bürünerek Ortadaki Adam (MitM) saldırısı yapmaya çalışan cihazları anında yakalar.
- **Port ve Ağ Taramaları:** Nmap, Masscan gibi araçlarla yapılan `SYN`, `FIN`, `NULL`, `XMAS` ve `UDP` port taramalarını hız ve desen analizi ile tespit eder.
- **Denial of Service (DoS):** Hedef sisteme yönelik aşırı SYN paketi veya UDP flood saldırılarını tespit edip oran limiti ile bloklar.
- **Kablosuz Ağ (Wi-Fi) Tehditleri:** `Deauth` (Ağdan düşürme) saldırılarını, sahte ağ yayınlarını (Beacon Flood) ve Şeytani İkiz (Evil Twin) ağlarını tespit eder.
- **Bubi Tuzakları (Canary Tokens):** Ağda paylaşılan sahte dosyalar (`sirket_sifreleri.pdf`, `banka_bilgileri.xlsx`) açılmaya veya indirilmeye çalışıldığında alarm verir.

### 2. 🛡️ Acımasız Saldırı Önleme (IPS - Intrusion Prevention)
- **Layer 3 (IP/MAC) Ban:** Saldırganı `iptables` ile çekirdek düzeyinde engeller.
- **Layer 2 Ağ İzolasyonu (ARP Blackholing):** VPN, Proxy veya DNS değiştirmek saldırganı kurtarmaz! IPS, modemi ve saldırganı sahte (00:00:00:00:00:00) MAC adresleriyle zehirleyerek saldırganın modeme ve internete olan fiziksel/mantıksal erişimini tamamen keser.
- **Akıllı Süreli Ban:** Otomatik tespit edilen saldırganlar için ban süresi belirlenebilir, süre sonunda kilit otomatik açılır.

### 3. 🌐 Canlı SOC Arayüzü (Premium Dashboard)
- **Gerçek Zamanlı Ağ Haritası (Vis.js):** Ağdaki cihazları (Modem, PC, Telefon) simgelerle haritalandırır. Güvenli cihazlar yeşil, şüpheliler sarı, tehlikeliler kırmızı ile işaretlenir. Uyuyan cihazlar haritadan akıllıca gizlenir.
- **Socket.IO Entegrasyonu:** Alarmlar ve yeni cihazlar, sayfayı yenilemeye gerek kalmadan anında ekrana (canlı akışa) yansır.
- **Glassmorphism UI:** Uzay mavisi animasyonlu arka plan (Grid), buzlu cam kart tasarımları, hover mikro-animasyonlar ve fütüristik renk paleti ile üst düzey profesyonel görünüm.

### 4. 📲 Uzaktan Bildirim ve Raporlama
- **Discord Webhook Entegrasyonu:** Ofiste değilken bile ağınıza bir saldırı olduğunda Discord sunucunuza saniyesinde kritik uyarı mesajları düşer.
- **Sesli Alarmlar:** Kritik saldırılarda kontrol paneli (bilgisayar hoparlörü) üzerinden alarm sesleri çalarak operatörü uyarır.
- **Adli Bilişim (PCAP) Kaydı:** Kritik (Kırmızı) seviye bir saldırı tespit edildiğinde, kanıt sunmak amacıyla saldırganın 60 saniyelik ağ trafiğini `tcpdump` ile PCAP dosyası olarak kaydeder.

### 5. 🔒 Askeri Düzey Arayüz Güvenliği
- **HTTPS (SSL/TLS) Zorunluluğu:** Sistem `Adhoc SSL` ile çalışır, Burp Suite gibi Man-in-the-Middle Proxy araçlarının trafiği arasına girmesini (HSTS, CSP ile) engeller.
- **JavaScript Obfuscation & Anti-Debugger:** Arayüzün kaynak kodları tamamen şifrelenmiştir. F12 (DevTools), Sağ tık veya kısayollarla kodları incelemeye çalışanların tarayıcıları Anti-Debugger döngüsü ile kilitlenir.
- **Brute-Force ve CSRF Koruması:** Panele yetkisiz girişleri önlemek için 3 yanlış şifre denemesinde IP adresi 30 dakika kitlenir.

---

## 🛠️ Kurulum ve Çalıştırma

### Gereksinimler
- Linux Tabanlı İşletim Sistemi (Kali Linux, Arch, Ubuntu vb.)
- Python 3.x
- Root (`sudo`) yetkisi (IPS ve paket dinleme işlemleri için zorunludur)

### Başlatma
1. Sistemdeki gerekli Python kütüphanelerini kurun: `pip install -r requirements.txt` (Eğer varsa)
2. Uygulamayı başlatın:
```bash
sudo python3 main.py -i eth0 -m ips
```
*(Kablosuz ağ dinlemesi yapmak için komutun sonuna `--wifi` ekleyebilirsiniz.)*

3. Tarayıcınızdan **https://localhost:5000** veya **https://127.0.0.1:5000** adresine gidin.
4. İlk girişte tarayıcı SSL uyarısı verecektir (Gelişmiş > İlerle diyerek geçin).
5. Terminalde yazan "Rastgele Üretilen" Kullanıcı Adı ve Şifre ile sisteme giriş yapın.

---

## ⚖️ Yasal Uyarı ve Lisans
Bu yazılım **Kadir Kırmacı** tarafından geliştirilmiş olup, tüm telif ve fikri mülkiyet hakları saklıdır. Herhangi bir şirkette, kurumda veya mekanda **izinsiz kullanımı, kodlarının değiştirilmesi veya kopyalanması kesinlikle yasaktır.**

Yazılım "OLDUĞU GİBİ" sağlanmaktadır. Meydana gelebilecek ağ kesintilerinden, yasal yaptırımlardan veya fiziksel zararlardan geliştirici (Kadir Kırmacı) kesinlikle sorumlu tutulamaz. Detaylar için `LICENSE` dosyasına bakınız.
