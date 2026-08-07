<h1 align="center">🛡️🇹🇷 DS-IPS (Intrusion Prevention System) - Premium SOC Edition</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0-00e5ff.svg?style=for-the-badge&logo=appveyor" alt="Version">
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

### 🌟 Yeni Eklenen v3.0 Özellikleri (Premium Güncelleme)
- **Canlı Siber Radar (Cyber Radar):** Ağdaki kritik tehditleri (Örn: Rusya tabanlı C2 bağlantıları) radar ekranında görsel "Blip" (hedef) olarak yansıtan askeri tarz animasyon.
- **Derin Paket İnceleme (DPI) ile SNI Sniffing:** DNS önbelleğini (Cache) ve Güvenli DNS'i (DoH) aşarak, internete çıkan şifreli (HTTPS) trafiğin içindeki alan adlarını (SNI) cımbızla çeker ve Canlı Gözetleme ekranına anında yansıtır.
- **Anti-MITM Healing (Aktif İyileştirme):** Ağda bir ARP zehirlenmesi tespit edildiğinde saldırganı engellemekle kalmaz, kurban cihazların bağlantısı kopmasın diye ağa "Onarıcı (Healing)" Broadcast ARP paketleri fırlatır. Kendi koruma modülleriyle (Blocker) çakışmaması için Akıllı Beyaz Liste (Whitelist) kullanır.
- **Akıllı Ses/Alarm Yönetimi (Debounce):** Yoğun ağ saldırılarında (Örn: Flood) üst üste binen alarm seslerini engelleyen 4 saniyelik Akıllı Cooldown algoritması.
- **Gelişmiş Risk Grafiği:** Alarmları sadece "Risk Seviyesine" (Kritik🔴, Yüksek🟡, Orta🔵, Düşük🔘) göre dinamik 4 dilimde gruplayıp, üzerine gelindiğinde detaylı yüzdelik kırılımları gösteren profesyonel Tooltip entegrasyonu.

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
- **Discord & Telegram Entegrasyonu:** Ofiste değilken bile ağınıza bir saldırı olduğunda Discord sunucunuza veya Telegram botunuza saniyesinde kritik uyarı mesajları düşer.
- **Sesli Alarmlar:** Kritik saldırılarda kontrol paneli (bilgisayar hoparlörü) üzerinden alarm sesleri çalarak operatörü uyarır.
- **Adli Bilişim (PCAP) Kaydı:** Kritik (Kırmızı) seviye bir saldırı tespit edildiğinde, kanıt sunmak amacıyla saldırganın 60 saniyelik ağ trafiğini `tcpdump` ile PCAP dosyası olarak kaydeder.

### 5. ⚡ Performans ve Otonom Optimizasyon (V2 Özellikleri)
- **Akıllı Çöpçü (Garbage Collector):** Veritabanının şişmesini engellemek için, ağdaki cihazların ürettiği DNS (girilen site) loglarını tam 10 dakika sonra saniyesi saniyesine otomatik olarak kalıcı siler. Sistem yıllarca açık kalsa bile disk veya RAM dolmaz.
- **Dinamik Ağ Gözetleme (Dynamic UI):** Paneldeki aktif cihazlar listesi, son 10 dakika içerisinde sinyal vermeyen (uyuyan veya ağdan kopan) cihazları arayüzden tamamen gizleyerek operatörün sadece o anki "Canlı" cihazlara odaklanmasını sağlar.
- **False-Positive Koruması:** Sistemin kendi yaptığı periyodik ağ taramalarını (ARP) ve modemin DNS yanıt portlarını (53, 67, 68) beyaz listeye (Whitelist) alarak, kendi kendine sahte UDP Scan veya ARP DDoS alarmı üretmesini engeller. Sadece gerçek tehditlere odaklanır.

### 6. 🔒 Askeri Düzey Arayüz Güvenliği
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

![License](https://img.shields.io/badge/License-Custom_NonCommercial-red.svg)

# DS-IPS (Premium SOC Edition)
**© 2026 Kadir Kırmacı. Tüm Hakları Saklıdır.**

> 💡 **Mülkiyet Bildirimi:** Bu proje tamamen **Kadir Kırmacı**'ya aittir ve onun tarafından tasarlanıp geliştirilmiştir. 

## ⚖️ Lisans ve Kullanım Şartları

Bu proje **DS-IPS Özel Lisansı (Non-Commercial & Modifiable)** ile korunmaktadır. Projeyi kullanan veya kodları inceleyen herkes bu şartları kabul etmiş sayılır.

**✅ İzin Verilenler (Serbest Kullanım ve Geliştirme):**
* Kişisel bilgisayarlarda, ev ağlarında ve eğitim laboratuvarlarında ücretsiz kullanım.
* Projeyi eğitim amaçlı inceleme, kaynak kodunu geliştirme ve kişisel ihtiyaçlara göre özelleştirme.

**❌ Kesinlikle Yasak Olanlar:**
* **Ticari Kullanım:** Bu yazılımın (veya tarafınızca değiştirilmiş türevlerinin) herhangi bir gelir elde edilen ortamda (şirketler, kurumlar, ticari ağlar vb.) kullanılması, satılması veya hizmet olarak sunulması KESİNLİKLE YASAKTIR.
* **Tersine Mühendislik:** Projenin güvenlik mekanizmalarını atlatmaya çalışmak, korumalı modülleri parçalamak (disassembly) veya tersine mühendislik yapmak yasaktır.

> ⚠️ **Bağımlılıklar Hakkında Önemli Not:** 
> Yasal uyumluluk gereği, bu proje `Scapy` gibi harici kütüphaneleri kaynak koduna gömülü (bundle) olarak barındırmaz. Aracı çalıştırmadan önce bağımlılıkları kendi sisteminize kurmanız gerekmektedir:
> ```bash
> pip install -r requirements.txt
> ```

Tüm yasal kısıtlamalar ve detaylar için lütfen proje dizinindeki [LICENSE](LICENSE) dosyasını inceleyiniz.
