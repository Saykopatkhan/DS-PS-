# DS-IPS v5.0 Kapsamlı QA ve Penetrasyon Test Planı

Bu belge, "Kıdemli Siber Güvenlik Test Uzmanı (QA Security Engineer)" perspektifiyle DS-IPS (Next-Gen Hybrid IDS/IPS) sisteminin canlı ortama (Production) geçmeden önce tüm modüllerinin doğrulanması amacıyla hazırlanmıştır. 

Aşağıdaki komutları kendi yerel ağınızda veya sanal laboratuvarınızda (örn: Kali Linux üzerinden Hedef Sunucuya) çalıştırarak sistemi simüle edebilirsiniz.

> [!WARNING]
> Bu testleri yalnızca yetkili olduğunuz sistemlerde (laboratuvar ortamında) çalıştırın. Canlı (Production) ağdaki diğer cihazları etkilememek için `eth0` yerine kapalı devre bir ağ veya VM arayüzü kullanmanız tavsiye edilir.

---

## 1. Sistem ve Servis Sağlamlık Testleri (Health Checks)

### 1.1. Konfigürasyon Dosyası Okuma Testi
**Amacı:** Sistem `/etc/dsips/config.json` dosyasındaki ayarları okuyabiliyor mu?
**Komut:**
```bash
# Geçici olarak bozuk bir JSON yapısı oluşturun
sudo echo "{ invalid json" > /etc/dsips/config.json
sudo python3 web_main.py -i eth0
```
**Beklenen Çıktı:** Uygulama çökmek yerine varsayılan (default) ayarları yüklemeli veya okuma hatasını loglara düzgün bir şekilde yazıp çalışmaya devam etmelidir. Test sonrası dosyayı düzeltin.

### 1.2. Servis Çökme ve Otomatik Başlama (systemd)
**Amacı:** Sistem beklenmedik bir şekilde kapandığında Linux `systemd` servisi tekrar ayağa kaldırıyor mu?
**Komut:**
```bash
# DS-IPS'in çalıştığı PID'yi bulup acımasızca (SIGKILL) öldürün
sudo kill -9 $(pgrep -f "python3 web_main.py")

# Servisin otomatik olarak tekrar başlayıp başlamadığını kontrol edin
sudo systemctl status dsips.service
```
**Beklenen Çıktı:** Status çıktısında "Active: active (running)" yazmalı ve servisin birkaç saniye içinde kendini yeniden başlattığı (Restart=always) görülmelidir.

### 1.3. Dry-Run (Simülasyon) Modu Testi
**Amacı:** Dry-Run aktifken IP'ler gerçekten engelleniyor mu?
**Komut:**
```bash
sudo python3 web_main.py -i eth0 --dry-run
# Uygulama açıldıktan sonra başka bir terminalden API'ye ban isteği atın
curl -X POST http://127.0.0.1:5000/api/ban -H "Content-Type: application/json" -H "X-Requested-With: XMLHttpRequest" -d '{"ip":"8.8.8.8","mac":"","reason":"QA Dry-Run Test"}'

# ipset kurallarını kontrol edin
sudo ipset list dsips_blacklist
```
**Beklenen Çıktı:** API "success: True" döndürebilir ancak loglarda `[DRY RUN]` yazmalı ve `ipset list` komutunun çıktısında `8.8.8.8` IP adresi KESİNLİKLE görünmemelidir.

### 1.4. Whitelist (Beyaz Liste) Koruması
**Amacı:** Yöneticinin kendi IP'sini yanlışlıkla banlamasının önüne geçiliyor mu?
**Komut:**
```bash
# Kendi cihazınızın IP'sini engellemeye çalışın (örn: 127.0.0.1)
curl -X POST http://127.0.0.1:5000/api/ban -H "Content-Type: application/json" -H "X-Requested-With: XMLHttpRequest" -d '{"ip":"127.0.0.1","mac":"","reason":"QA Whitelist Test"}'
```
**Beklenen Çıktı:** API, `400 Bad Request` veya benzeri bir hata koduyla birlikte `"Bu IP beyaz listede (korumalı) olduğu için engellenemez"` mesajını dönmelidir.

---

## 2. L2/L3/L4 Ağ Katmanı Testleri (NIDS & WIDS)

### 2.1. ARP Spoofing (MITM) Simülasyonu
**Amacı:** Sistem sahte ARP cevaplarını (Man-in-the-Middle) yakalayabiliyor mu?
**Komut:** (Saldırgan makineden)
```bash
# Ağa izinsiz gratuitous ARP veya sahte MAC yanıtı basma
sudo arpspoof -i eth0 -t <Hedef_IP> <Gateway_IP>
```
**Beklenen Çıktı:** DS-IPS konsolunda veya Web Panelinde **Kritik** seviyede "ARP Spoofing" alarmı belirmeli ve saldırganın MAC/IP adresi ağ haritasında "⚠️" işareti ile işaretlenmelidir.

### 2.2. Port Tarama (Nmap SYN, FIN, XMAS) Testi
**Amacı:** Farklı bayraklara (TCP Flags) sahip gizli port taramaları tespit ediliyor mu?
**Komut:** (Saldırgan makineden)
```bash
# SYN Tarama
sudo nmap -sS -p- -T4 <DS-IPS_Sunucu_IP>
# XMAS Tarama
sudo nmap -sX -p 21,22,80,443 <DS-IPS_Sunucu_IP>
```
**Beklenen Çıktı:** Belirli bir eşiğin (threshold) üzerinde paket geldiğinde Web Panelde "SYN Port Scan" veya "XMAS Port Scan" alarmları düşmeli, Saldırgan IP'si izlemeye alınmalıdır.

### 2.3. Adli Bilişim Delili (.pcap) Oluşturma Testi
**Amacı:** Kritik saldırılarda paket dökümü otomatik olarak diske yazılıyor mu?
**Beklenen Çıktı:** Port taraması veya WAF saldırısı sonrası `/home/kali/İndirilenler/ds_ips_project/pcaps/` (veya ilgili dizinde) saldırgana ait IP ve zaman damgası içeren bir `.pcap` dosyasının başarıyla oluşturulduğunu teyit edin. `tshark -r dosya.pcap` ile okunabilir olmalıdır.

---

## 3. L7 WAF ve Log Analizi Testleri (HIDS)

*(Aşağıdaki testler için sunucuda Nginx/Apache'nin çalıştığını ve DS-IPS HIDS motorunun `/var/log/nginx/access.log` dosyasını dinlediğini varsayıyoruz.)*

### 3.1. SQL Injection & XSS & RCE & LFI Testleri
**Amacı:** Geleneksel web saldırısı payload'ları asenkron log analizinden geçiyor mu?
**Komut:** (Saldırgan makineden, sırasıyla çalıştırın)
```bash
# SQL Injection Testi
curl -A "Mozilla/5.0" "http://<DS-IPS_Sunucu_IP>/?id=1' UNION SELECT NULL,NULL--"

# XSS Testi
curl -A "Mozilla/5.0" "http://<DS-IPS_Sunucu_IP>/?search=<script>alert(1)</script>"

# LFI Testi
curl -A "Mozilla/5.0" "http://<DS-IPS_Sunucu_IP>/?file=../../../../etc/passwd"

# RCE (Command Injection) Testi
curl -A "Mozilla/5.0" "http://<DS-IPS_Sunucu_IP>/?cmd=cat+/etc/shadow|bash"
```
**Beklenen Çıktı:** Web paneli anında **"SQL Injection Tespiti"**, **"XSS Tespiti"** gibi yüksek öncelikli alarmları göstermeli. Atak yapan IP adresi, IPS aktifse `ipset` tarafından otomatik olarak kara listeye alınmalıdır.

### 3.2. HTTP DDoS (Rate Limiting) Testi
**Amacı:** Belirlenen eşik değerinin üzerindeki aşırı GET/POST istekleri kesiliyor mu?
**Komut:**
```bash
# Apache Benchmark (ab) ile eşzamanlı 100 istek atma
ab -n 500 -c 50 http://<DS-IPS_Sunucu_IP>/
```
**Beklenen Çıktı:** Sistem ilk 100-150 istekten sonra "HTTP Flood / DDoS" alarmı üretmeli ve saldırganın IP adresini geçici süreyle bloklamalıdır (Rate Limit). `ab` aracında *Connection Refused* veya *Timeout* hataları görülmelidir.

### 3.3. SSH Brute Force (Hydra) Testi
**Amacı:** SSH denemeleri auth.log (veya benzeri loglar) üzerinden yakalanıyor mu?
**Komut:**
```bash
# Geçersiz şifrelerle 10 saniye içinde 20 deneme
hydra -l root -P /usr/share/wordlists/fasttrack.txt ssh://<DS-IPS_Sunucu_IP>
```
**Beklenen Çıktı:** "SSH Brute Force" alarmı oluşmalı ve Hydra'nın bağlantısı hedef sunucu tarafından aniden kesilmelidir.

---

## 4. Honeypot ve Deception (Siber Tuzak) Testleri

### 4.1. Honeytoken (Sahte Dosya) Dokunma Testi
**Amacı:** Hassas dizinlere yerleştirilen tuzak dosyalar izleniyor mu?
**Komut:** (Sunucu içinde yetkisiz veya yetkili bir kullanıcı gibi davranarak)
```bash
# Tuzağa düşürülecek sahte dosyanın (örn: gizli_maaslar.xlsx) okunması
cat /opt/dsips/honeytokens/gizli_maaslar.xlsx
```
**Beklenen Çıktı:** Dosyaya erişildiği an Inotify/FSEvents tetiklenmeli ve "Bubi Tuzağı İhlali" (Honeytoken Triggered) alarmı Web Panel'e Kritik seviyede düşmelidir.

### 4.2. Sahte SSH Honeypot Testi
**Amacı:** Sahte bir servise (örn: port 2222) yapılan girişler analiz ediliyor mu?
**Komut:**
```bash
ssh root@<DS-IPS_Sunucu_IP> -p 2222
# Çıkan ekrana rastgele bir şifre girin
```
**Beklenen Çıktı:** Bağlantı başarılı gibi görünebilir ancak asıl sistem loglarına "Honeypot Bağlantı Denemesi" olarak yansımalı. Girilen sahte şifreler (örn: 123456) loglanmalı ve IP anında banlanmalıdır.

---

## 5. Aksiyon ve Bildirim Testleri (Mitigation & Alerting)

### 5.1. Telegram C2 & Bildirim Akışı
**Amacı:** Kritik olaylar saniyeler içinde yetkili personele iletiliyor mu?
**Test Adımı:** 3. maddedeki SQLi veya LFI payload'ını gönderin.
**Beklenen Çıktı:** Telegram botu akıllı telefonunuza Markdown formatında şu mesajı atmalıdır:
`🔴 KRİTİK ALARM!`
`Atak Türü: SQL Injection`
`Saldırgan IP: <Saldırgan_IP>`
`Hedef: Web Sunucusu`

### 5.2. Inline Bot Kontrol (Asenkron Ban)
**Amacı:** Telegram üzerinden gelen mesaja tıklanarak sisteme uzaktan komut verilebiliyor mu?
**Test Adımı:** Telegram'a düşen mesajın altındaki **[Banu Kaldır / Engelle]** butonuna tıklayın.
**Beklenen Çıktı:** Telegram botu "İşlem Başarılı" yanıtını dönmeli. DS-IPS sunucusunda `sudo ipset list dsips_blacklist` yazıldığında IP'nin silindiği veya eklendiği teyit edilmelidir.

### 5.3. Web SOC Paneli (WebSocket) Gerçek Zamanlılık Testi
**Amacı:** Arayüz yenilenmeden (F5 yapmadan) ataklar ve bloklamalar arayüze düşüyor mu?
**Test Adımı:** Ekranın bir tarafında Web Dashboard açıkken, diğer taraftan Nmap taraması başlatın.
**Beklenen Çıktı:** 
- Alarmlar kısmına atak anında yeni bir satır eklenmeli.
- "Ağ Trafik Analizi" radar haritasında yeni saldırgan cihaz "Kırmızı" (Tehlike) rengine dönerek belirmeli.
- Dashboard metriklerindeki (İstisnalar, SQLi Sayacı) rakamlar artmalıdır.

### 5.4. Akıllı Ceza ve Zaman Aşımı (TTL) Testi
**Amacı:** Farklı tehdit tipleri için farklı ban süreleri (TTL) doğru çalışıyor mu?
**Komut:** (SQLi atağı yapıldıktan sonra)
```bash
sudo ipset list dsips_blacklist
```
**Beklenen Çıktı:** Çıktıda yer alan IP'nin yanında yazan `timeout` değeri, SQLi/Kritik seviye için atanan değer (örn: 3600 sn - 1 Saat veya 86400 sn - 24 Saat) ile eşleşmeli, basit bir port taraması ise daha kısa (örn: 300 sn - 5 Dk) bir timeout'a sahip olmalıdır.

---
**Sonuç:**
Bu QA planındaki tüm "Beklenen Çıktılar" başarıyla doğrulanırsa, DS-IPS v5.0 sistemi canlı ortam (Production) kullanımına ve kurumsal ağ entegrasyonuna hazır kabul edilecektir. Başarılar dilerim!
