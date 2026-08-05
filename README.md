<div align="center">
  <br>
  <h1>🛡️ DS IPS (Intrusion Prevention System)</h1>
  <p>
    <b>Yapay Zeka Mantıklı, Aktif Savunma ve Sıfır Güven (Zero-Trust) Odaklı Siber Olay Yeri İnceleme ve Ağ Güvenlik Sistemi.</b>
  </p>
  <br>
</div>

## 📌 Proje Hakkında
DS IPS, sıradan bir izleme aracı (IDS) olmaktan öte, ağa giren saldırganı aktif olarak tuzağa düşüren, siber istihbarat toplayan ve delil (PCAP) oluşturan gelişmiş bir **Siber Güvenlik Askeri Üssü**'dür. Sistem, ağdaki tüm cihazları ve trafik akışını dinamik bir fizik motoruyla (Vis.js) görselleştirir, anormallikleri tespit eder ve saldırganları otomatik olarak Telegram üzerinden yöneticisine raporlar.

**Önemli Not:** DS IPS'in felsefesi gereği "Otomatik Ban (İnfaz)" özelliği bilerek kapalıdır. Sistem tespiti, delil toplamayı ve istihbaratı kusursuz yapar ancak nihai ağdan atma (Ban) kararını sistem yöneticisine bırakır.

---

## 🚀 Öne Çıkan Özellikler

### 1. 🕸️ Sıfır Güven (Zero-Trust) Tuzakları
- **Honeytokens (Bubi Tuzakları):** Ağda korunmasız gibi görünen sahte "Şirket Şifreleri" dosyaları sunar. Bu dosyalara dokunan saldırganı anında fişler.
- **Deep SSH Honeypot:** 22 numaralı portu açık bırakarak Brute-Force (Kaba Kuvvet) saldırılarını üzerine çeker ve saldırganın denediği parolaları kaydeder.
- **Decoy Traffic (Beyaz Gürültü):** Wireshark veya Bettercap ile ağınızı dinleyen hacker'ları kör etmek için etrafa sahte DNS ve HTTP trafikleri saçar.

### 2. 🌍 Küresel İstihbarat (Threat Intel & Geo-IP)
- Ağdaki tüm cihazların dış bağlantılarını anlık takip eder. Cihazlarınız gizlice Düşman Devlet (Rusya, Çin vb.) sunucularına veri sızdırıyorsa **"Arka Kapı (Backdoor) Trojanı"** alarmı verir.

### 3. 🚨 Olay Yeri İnceleme (Automated Forensics)
- Sistem kritik bir saldırı sezdiğinde (örn: Nmap port taraması), anında `tcpdump` tetikler ve saldırganın sonraki 60 saniyelik ham ağ trafiğini `.pcap` olarak kaydeder. Wireshark'ta adli bilişim (Forensic) incelemesi yapmanız için delil sunar.
- Uçtan uca şifreli Telegram Entegrasyonu sayesinde, kırmızı alarmları anında cebinize gönderir.

### 4. ⚔️ Ağ Kalkanları (Detection Engines)
- **ARP Spoofing Koruması:** Ortadaki Adam (MitM) saldırılarını yakalar.
- **Derin Port Taraması Tespiti:** SYN/XMAS taramalarını anında ifşa eder.
- **DNS Sinkhole:** Zararlı yazılımlara giden DNS bağlantılarını işaretler.

---

## 🛠️ Kurulum ve Çalıştırma

### Gereksinimler
Sistemin ağ paketlerini (Packet Sniffing) yakalayabilmesi için **Linux tabanlı bir işletim sistemi (Örn: Kali Linux, Ubuntu)** kullanılması zorunludur.

1. Projeyi indirin ve klasöre girin:
```bash
git clone https://github.com/KULLANICI_ADINIZ/ds-ips.git
cd ds-ips
```

2. Gerekli kütüphaneleri yükleyin:
```bash
sudo pip3 install -r requirements.txt
```
*(Eğer "externally-managed-environment" hatası alırsanız komutun sonuna `--break-system-packages` ekleyebilirsiniz).*

3. Sistemi yönetici yetkileriyle (Root) başlatın:
**Kablolu Bağlantı (Ethernet) için:**
```bash
sudo python3 web_main.py -i eth0
```
**Kablosuz Bağlantı (Wi-Fi) için:**
```bash
sudo python3 web_main.py -i wlan0 --wifi
```

4. Kurulum tamamlandıktan sonra tarayıcınızdan Web Paneline giriş yapın:
👉 `http://127.0.0.1:5000` (Kullanıcı Adı: `Saykopatkhan16` Şifre: `khanfq`)

---

## 📱 Telegram Alarm Kurulumu
1. Telegram'da `@BotFather` ile yeni bir bot oluşturun ve **API Token**'ı alın.
2. Telegram'da `@userinfobot` ile kendi **Chat ID**'nizi öğrenin.
3. DS IPS Web Paneli -> Ayarlar menüsüne girip bu iki bilgiyi kaydedin.
4. Test etmek için: `http://127.0.0.1:5000/sirket_sifreleri.pdf` adresine tıklayın ve telefonunuza düşen sireni dinleyin!

---
*DS IPS, açık kaynak siber güvenlik vizyonuyla geliştirilmiştir. Sorumluluk kullanıcıya aittir.*
