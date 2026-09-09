# DS-IPS (Premium SOC Edition)
**© 2026 Kadir Kırmacı. Tüm Hakları Saklıdır.**

DS-IPS, modern siber tehditleri ağ (Network) ve uygulama (Application) seviyelerinde gerçek zamanlı olarak saptayan, görselleştiren ve engelleyen kurumsal düzey (Enterprise-Grade) bir Ağ Saldırı Tespit ve Önleme (NIDS/NIPS) platformudur.

---

## 🚀 Sistemin Genel Mimarisi

DS-IPS, esnek ve modüler yapısıyla bir şirketin "Security Operations Center" (SOC) odasındaki ekranları aratmayacak gerçek zamanlı bir **Web Dashboard** sunar. Sistem temelde 3 ana hattan oluşur:

1. **Paket Dinleyici (Sniffer):** Scapy kütüphanesi üzerine inşa edilmiştir. Ağa düşen tüm şifreli ve şifresiz paketleri yakalar ve alt sensörlere (modüllere) analiz etmeleri için paslar.
2. **Güvenlik Sensörleri (Modules):** Her biri farklı tipteki bir siber saldırıyı saptamak üzere eğitilmiş bağımsız algoritmalardır. (Bkz: Koruma Katmanları)
3. **Reaksiyon & Engelleme (Blocker):** Saldırı tespit edildiğinde IP veya MAC adresini `iptables` ve `ARP Blackholing` yöntemleriyle tüm ağdan saniyeler içinde izole eder.

---

## 🛡️ Neleri Koruyor? (Koruma Katmanları)

Sisteminiz baştan sona şu tehditleri savuşturmak üzere programlanmıştır:

### 1. Keşif ve Tarama (Reconnaissance) Saldırıları
- **Gizli (Stealth) Port Taramaları:** `-sS (SYN)`, `-sF (FIN)`, `-sX (XMAS)` ve `-sU (UDP)` gibi Nmap taramalarını şimşek hızında saptar.
- **Güvenlik Duvarı Atlatma:** Paketleri parçalayarak (Fragmentation) gizlenmeye çalışan sinsi taramaları (`-f`) "Anti-Evasion" modülüyle birleştirir ve yakalar.

### 2. DDoS ve Flood (Hizmet Aksatma) Saldırısı
- **SYN/UDP Flood:** Hping3 veya Botnet'ler kullanılarak ağa saniyede binlerce sahte paket yollandığında `_check_flood` algoritması devreye girer. Saniyede 2000 paketi aşan Flood saldırılarını saptayıp saldırgan IP'yi banlar.

### 3. Web Uygulama Zafiyetleri (WAF Modülü)
- **Dizin Kaba Kuvveti (Directory Bruteforce):** Gobuster, Dirb veya Nikto gibi araçlarla sunucunun gizli klasörlerini bulmaya çalışan saldırganları, saniyede dönen aşırı `HTTP 404` (Not Found) hatalarından saptar ve "Web Dir-Bruteforce" alarmı vererek banlar.
- **Layer 7 DoS:** Uygulama seviyesinde saniyede çok yüksek sayıda `HTTP GET` isteği yapan IP'leri engeller.

### 4. Derin Paket İncelemesi (DPI Modülü)
- **Tersine Bağlantı (Reverse Shell):** Netcat (`nc`), Metasploit veya benzeri araçlarla ağın içine şifresiz bir tersine bağlantı açıldığında ağdan geçen paketlerin (Payload) içini okur.
- **Komut Satırı Avcısı:** Paket içinde `cmd.exe`, `powershell`, `uid=0(root)` veya `/bin/bash` metinlerini gördüğü an Kırmızı Alarm çalar.

### 5. Yerel Ağ (LAN) Saldırıları
- **ARP Zehirlenmesi (MitM):**

### Öne Çıkan Özellikler (Phase 1-2-3 Sonrası)
1. **Dinamik Ağ Haritası**: Ağdaki tüm cihazları görsel bir ağaç yapısında listeler.
2. **Kapsamlı Trafik Analizi**: Cihazların hedeflediği IP, port ve domainleri gerçek zamanlı izler.
3. **Flood ve L4 DoS Koruması**: Saniyede 10.000'den fazla paket atan kaynakları hız kesici (cooldown) algoritmalarla analiz eder.
4. **WAF (Web Application Firewall)**: L7 HTTP/HTTPS üzerinden yapılan Layer 7 DoS ve 404 Bruteforce (Dirb/Gobuster) saldırılarını saptar.
5. **DPI (Deep Packet Inspection) ve De-Obfuscation**: Payload'u (paket verisini) inceler; gizlenmiş (Base64/URL Encoded) Reverse Shell, `cmd.exe` veya yetki yükseltme imzalarını bulur.
6. **LLMNR ve DNS Zehirlenmesi**: Ağ içinde sahte DNS (Responder vb.) ataklarını tespit eder.
7. **C2 Beaconing (Zaman Serisi Analizi)**: Ağ içinden dışarıya sızan düzenli sinyalleri (Command & Control sunucu iletişimlerini) matematiksel standart sapma ile yakalar.
8. **Otomatik PCAP Adli Bilişim**: Herhangi bir kırmızı alarm (Critical) anında otomatik olarak o saldırıya ait son 1000 paketi kanıt `.pcap` olarak kaydeder ve web panelden indirilebilir sunar.
9. **Aktif Koruma (Bubi Tuzakları)**: Sahte SSH, HTTP HoneyPot portları üzerinden saldırganları tuzağa düşürür ve anında izole eder.spit eder.
- **DNS Tünelleme (Exfiltration):** Ağa sızmış bir zararlının, verileri sızdırmak için aşırı uzun alt alan adları (subdomain) kullanmasını (Örn: `xyz123...456.hacker.com`) tespit eder.
- **DNS Sinkhole:** Bilinen zararlı adreslere (Malware, Phishing) gitmeye çalışan kullanıcıları `127.0.0.1` adresine yönlendirerek zararlıdan korur.

### 7. Bubi Tuzakları (Honeypot)
- **Açık Port Tuzakları:** FTP (21), Telnet (23), SMB (445) ve SSH (22) gibi heves uyandıran portları sanal olarak açıkmış gibi gösterir. Saldırgan bu portlara dokunduğu an "Honeypot Trap" alarmı çalar ve av avcıya dönüşür.

---

## 🗃️ Kullanım ve Güncel Teslimat

Tüm sistem dosyalarınız, Gereksiz/Önbellek (Cache) dosyalarından arındırılmış bir şekilde en saf ve güncel kaynak kodlarıyla tek bir sıkıştırılmış dosya (ZIP) haline getirilmiştir.

> [!TIP]
> **Projenizi İndirin:** Tüm kodlarınıza bilgisayarınızdaki `/home/kali/İndirilenler/ds_ips_project_v2.zip` dizininden ulaşabilirsiniz.

Sistemi başlatmak için terminalden `ds_ips_project` dizinine girip şu komutu vermeniz yeterlidir:
```bash
python3 web_main.py
```
*(Sistem otomatik olarak tüm ağ kartlarını (`any`) dinlemeye başlar ve `http://127.0.0.1:5000` adresinden panele güvenle (Adhoc SSL) ulaşabilirsiniz.)*
