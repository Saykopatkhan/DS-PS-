# DS IPS v3.5 - Gelişmiş Özellikler ve Sistem Mimarisi (Whitepaper)

Bu belge, geliştirdiğimiz **DS IPS (Intrusion Prevention System - Saldırı Önleme Sistemi)** projesinin sahip olduğu tüm efsanevi özellikleri, yapay zeka destekli modüllerini ve güvenlik katmanlarını detaylı olarak açıklar. Sistemin modüler yapısı, onu sıradan bir izleme aracı olmaktan çıkarıp, aktif savunma yapan bir "Otonom Siber Ordu" seviyesine taşımaktadır.

---

## 1. 👁️ Çekirdek Sistem ve Ağ İzleme (Core & Monitoring)
Sistemin temeli, ağa körü körüne bakmak yerine ağı "anlamaya" dayanır.

*   **Gerçek Zamanlı Paket Analizi (Packet Sniffing):** Ağ arayüzü (`eth0` veya `wlan0`) üzerinden geçen tüm paketler yakalanır. Scapy kütüphanesi kullanılarak her paket saniyenin binde biri hızda analiz edilir.
*   **İnteraktif Ağ Haritası (Vis.js Dashboard):** Ağa bağlanan cihazlar (Node'lar) ve bu cihazların birbirleriyle olan ilişkileri (Edge'ler) dinamik bir fizik motoruyla ekranda çizilir. Cihazların üstüne tıklandığında IP, MAC ve Tehdit Skorları görülebilir.
*   **MAC ve Üretici (Vendor) Tespiti:** Ağa giren bir IP adresinin MAC adresini anında yakalar ve OUI veritabanını kullanarak cihazın markasını (Apple, Samsung, Cisco vb.) otomatik tespit edip ekrana yansıtır.
*   **Altın-Kırmızı Türk Bayrağı Teması:** Ana ekranda altın rengi hilal ve kırmızı yıldızdan oluşan, karanlık modla uyumlu dev bir silüet ve ortam (glow) ışıkları mevcuttur.

## 2. 🧱 Web Uygulama Güvenlik Duvarı (WAF & Login Security)
DS IPS paneline yönelik saldırıları bertaraf eden gelişmiş güvenlik kalkanı.

*   **OTP (Rastgele Şifre) Sistemi:** Sistem her başlatıldığında konsolda otomatik olarak 8 haneli rastgele bir şifre üretir. Sabit şifre (hardcoded password) zafiyeti yoktur.
*   **Bruteforce Kalkanı:** Login sayfasına ardışık 5 kez hatalı şifre denemesi yapan bir IP adresi, WAF tarafından anında 5 dakika boyunca kilitlenir (Ban).
*   **Method Tampering Engelleme:** Sadece okuma (GET) yetkisi olan sayfalara, arka kapı aramak için zararlı metotlarla (`PUT`, `DELETE`) istek atan saldırganlar anında izole edilir.

## 3. 🌶️ Anti-Capsaicin WAF (İleri Seviye Dizin ve Varlık Keşif Koruması)
ffuf, dirb ve yeni nesil "Capsaicin" gibi yapay zeka destekli web tarama araçlarına karşı agresif savunma yapar.

*   **Jitter ve Akıllı Kalibrasyon Sabotajı:** 404 (Bulunamadı) sayfalarının boyutlarını her istekte rastgele (0-50 satır arası gizli yorumla) değiştirerek, araçların otomatik boyut profillemesini (Auto-Calibration) kör eder.
*   **Shannon Entropi Tuzakları (Honeypot Tokens):** 404 sayfalarının kaynak kodunda, sahte AWS (`AKIA...`) ve Stripe API anahtarları üretip gizler. Akıllı tarayıcılar bu şifreleri bulduğunda yüksek entropili (kriptografik) oldukları için "Kritik Açık" sanır ve saldırganın verilerini çöpe çevirir.
*   **Zehirli Başlık (Header Injection) Tespit:** 403 sayfalarını atlatmak için kullanılan sahte `X-Forwarded-For` veya `X-Original-URL` başlıklarını taşıyan her cihaz anında ağdan kalıcı olarak banlanır.
*   **Dizin Tarama (Directory Bruteforce) Banı:** 10 saniye içinde 4'ten fazla 404 sayfasına (olmayan sayfaya) girmeye çalışan IP adresleri, otomatik dizin taraması yapıldığı gerekçesiyle tespit edilip engellenir.

## 4. 🥷 Kural Tabanlı Ağ Tespit Mekanizmaları
Ağdaki diğer cihazlara yapılan saldırıları saptayan dedektif modüllerimiz.

*   **ARP Zehirlenmesi (ARP Spoofing) Kalkanı:** Bir saldırgan (Örn: Bettercap) modemmiş gibi davranıp "Ortadaki Adam (MitM)" saldırısı yapmaya kalkarsa, sistem sahte MAC-IP eşleşmelerini milisaniyeler içinde yakalar.
*   **Derin Port Taraması (Port Scan) Dedektörü:** Nmap veya Zenmap gibi araçlarla ağınızda açık kapı (port) arayan bir cihaz, SYN, ACK, FIN paket dizilimleri analiz edilerek deşifre edilir.
*   **DNS Sinkhole (Kara Delik):** Cihazların hangi sitelere girmeye çalıştığını izler. Eğer bilinen bir zararlı yazılım sunucusuna veya yasadışı bir domaine DNS sorgusu gönderilirse, bu paketi işaretler.

## 5. 🕷️ Askeri Seviye Tuzaklar (Deception & Zero-Trust)
Saldırganı, içeri girdiği an pişman eden yanıltıcı savunmalar.

*   **Bubi Tuzakları (Honeytokens):** Sistemin Web Arayüzünün arkasında gizli duran sahte dosyalar (`/sirket_sifreleri.pdf` vb.) bulunur. Bir hacker bu dosyalara dokunduğu an tuzağa düşer ve sistem "Kritik Alarm" verir.
*   **Derin SSH Bal Küpü:** Ağda sahte bir 22 numaralı port (SSH sunucusu) açık bırakılır. Kaba kuvvet (Brute-Force) ile şifre kırmaya çalışan hacker, içeri girdiğini sanır ama sistem onun tüm denediği şifreleri size raporlar.
*   **Beyaz Gürültü Üretici (Decoy Traffic):** Ağı dinleyen bir hacker'ı kör etmek için etrafa rastgele sahte HTTP ve DNS paketleri saçar. Hacker sizin gerçek trafiğinizi göremez.

## 6. 👑 Otonom SOC ve Yapay Zeka Özellikleri (Premium SOC Modülü)
DS IPS'i tek başına bir "Güvenlik Operasyon Merkezi" (SOC) yapan özel arayüz.

*   **Otonom Zafiyet Tarayıcı (Vuln Scanner):** Sistem ağa yeni katılan cihazlara otomatik olarak Mini-Nmap taraması yapar. FTP, SSH, Telnet gibi zayıf portlar açıksa anında zafiyet listesine düşürür. Manuel "Tara" butonu da mevcuttur.
*   **UEBA (Davranışsal Analiz) Motoru:** Ağdaki cihazların normal davranışlarını öğrenir. Örneğin her gün sadece HTTP (80) kullanan bir cihaz, aniden SSH (22) bağlantısı yapmaya kalkarsa, kurala uymasa bile "Anormal Davranış" olarak raporlanır.
*   **Tehdit Radarı (Threat Radar):** SOC ekranında, ağınızda dolaşan IP'leri yeşil ve kırmızı noktalar olarak hareketli bir radar üzerinde gösterir.

## 7. 🔪 Siber Olay Yeri İnceleme & Kesin İnfaz (Isolation Engine)
Saldırı tespit edildikten sonra adaleti sağlayan devasa motor: **v5 Blocker**

*   **Otomatik PCAP Delil Toplayıcı:** Kritik seviyeli bir saldırı tespit edildiği an, sistem otomatik olarak `tcpdump` aracını tetikler. Saldırganın sonraki 60 saniyelik ağ trafiğini mahkemelik delil olarak `.pcap` uzantısıyla kaydeder.
*   **Üç Yönlü Gelişmiş İzolasyon Motoru:** Siz "Ağdan At (Ban)" dediğinizde:
  1. Iptables ile Layer 3/4 yönlendirmelerini (İnternet) keser.
  2. IPset entegrasyonuyla 10.000 IP bile banlansa sistem hızından ödün vermez.
  3. Scapy ARP Poisoning ile yerel ağ (LAN) iletişimini bozar. Saldırgan ne modeme gidebilir ne de sizin bilgisayarınıza erişebilir (Layer 2 Koruması).
*   **IP-MAC Eşitleme Hafızası:** İzolasyon motoru çok akıllıdır. Saldırgan IP'sini statik olarak değiştirse bile, MAC adresi üzerinden tespit edip zehirlemeye devam eder.

---
> [!IMPORTANT]
> **DS IPS Neden Farklıdır?**
> Klasik sistemler sadece sizin "istediğinizde" çalışan pasif araçlardır. **DS IPS ise 7/24 yaşayan, öğrenen, aktif tuzak kuran, WAF ile paneli koruyan ve tehlike anında saldırganı doğrudan imha eden otonom bir yapay zekadır.**
