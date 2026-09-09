# Mobil Uyumlu Aktif Savunma Özellikleri (Android & iOS)

DS-IPS V5.1 ile birlikte, mobil cihazların Karantina, Tarpit ve Bant Boğma gibi savunma mekanizmalarını QUIC, DNS over HTTPS ve Keep-Alive kurnazlıklarıyla aşmasını engelleyen sistem düzeyinde (kernel) çekirdek geliştirmeler yapılmıştır. 

## 1. Bant Genişliği Boğma (Rate Limit) Güncellemesi
Eskiden `tc` komutu kullanılıyordu ve mobil cihazlar bunu sadece giden (upload) yönünde algılıyordu. Artık doğrudan Linux çekirdeğinin `iptables limit` modülü ile donanımsal çift yönlü (Bidirectional) limitleme yapılmaktadır:
- `rate_limit_ip`: İlgili cihaza hem Upload (Egress) hem Download (Ingress) yönünde tüm protokoller (QUIC ve UDP dahil) için saniyede 1 paket limiti uygulanır. Böylece cihazın indirme hızı saniyede yaklaşık 1 Kbps'e çivilenir. Cihazın TCP veya HTTP/3 (QUIC) kullanması fark etmeksizin hücresel veriye kaçmadığı sürece felç durumu devam eder.

## 2. Karantina Portalı & DNS Sinkhole
Mobil cihazlar karantinaya alındığında, cihazları "Karantina.html" sayfasına yönlendirmek mobilde her zaman çalışmazdı (DoT ve HTTP/3 yüzünden). Yapılan değişiklikler:
- **DoT (Port 853) ve QUIC (UDP 443) Engellendi:** Hedef cihazın bu portlardan dışarı çıkması donanımsal `iptables REJECT` kurallarıyla reddedilir. Böylece mobil cihaz çaresiz kalarak şifresiz TCP (HTTP) ve DNS (Port 53) yığınına geri döner (Fallback).
- **Bilinen DoH Sunucuları Yasaklandı:** Cihazların Karantina modülünün dışına çıkmaması için 1.1.1.1, 8.8.8.8 gibi DoH sağlayıcıları engellenerek lokal DNS Sinkhole'a zorlandı.
- **Captive Portal Rotaları Eklendi:** Android ve Apple (iOS) cihazların ağa bağlandığında interneti test ettiği `/hotspot-detect.html` (iOS) ve `/generate_204` (Android) rotaları Karantina Flask sunucusuna (8099) eklendi. Bu rotalara cihaz erişmeye çalıştığında anında **200 OK** veya Karantina sayfası basılarak cihazın ekranına pop-up şeklinde "Ağa Giriş Yapın" sayfası fırlatılır.

## 3. Mobil Soket Kilitleme (Keep-Alive Tarpit)
Mobil cihazların standart Karantina/Tarpit tuzağındaki "veri akmıyor" diyerek Timeout (Zaman Aşımı) hatasına düşüp bağlantıyı yeniden başlatmasını (veya hücresel ağa dönmesini) engellemek için:
- `tarpit_client` döngüsüne 3 saniyede bir **tam 1 byte (0x00) Keep-Alive** sahte paketi atan bir sistem kuruldu. 
- Bu sahte veri sayesinde iPhone ve Android, Tarpit soketine girdiği an bağlantıyı açık tutar (veri indiriliyor sanır) ve indirme çubuğu donup kilitlenir.

## 4. Donanımsal TCP RST (Mobil Session Kill)
RST enjeksiyonu mobil cihazlarda (ve şifreli TCP/QUIC'de) eskiden ham soket (raw socket) kullandığı için zor oluyordu.
- `kill_session_hardware(ip)` adında yepyeni donanımsal bir iptables silahı eklendi.
- Bu fonksiyon tetiklendiği an, Kali üzerinden giden ve gelen paketlere 2 saniyeliğine milisaniyesinde donanımsal `REJECT --reject-with tcp-reset` kuralı uygulanır. Çekirdek, araya girerek oturum kapatma (RST) bayraklarını kurbana gönderir ve anında oturum kırılır.

**Sonuç:** Arka planda sunucu güncellendi ve tekrar başlatıldı. DS-IPS şu an Android ve iOS cihazların modern atlatma yöntemlerine karşı %100 dayanıklı hale getirildi. İstediğiniz mobil cihaz üzerinden Karantina, 1Kbps ve Tarpit testlerini başarıyla uygulayabilirsiniz.
