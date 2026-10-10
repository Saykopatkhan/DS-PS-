# Güvenilir tespit ve kontrollü müdahale

Tarih: 9 Ekim 2026

Bu inceleme mevcut Python algılayıcılarını, paket yakalama hattını, engelleme
motorunu, SQLite kayıtlarını, web yönetimini ve servis yaşam döngüsünü kapsar.
Değişiklikler yerel sentetik veriler ve taklit güvenlik duvarı çağrılarıyla
doğrulanır. Gerçek ağda saldırı, tarama veya engelleme uygulanmamıştır.

## Düzeltilen davranışlar

| Alan | Önceki sorun | Yeni davranış |
| --- | --- | --- |
| Port taraması | Farklı hedeflerin portları birleştiriliyor, bazı UDP cevapları tarama sayılıyordu. | Kaynak/hedef çiftine ait kayan pencere, farklı port sayımı ve gözlenen UDP ters akış korelasyonu kullanılır. |
| Hız algılama | Trafik hacmi tek başına doğrudan ban üretiyordu. | FastSniffer hedef bazında sayar; SYN tekrarlarını ayırır, ICMP cevaplarını echo saldırısı saymaz. Hız gözlemi danışma niteliğindedir. |
| DNS | Tek uzun etiket kritik veri sızdırma alarmı üretebiliyordu. | Aynı hedef ad grubu için çeşitli uzun ve yüksek entropili sorgular birikmeden tünelleme alarmı oluşmaz. |
| C2 | ACK/veri paketleri bağlantı periyodu sayılıyor; genel IP/port istisnaları görünürlüğü azaltıyordu. | TCP başlangıçları ve farklı UDP akış gözlemleri değerlendirilir; periyodiklik tek başına kesin C2 veya ban değildir. |
| ARP/MAC | Öğrenilmiş bir eşleşmenin değişmesi, iddia edilen mağdur IP'nin engellenmesine veya doğrulanmamış iyileştirmeye yol açabiliyordu. | Değişim gözlem olarak kalır; sıradan LAN başlangıcı ve farklı cihazların MAC adresleri tek başına sahtecilik sayılmaz. |
| DHCP | Tekrar iletilen aynı işlem saldırı sayımını artırıyor; röle ve atanmış IP ayrımı bozulabiliyordu. | İşlem çeşitliliği ve gerçek sunucu kimliği dikkate alınır; atanmış IP'si olmayan istemci ortak `N/A` kaydına yazılmaz. |
| DPI/HTTP | Normal yanıt ve belge içeriğindeki kelimeler zararlı yük sayılabiliyordu. | Genel kelime eşleşmeleri daraltıldı; HTTP istek/yanıt yönü ve tekrarlar ayrıldı. Dizin taraması için farklı yolların ilişkili 404 cevapları aranır. |
| UEBA/Wi-Fi | Tek akışın paketleri öğrenmeyi tüketiyor, aynı SSID'li meşru erişim noktaları Evil Twin sayılabiliyordu. | Akış tekrarları bastırılır; AP kimliği kararı açıkça sağlanan güvenilir BSSID envanterine bağlıdır. |
| HIDS | Bağlantı kapanışı başarısız parola sayılıyor; kullanıcı adındaki IP kaynak sanılabiliyordu. | Gerçek sshd parola başarısızlığı kaydı ayrıştırılır; IPv6 desteklenir. Sayaçlar sınırlıdır, tekrarlı alarmların bekleme süresi vardır. |
| HIDS imzaları | `/docs/curl` gibi normal yollar ve URL içindeki tarayıcı adları alarm üretebiliyordu. | Komut bağlamı ve SQL kelime sınırları daraltıldı; tarayıcı imzası User-Agent alanında aranır. |
| IP/MAC engeli | IP kararı yönlendiriciye ait ortak MAC'i de engelliyor; IP unban başka MAC yasağını kaldırabiliyordu. | Yeni IP ve MAC yasakları ayrı kapsamda uygulanır; eski birleşik kayıtların ortak referansları korunur. |
| İzin listesi | Bir bozuk kayıt sonraki geçerli kayıtları düşürüyor; CIDR desteklenmiyordu. | Geçerli girdiler korunur; tek IP ve CIDR desteklenir. |
| Süre ve hata yönetimi | Eski kayıtlar yeniden başlatmada uzayabiliyor; eski ban yeni banı pasifleştirebiliyordu. | UTC süreleri ve eski kayıt zamanı kullanılır; kayıt kimliği bazında temizlik, geri alma ve tekrar denenebilir başarısız temizlik eklenmiştir. |
| Hız sınırlaması | `ACCEPT` kuralı sonraki güvenlik duvarı politikasını atlatabiliyordu. | Yalnızca sınırı aşan trafik düşürülür; diğer trafik mevcut kurallara devam eder. |
| Web işlemleri | Eksik unban veya kısmen başarılı birleşik ban tamamen başarılı/başarısız gibi gösterilebiliyordu. | Uygulanan ve kalan işlemler bildirilir; başarısız temizlik kaydı silinmez. |
| Canary ve tuzaklar | Basit erişim doğrulanmış sızma gibi sunuluyor; aynı olay iki Socket.IO alarmı oluşturabiliyordu. | Canary erişimi doğrulanmamış gözlem olarak sınırlanır; tuzak alarmı tek kanaldan geçer. Kurulmuş bağlantı, gerçek sistemde sızma kanıtı olarak sunulmaz. |
| PCAP | Dosya izinleri umask'a bağlıydı; yarım yazılan dosya kalabiliyordu. | PCAP, `0600` izinli geçici dosyaya yazılıp atomik yayımlanır. Yeni kanıt dizini `0700` olur. |
| Servis sağlığı | Arka plan okuyucu veya Telegram hatası başlangıç başarısı gibi görünebiliyordu. | Hazır olma, okuyucu sağlık durumu ve başarısız başlangıç görünürdür. Eksik isteğe bağlı log web uygulamasını kapatmaz. |
| Eşzamanlı kapanış | Kuyrukta bekleyen engelleme, kapanış temizliğinden sonra kural ekleyebiliyordu. | IP/MAC engeli ve hız sınırı, kilit alındıktan sonra çalışma durumunu yeniden doğrular. |

## Yeni olay değerlendirmesi

`core/response_policy.py` aynı kaynak IP için ilk gözlemden başlayan **300
saniyelik sabit pencere** kullanır. Aynı ailenin tekrar sayısı saklanır; ağırlığı
bir kez hesaba katılır. Pencere bittiğinde sonraki gözlem yeni olay açar.

| Bulgu ailesi | En yüksek katkı |
| --- | ---: |
| SSH kimlik doğrulama hataları | 50 |
| Kaynağı yerel bağlantıyla doğrulanmış tuzak erişimi | 35 |
| Doğrulanmamış tuzak portu SYN gözlemi | 10 |
| Uygulama içeriği | 25 |
| Tehdit istihbaratı | 25 |
| Tarama | 20 |
| DNS anomalisi | 15 |
| Davranış/periyodiklik | 15 |
| Trafik hızı | 10 |
| ARP/DHCP/MAC iddiaları, coğrafya, uygulamanın kendi port envanteri | 0 |

Toplam en fazla 100'dür. Bu puan bir olasılık veya kesin saldırı derecesi
değildir. Eski cihaz tehdit skoru geçmiş alarm göstergesidir; yeni otomatik
müdahale kararı ona dayanmaz.

Otomatik engelleme tüm koşulları gerektirir:

1. `DS_IPS_AUTO_RESPONSE=true`, IPS modu, çalışan izleme ve kapalı dry-run.
2. Aynı pencerede en az iki pozitif katkılı bulgu ailesi ve en az 80 puan.
3. Gerçek yerel sshd parola başarısızlığı kaydı veya kurulmuş tuzak bağlantısı
   üzerinden en az bir kaynak doğrulaması. Salt paket IP başlığı yeterli değildir.
4. Hedefin altyapı/izin listesi koruması dışında olması ve IPv4 olması.

Uygulanan işlem `Blocker.block_ip(..., severity='high')` ile süreli IP engelidir.
Süre, engelleme motorunun `block_high` ayarına bağlıdır. Tek bir hızlı trafik
alarmı veya aynı alarmın yüzlerce tekrarı bu koşulları sağlamaz.

Olaylar ve eylemler SQLite'ta tutulur. Güvenlik duvarı çağrısından önce `pending`
kaydı kalıcılaştırılır. Sonuç `blocked` veya `failed` olur. Bir olayda tekrar
alarmı, başarısız eylemi her paket için yeniden denetmez; süreç yeniden
başlatıldığında aynı eylem tekrar uygulanmaz. `pending`, işlem sırasında
kesinti olduğunu ve mevcut firewall durumunun operatörce doğrulanması
gerektiğini ifade eder. Geçmişteki `blocked` kaydı mevcut banın hâlâ aktif
olduğunu garanti etmez; güncel yasaklar ayrı ban listesindedir.

## Kullanım

Varsayılan `.env` ayarı değerlendirme yapar:

```dotenv
DS_IPS_AUTO_RESPONSE=false
```

Savunma yönetimindeki olay tablosunda gerçek ağın normal davranışı incelendikten
ve `/etc/dsips/config.json` içindeki `whitelisted_ips` yönetim adresleriyle
doldurulduktan sonra otomatik yanıt açılabilir. Örneğin tek bir yönetim IP'si
veya yönetim ağı CIDR'si eklenebilir. Geniş bir istemci ağını koruma listesine
almak, o ağdaki gerçek tehditlere otomatik IP engelini de engeller.

Panel ve API'ler kimlik doğrulaması gerektirir:

- `/api/incidents?limit=20`: bulgular, puan, durum ve gerekçe.
- `/api/response-policy`: etkin politika ve koşulları.
- `/api/service-health`: servis/okuyucu durumları; özel hata metinleri yayınlanmaz.

IPS başlangıcında veya alarm sonrasında üçüncü taraf kaynağa otomatik geri
port taraması bağlanmaz. Mevcut elle başlatılan yönetim işlemleri ayrı kalır.

## Doğrulama ve sınırlar

9 Ekim 2026 radar/cihaz haritası düzeltmeleriyle son doğrulama:

- Python 3.14.7: **209 test geçti**, atlanan/başarısız test yok. Gerçek Gunicorn
  başlangıcı, yetkili API ve temiz kapanış testi bu sayıya dahildir.
- Gerçek Chromium/Playwright: giriş, Socket.IO, olay tablosu, güvenilmeyen
  metin gösterimi, ayarlar, mobil yerleşim, klavye pencereleri ve çıkış geçti.
- 100 cihazın ölçülen kutularının çakışmadığı; normal/azaltılmış hareket,
  masaüstü/mobil yerleşim, yenilemede konum korunması, silinen cihazların
  temizlenmesi, radar sekmesine dönüş ve gerçek Socket.IO olayının görünmesi
  tarayıcıda doğrulandı. Başlangıçtaki harita/veri yarışı ve MAC bazlı cihaz
  kaybı giderildi. Yakalama durumunda durmuş/kısmi backend ayrımı eklendi.
- Ruff, JavaScript sözdizimi, Prettier, Bash sözdizimi, `git diff --check` ve
  `pip check` geçti.
- Scapy'nin TLS yardımcı modülünden bir cryptography kullanım dışı kalma
  uyarısı geldi; test başarısızlığı değildir. Python 3.12/3.13 ve uzak CI bu
  çalışma sırasında yeniden çalıştırılmadı.

Regresyonlar; meşru DNS/HTTP trafiği, bağlantı tekrarları, gerçek eşik aşımı,
IPv6 SSH kayıtları, korunan adresler, IDS/dry-run, başarısız firewall, paralel
olaylar, yeniden başlatma ve okuyucu hatalarını kapsar. Testler gerçek ağda
saldırı paketi göndermez. Tarayıcı kontrolü geçici veritabanı ve loopback paneli
kullanır; gerçek paket yakalamayı veya savunma servislerini başlatmaz.

Bu değişiklikler yanlış pozitifleri tamamen ortadan kaldırmaz veya sisteme
sızmanın önleneceğini garanti etmez. NAT arkasında ortak kaynak IP, yetkili
tarayıcılar ve yoğun meşru istemciler için yerel eşik/izin listesi değerlendirmesi
gerekir. DNS hedef gruplaması tam Public Suffix List çözümü değildir.

TCP akış birleştirmesi, TLS/ECH ve şifreli DNS çözümü yoktur. Asimetrik yakalama
UDP/HTTP korelasyonunu sınırlar. Wi-Fi doğrulaması için
`WiFiDetector.trusted_bssids` envanteri programatik olarak sağlanmalıdır;
bu envanteri düzenleyen bir panel/ayar ekranı eklenmemiştir. Otomatik firewall
yanıtı IPv4 ile sınırlıdır.

Eski süreçten kalan rate-limit/tarpit kurallarının tamamı çöküş sonrası yeniden
kurulmaz veya uzlaştırılmaz. Sürüm geçişinden önce eski servisin temiz kapanışı
ve sahip olduğu kuralların kontrolü gerekir. Özellikle eski `dsips-rate ACCEPT`
kuralları, önceki süreç düzgün kapanmadıysa çekirdekte kalmış olabilir.
Gerçek iptables/ipset davranışı ve ağ topolojisi ayrı laboratuvar kabul testi
gerektirir. SQLite olay/alarm geçmişi için disk saklama politikası işletim
ortamında ayrıca planlanmalıdır.
