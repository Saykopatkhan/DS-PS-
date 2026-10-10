# Teknik denetim ve düzeltme raporu

Tarih: 19 Eylül 2026

Denetim; Python giriş noktaları, web API'leri, tarayıcı kodu, SQLite katmanı,
paket algılama modülleri, ağ müdahale bileşenleri, bildirimler ve kurulum
betikleri üzerinde yürütüldü. Bulgular çalışma ağını değiştirmeden, geçici
veritabanları ve taklit sistem çağrılarıyla doğrulandı.

## Düzeltilen başlıca sorunlar

| Alan | Bulgu ve düzeltme |
| --- | --- |
| Giriş ve oturum | Gerçek CSRF belirteci eklendi. Giriş, API değişiklikleri ve POST çıkışı doğrulanıyor. Oturumlar sunucudan geçersizleştirilebiliyor; başarısız girişler HTTP 429 ile sınırlandırılıyor. |
| Socket.IO | Uygulama genelindeki tek belirteç yerine etkin kullanıcı oturumu ve oturuma özgü belirteç gerekiyor. Çıkışta ve süre dolumunda bağlantılar kapatılıyor. |
| PCAP | Kimlik doğrulaması olmayan statik dosya yolundan paket kayıtlarına erişim kaldırıldı. Yeni kayıtlar veri dizininde, indirmeler yetkili API'de. |
| API ve XSS | JSON şekli, IP/MAC, sayısal sınırlar, arayüz adı ve alan adı listeleri doğrulanıyor. Alarm, cihaz ve rapor metinleri HTML'e güvenli aktarılıyor. |
| Ters proxy | Meşru proxy başlıklarını saldırı kabul eden kontrol kaldırıldı. Proxy güveni açık yapılandırma gerektiriyor. Secure cookie ve proxy seçenekleri `true`/`false` değerlerini doğru okuyor. |
| Başlangıç ve kapanış | Nesne oluştururken tarpit, DNS ve honeypot dinleyicileri başlamıyor. İzleme ve arka plan servislerinin açık başlangıç/kapanış yaşam döngüsü var. HIDS/Telegram veritabanından önce durduruluyor. |
| IDS / dry-run | Pasif tespitte DNS yanıtı veya ARP iyileştirme paketi gönderilmesi engellendi. Dry-run MAC/IP engellemesi ve aktif tarama yapmıyor; uygulanmayan banlar gerçek ban olarak kaydedilmiyor. |
| Engelleme motoru | İç içe kilitlenme düzeltildi. IP/MAC doğrulaması, güvenlik duvarı sonuç kontrolü, başarısız işlem geri alma ve süreli MAC/IP temizliği iyileştirildi. |
| Savunmayı temizleme | Kayıtların ağ kuralları kaldırılmadan silinmesi düzeltildi. Başarısız kaldırmalarda ilgili kayıt korunuyor. Üretici thread'ler temizlikten önce durduruluyor. |
| Gateway / DHCP | Yalnızca bileşenin eklediği kurallar kaldırılıyor; önceki IP forwarding değeri geri yükleniyor. DHCP geçici dosyaları, süreç sahipliği ve gerçek alt ağa uygun adres havuzu düzeltildi. |
| Paket yakalama | Tshark EK alanları doğru okunuyor. Kapanış ve süreç/thread yönetimi iyileştirildi. Sıradan uzak SMB/HTTP bağlantıları honeypot olarak sınıflandırılmıyor; tekrarlı flood alarmları sınırlandırılıyor. |
| DNS / TLS | Sorgu-yanıt ayrımı, alan adı sınırlarına göre liste eşleşmesi, geçerli DNS soru tipleri ve sınırlı TLS ClientHello ayrıştırması eklendi. Kısa/bozuk DNS paketinin dinleyiciyi düşürmesi düzeltildi. Örnek alan adları gerçek tehdit göstergesi olarak otomatik yüklenmiyor. |
| C2 / UEBA | Başlangıcı çökerten CIDR ve yerel ağ kaynaklarını dışlayan koşul düzeltildi. UEBA, TCP veri paketlerini yeni bağlantı sayarak öğrenme süresini tüketmiyor. |
| HIDS | Normal tarayıcı User-Agent noktalamasından üretilen komut enjeksiyonu yanlış alarmı giderildi. URL kodlaması çözülüyor; log takip alt süreçleri kapanışta toplanıyor. |
| Kaynak kullanımı | Birçok izleme tablosuna sınır/temizlik eklendi. Port taramaları, SSH tuzağı ve bildirim thread'lerinin eşzamanlılığı sınırlandırıldı. |
| Veritabanı | Kısmen eski şemaların sütun bazında yükseltilmesi, callback'lerin kilit dışında çağrılması, doğru alarm kimliği/sıralaması, UTC zaman karşılaştırmaları ve ban geçmişi güncellemesi düzeltildi. |
| Telegram | Yönetim düğmeleri yapılandırılmış sohbetle sınırlı. Asenkron olay döngüsü polling başlatıldıktan sonra yaşamaya devam ediyor. |
| Web arayüzü | Risk grafiğinin eksik kurulumu ve tekrar başlatılan ağ haritası düzeltildi. Cihaz API uyumsuzluğu, eksik DHCP işlevi, aktif savunma yanıt biçimi ve yeni port tarama sonuçlarının listelenmesi düzeltildi. |
| PDF / konsol | Unicode metinlerden PDF üretirken çökme ve en eski satırların seçilmesi düzeltildi. Yerleşik PDF fontunda Türkçe harfler sadeleştiriliyor. Konsolun olmayan veritabanı metodu/sütunu kullanması giderildi. |
| Kurulum / üretim | Eksik bağımlılıklar tamamlandı; temel bağımlılıklar sabitlendi. Kurulum sanal ortam kullanıyor. Üretim giriş noktası tek threaded Gunicorn worker çalıştırıyor; sabit kullanıcı dizini ve zorunlu `wlan0` kaldırıldı. |
| Nginx | HTTPS şablonu, WebSocket proxy ayarları ve yapılandırma hatasında geri dönüş eklendi. Diğer siteler silinmiyor; sistem DNS servisi durdurulmuyor. |
| Laboratuvar araçları | Paket gönderimi ve zaman aşımının otomatik başarı sayılması düzeltildi. Giriş hız sınırı testi geçerli CSRF oturumuyla HTTP 429 arıyor; CSRF 403 yanıtını ban olarak kabul etmiyor. |

## Doğrulama

- Python 3.12: 78 otomatik regresyon testi geçti.
- Python 3.14: aynı 78 otomatik regresyon testi geçti.
- Gerçek Chromium: giriş, Socket.IO bağlantısı, güvenilmeyen cihaz/alarm metni,
  ayar kaydı, Premium panel ve çıkış akışları JavaScript hatası olmadan geçti.
- Gerçek Gunicorn: geçici veritabanıyla açılış, giriş, yetkili/yetkisiz API,
  Engine.IO el sıkışması ve düzgün kapanış doğrulandı.
- Ruff (`E9` ve tüm `F` kuralları), JavaScript sözdizimi, Bash sözdizimi ve
  `git diff --check` kontrolleri geçti.
- Sabitlenmiş temel bağımlılıklarda `pip-audit` bilinen açık bildirmedi.
  Paramiko 4.0.0 bulgusunun ardından 5.0.0'a yükseltildi.
- Python 3.12/3.13/3.14 matrisi için CI yapılandırması eklendi; uzak CI bu
  çalışma sırasında çalıştırılmadı.

Yeni testler `tests/` dizinindedir. Önceki dört kök dizin test dosyası, import
sırasında çalışan örnekler veya doğrulama yapmayan denemelerdi; bunların yerine
izole regresyonlar kondu. Önceki dosyalar Git geçmişinden geri alınabilir.

## Doğrulamanın sınırları

Gerçek ağa ARP/DNS yanıtı, saldırı trafiği veya güvenlik duvarı kuralı
uygulanmadı. Donanım, monitor mode, yönlendirme topolojisi, dağıtıma özgü
iptables/nftables davranışı ve gerçek TLS sertifikalı Nginx kurulumu ayrı bir
laboratuvar kabul testi gerektirir. Mock testleri bu çevresel koşulların
yerine geçmez.

SNI ayrıştırması TCP yeniden birleştirmesi/ECH çözme sağlamaz. Açık portlar
zafiyet kanıtı değildir. Algılama kuralları yanlış pozitif/negatif verebilir;
bu inceleme tüm olası kusurların veya saldırıların ortadan kalktığı garantisi
değildir. Scapy'nin Cryptography FFDH API'sine ilişkin üçüncü taraf
deprecation uyarısı vardır; test başarısını etkilemez.

## İlgili birincil kaynaklar

Threaded Gunicorn ve tek worker seçimi:
[Flask-SocketIO dağıtım belgesi](https://flask-socketio.readthedocs.io/en/stable/deployment.html).

SSH bağımlılığı incelemesi:
[Paramiko sürümleri](https://pypi.org/project/paramiko/) ve
[SHA-1 RSA desteğini kaldıran upstream değişiklik](https://github.com/paramiko/paramiko/commit/a448945).
