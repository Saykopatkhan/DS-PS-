# 🚀 DS-IPS v3.0 (Premium SOC Edition) - Major Update

DS-IPS projesinin **v3.0** sürümü, bir Ağ İhlal Tespit Sistemini (IDS) gerçek bir **Aktif Savunma ve Siber Operasyon Merkezine (SOC)** dönüştüren devrim niteliğinde özellikler içermektedir.

Bu sürümle birlikte sistem sadece saldırıları izlemekle kalmaz; şifreli trafiğin derinlerine iner, ağdaki anormalliklere otonom olarak müdahale eder ve görsel/işitsel bir SOC deneyimi sunar.

## 🔥 v3.0 ile Gelen Yeni Özellikler

### 1. 📡 Canlı Siber Radar (Cyber Radar Overlay)
Dashboard üzerine entegre edilen tam donanımlı askeri sınıf radar sistemi.
* Sistem kritik bir tehdit (Örn: Rusya tabanlı C2 bağlantısı) algıladığında, radar üzerinde kırmızı parlayan bir hedef (Blip) belirir.
* Tehdidin IP adresi ve kaynağı radar ekranında 20 saniye boyunca görsel olarak raporlanır ve ardından kaybolur.

### 2. 👁️ Derin Paket İnceleme (DPI) ile SNI ve HTTP Gözetleme
Kullanıcıların DNS Önbelleği (Cache) veya Güvenli DNS (DoH - DNS over HTTPS) kullanarak izlenmekten kaçmasını imkansız kılan yeni DPI motoru.
* İnternete çıkan şifreli **HTTPS (TLS Handshake - Client Hello)** paketlerinin içine girerek **SNI (Server Name Indication)** verilerini cımbızla çeker.
* Şifresiz HTTP trafiklerindeki **Host Header** verilerini okur.
* Bu sayede "Ağ Gözetleme (Traffic Monitor)" ekranında şifreli/şifresiz tüm domainler saniyesi saniyesine canlı olarak akar.

### 3. 📊 Gelişmiş Risk ve Alarm Grafiği (Interactive Doughnut)
Arayüzdeki karmaşık log yığınlarını profesyonel SOC standartlarına getiren yeni grafik motoru.
* Alarmlar isimlerine göre değil, **Risk Seviyelerine (Severity)** göre 4 ana kategoride (Kritik🔴, Yüksek🟡, Orta🔵, Düşük🔘) toplanır.
* Fare (Mouse) ile grafikteki dilimlerin üzerine gelindiğinde, o risk grubunun içindeki saldırıların (Örn: %50 C2 Beaconing, %30 Ağ Taraması) **yüzdelik kırılımlarını gösteren detaylı Tooltip** menüleri açılır.

### 4. 🎧 Akıllı Ses/Alarm Yönetimi (Audio Debounce)
Özellikle DNS Flood, SYN Flood veya seri C2 Beaconing saldırılarında üst üste binen robot seslerinin yarattığı gürültü kirliliğini (Cacophony) önleyen algoritma.
* Sisteme 4 saniyelik global bir **Cooldown (Bekleme)** süresi eklendi.
* 1 saniye içinde 100 saldırı gelse bile, sistem sadece 1. alarmı sesli okur ve diğerlerini "yutarak" Analistin odaklanmasını sağlar. Görsel loglar akmaya devam eder.

---

## 🚀 Gelecek Planları (Future Works - v4.0 Vizyonu)

DS-IPS, sürekli gelişen bir siber savunma kalkanı olarak tasarlanmıştır. Projenin gelecek sürümlerinde (v4.0) şu kurumsal SOC seviyesi özelliklerin eklenmesi planlanmaktadır:

* **🧠 Yapay Zeka (AI) ve Makine Öğrenimi (ML):** Sistemin sadece "kurallara" (Rule-based) göre değil, ağdaki kullanıcıların normal davranış modellerini öğrenerek (UEBA) hiç bilinmeyen (Zero-Day) anormallikleri saptaması.
* **🚧 Karantina Ağı (VLAN İzolasyonu):** Sadece yerel güvenlik duvarı (iptables) ile değil, kurumsal Switch'lerle (Cisco, Aruba vb.) 802.1x veya SNMP üzerinden haberleşip saldırganın fiziksel ağ kablosunu Karantina VLAN'ına atma yeteneği.
* **🕷️ Otonom Zafiyet Taraması:** Ağa katılan her yeni cihazı (Misafir Telefonu, Akıllı TV) otomatik ve sessizce tarayıp, sistem yöneticisine cihazdaki potansiyel açıkları (Açık SSH, Telnet) raporlaması.
* **🌍 Merkezi Bulut SIEM (ELK Stack):** Sistemi dağıtık (Distributed) sensörler halinde şirket şubelerine kurup, tüm saldırı verilerini ElasticSearch & Kibana üzerinde toplayan merkezi bir mimariye geçiş.
* **🔓 SSL/TLS Decryption (Tam Şifre Çözme):** Sadece SNI (Domain) bilgilerini okumakla kalmayıp, uç noktalara (Endpoint) kurulacak bir Root sertifikasıyla HTTPS trafiğinin içeriğini çözüp derin inceleme yapılması.

---

**🎓 Geliştirici:** Kadir Kırmacı
**📅 Sürüm:** v3.0
**🔒 Lisans:** MIT / Eğitim Amaçlıdır
