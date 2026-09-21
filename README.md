# DS-IPS — Ağ Tespit ve Önleme Paneli

Python, Flask/Socket.IO, Scapy ve tshark tabanlı ağ izleme uygulaması. Web paneli; cihaz envanteri, alarm akışı, DNS/HTTP/TLS SNI gözlemleri ve elle yönetilen savunma işlemlerini bir araya getirir.

## Kurulum

Linux ve Python 3.12+ kullanın. Python bağımlılıkları sürümleri sabitlenmiş `requirements.txt` dosyasındadır; isteğe bağlı YARA ve Telegram yönetim botu ayrı tutulur.

```bash
./install.sh
cp config/env.example .env
.venv/bin/python web_main.py --mode ids --interface eth0
```

Panel: **http://127.0.0.1:5000**. Kullanıcı adı varsayılan olarak `admin`; parola belirtilmezse başlangıçta üretilip terminalde gösterilir. Sabit giriş bilgileri için `.env` içinde `DS_IPS_USER`, `DS_IPS_PASSWORD` ve uzun rastgele bir `DS_IPS_SECRET_KEY` tanımlayın.

Panelin açılması paket yakalamayı veya aktif savunmayı başlatmaz. İzlemeyi paneldeki **Başlat** düğmesiyle açın. Paket yakalama için sistemde **tshark, libpcap** ve uygun yakalama yetkileri gerekir. IPS işlemleri ayrıca **iptables, ipset, iproute2** ve root yetkisi kullanır; DHCP özelliği **dnsmasq** gerektirir. Bu sistem araçları Python kurulum betiği tarafından kurulmaz.

```bash
# IPS: gerçek ağ arayüzünüzü belirtin.
sudo .venv/bin/python web_main.py --mode ips --interface eth0

# Panel ile birlikte gerçek paket yakalama ve IPS servislerini başlatın.
sudo .venv/bin/python web_main.py --mode ips --interface eth0 --autostart

# Tespit çalışsın, engelleme ve aktif tarama yapılmasın.
.venv/bin/python web_main.py --mode ips --dry-run --interface eth0

# ARP keşfi için alt ağı açıkça seçin.
sudo .venv/bin/python web_main.py --interface eth0 --target 192.168.1.0/24

# İsteğe bağlı entegrasyonlar
.venv/bin/python -m pip install -r requirements-optional.txt
```

`any` yakalama arayüzü seçeneğidir; ARP keşfi, yönlendirme ve IPS için fiziksel ağ arayüzünü kullanın. Wi-Fi algılama uygun donanım ve monitor mode ister.

## Web arayüzü

Ana panel, giriş ekranı ve SOC analiz sayfası ortak bir tasarım sistemi kullanır. Mobil yan menü, klavye ile yönetilebilen pencereler, canlı alarm filtreleri ve yerel coğrafi harita dahildir. İşletim sisteminin hareketi azaltma tercihi desteklenir.

[Lenis 1.3.26](https://github.com/darkroomengineering/lenis) sayfa kaydırmasını, [Anime.js 4.5.0](https://animejs.com/documentation/) bölüm geçişlerini ve bildirim animasyonlarını yönetir. Sürümleri sabitlenmiş dosyalar ve lisansları `web/static/vendor/` içinde bulunur; paneli çalıştırmak için Node.js veya CDN bağlantısı gerekmez. IP konumu sorguları sunucu üzerinden harici GeoIP hizmetini kullanmaya devam eder.

Frontend bağımlılıklarını yeniden hazırlamak veya geliştirme kontrollerini çalıştırmak için:

```bash
npm ci --ignore-scripts
npm run vendor
npm run check
npm run format:check
```

Tarayıcı regresyonu, Playwright ve Chromium kurulu geliştirme ortamında çalışır. Geçici veritabanı kullanır; paket yakalama veya aktif savunma başlatmaz:

```bash
PYTHONPATH=. .venv/bin/python tests/browser_smoke.py
# İsteğe bağlı masaüstü/mobil ekran görüntüleri:
DS_IPS_SCREENSHOTS=/tmp/dsips-ui PYTHONPATH=. .venv/bin/python tests/browser_smoke.py
```

## Çalışma modları

- **IDS:** algılama yapar; otomatik ARP iyileştirme, DNS sahte yanıtı ve engelleme uygulamaz. Elle başlatılan keşif/port taraması aktif trafik üretir.
- **IPS:** izleme başlatıldığında engelleme motoru ve tuzak servislerini de açar. Algılama kuralları, yerleşim ve beyaz liste ağınıza göre değerlendirilmelidir.
- **Dry-run:** aktif savunma ve aktif tarama kapalıdır; engelleme başarısı veya gerçek ban kaydı üretmez.

DNS gözlemleri sorgu ve yanıt ayrımı yapar. SNI ayrıştırması tek paketteki tam TLS ClientHello üzerinde çalışır; parçalanmış TCP akışını birleştirmez ve ECH/şifreli DNS içeriğini çözmez. Açık port taraması bir servisin erişilebilir olduğunu gösterir; zafiyet bulunduğuna tek başına kanıt oluşturmaz.

## Üretim sunucusu

```bash
./start_prod.sh
```

Başlatıcı, tek süreçte 20 thread kullanan Gunicorn sunucusunu açar. Varsayılan adres `127.0.0.1:5000`, varsayılan mod IDS'dir. `.env` içindeki `DS_IPS_BIND`, `DS_IPS_INTERFACE`, `DS_IPS_MODE`, `DS_IPS_DB` ve diğer seçenekler `config/env.example` içinde açıklanır. Sensörler, oturumlar ve ağ kuralları süreç içinde tutulduğu için worker sayısını artırmayın ve `--preload` kullanmayın.

Nginx HTTPS kurulumu için var olan sertifika/anahtarı kullanın:

```bash
sudo env DSIPS_SERVER_NAME=soc.example.org \
  DSIPS_TLS_CERT=/etc/letsencrypt/live/soc.example.org/fullchain.pem \
  DSIPS_TLS_KEY=/etc/letsencrypt/live/soc.example.org/privkey.pem \
  ./setup_nginx.sh
```

Bu kurulumda `.env` için `DS_IPS_TRUST_PROXY=true` ve `DS_IPS_COOKIE_SECURE=true` ayarlayın; backend loopback adresinde kalsın. Doğrudan yerel HTTP kullanımında iki seçenek de `false` olmalıdır. Nginx betiği mevcut diğer siteleri silmez, yapılandırma doğrulaması başarısız olursa önceki dosyayı geri yükler.

`dsips.service` dosyası `/opt/ds-ips` kurulumu için örnektir. Dosya yollarını kurulumunuza göre düzenleyip servis olarak yükleyin. Kurulum ve başlatma betikleri `systemd-resolved` servisini durdurmaz veya kendiliğinden IP forwarding açmaz. Gateway işlemi kendi eklediği kuralları ve önceki forwarding değerini izler.

## Oturumlar ve veri

Giriş, API değişiklikleri ve çıkış CSRF doğrulaması kullanır. Socket.IO bağlantısı aynı etkin oturuma bağlıdır; çıkış bağlantıyı ve oturumu geçersizleştirir. HTTPS ters proxyde sonlandırılır. PCAP kayıtları statik dizinden sunulmaz; indirme yetkili API üzerinden yapılır.

HIDS, geliştirme ve üretim giriş noktalarında ortak yaşam döngüsüyle çalışır. `DS_IPS_HIDS=false` ile kapatılabilir. Telegram yönetim botu için isteğe bağlı bağımlılıkları kurup `DS_IPS_TELEGRAM=true`, `BOT_TOKEN` ve `CHAT_ID` tanımlayın. Bot komutları yapılandırılmış sohbetle sınırlıdır.

## Doğrulama

```bash
.venv/bin/python -m pip install -r requirements-dev.txt -r requirements-optional.txt
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
node --check web/static/app.js
node --check web/static/security.js
bash -n install.sh start_prod.sh setup_nginx.sh
```

`tests/` altındaki regresyonlar sentetik paketler, geçici veritabanları ve taklit ağ işlemleri kullanır. Otomatik testler ağa saldırı paketi göndermez ve gerçek güvenlik duvarını değiştirmez. `ds_ips_auditor.py` ve `ds_ips_qa_suite.py` ise elle kullanılan aktif laboratuvar araçlarıdır; bağlantı hataları veya paket gönderimi, tespitin doğrulandığı anlamına gelmez.

Tarayıcı kontrolü için Playwright ve Chromium kurulu olmalıdır:

```bash
.venv/bin/python -m pip install playwright
PYTHONPATH=. .venv/bin/python tests/browser_smoke.py
```

Bu kontrol geçici veritabanıyla giriş, Socket.IO, güvenilmeyen metin gösterimi, ayarlar, Premium panel ve çıkışı doğrular. Chromium yolu varsayılan olarak `/usr/bin/chromium` kullanılır.

Denetim kapsamı ve doğrulama sonuçları: [Teknik denetim raporu](docs/TEKNIK_DENETIM.md). Eski sürüm sunumları ve özellik metinleri tarihsel belgelerdir; güncel kurulum ve davranış için bu dosyayı esas alın.

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
