# DS IPS - Proje Sunum Metni ve Rehberi

Bu rehber, projenizi jüriye, yöneticilere veya bir izleyici kitlesine sunarken kullanabileceğiniz en etkili anlatım sırasını ve konuşma metinlerini içerir.

---

## 1. Giriş ve İddialı Başlangıç (Kanca)
*Burada izleyicinin dikkatini çekmek için projenin sıradan bir yazılım olmadığını vurguluyoruz.*

**Sizin Konuşmanız:**
> "Herkese merhaba. Bugün sizlere sadece ağ trafiğini izleyen sıradan bir program değil; kendi istihbaratını üreten, tuzaklar kuran ve bir askeri üs mantığıyla çalışan **DS IPS (Intrusion Prevention System - Saldırı Önleme Sistemi)** projesini sunacağım. 
> Klasik güvenlik sistemleri saldırganı içeri girdikten sonra bulmaya çalışır. Bizim sistemimiz ise **Zero-Trust (Sıfır Güven)** prensibiyle çalışarak; ağın içine tuzaklar, sahte sistemler ve kör edici beyaz gürültüler yerleştirerek saldırganı daha ilk adımında avlamak üzere tasarlandı."

## 2. Projenin 3 Temel Gücü (Mimari)
*Burada çok fazla koda boğulmadan, projenin en havalı 3 özelliğini basit bir dille anlatıyoruz.*

**Sizin Konuşmanız:**
> "Projemizin kalbinde şu 3 devasa güvenlik katmanı yatıyor:
> 
> **Birincisi, Etkileşimli Gerçek Zamanlı Dashboard:** Ağımızdaki tüm cihazları, onlara gelen saldırıları ve MAC adreslerini saniyeler içinde ekrandaki dinamik haritada (Node yapısı) görebiliyoruz. Tespit edilen her tehdit, şık bir arayüzde önümüze düşüyor.
> 
> **İkincisi, Akıllı İstihbarat (Geo-IP) Modülü:** Ağımızdaki bir bilgisayar gizlice Rusya, Çin veya Kuzey Kore'deki şüpheli bir sunucuyla veri alışverişi yaparsa, sistem bunu bir 'Arka Kapı (Backdoor) Trojanı' olarak yakalayıp bizi uyarıyor.
> 
> **Üçüncüsü ve en önemlisi; Aktif Tuzağa Düşürme (Honeytokens & Decoy Traffic):** Sistemde saldırganı kandırmak için sahte 'Şirket Şifreleri' dosyalarımız ve sahte SSH/Web sunucularımız var. Hacker ağa sızıp etrafı dinlemeye başladığında, sistemimiz ortalığa sahte veri paketleri (beyaz gürültü) yayıyor. Hacker bu yalan verilerin veya tuzak dosyaların üzerine atladığı milisaniye içerisinde Telegram botumuzdan telefonumuza **'Kırmızı Alarm'** düşüyor!"

## 3. Canlı Gösterim (Demo Aşaması)
*Burada anlattıklarınızı uygulamalı olarak gösterin. Bu kısım jüriyi en çok etkileyecek yerdir.*

**Yapmanız Gerekenler:**
1. Ekranı yansıtın ve Web Paneli (`http://127.0.0.1:5000`) açın.
2. Haritayı ve sağdaki akan logları (Canlı Akış) gösterin.
3. Arka planda bir terminalden Nmap taraması başlatın (veya birinden sizin ağınıza tarama yapmasını isteyin). Panelde "Ağ Taraması (Port Scan)" alarmının nasıl düştüğünü gösterin.
4. **Vurucu Darbe:** *"Şimdi bir hacker'ın gizli dosyalarımıza sızdığını varsayalım"* deyin ve tarayıcıdan `http://127.0.0.1:5000/sirket_sifreleri.pdf` adresine gidin. Ekranda 'Bozuk Dosya' uyarısını ve aynı saniye telefonunuzdan çalan Telegram bildirim sesini jüriye gösterin.

## 4. Kapanış ve Gelecek Vizyonu
*Sistemin ne kadar modüler olduğunu anlatarak bitirin.*

**Sizin Konuşmanız:**
> "Sistemimizin en büyük kurallarından biri **'Otomatik Ban' özelliğinin kapalı olmasıdır.** Çünkü bu bir askeri üs; sistem yapay zekasıyla tespiti yapar, delilleri toplar, kırmızı alarmı verir ancak 'İnfaz' yani ağdan atma (Ban) yetkisi her zaman insan kontrolündedir (Sağ tıklayıp Banla).
> Gelecekte bu projeyi Makine Öğrenimi (AI) ile birleştirip, sadece kural tabanlı değil, anormal davranış tabanlı (Davranışsal Analiz) bir boyuta taşımayı hedefliyorum. Dinlediğiniz için teşekkür ederim."
