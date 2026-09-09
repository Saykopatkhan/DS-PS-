# DS-IPS v3.5 - Yeni Eklenen Özellikler Özeti

Son yaptığımız güncellemelerle birlikte DS-IPS, hem arayüz hem de güvenlik anlamında çok daha profesyonel ve dayanıklı bir sisteme dönüştü. İşte son güncellemelerle eklenen yeni yetenekler:

## 1. 🛡️ Gelişmiş Giriş ve Oturum Sistemi (Auth & Session)
- **Tarayıcı Popup'ı Kaldırıldı:** Eski, can sıkıcı HTTP Basic Auth (tarayıcının üstten çıkardığı giriş penceresi) tamamen kaldırılarak modern, HTML tabanlı ve güvenli bir `/login` ekranı oluşturuldu.
- **Rastgele Şifre (OTP):** Sistem her başlatıldığında (`sudo python3 web_main.py -i wlan0`) otomatik olarak **rastgele 8 haneli yepyeni bir şifre** üretir ve bunu sadece sunucu terminalinde gösterir. Bu sayede sabit şifre zafiyeti ortadan kalkmıştır.
- **Güvenli Çıkış (Logout):** Ana panele güvenli çıkış yapabilmeniz için kırmızı renkli **"🚪 Çıkış"** butonu eklendi.

## 2. 🧱 Web Uygulama Güvenlik Duvarı (WAF) Modülü
- **Bruteforce Koruması:** Giriş ekranında art arda **5 kez** hatalı şifre giren bir IP adresi, WAF tarafından anında **5 dakika** boyunca engellenir.
- **Zehi̇rli̇ Başlik (Header Injection) Engelleme:** Saldırganların yetki atlatmak için kullandığı sahte IP başlıkları (`X-Forwarded-For`, `X-Original-URL` vb.) anında tespit edilir ve kaynak IP kalıcı olarak izole edilir.
- **Method Tampering:** Beklenmeyen HTTP metotlarıyla (Örn: `PUT`, `DELETE`) arka kapı arayan tarayıcılar anında engellenir.

## 3. 🌶️ Anti-Capsaicin & Dizin Tarama Koruması
*Gelişmiş sızma testi araçlarına (Capsaicin, ffuf, dirb) karşı geliştirilen özel savunmalar:*
- **Honeypot (Bal Küpü) Tuzakları:** 404 (Bulunamadı) sayfalarının görünmez kısımlarına **sahte AWS ve Stripe API anahtarları** gömülmüştür. Akıllı tarayıcılar bu anahtarları bulup gerçek sanacak ve saldırganın raporlarını çöpe çevirecektir.
- **Jitter & Kalibrasyon Bozucu:** 404 sayfalarının boyutu her istekte rastgele değişir (0-50 satır anlamsız yorum eklenir). Böylece tarama araçlarının boyut bazlı filtreleme yeteneği kör edilir.
- **Agresif Dizin Tarama Banı:** Bir cihaz **10 saniye içinde 4'ten fazla** olmayan sayfaya gitmeye (404 hatası almaya) çalışırsa, sistem bunun bir "Dizin Taraması" olduğunu anlar ve cihazı ARP poisoning & Iptables ile ağdan tamamen atar.

## 4. 🎨 Tema ve UI İyileştirmeleri
- **Altın & Türk Bayrağı Teması:** Ana ekranın arka planında altın rengi hilal ve kırmızı yıldızdan oluşan dev bir Türk Bayrağı silüeti eklendi.
- **Ambiyans Aydınlatması:** Arka plana, kırmızı ve altın sarısı renklerin harmanlandığı hafif bir radyal ambiyans (glow) eklendi.
- **Premium SOC Butonu:** Tasarıma uyumlu Altın Sarısı buton stili entegre edildi.

## 5. 🛠️ Çekirdek Hata Düzeltmeleri (Audit Fixes)
- HIDS ve FastSniffer'ın yanlış parametre gönderip alarm oluşturamaması (TypeError) sorunu çözüldü.
- Sadece `ids` (İzleme) modunda başlatıldığında sistemin çökmesine neden olan `AttributeError` düzeltildi.
- SOC Premium ekranındaki otonom tarama butonunun CSRF (403 Forbidden) hatasına düşmesi engellendi.
