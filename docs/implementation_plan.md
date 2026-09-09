# Mobil Uyumlu Aktif Savunma İyileştirmeleri (Android & iOS)

Mobil işletim sistemlerinin ağ yığınları, standart masaüstü tarayıcılara kıyasla QUIC (HTTP/3), DNS over TLS (DoT), DNS over HTTPS (DoH) gibi modern şifreleme ve atlatma protokollerini agresif şekilde kullanır. Bu nedenle IPS'in 4 temel modülü mobilde bypass edilmektedir. Bu planda, sistemin bu atlatma mekanizmalarını donanımsal olarak nasıl engelleyeceği ve iOS/Android sistemleri nasıl "kapatacağı" detaylandırılmaktadır.

## User Review Required
> [!WARNING]
> Sistem konteyner ortamında (sudo yetkilerinde bazı kısıtlamalarla - "no new privileges") çalıştığı için Linux `ifb` (Intermediate Functional Block) çekirdek modülü yüklenemiyor. Bu nedenle **Ingress (Download) Rate Limiting** için `tc` yerine, iki yönlü (bi-directional) limit uygulayabilen `iptables limit` veya `hashlimit` modülleri kullanılacaktır. Bu yöntem mobil cihazların hızını kestiği için yeterli olacaktır. Onaylıyorsanız devam edeceğim.

## Proposed Changes

### `responder/blocker.py` (Rate Limiting & TCP RST Çekirdek Güçlendirmesi)

#### [MODIFY] `blocker.py`
- `rate_limit_ip`: Mobil cihazlar için Rate Limit kuralına, bağlantıyı tamamen saniyede 1 pakete kilitleyecek daha sert çift yönlü iptables kuralları eklenecek.
  - Sadece TCP değil, tüm protokoller (QUIC için UDP dahil) sınırlanacak.
- Yeni `kill_session_hardware(self, ip)` metodu eklenecek.
  - Bu metod, hedefin IP'sine giden ve gelen tüm TCP paketlerine anında `--reject-with tcp-reset` donanımsal kuralını basacak, 2 saniye bekleyecek ve kuralı geri çekecektir (Mobil session kill).

### `modules/dns_sinkhole.py` (Mobil DoT/DoH/QUIC Engelleme & Captive Portal)

#### [MODIFY] `dns_sinkhole.py`
- `redirect_to_quarantine` fonksiyonuna yeni IPTables kuralları eklenecek:
  - DoT (Port 853 TCP/UDP) engellenecek (REJECT).
  - QUIC (Port 443 UDP) engellenecek ki cihaz TCP'ye (HTTP/2) düşsün (REJECT).
  - Popüler DoH sunucularına (8.8.8.8, 1.1.1.1, 9.9.9.9 vb.) giden trafik engellenecek.
- Flask (8099) sunucusuna Captive Portal (Ağa Oturum Açın) rotaları eklenecek:
  - `@self.app.route('/generate_204')` (Android) -> HTTP 302 Karantina sayfasına.
  - `@self.app.route('/hotspot-detect.html')` (iOS) -> HTTP 302 Karantina sayfasına.
  - `@self.app.route('/canonical.html')`, vb.

### `responder/tarpit.py` (Mobil Keep-Alive Tuzağı)

#### [MODIFY] `tarpit.py`
- `_tarpit_client` metodundaki `time.sleep(5)` kaldırılacak.
- Bunun yerine sonsuz bir döngüde `time.sleep(3)` ve ardından `client_socket.send(b'\x00')` veya boşluk karakteri (1 byte Keep-Alive) gönderilecek. Bu sayede mobil cihazlar "veri hala geliyor" sanıp bağlantıyı koparmayacak, böylece indirme çubuğu donup kalacak.

### `web/app.py` (RST Entegrasyonu)

#### [MODIFY] `app.py`
- `/api/active_defense` içindeki `tcp_reset` aksiyonu güncellenerek, `blocker.kill_session_hardware(target_ip)` metodunu çağıracak. (Mobil için daha kesin).

## Verification Plan
1. `start_prod.sh` yeniden başlatılacak.
2. iPhone/Android üzerinden Tarpit, 1Kbps ve Karantina test edilecek.
3. Karantina durumunda telefonda otomatik "Ağa Giriş Yapın" (Captive Portal) ekranının çıktığı doğrulanacak.
4. Tarpit'e alınan telefonun indirme/bağlantı durumunun sonsuza kadar kilitlendiği (kopmadığı) gözlemlenecek.
