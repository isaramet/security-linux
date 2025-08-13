# 🛡️ Linux Security Hardening Script

Bu proje, Debian/Ubuntu tabanlı sistemlerde temel güvenlik sertleşmesini (hardening) kolayca uygulamak için geliştirilmiş bir **otomasyon scriptidir**.  
SSH, UFW, Fail2Ban, MFA (Google Authenticator) ve sistem ayarlarını tek komutla güvenli hale getirir.  

## 🚀 Özellikler

- **SSH Güvenliği**
  - Port değişikliği (`NEW_SSH_PORT` değişkeni ile)
  - `PermitRootLogin no` (root ile SSH girişi kapatılır)
  - `PasswordAuthentication no` (şifre ile giriş kapatılır, MFA/Public Key önerilir)
  - SSH idle timeout (30 dakika)
  - `MaxAuthTries` sınırı (3 deneme)
  - MFA (Google Authenticator) desteği
  - `LogLevel VERBOSE` ile giriş denemelerinin ayrıntılı loglanması
  - `sshd_config` dosyası otomatik yedeklenir

- **Güvenlik Duvarı (UFW)**
  - Varsayılan: `deny incoming`, `allow outgoing`
  - HTTP (80), HTTPS (443), özel portlar (ör. 8443) ve yeni SSH portu açık

- **Fail2Ban**
  - SSH brute-force saldırılarını engeller
  - Otomatik olarak yeni SSH portunu dinler
  - Yanlış girişte 24 saat ban (bantime = 86400 saniye)
  - `maxretry = 3`, `findtime = 300s`

- **Sistem Güvenliği**
  - `/etc/issue.net` üzerinden yetkisiz giriş uyarısı
  - Bash history’e zaman damgası eklenir
  - ICMP (ping) isteklerine rate limit uygulanır (tamamen kapatmaz)

## 📦 Kurulum

```bash
git clone https://github.com/kullanici/linux-security-hardening.git
cd linux-security-hardening
chmod +x security.sh
./security.sh
