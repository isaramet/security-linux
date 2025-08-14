# 🛡️ Linux Security Hardening Script [TR/ENG]
## Türkçe

Bu proje, Debian/Fedora/Ubuntu tabanlı sistemlerde temel güvenlik sertleşmesini (hardening) kolayca uygulamak için geliştirilmiş bir **otomasyon scriptidir**.  
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
git clone https://github.com/isaramet/security-linux.git
cd security-linux
chmod +x security.sh
./security.sh
```

## English

A lightweight automation script for Debian/Ubuntu-based systems that applies essential security hardening with a single command.  
Includes SSH security, UFW firewall configuration, Fail2Ban setup, MFA (Google Authenticator) integration, and additional system-level protections.

---

## 🚀 Features

### **🔐 SSH Security**
- Change SSH port (`NEW_SSH_PORT` variable)
- Disable root login (`PermitRootLogin no`)
- Disable password authentication (`PasswordAuthentication no`)
- 30-minute session timeout
- Limit maximum authentication attempts (`MaxAuthTries`)
- MFA support (Google Authenticator)
- Detailed logging (`LogLevel VERBOSE`)
- Backup `sshd_config` before changes

### **🛡️ UFW Firewall**
- Default policy: `deny incoming`, `allow outgoing`
- Open ports:
  - HTTP (80)
  - HTTPS (443)
  - Custom ports (e.g., 8443)
  - New SSH port

### **🚫 Fail2Ban**
- Protection against SSH brute-force attacks
- Automatically monitors the new SSH port
- 24-hour ban after multiple failed login attempts

### **⚙️ System Hardening**
- Unauthorized access warning banner (`/etc/issue.net`)
- Timestamped command history
- ICMP ping rate limiting

---

## 📦 Installation

```bash
git clone https://github.com/isaramet/security-linux.git
cd security-linux
chmod +x security.sh
./security.sh
