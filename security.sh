#!/bin/bash

# =================== SSH PORTU SOR ===================
read -p "🔢 Yeni SSH port numarasını girin (Varsayılan: 2221): " USER_SSH_PORT
NEW_SSH_PORT=${USER_SSH_PORT:-2221}

# =================== BELİRLİ BİR IP İÇİN ERİŞİM ===================
read -p "🌐 SSH bağlantısı sadece belirli bir IP'den mi yapılacak? (e/h): " IP_LIMIT_ANSWER

if [[ "$IP_LIMIT_ANSWER" =~ ^[eEyY]$ ]]; then
  read -p "📍 SSH erişimine izin verilecek IP adresini girin: " ALLOWED_IP
  IP_RESTRICTED=true
else
  IP_RESTRICTED=false
fi

read -p "🌍 SSH'a sadece belirli ülke kodlarına (TR, DE, US vs.) izin verilsin mi? (e/h): " GEO_LIMIT_ANSWER
if [[ "$GEO_LIMIT_ANSWER" =~ ^[eEyY]$ ]]; then
  read -p "🌐 İzin verilecek ülke kodlarını (virgülle ayır, örn: TR,DE): " ALLOWED_COUNTRIES
  GEO_RESTRICTED=true
else
  GEO_RESTRICTED=false
fi

echo "🚀 SSH güvenlik scripti başlıyor..."

# =================== GÜNCELLEME VE ARAÇLAR ===================
echo "📦 Gerekli paketler kuruluyor..."
sudo apt update
sudo apt install -y ufw fail2ban libpam-google-authenticator rsyslog iptables-persistent xtables-addons-common libtext-csv-xs-perl libgeoip1 geoip-database unzip dkms ipset


# =================== GEOIP VERİ TABANI OLUŞTURMA ===================
if $GEO_RESTRICTED; then
  echo "🌐 GeoIP verisi indiriliyor ve hazırlanıyor..."
  sudo mkdir -p /usr/share/xt_geoip
  cd /usr/share/xt_geoip
  sudo /usr/lib/xtables-addons/xt_geoip_dl
  sudo /usr/lib/xtables-addons/xt_geoip_build -D . csv
fi

# =================== SSH GÜVENLİĞİ ===================
echo "🔐 SSH yapılandırması düzenleniyor..."

# SSH config yedeği
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak_$(date +%F_%T)

# Temel güvenlik ayarları
sudo sed -i "s/^#\?Port .*/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?UsePAM .*/UsePAM yes/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication yes/" /etc/ssh/sshd_config

# KbdInteractiveAuthentication mutlaka yes olmalı
grep -q "^KbdInteractiveAuthentication" /etc/ssh/sshd_config && \
  sudo sed -i "s/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/" /etc/ssh/sshd_config || \
  echo "KbdInteractiveAuthentication yes" | sudo tee -a /etc/ssh/sshd_config

# AuthenticationMethods satırı varsa sil
sudo sed -i '/^AuthenticationMethods/d' /etc/ssh/sshd_config

# SSH idle timeout ayarları (30 dakika)
grep -q "ClientAliveInterval" /etc/ssh/sshd_config && \
  sudo sed -i "s/^#\?ClientAliveInterval.*/ClientAliveInterval 300/" /etc/ssh/sshd_config || \
  echo "ClientAliveInterval 300" | sudo tee -a /etc/ssh/sshd_config

grep -q "ClientAliveCountMax" /etc/ssh/sshd_config && \
  sudo sed -i "s/^#\?ClientAliveCountMax.*/ClientAliveCountMax 6/" /etc/ssh/sshd_config || \
  echo "ClientAliveCountMax 6" | sudo tee -a /etc/ssh/sshd_config

# MFA PAM modülü ekleme (doğru konuma ekle)
if ! grep -q 'pam_google_authenticator.so' /etc/pam.d/sshd; then
  sudo sed -i '/^@include common-auth/a auth required pam_google_authenticator.so nullok' /etc/pam.d/sshd
fi

# SSH log seviyesi ve deneme sınırı
sudo sed -i "s/^#\?LogLevel.*/LogLevel VERBOSE/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?MaxAuthTries.*/MaxAuthTries 3/" /etc/ssh/sshd_config

# =================== MFA SADECE ROOT DIŞI ===================
echo "🔐 MFA ayarlanıyor (sadece root dışı)..."
if ! grep -q 'pam_google_authenticator.so' /etc/pam.d/sshd; then
  sudo sed -i '/^@include common-auth/a auth [success=1 default=ignore] pam_succeed_if.so user = root\nauth required pam_google_authenticator.so nullok' /etc/pam.d/sshd
fi

echo "📌 Kullanıcılara MFA zorunluluğu ekleniyor..."

for home in /home/*; do
  user=$(basename "$home")
  profile="$home/.bash_profile"

  # Sadece normal kullanıcılar için uygula
  if id "$user" &>/dev/null && [[ "$user" != "root" ]]; then
    # Eğer bash_profile yoksa oluştur
    sudo touch "$profile"
    sudo chown "$user:$user" "$profile"

    # MFA kontrol kodu zaten eklenmemişse ekle
    if ! grep -q '## MFA CHECK START ##' "$profile" 2>/dev/null; then
      cat <<'EOF' | sudo tee -a "$profile" > /dev/null

## MFA CHECK START ##
if [[ -n "$SSH_TTY" && ! -f "$HOME/.google_authenticator" ]]; then
  echo ""
  echo "⚠️  Google Authenticator kurulumu yapılmamış."
  echo "🔐 MFA kurulumu başlatılıyor (zorunlu)..."
  sleep 1
  google-authenticator
fi
## MFA CHECK END ##
EOF
      sudo chown "$user:$user" "$profile"
    fi
  fi
done

sudo tee /etc/skel/.bash_profile > /dev/null <<'EOF'
## MFA CHECK START ##
if [[ -n "$SSH_TTY" && ! -f "$HOME/.google_authenticator" ]]; then
  echo ""
  echo "⚠️  Google Authenticator kurulumu yapılmamış."
  echo "🔐 MFA kurulumu başlatılıyor (zorunlu)..."
  sleep 1
  google-authenticator
fi
## MFA CHECK END ##
EOF


# =================== LOGIN UYARI ===================
sudo tee /etc/issue.net > /dev/null <<EOF
███████╗ █████╗ ██████╗  █████╗ ███╗   ███╗███████╗████████╗
██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝╚══██╔══╝
███████╗███████║██████╔╝███████║██╔████╔██║█████╗     ██║
╚════██║██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝     ██║
███████║██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗   ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝
 
███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝
 
███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗
██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║
███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║
╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║
███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║
╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
Uyarı: Bu sistem yalnızca yetkili kullanıcılar içindir. İzinsiz girişler kaydedilir ve cezai işlem uygulanabilir.
EOF

sudo sed -i "s|^#\?Banner .*|Banner /etc/issue.net|" /etc/ssh/sshd_config

# =================== UFW AYARI ===================

echo "🧱 UFW yapılandırması yapılıyor..."
sudo ufw default deny incoming
sudo ufw default allow outgoing

if $IP_RESTRICTED; then
  echo "🔐 SSH bağlantısı sadece $ALLOWED_IP IP adresine izin verilecek..."
  sudo ufw allow from $ALLOWED_IP to any port $NEW_SSH_PORT proto tcp
else
  sudo ufw allow $NEW_SSH_PORT/tcp
fi

sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable


# =================== Fail2Ban ===================
echo "👮 Fail2Ban yapılandırması yapılıyor..."
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[sshd]
enabled = true
port = $NEW_SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
findtime = 300
bantime = 86400
EOF

sudo systemctl restart fail2ban

# =================== BASH HISTORY ZAMAN DAMGASI ===================
echo "📜 Bash geçmişine zaman damgası ekleniyor..."
echo 'export HISTTIMEFORMAT="%F %T "' >> ~/.bashrc
echo 'export HISTTIMEFORMAT="%F %T "' | sudo tee -a /root/.bashrc

# =================== PING RATE LIMIT ===================
echo "📉 ICMP ping rate limit ayarlanıyor..."
sudo tee -a /etc/sysctl.conf > /dev/null <<EOL
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ratelimit = 1000
net.ipv4.icmp_ratemask = 88089
EOL
sudo sysctl -p
sudo sysctl --system

# =================== SSH LOG DOSYASI OLUŞTURMA ===================
echo "📝 SSH girişleri /var/log/ssh_login.log dosyasına yönlendiriliyor..."
sudo tee /etc/rsyslog.d/50-ssh-log.conf > /dev/null <<EOL
:programname, isequal, "sshd" /var/log/ssh_login.log
& stop
EOL
sudo systemctl restart rsyslog

# =================== GEOIP ENGELİ (ÜLKE BAZLI) ===================
if $GEO_RESTRICTED; then
  echo "🛂 Yalnızca şu ülkelere SSH izni veriliyor: $ALLOWED_COUNTRIES"
  IFS=',' read -ra COUNTRY_ARRAY <<< "$ALLOWED_COUNTRIES"
  for CODE in "${COUNTRY_ARRAY[@]}"; do
    CODE=$(echo $CODE | xargs) # boşluk temizle
    sudo iptables -A INPUT -p tcp --dport $NEW_SSH_PORT -m geoip ! --src-cc $CODE -j DROP
  done
  sudo netfilter-persistent save
fi

# =================== SSH TEST ===================
echo "🔄 SSH servisi yeniden başlatılıyor..."
sudo systemctl restart ssh

echo "⌛ 5 saniye içinde SSH bağlantınızı test edin! (Ayrı terminalde: ssh -p $NEW_SSH_PORT user@sunucu)"
sleep 5

echo ""
echo "✅ Tamamlandı!"
echo "📌 SSH portu: $NEW_SSH_PORT"
echo "📌 Sadece $ALLOWED_IP IP adresine SSH tanımlı."
echo "📌 Yalnızca $ALLOWED_COUNTRIES 'den SSH yapılabilir."
echo "📌 SSH idle timeout: 30 dakika"
echo "📌 Firewall ve Fail2Ban ayarlandı"
echo "📌 MFA aktif: Her kullanıcı kendi hesabında 'google-authenticator' çalıştırmalı"
