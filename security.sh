#!/bin/bash

# =================== SELECT LANGUAGE ===================
echo "Please select language / Lütfen dil seçin:"
echo "1) English"
echo "2) Türkçe"
read -p "Choice / Seçim: " LANG_CHOICE

if [ "$LANG_CHOICE" == "2" ]; then
    LANG="TR"
else
    LANG="EN"
fi

# =================== MESSAGES ===================
if [ "$LANG" == "TR" ]; then
    MSG_SSH_PORT="🔢 Yeni SSH port numarasını girin (Varsayılan: 2221): "
    MSG_IP_LIMIT="🌐 SSH bağlantısı sadece belirli bir IP'den mi yapılacak? (e/h): "
    MSG_GEO_LIMIT="🌍 SSH'a sadece belirli ülke kodlarına izin verilsin mi? (e/h): "
    MSG_START="🚀 SSH güvenlik scripti başlıyor..."
    MSG_PACKAGES="📦 Gerekli paketler kuruluyor..."
    MSG_MFA_SETUP="🔐 MFA kurulumu başlatılıyor..."
    MSG_COMPLETED="✅ Tamamlandı!"
else
    MSG_SSH_PORT="🔢 Enter new SSH port number (Default: 2221): "
    MSG_IP_LIMIT="🌐 Restrict SSH access to a specific IP? (y/n): "
    MSG_GEO_LIMIT="🌍 Restrict SSH access to specific countries? (y/n): "
    MSG_START="🚀 Starting SSH security script..."
    MSG_PACKAGES="📦 Installing required packages..."
    MSG_MFA_SETUP="🔐 Starting MFA setup..."
    MSG_COMPLETED="✅ Completed!"
fi

# =================== USER MANUEL ===================
read -p "$MSG_SSH_PORT" USER_SSH_PORT
NEW_SSH_PORT=${USER_SSH_PORT:-2221}

read -p "$MSG_IP_LIMIT" IP_LIMIT_ANSWER
if [[ "$IP_LIMIT_ANSWER" =~ ^[eEyY]$ ]]; then
  read -p "$( [ "$LANG" == "TR" ] && echo "📍 SSH erişimine izin verilecek IP adresini girin: " || echo "📍 Enter allowed IP address for SSH: " )" ALLOWED_IP
  IP_RESTRICTED=true
else
  IP_RESTRICTED=false
fi

read -p "$MSG_GEO_LIMIT" GEO_LIMIT_ANSWER
if [[ "$GEO_LIMIT_ANSWER" =~ ^[eEyY]$ ]]; then
  read -p "$( [ "$LANG" == "TR" ] && echo "🌐 İzin verilecek ülke kodlarını (virgülle ayır, örn: TR,DE): " || echo "🌐 Enter allowed country codes (comma-separated, e.g., TR,DE): " )" ALLOWED_COUNTRIES
  GEO_RESTRICTED=true
else
  GEO_RESTRICTED=false
fi

echo "$MSG_START"

# =================== SECURITY AND PACKAGES ===================
echo "$MSG_PACKAGES"
sudo apt update
sudo apt install -y ufw fail2ban libpam-google-authenticator rsyslog iptables-persistent xtables-addons-common libtext-csv-xs-perl libgeoip1 geoip-database unzip dkms ipset

# =================== GEOIP ===================
if $GEO_RESTRICTED; then
  echo "$( [ "$LANG" == "TR" ] && echo "🌐 GeoIP verisi indiriliyor ve hazırlanıyor..." || echo "🌐 Downloading and preparing GeoIP database..." )"
  sudo mkdir -p /usr/share/xt_geoip
  cd /usr/share/xt_geoip
  sudo /usr/lib/xtables-addons/xt_geoip_dl
  sudo /usr/lib/xtables-addons/xt_geoip_build -D . csv
fi

# =================== SSH CONFIG ===================
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak_$(date +%F_%T)

sudo sed -i "s/^#\?Port .*/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?UsePAM .*/UsePAM yes/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication yes/" /etc/ssh/sshd_config

grep -q "^KbdInteractiveAuthentication" /etc/ssh/sshd_config && \
  sudo sed -i "s/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/" /etc/ssh/sshd_config || \
  echo "KbdInteractiveAuthentication yes" | sudo tee -a /etc/ssh/sshd_config

sudo sed -i '/^AuthenticationMethods/d' /etc/ssh/sshd_config
grep -q "ClientAliveInterval" /etc/ssh/sshd_config && \
  sudo sed -i "s/^#\?ClientAliveInterval.*/ClientAliveInterval 300/" /etc/ssh/sshd_config || \
  echo "ClientAliveInterval 300" | sudo tee -a /etc/ssh/sshd_config

grep -q "ClientAliveCountMax" /etc/ssh/sshd_config && \
  sudo sed -i "s/^#\?ClientAliveCountMax.*/ClientAliveCountMax 6/" /etc/ssh/sshd_config || \
  echo "ClientAliveCountMax 6" | sudo tee -a /etc/ssh/sshd_config

sudo sed -i "s/^#\?LogLevel.*/LogLevel VERBOSE/" /etc/ssh/sshd_config
sudo sed -i "s/^#\?MaxAuthTries.*/MaxAuthTries 3/" /etc/ssh/sshd_config

# =================== MFA SETTINGS ===================
echo "$MSG_MFA_SETUP"
if ! grep -q 'pam_google_authenticator.so' /etc/pam.d/sshd; then
  sudo sed -i '/^@include common-auth/a auth required pam_google_authenticator.so nullok' /etc/pam.d/sshd
fi

# =================== LOGIN BANNER ===================
if [ "$LANG" == "TR" ]; then
    BANNER_TEXT="███████╗ █████╗ ██████╗  █████╗ ███╗   ███╗███████╗████████╗
██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝╚══██╔══╝
███████╗███████║██████╔╝███████║██╔████╔██║█████╗     ██║
╚════██║██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝     ██║
███████║██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗   ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝

Uyarı: Bu sistem yalnızca yetkili kullanıcılar içindir. İzinsiz girişler kaydedilir ve cezai işlem uygulanabilir."
else
    BANNER_TEXT="███████╗ █████╗ ██████╗  █████╗ ███╗   ███╗███████╗████████╗
██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝╚══██╔══╝
███████╗███████║██████╔╝███████║██╔████╔██║█████╗     ██║
╚════██║██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝     ██║
███████║██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗   ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝

Warning: Authorized users only. Unauthorized access will be logged and may result in legal action."
fi

sudo tee /etc/issue.net > /dev/null <<< "$BANNER_TEXT"
sudo sed -i "s|^#\?Banner .*|Banner /etc/issue.net|" /etc/ssh/sshd_config

# =================== UFW SETTINGS ===================
sudo ufw default deny incoming
sudo ufw default allow outgoing
if $IP_RESTRICTED; then
  sudo ufw allow from $ALLOWED_IP to any port $NEW_SSH_PORT proto tcp
else
  sudo ufw allow $NEW_SSH_PORT/tcp
fi
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# =================== Fail2Ban ===================
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

# =================== Bash History ===================
echo 'export HISTTIMEFORMAT="%F %T "' >> ~/.bashrc
echo 'export HISTTIMEFORMAT="%F %T "' | sudo tee -a /root/.bashrc

# =================== SSH RESTART ===================
sudo systemctl restart ssh

echo "$MSG_COMPLETED"
echo "📌 SSH port: $NEW_SSH_PORT"
[ "$IP_RESTRICTED" == true ] && echo "📌 Sadece $ALLOWED_IP IP adresine izin verildi. / Only $ALLOWED_IP is allowed."
[ "$GEO_RESTRICTED" == true ] && echo "📌 Yalnızca $ALLOWED_COUNTRIES ülkelerinden SSH yapılabilir. / Only from $ALLOWED_COUNTRIES countries."
