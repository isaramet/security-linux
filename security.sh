#!/bin/bash

# =================== DİL SEÇİMİ ===================
echo "Please select language / Lütfen dil seçin:"
echo "1) English"
echo "2) Türkçe"
read -p "Choice / Seçim: " LANG_CHOICE

if [ "$LANG_CHOICE" == "2" ]; then
    LANG="TR"
else
    LANG="EN"
fi

# =================== MESAJ SÖZLÜĞÜ ===================
declare -A MSG

if [ "$LANG" == "TR" ]; then
    MSG[SSH_PORT]="🔢 Yeni SSH port numarasını girin (Varsayılan: 2221): "
    MSG[IP_LIMIT]="🌐 SSH bağlantısı sadece belirli bir IP'den mi yapılacak? (e/h): "
    MSG[IP_INPUT]="📍 SSH erişimine izin verilecek IP adresini girin: "
    MSG[GEO_LIMIT]="🌍 SSH'a sadece belirli ülke kodlarına izin verilsin mi? (e/h): "
    MSG[GEO_INPUT]="🌐 İzin verilecek ülke kodlarını (virgülle ayır, örn: TR,DE): "
    MSG[START]="🚀 SSH güvenlik scripti başlıyor..."
    MSG[PACKAGES]="📦 Gerekli paketler kuruluyor..."
    MSG[MFA_SETUP]="🔐 MFA kurulumu başlatılıyor..."
    MSG[COMPLETED]="✅ Tamamlandı!"
    MSG[BANNER]="Uyarı: Bu sistem yalnızca yetkili kullanıcılar içindir. İzinsiz girişler kaydedilir ve cezai işlem uygulanabilir."
    MSG[ALLOW_IP]="📌 Sadece %s IP adresine izin verildi."
    MSG[ALLOW_COUNTRIES]="📌 Yalnızca %s ülkelerinden SSH yapılabilir."
    MSG[TEST]="⌛ 5 saniye içinde SSH bağlantınızı test edin! (Ayrı terminalde: ssh -p %s user@sunucu)"
    MSG[GEO_DOWNLOAD]="🌐 GeoIP verisi indiriliyor ve hazırlanıyor..."
    MSG[SSHD_ERROR]="❌ SSH yapılandırmasında hata var! sshd servisi yeniden başlatılmadı."
    MSG[PING_LIMIT]="📉 ICMP ping rate limit ayarlanıyor..."
    MSG[SSH_LOG]="📝 SSH girişleri /var/log/ssh_login.log dosyasına yönlendiriliyor..."
    MSG[MFA_USER]="📌 Kullanıcılara MFA zorunluluğu ekleniyor..."
else
    MSG[SSH_PORT]="🔢 Enter new SSH port number (Default: 2221): "
    MSG[IP_LIMIT]="🌐 Restrict SSH access to a specific IP? (y/n): "
    MSG[IP_INPUT]="📍 Enter allowed IP address for SSH: "
    MSG[GEO_LIMIT]="🌍 Restrict SSH access to specific countries? (y/n): "
    MSG[GEO_INPUT]="🌐 Enter allowed country codes (comma-separated, e.g., TR,DE): "
    MSG[START]="🚀 Starting SSH security script..."
    MSG[PACKAGES]="📦 Installing required packages..."
    MSG[MFA_SETUP]="🔐 Starting MFA setup..."
    MSG[COMPLETED]="✅ Completed!"
    MSG[BANNER]="Warning: Authorized users only. Unauthorized access will be logged and may result in legal action."
    MSG[ALLOW_IP]="📌 Only %s IP is allowed."
    MSG[ALLOW_COUNTRIES]="📌 SSH allowed only from %s countries."
    MSG[TEST]="⌛ Test your SSH connection in 5 seconds! (In a separate terminal: ssh -p %s user@server)"
    MSG[GEO_DOWNLOAD]="🌐 Downloading and preparing GeoIP database..."
    MSG[SSHD_ERROR]="❌ Error in SSH config! sshd service NOT restarted."
    MSG[PING_LIMIT]="📉 Setting ICMP ping rate limit..."
    MSG[SSH_LOG]="📝 Redirecting SSH logs to /var/log/ssh_login.log..."
    MSG[MFA_USER]="📌 Enforcing MFA for users..."
fi

# =================== KULLANICI GİRDİLERİ ===================
read -p "${MSG[SSH_PORT]}" USER_SSH_PORT
NEW_SSH_PORT=${USER_SSH_PORT:-2221}

read -p "${MSG[IP_LIMIT]}" IP_LIMIT_ANSWER
IP_LIMIT_ANSWER_LOWER=$(echo "$IP_LIMIT_ANSWER" | tr '[:upper:]' '[:lower:]')
if [[ "$IP_LIMIT_ANSWER_LOWER" =~ ^(e|y)$ ]]; then
  read -p "${MSG[IP_INPUT]}" ALLOWED_IP
  IP_RESTRICTED=true
else
  IP_RESTRICTED=false
fi

read -p "${MSG[GEO_LIMIT]}" GEO_LIMIT_ANSWER
GEO_LIMIT_ANSWER_LOWER=$(echo "$GEO_LIMIT_ANSWER" | tr '[:upper:]' '[:lower:]')
if [[ "$GEO_LIMIT_ANSWER_LOWER" =~ ^(e|y)$ ]]; then
  read -p "${MSG[GEO_INPUT]}" ALLOWED_COUNTRIES
  GEO_RESTRICTED=true
else
  GEO_RESTRICTED=false
fi

echo "${MSG[START]}"

# =================== GÜVENLİK VE PAKETLER ===================
echo "${MSG[PACKAGES]}"
sudo apt update
sudo apt install -y ufw fail2ban libpam-google-authenticator rsyslog iptables-persistent xtables-addons-common libtext-csv-xs-perl libgeoip1 geoip-database unzip dkms ipset

# =================== GEOIP VERİ TABANI ===================
if [ "$GEO_RESTRICTED" == "true" ]; then
  echo "${MSG[GEO_DOWNLOAD]}"
  sudo mkdir -p /usr/share/xt_geoip
  cd /usr/share/xt_geoip
  sudo /usr/lib/xtables-addons/xt_geoip_dl
  sudo /usr/lib/xtables-addons/xt_geoip_build -D . csv
  ALLOWED_COUNTRIES_CLEANED=$(echo "$ALLOWED_COUNTRIES" | tr ',' ' ')
  sudo iptables -A INPUT -p tcp --dport "$NEW_SSH_PORT" -m geoip ! --src-cc $ALLOWED_COUNTRIES_CLEANED -j DROP
  sudo netfilter-persistent save
  sudo netfilter-persistent reload
fi

# =================== SSH YAPILANDIRMA ===================
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

# SSHD TEST
if ! sudo sshd -t; then
  echo "${MSG[SSHD_ERROR]}"
  exit 1
fi

# =================== MFA AYARI ===================
echo "${MSG[MFA_SETUP]}"
if ! grep -q 'pam_google_authenticator.so' /etc/pam.d/sshd; then
  sudo sed -i '/^@include common-auth/a auth required pam_google_authenticator.so nullok' /etc/pam.d/sshd
fi

# Kullanıcılar için MFA zorunluluğu
echo "${MSG[MFA_USER]}"
for home in /home/*; do
  user=$(basename "$home")
  profile="$home/.bash_profile"
  if id "$user" &>/dev/null && [[ "$user" != "root" ]]; then
    sudo touch "$profile"
    sudo chown "$user:$user" "$profile"
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

# =================== LOGIN BANNER ===================
sudo tee /etc/issue.net > /dev/null <<EOF
███████╗ █████╗ ██████╗  █████╗ ███╗   ███╗███████╗████████╗
██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝╚══██╔══╝
███████╗███████║██████╔╝███████║██╔████╔██║█████╗     ██║
╚════██║██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝     ██║
███████║██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗   ██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝

${MSG[BANNER]}
EOF
sudo sed -i "s|^#\?Banner .*|Banner /etc/issue.net|" /etc/ssh/sshd_config

# =================== UFW AYARI ===================
sudo ufw default deny incoming
sudo ufw default allow outgoing
if [ "$IP_RESTRICTED" == "true" ]; then
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
sudo fail2ban-client reload

# =================== Bash History Zaman Damgası ===================
echo 'export HISTTIMEFORMAT="%F %T "' | sudo tee -a /etc/skel/.bashrc > /dev/null
echo 'export HISTTIMEFORMAT="%F %T "' | sudo tee -a /root/.bashrc > /dev/null

# =================== PING RATE LIMIT ===================
echo "${MSG[PING_LIMIT]}"
sudo tee -a /etc/sysctl.conf > /dev/null <<EOL
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ratelimit = 1000
net.ipv4.icmp_ratemask = 88089
EOL
sudo sysctl -p
sudo sysctl --system

# =================== SSH LOG DOSYASI ===================
echo "${MSG[SSH_LOG]}"
sudo tee /etc/rsyslog.d/50-ssh-log.conf > /dev/null <<EOL
:programname, isequal, "sshd" /var/log/ssh_login.log
& stop
EOL
sudo systemctl restart rsyslog

# =================== SSH RESTART ===================
sudo systemctl restart ssh

# =================== SON MESAJ ===================
echo "${MSG[COMPLETED]}"
echo "📌 SSH port: $NEW_SSH_PORT"
[ "$IP_RESTRICTED" == "true" ] && printf "${MSG[ALLOW_IP]}\n" "$ALLOWED_IP"
[ "$GEO_RESTRICTED" == "true" ] && printf "${MSG[ALLOW_COUNTRIES]}\n" "$ALLOWED_COUNTRIES"
printf "${MSG[TEST]}\n" "$NEW_SSH_PORT"
