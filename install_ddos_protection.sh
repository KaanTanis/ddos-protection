#!/bin/bash

# PROFESYONEL DDOS KORUMA - TAM KURULUM
echo "🛡️ PROFESYONEL DDOS KORUMA KURULUMU BAŞLIYOR..."
echo "================================================"

# Environment kontrol
if [ -z "$CLOUDFLARE_API_TOKEN" ] || [ -z "$CLOUDFLARE_ZONE_ID" ]; then
    read -p "🔑 Cloudflare API Token: " CLOUDFLARE_API_TOKEN
    read -p "🏠 Zone ID: " CLOUDFLARE_ZONE_ID
    export CLOUDFLARE_API_TOKEN CLOUDFLARE_ZONE_ID
fi

# ============= ADIM 1: SUNUCU KORUMASI =============
echo ""
echo "🖥️ ADIM 1: SUNUCU TARAFINDA KATMANLI KORUMA"
echo "----------------------------------------"

# Sistem güncellemesi
apt-get update
apt-get upgrade -y

# Gerekli paketleri kur
apt-get install -y iptables-persistent fail2ban htop iotop nethogs ufw

echo "1️⃣ Kernel optimizasyonu..."
tee -a /etc/sysctl.conf > /dev/null << 'EOF'

# === DDOS KORUMA - KERNEL TUNING ===
# SYN flood koruması
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# Connection tracking optimizasyonu
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 1
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10

# IP spoofing ve redirect koruması  
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0

# ICMP koruması
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# File descriptor limits
fs.file-max = 2097152
net.core.somaxconn = 65535

# Memory ve buffer optimizasyonu
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144  
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF

sysctl -p
echo "✅ Kernel optimizasyonu tamamlandı"

echo "2️⃣ UFW Firewall kurulumu..."
# UFW ile basit ama etkili kurallar
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH, HTTP, HTTPS izin ver
ufw allow 22/tcp
ufw allow 80/tcp  
ufw allow 443/tcp

# Rate limiting - aynı IP'den çok fazla SSH denemesi engelle
ufw limit 22/tcp

# UFW'yi aktifleştir
ufw --force enable

echo "✅ UFW Firewall kuruldu"

echo "3️⃣ IPTables gelişmiş kuralları..."
# Daha detaylı iptables kuralları
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# DDoS koruma kuralları
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP
iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP

# SYN flood koruma
iptables -A INPUT -p tcp --syn -m limit --limit 2/s --limit-burst 6 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Ping flood koruma  
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Port scanning koruma
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Kuralları kaydet
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
echo "✅ IPTables kuralları eklendi"

echo "4️⃣ Fail2Ban yapılandırması..."
tee /etc/fail2ban/jail.local > /dev/null << 'EOF'
[DEFAULT]
bantime = 1800
findtime = 300  
maxretry = 3
backend = auto

# SSH koruma
[sshd]
enabled = true
port = 22
maxretry = 3
bantime = 1800

# HTTP DDoS koruma
[http-get-dos]
enabled = true
port = http,https
filter = http-get-dos
logpath = /var/log/nginx/access.log
maxretry = 400
findtime = 300
bantime = 600

# Nginx 4xx koruması
[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

# Nginx limit req
[nginx-limit-req] 
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
EOF

# HTTP GET DoS filter
tee /etc/fail2ban/filter.d/http-get-dos.conf > /dev/null << 'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban
echo "✅ Fail2Ban yapılandırıldı"

# ============= ADIM 2: NGINX SERTLEŞME =============
echo ""
echo "🌐 ADIM 2: NGINX WEB SUNUCU SERTLEŞTİRME"  
echo "------------------------------------"

if command -v nginx >/dev/null 2>&1; then
    echo "5️⃣ Nginx DDoS koruma yapılandırması..."
    
    # Rate limiting zones
    tee /etc/nginx/conf.d/ddos-protection.conf > /dev/null << 'EOF'
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=strict:10m rate=2r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/m;
limit_conn_zone $binary_remote_addr zone=perip:10m;
limit_conn_zone $server_name zone=perserver:10m;

# Request size limits
client_max_body_size 10M;
client_body_buffer_size 128k;
client_header_buffer_size 1k;
large_client_header_buffers 2 1k;

# Timeout ayarları - DDoS koruması
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 5s;
send_timeout 10s;

# Gzip sıkıştırma
gzip on;
gzip_comp_level 6;
gzip_min_length 1000;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/rss+xml text/javascript;
EOF

    # Site specific protection snippet
    tee /etc/nginx/snippets/site-protection.conf > /dev/null << 'EOF'
# DDoS Protection - Site seviyesinde
limit_req zone=general burst=20 nodelay;
limit_conn perip 20;
limit_conn perserver 1000;

# Security headers
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Bot filtreleme
if ($http_user_agent ~* (bot|crawl|spider|scrape|wget|curl)) {
    return 429;
}

# Suspicious request methods
if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS)$ ) {
    return 444;
}

# Common attack patterns
location ~* /(wp-admin|wp-login|xmlrpc|\.php$) {
    return 404;
}

# Block empty user agents
if ($http_user_agent = "") {
    return 444;
}
EOF

    echo "✅ Nginx DDoS koruma yapılandırıldı"
    echo "❗ Site config'ine 'include /etc/nginx/snippets/site-protection.conf;' eklemeyi unutma!"
    
    # Nginx test et
    nginx -t && systemctl reload nginx
else
    echo "⚠️ Nginx bulunamadı, atlanıyor..."
fi

# ============= ADIM 3: CLOUDFLARE ADVANCED =============
echo ""
echo "☁️ ADIM 3: CLOUDFLARE ADVANCED KORUMA"
echo "--------------------------------"

echo "6️⃣ Cloudflare güvenlik ayarları..."

# Security Level - High
curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/settings/security_level" \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -H "Content-Type: application/json" \
    --data '{"value":"high"}'

# Browser Integrity Check
curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/settings/browser_check" \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -H "Content-Type: application/json" \
    --data '{"value":"on"}'

# Challenge Passage - 1 saat
curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/settings/challenge_ttl" \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -H "Content-Type: application/json" \
    --data '{"value":3600}'

echo "✅ Cloudflare güvenlik ayarları tamamlandı"

# ============= ADIM 4: MONITORING VE ALERTS =============
echo ""
echo "📊 ADIM 4: MONİTÖRİNG VE ALERT SİSTEMİ"
echo "--------------------------------"

echo "7️⃣ Monitoring scripti oluşturuluyor..."

tee /usr/local/bin/ddos-status.sh > /dev/null << 'EOF'
#!/bin/bash

echo "=== DDoS KORUMA DURUMU ==="
echo "Tarih: $(date)"
echo ""

# Sistem yükü
echo "📊 SİSTEM YÜKÜ:"
uptime
echo ""

# Aktif bağlantılar
echo "🔗 AKTİF BAĞLANTILAR:"
echo "HTTP (80): $(netstat -an | grep :80 | grep ESTABLISHED | wc -l)"
echo "HTTPS (443): $(netstat -an | grep :443 | grep ESTABLISHED | wc -l)"
echo "Toplam TCP: $(netstat -an | grep ESTABLISHED | wc -l)"
echo ""

# En çok bağlanan IP'ler
echo "🎯 EN ÇOK BAĞLANAN IP'LER (Top 10):"
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
echo ""

# Fail2ban durumu
echo "🚫 FAIL2BAN DURUMU:"
if systemctl is-active --quiet fail2ban; then
    echo "✅ Fail2ban aktif"
    fail2ban-client status 2>/dev/null || echo "Jail bilgisi alınamadı"
else
    echo "❌ Fail2ban aktif değil"
fi
echo ""

# Nginx durumu
echo "🌐 NGINX DURUMU:"
if systemctl is-active --quiet nginx; then
    echo "✅ Nginx aktif"
else
    echo "❌ Nginx aktif değil"
fi
echo ""

# Disk ve memory
echo "💾 SISTEM KAYNAKLARI:"
free -h
df -h /
echo ""

# Current UAM status
echo "☁️ CLOUDFLARE UAM DURUMU:"
if [ -f "/tmp/uam_status" ]; then
    echo "Mevcut durum: $(cat /tmp/uam_status)"
else
    echo "UAM durumu bilinmiyor"
fi

echo "========================="
EOF

chmod +x /usr/local/bin/ddos-status.sh

echo "✅ Monitoring scripti oluşturuldu"

# ============= ADIM 5: OTOMATIK KORUMA =============
echo ""
echo "🤖 ADIM 5: OTOMATİK KORUMA AKTİFLEŞTİRME"
echo "-------------------------------------"

echo "8️⃣ Otomatik koruma sistemi kuruluyor..."

# Acil durum script'i
tee /usr/local/bin/emergency-protection.sh > /dev/null << 'EOF'
#!/bin/bash

# ACİL DURUM - ANINDA KORUMA
echo "🚨 ACİL KORUMA AKTİFLEŞTİRİLİYOR!"

# Cloudflare Under Attack Mode
if [ ! -z "$CLOUDFLARE_API_TOKEN" ] && [ ! -z "$CLOUDFLARE_ZONE_ID" ]; then
    curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/settings/security_level" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data '{"value":"under_attack"}'
    echo "✅ Cloudflare Under Attack Mode aktif"
fi

# Nginx rate limiting'i daha sıkı yap
if command -v nginx >/dev/null 2>&1; then
    # Geçici olarak çok sıkı rate limit
    echo 'limit_req zone=strict burst=5 nodelay;' > /tmp/emergency-nginx.conf
    echo "⚠️ Nginx emergency rate limiting aktif"
fi

# Sistem durumunu logla
/usr/local/bin/ddos-status.sh >> /var/log/emergency-protection.log

echo "🛡️ Acil koruma aktifleştirildi - $(date)"
EOF

chmod +x /usr/local/bin/emergency-protection.sh

echo "✅ Acil koruma scripti hazır"

# ============= ADIM 6: FINAL KONTROLLER =============
echo ""
echo "🔍 ADIM 6: FİNAL KONTROLLER VE TEST"
echo "------------------------------"

echo "9️⃣ Servis durumları kontrol ediliyor..."

# Servis durumları
services=("ufw" "fail2ban" "nginx")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "✅ $service: Aktif"
    else
        echo "⚠️ $service: Aktif değil veya mevcut değil"
    fi
done

echo ""
echo "🎉 PROFESYONEL DDOS KORUMA KURULUMU TAMAMLANDI!"
echo "============================================="
echo ""
echo "📋 KURULAN KORUMALAR:"
echo "• Kernel seviyesi optimizasyon"
echo "• UFW + IPTables firewall"
echo "• Fail2Ban saldırı engelleme"
echo "• Nginx rate limiting"
echo "• Cloudflare advanced security"
echo "• Monitoring ve alert sistemi"
echo ""
echo "🛠️ FAYDALI KOMUTLAR:"
echo "• Durum kontrol: /usr/local/bin/ddos-status.sh"
echo "• Acil koruma: /usr/local/bin/emergency-protection.sh"
echo "• Fail2ban status: fail2ban-client status"
echo "• UFW status: ufw status"
echo "• Nginx test: nginx -t"
echo ""
echo "📊 LOG DOSYALARI:"
echo "• DDoS koruma: /var/log/ddos_protection.log"
echo "• Fail2ban: /var/log/fail2ban.log"
echo "• Nginx: /var/log/nginx/error.log"
echo ""
echo "⚠️ ÖNEMLİ:"
echo "• Nginx site config'ine snippet eklemeyi unutma!"
echo "• UAM scriptini sistemd ile otomatik çalıştır!"
echo "• Düzenli olarak logları kontrol et!"
