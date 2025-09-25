## hızlı manual koruma
# 1. IPTables klasörü oluştur
mkdir -p /etc/iptables

# 2. Mevcut kuralları kaydet
iptables-save > /etc/iptables/rules.v4

# 3. Nginx site config'ini düzenle
nano /etc/nginx/sites-available/default

## nginx settings
```bash
server {
    # Mevcut ayarların altına ekle:
    include /etc/nginx/snippets/site-protection.conf;
    
    # Rate limiting
    limit_req zone=general burst=20 nodelay;
    limit_conn perip 20;
}
```

## acil durum
# 1. Anında koruma için
/usr/local/bin/emergency-protection.sh

# 2. Cloudflare'i manual olarak Under Attack Mode'a al
./uam.sh force-uam

# 🛠️ FAYDALI KOMUTLAR:
- Durum kontrol: /usr/local/bin/ddos-status.sh
- Acil koruma: /usr/local/bin/emergency-protection.sh
- Fail2ban status: fail2ban-client status
- UFW status: ufw status
- Nginx test: nginx -t

# 4. UAM scriptini 5 saniyede bir çalıştır
```bash
(crontab -l; echo "* * * * * /home/underattack/uam.sh check") | crontab -
(crontab -l; echo "* * * * * sleep 5; /home/underattack/uam.sh check") | crontab -
(crontab -l; echo "* * * * * sleep 10; /home/underattack/uam.sh check") | crontab -
```