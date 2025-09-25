#!/bin/sh

# PATH'i genişlet - curl'ün bulunması için
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Konfigürasyon
CLOUDFLARE_API_TOKEN=""  # Environment variable'dan al
ZONE_ID=""                 # Environment variable'dan al
LOAD_THRESHOLD=2.0                              # CPU sayına göre ayarla
CONNECTION_THRESHOLD=1000                       # Aktif bağlantı limiti
CHECK_INTERVAL=15                               # Saniye cinsinden kontrol aralığı
LOG_FILE="/var/log/ddos_protection.log"
STATUS_FILE="/tmp/uam_status"

# Log fonksiyonu
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Hata kontrolü fonksiyonu
check_requirements() {
    # Gerekli komutları kontrol et - daha esnek yöntem
    for cmd in curl bc netstat; do
        if ! which "$cmd" >/dev/null 2>&1 && ! type "$cmd" >/dev/null 2>&1; then
            log_message "HATA: $cmd komutu bulunamadı! PATH'te mevcut değil."
            log_message "Mevcut PATH: $PATH"
            # curl için alternatif yolları kontrol et
            if [ "$cmd" = "curl" ]; then
                for path in /usr/bin/curl /usr/local/bin/curl /bin/curl; do
                    if [ -x "$path" ]; then
                        log_message "curl bulundu: $path"
                        export CURL_PATH="$path"
                        break
                    fi
                done
                if [ -z "$CURL_PATH" ]; then
                    exit 1
                fi
            else
                exit 1
            fi
        fi
    done
    
    # API token kontrolü
    if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
        log_message "HATA: CLOUDFLARE_API_TOKEN environment variable tanımlı değil!"
        exit 1
    fi
    
    # Zone ID kontrolü
    if [ -z "$ZONE_ID" ]; then
        log_message "HATA: CLOUDFLARE_ZONE_ID environment variable tanımlı değil!"
        exit 1
    fi
}

# Sistem metrikleri alma
get_system_metrics() {
    # CPU Load Average (1 dakika)
    LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')
    
    # Aktif TCP bağlantı sayısı - daha güvenli yöntem
    CONNECTIONS=$(netstat -an 2>/dev/null | grep ":80 " | grep ESTABLISHED | wc -l)
    # Eğer netstat çalışmazsa ss kullan
    if [ -z "$CONNECTIONS" ] || [ "$CONNECTIONS" = "" ]; then
        CONNECTIONS=$(ss -tn 2>/dev/null | grep ":80 " | grep ESTAB | wc -l)
    fi
    # Hala boşsa 0 yap
    if [ -z "$CONNECTIONS" ] || [ "$CONNECTIONS" = "" ]; then
        CONNECTIONS=0
    fi
    
    # HTTP ve HTTPS bağlantılarını da say
    HTTP_CONNECTIONS=$(netstat -an 2>/dev/null | grep -E ":(80|443) " | grep ESTABLISHED | wc -l)
    if [ -z "$HTTP_CONNECTIONS" ] || [ "$HTTP_CONNECTIONS" = "" ]; then
        HTTP_CONNECTIONS=$(ss -tn 2>/dev/null | grep -E ":(80|443) " | grep ESTAB | wc -l)
    fi
    if [ -z "$HTTP_CONNECTIONS" ] || [ "$HTTP_CONNECTIONS" = "" ]; then
        HTTP_CONNECTIONS=0
    fi
    
    # Hafıza kullanımı (opsiyonel)
    MEMORY=$(free | grep Mem | awk '{printf "%.1f", ($3/$2)*100}')
    
    echo "Load: $LOAD, Connections: $CONNECTIONS, HTTP_Total: $HTTP_CONNECTIONS, Memory: ${MEMORY}%"
}

# Cloudflare API çağrısı
set_security_level() {
    local security_level="$1"
    local response
    local curl_cmd="${CURL_PATH:-curl}"
    
    response=$($curl_cmd -s -w "%{http_code}" -X PATCH \
        "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/settings/security_level" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"value\":\"$security_level\"}")
    
    local http_code=$(echo "$response" | tail -c 4)
    local body=$(echo "$response" | sed 's/...$//')
    
    if [ "$http_code" = "200" ]; then
        log_message "✓ Güvenlik seviyesi '$security_level' olarak ayarlandı"
        echo "$security_level" > "$STATUS_FILE"
        return 0
    else
        log_message "✗ API çağrısı başarısız! HTTP Code: $http_code, Response: $body"
        return 1
    fi
}

# Mevcut durumu kontrol et
get_current_status() {
    if [ -f "$STATUS_FILE" ]; then
        cat "$STATUS_FILE"
    else
        echo "unknown"
    fi
}

# Sayısal karşılaştırma fonksiyonu
compare_float() {
    # $1 > $2 ise 1, değilse 0 döndürür
    awk -v a="$1" -v b="$2" 'BEGIN { print (a > b) ? 1 : 0 }'
}

# Ana kontrol fonksiyonu
check_and_act() {
    local metrics
    local current_status
    
    metrics=$(get_system_metrics)
    current_status=$(get_current_status)
    
    log_message "Sistem durumu: $metrics"
    
    # Load ve bağlantı sayısını kontrol et - güvenli parsing
    LOAD=$(echo "$metrics" | awk -F'Load: |,' '{print $2}' | tr -d ' ')
    CONNECTIONS=$(echo "$metrics" | awk -F'Connections: |,' '{print $2}' | tr -d ' ')
    HTTP_CONNECTIONS=$(echo "$metrics" | awk -F'HTTP_Total: |,' '{print $2}' | tr -d ' ')
    
    # Boş değerleri kontrol et ve varsayılan değer ata
    if [ -z "$LOAD" ] || [ "$LOAD" = "" ]; then LOAD="0.0"; fi
    if [ -z "$CONNECTIONS" ] || [ "$CONNECTIONS" = "" ]; then CONNECTIONS="0"; fi
    if [ -z "$HTTP_CONNECTIONS" ] || [ "$HTTP_CONNECTIONS" = "" ]; then HTTP_CONNECTIONS="0"; fi
    
    # Debug için değerleri logla
    log_message "Debug - LOAD: '$LOAD', CONNECTIONS: '$CONNECTIONS', HTTP_CONNECTIONS: '$HTTP_CONNECTIONS'"
    
    # Saldırı algılama mantığı
    attack_detected=false
    
    # Yüksek load kontrolü
    if [ "$(compare_float "$LOAD" "$LOAD_THRESHOLD")" = "1" ]; then
        log_message "⚠️  Yüksek load tespit edildi: $LOAD"
        attack_detected=true
    fi
    
    # Yüksek bağlantı sayısı kontrolü - güvenli sayısal karşılaştırma
    if [ "$CONNECTIONS" -gt 0 ] 2>/dev/null && [ "$CONNECTIONS" -gt "$CONNECTION_THRESHOLD" ] 2>/dev/null; then
        log_message "⚠️  Yüksek bağlantı sayısı tespit edildi: $CONNECTIONS"
        attack_detected=true
    fi
    
    # HTTP+HTTPS toplam bağlantı kontrolü
    if [ "$HTTP_CONNECTIONS" -gt 0 ] 2>/dev/null && [ "$HTTP_CONNECTIONS" -gt "$CONNECTION_THRESHOLD" ] 2>/dev/null; then
        log_message "⚠️  Yüksek HTTP/HTTPS bağlantı sayısı tespit edildi: $HTTP_CONNECTIONS"
        attack_detected=true
    fi
    
    # Durum değerlendirmesi ve aksiyon alma
    if [ "$attack_detected" = "true" ] && [ "$current_status" != "under_attack" ]; then
        log_message "🚨 SALDIRI TESPİT EDİLDİ! Under Attack Mode aktifleştiriliyor..."
        set_security_level "under_attack"
        
    elif [ "$attack_detected" = "false" ] && [ "$current_status" = "under_attack" ]; then
        log_message "✅ Sistem normale döndü. Under Attack Mode devre dışı bırakılıyor..."
        set_security_level "high"
        
    else
        log_message "ℹ️  Durum değişikliği gerekmiyor. Mevcut durum: $current_status"
    fi
}

# Sürekli monitör fonksiyonu
monitor_continuous() {
    log_message "🔄 Sürekli monitörleme başlatıldı (${CHECK_INTERVAL}s aralıklarla)"
    
    while true; do
        check_and_act
        sleep "$CHECK_INTERVAL"
    done
}

# Ana program
main() {
    case "${1:-check}" in
        "check")
            check_requirements
            check_and_act
            ;;
        "monitor")
            check_requirements
            monitor_continuous
            ;;
        "status")
            echo "Mevcut durum: $(get_current_status)"
            get_system_metrics
            ;;
        "force-uam")
            check_requirements
            set_security_level "under_attack"
            ;;
        "force-normal")
            check_requirements
            set_security_level "high"
            ;;
        *)
            echo "Kullanım: $0 {check|monitor|status|force-uam|force-normal}"
            echo ""
            echo "  check       - Tek seferlik kontrol yap"
            echo "  monitor     - Sürekli monitörleme başlat"
            echo "  status      - Mevcut durumu göster"
            echo "  force-uam   - Under Attack Mode'u zorla aktifleştir"
            echo "  force-normal- Normal moda zorla geç"
            exit 1
            ;;
    esac
}

# Programı çalıştır
main "$@"