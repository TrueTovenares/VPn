#!/bin/bash
# Инкрементальное обновление RU-маршрутов в таблице 100.
# Добавляет только новые сети и удаляет только исчезнувшие;
# неизменённые маршруты не трогает (нет простоя RU-трафика).
# Запускать от root (cron/панель уже оборачивают вызов в flock).

set -u
export LC_ALL=C

LOG_FILE="${LOG_FILE:-/var/log/ru-routes-update.log}"
TABLE="${TABLE:-100}"
GATEWAY="${GATEWAY:-192.168.89.1}"
WAN_IF="${WAN_IF:-eth0}"
RU_LIST="${RU_LIST:-/tmp/ru-aggregated.zone}"
RU_URL="${RU_URL:-https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone}"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S'): $*" >> "$LOG_FILE"; }
say() { log "$*"; echo "$*"; }

TMP_LIST="$(mktemp /tmp/ru-routes.XXXXXX)" || exit 1
TMP_NORM="${TMP_LIST}.norm"
TMP_CUR="${TMP_LIST}.cur"
trap 'rm -f "$TMP_LIST" "$TMP_NORM" "$TMP_CUR"' EXIT

log "Starting RU routes update"

# 1. Скачиваем список во временный файл. При ошибке старые маршруты не трогаем.
if ! curl -fsS --max-time 60 --retry 2 --retry-delay 2 "$RU_URL" -o "$TMP_LIST"; then
    say "ERROR: download failed: $RU_URL"
    exit 1
fi
if [ ! -s "$TMP_LIST" ]; then
    say "ERROR: RU list is empty"
    exit 1
fi

# 2. Нормализуем: убираем CR/пробелы, оставляем только IPv4-CIDR, сортируем.
sed -e 's/\r$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$TMP_LIST" \
    | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' \
    | sort -u > "$TMP_NORM"
if [ ! -s "$TMP_NORM" ]; then
    say "ERROR: no valid networks in RU list"
    exit 1
fi

# 3. Текущие маршруты через LAN-шлюз в таблице 100.
ip route show table "$TABLE" 2>/dev/null \
    | awk -v gw="$GATEWAY" '{for (i = 1; i < NF; i++) if ($i == "via" && $(i+1) == gw) {print $1; break}}' \
    | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' \
    | sort -u > "$TMP_CUR"

declare -A NEW=() CUR=()
while IFS= read -r net; do NEW["$net"]=1; done < "$TMP_NORM"
while IFS= read -r net; do CUR["$net"]=1; done < "$TMP_CUR"

TOTAL=$(wc -l < "$TMP_NORM" | tr -d ' ')
UNCHANGED=$(comm -12 "$TMP_NORM" "$TMP_CUR" | wc -l | tr -d ' ')
ADDED=0; ADD_FAIL=0; REMOVED=0; DEL_FAIL=0

# 4. Сначала добавляем новые — существующие маршруты продолжают работать.
while IFS= read -r net; do
    [ -n "${CUR[$net]:-}" ] && continue
    if ip route replace "$net" via "$GATEWAY" dev "$WAN_IF" table "$TABLE" 2>/dev/null; then
        ADDED=$((ADDED + 1))
    else
        ADD_FAIL=$((ADD_FAIL + 1))
    fi
done < "$TMP_NORM"

# 5. Затем удаляем только те, которых больше нет в списке.
while IFS= read -r net; do
    [ -n "${NEW[$net]:-}" ] && continue
    if ip route del "$net" table "$TABLE" 2>/dev/null; then
        REMOVED=$((REMOVED + 1))
    else
        DEL_FAIL=$((DEL_FAIL + 1))
    fi
done < "$TMP_CUR"

# 6. Список сохраняем после применения: mtime — это «последнее обновление».
mv -f "$TMP_NORM" "$RU_LIST"
chmod 644 "$RU_LIST" 2>/dev/null || true

FAILED=$((ADD_FAIL + DEL_FAIL))
log "Downloaded $TOTAL RU networks"
say "Added $ADDED RU routes, removed $REMOVED, unchanged $UNCHANGED, failed $FAILED (total $TOTAL)"
log "Update complete"

if [ "$FAILED" -ne 0 ]; then
    exit 2
fi
exit 0
