#!/bin/bash
# Read-only проверка здоровья AWG Router. Ничего не меняет.
# Запуск: sudo bash scripts/verify.sh
set -u

PANEL_DIR="${PANEL_DIR:-/home/pavelilyushin/awg-migration/web}"
PANEL_PORT="${PANEL_PORT:-51821}"
PANEL_USER="${PANEL_USER:-pavelilyushin}"
BASE="https://127.0.0.1:${PANEL_PORT}"
PASS="$(cat "$PANEL_DIR/web.pass" 2>/dev/null || true)"

pass=0
fail=0
ok()  { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }
code() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }

echo "== Сервисы =="
for s in awg-quick@awg0 awg-quick@awg1 awg-rules.service awg-web.service; do
    if systemctl is-active --quiet "$s"; then ok "$s active"; else bad "$s not active"; fi
done

echo "== Интерфейсы =="
awg show awg0 2>/dev/null | grep -q '^interface:' && ok "awg0 present" || bad "awg0 missing"
awg show awg1 2>/dev/null | grep -q '^interface:' && ok "awg1 present" || bad "awg1 missing"

echo "== Сеть =="
[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "1" ] && ok "ip_forward=1" || bad "ip_forward"
ip rule show 2>/dev/null | grep -q 'from 10.8.0.0/24 lookup awg_foreign' \
    && ok "policy rule 400" || bad "policy rule 400"
ip route show table 100 2>/dev/null | grep -q '^default dev awg1' \
    && ok "default via awg1 in table 100" || bad "default via awg1 in table 100"
iptables -t nat -S POSTROUTING 2>/dev/null | grep -q 'MASQUERADE' \
    && ok "NAT MASQUERADE" || bad "NAT MASQUERADE"
iptables -t mangle -S FORWARD 2>/dev/null | grep -q 'TCPMSS' \
    && ok "MSS clamping" || bad "MSS clamping"
RU_COUNT="$(ip route show table 100 2>/dev/null | grep -c 'via ')"
[ "$RU_COUNT" -gt 1000 ] && ok "RU routes: $RU_COUNT" || bad "RU routes: $RU_COUNT (мало)"

echo "== Панель =="
[ "$(code "$BASE/")" = "401" ] && ok "no auth -> 401" || bad "no auth -> 401"
if [ -n "$PASS" ]; then
    [ "$(code -u "$PANEL_USER:$PASS" "$BASE/")" = "200" ] \
        && ok "auth -> 200" || bad "auth -> 200"
else
    bad "web.pass пуст или недоступен"
fi
curl -sk -D - -o /dev/null "$BASE/" 2>/dev/null | tr -d '\r' \
    | grep -qi '^Server: gunicorn$' && ok "Server: gunicorn" || bad "Server header"
curl -sk -D - -o /dev/null "$BASE/" 2>/dev/null | tr -d '\r' \
    | grep -qi '^X-Content-Type-Options: nosniff' && ok "nosniff" || bad "nosniff"
[ "$(code "$BASE/favicon.ico")" = "204" ] && ok "favicon 204" || bad "favicon 204"
[ "$(code "$BASE/apple-touch-icon.png")" = "204" ] \
    && ok "apple-touch-icon 204" || bad "apple-touch-icon 204"
if curl -sk -D - -o /dev/null "$BASE/favicon.ico" 2>/dev/null | tr -d '\r' \
    | grep -qi '^WWW-Authenticate:'; then
    bad "favicon с WWW-Authenticate (iOS попросит пароль)"
else
    ok "favicon без WWW-Authenticate"
fi

echo "== Файлы =="
[ -f "$PANEL_DIR/app.py" ] && ok "app.py" || bad "app.py"
[ -f "$PANEL_DIR/web.pass" ] && ok "web.pass" || bad "web.pass"
[ -f "$PANEL_DIR/certs/server.crt" ] && ok "server.crt" || bad "server.crt"
[ -f "$PANEL_DIR/certs/server.key" ] && ok "server.key" || bad "server.key"
CLIENTS="$(ls -1 /etc/amnezia/amneziawg/clients/*.conf 2>/dev/null | wc -l)"
if [ $((CLIENTS % 2)) -eq 0 ]; then ok "client files: $CLIENTS (чётное)"; else bad "client files: $CLIENTS (нечётное)"; fi

echo "== Ошибки в журнале за 15 минут =="
if journalctl -u awg-web.service --since "-15 min" --no-pager 2>/dev/null \
    | grep -qiE 'traceback|critical|exception'; then
    bad "есть ошибки в журнале awg-web"
else
    ok "журнал awg-web чист"
fi

echo
echo "PASS=$pass FAIL=$fail"
if [ "$fail" -eq 0 ]; then
    echo "ALL GREEN"
    exit 0
else
    echo "THERE ARE FAILURES"
    exit 1
fi
