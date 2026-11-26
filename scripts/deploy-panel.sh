#!/bin/bash
# Безопасное обновление панели: бэкап -> проверка синтаксиса -> установка -> рестарт.
# Запускать от root:
#   sudo bash scripts/deploy-panel.sh panel/app.py
set -euo pipefail

SRC="${1:-panel/app.py}"
PANEL_USER="${PANEL_USER:-pavelilyushin}"
PANEL_DIR="${PANEL_DIR:-/home/pavelilyushin/awg-migration/web}"
PANEL_PORT="${PANEL_PORT:-51821}"
DEST="$PANEL_DIR/app.py"
TS="$(date +%Y%m%d-%H%M%S)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Ошибка: запускать от root (sudo)" >&2
    exit 1
fi
if [ ! -f "$SRC" ]; then
    echo "Ошибка: нет файла $SRC" >&2
    exit 1
fi

python3 -m py_compile "$SRC"
echo "syntax OK: $SRC"

if [ -f "$DEST" ]; then
    cp -a "$DEST" "$DEST.bak.$TS"
    echo "backup: $DEST.bak.$TS"
fi

install -m 0600 -o "$PANEL_USER" -g "$PANEL_USER" "$SRC" "$DEST"
systemctl restart awg-web.service
sleep 2

BASE="https://127.0.0.1:${PANEL_PORT}"
CODE_NOAUTH="$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/" || true)"
PASS="$(cat "$PANEL_DIR/web.pass" 2>/dev/null || true)"
CODE_AUTH=""
if [ -n "$PASS" ]; then
    CODE_AUTH="$(curl -sk -u "$PANEL_USER:$PASS" -o /dev/null -w '%{http_code}' "$BASE/" || true)"
fi

if systemctl is-active --quiet awg-web.service \
   && [ "$CODE_NOAUTH" = "401" ] \
   && { [ -z "$PASS" ] || [ "$CODE_AUTH" = "200" ]; }; then
    echo "OK: панель обновлена и запущена (401 без пароля, 200 с паролем)"
else
    echo "FAILED: панель не отвечает как ожидалось (noauth=$CODE_NOAUTH auth=$CODE_AUTH), откатываю бэкап" >&2
    journalctl -u awg-web.service -n 30 --no-pager >&2 || true
    if [ -f "$DEST.bak.$TS" ]; then
        cp -a "$DEST.bak.$TS" "$DEST"
        systemctl restart awg-web.service || true
    fi
    exit 1
fi
