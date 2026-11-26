# Эксплуатация, диагностика и обслуживание

Краткий справочник по повседневной работе с AWG Router.

---

## 1. Быстрая проверка состояния

```bash
# Все сервисы
systemctl is-active awg-quick@awg0 awg-quick@awg1 awg-rules.service awg-web.service

# Интерфейсы, handshake, трафик
awg show

# Policy-rule и таблица RU
ip rule show | grep 400
ip route show table 100 | head -5
ip route show table 100 | wc -l

# NAT и MSS
sudo iptables -t nat -S POSTROUTING | grep MASQUERADE
sudo iptables -t mangle -S FORWARD | grep TCPMSS

# Панель
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:51821/
```

Полный read-only чек-лист:

```bash
sudo bash scripts/verify.sh
```

---

## 2. Логи

| Что | Команда / файл |
|---|---|
| Панель (gunicorn, запросы, ошибки) | `journalctl -u awg-web.service -f` |
| Интерфейс `awg0` | `journalctl -u awg-quick@awg0 -f` |
| Интерфейс `awg1` | `journalctl -u awg-quick@awg1 -f` |
| Правила маршрутизации | `journalctl -u awg-rules.service` |
| Пересборка DKMS | `journalctl -u amneziawg-ensure-module.service` |
| RU-обновления | `/var/log/ru-routes-update.log` |
| DKMS-хук apt | `/var/log/amneziawg-ensure-module.log` |
| Ошибки панели за час | `journalctl -u awg-web.service --since -1h \| grep -iE 'traceback\|error'` |

Gunicorn пишет access-log в journal: IP, пользователь, метод, путь, код, размер,
User-Agent. Пароль в лог не попадает.

---

## 3. Панель: поведение и ограничения

- **Авторизация** — HTTP Basic. Пароль читается из `WEB_PASSWORD_FILE`
  (по умолчанию `.../web.pass`, права `600`).
- **Иконки** — `GET /favicon.ico` и `/apple-touch-icon*` отдаются без
  авторизации (`204`). iOS Safari запрашивает их отдельным процессом без
  Basic-кредов; если ответить `401`, появляется второе окно пароля сразу
  после успешного входа.
- **CSRF** — скрытое поле `csrf` во всех POST-формах; токен детерминированно
  выводится из пароля.
- **Rate-limit** — 10 неудачных попыток за 600 секунд на IP → `429` +
  `Retry-After: 600`. Счётчик хранится в памяти процесса и сбрасывается
  рестартом `awg-web.service`.
- **Автообновление** — страница опрашивает `/api/status`, `/api/peers`,
  `/api/ru` каждые 10 секунд.
- **Handshake** — зелёный ≤ 180 с, оранжевый ≤ 24 ч, красный > 24 ч,
  серый «нет». В таблице цвет применяется к тексту и точке, в карточках —
  к рамке и фону (`stale-warn` / `stale-err`).
- **MAC** — берётся из ARP (`ip neigh`) только для клиентов локальной сети,
  кэш `/var/lib/awg-web/peer-info.json` (TTL 120 с, обновление раз в 45 с).
  Для внешних клиентов MAC недоступен — прочерк.
- **Внешний IP** — определяется через `ifconfig.me`, кэш 60 с, fallback в
  `/var/lib/awg-web/last-external-ip`.
- **Локальный endpoint** — `detect_internal()` берёт адрес LAN-интерфейса и
  **исключает адреса `awg0`/`awg1`**. Иначе `ip route get 1.1.1.1` вернул бы
  `src 10.71.107.82`, и локальный конфиг клиента указывал бы на адрес внутри
  туннеля, недоступный до подключения. Переопределяется `INTERNAL_ENDPOINT`.
- **QR** — `qrencode`, страница с двумя кодами; **конфиги** — ZIP с двумя
  файлами (`<имя>.conf` и `<имя>-local.conf`).
- **Upstream** — редактор `awg1.conf`: проверка `awg-quick strip`,
  автодобавление `Table = off`, бэкап `awg1.conf.bak.<timestamp>`, рестарт
  `awg1`, ожидание handshake 25 с, откат при неудаче.
- **Перезагрузка RPi** — кнопка в шапке, команда `systemctl reboot --no-block`.

---

## 4. Типовые проблемы

### 4.1. Панель отвечает 401

- Неверный логин/пароль. Логин задан в `WEB_USER` (по умолчанию
  `pavelilyushin`).
- Проверьте файл:
  ```bash
  sudo cat /home/pavelilyushin/awg-migration/web/web.pass
  sudo systemctl restart awg-web.service
  ```
- Если пароль меняли — рестарт обязателен: он читается при старте процесса.

### 4.2. Панель отвечает 429

Слишком много неудачных попыток с вашего IP. Подождите 10 минут или
сбросьте счётчик рестартом:

```bash
sudo systemctl restart awg-web.service
```

### 4.3. Панель не открывается / connection refused

```bash
sudo systemctl status awg-web.service --no-pager
sudo journalctl -u awg-web.service -n 50 --no-pager
ss -ltnp | grep 51821
```

Частые причины:

- не установлен `gunicorn` или не тот путь в `ExecStart`;
- нет/просрочен сертификат или неверные права на `server.key`;
- порт занят другим процессом;
- синтаксическая ошибка в `app.py` — `python3 -m py_compile app.py`.

### 4.4. Клиент подключён, но нет handshake

```bash
awg show awg0
sudo journalctl -u awg-quick@awg0 -n 30 --no-pager
```

Проверьте:

- клиент импортировал именно тот конфиг (внешний/локальный endpoint);
- в локальном конфиге `Endpoint` — LAN-адрес роутера (`192.168.89.245`), а не
  `10.71.107.82` (адрес `awg1`) и не `0.0.0.0`;
- UDP `51820` доступен извне (проброс порта на домашнем роутере);
- `PublicKey` клиента совпадает с пиром в `awg0.conf`;
- `AllowedIPs` клиента — `10.8.0.X/32`, без пересечений;
- время на клиенте корректно (сильно сбитые часы ломают handshake).

Если локальный конфиг содержит `Endpoint = 10.71.107.82:51820`, он создан
старой версией панели (до исправления `detect_internal()`). Удалите такого
клиента и создайте заново — новый конфиг получит LAN-адрес.

### 4.5. `awg1` не поднимается / нет handshake провайдера

```bash
sudo systemctl status awg-quick@awg1 --no-pager
sudo journalctl -u awg-quick@awg1 -n 50 --no-pager
awg show awg1
```

Проверьте:

- `Table = off` присутствует;
- `Endpoint`, ключи и параметры обфускации (`Jc/Jmin/Jmax/S1–S4/H1–H4/i1`)
  совпадают с выданными провайдером;
- провайдер не сменил сервер;
- исходящий UDP не блокируется провайдером интернета.

### 4.6. Клиенты подключаются, но интернета нет

Проверьте по порядку:

```bash
sysctl net.ipv4.ip_forward                       # 1
ip rule show | grep 400                          # from 10.8.0.0/24 lookup awg_foreign
ip route show table 100 | head                   # default dev awg1
sudo iptables -t nat -S POSTROUTING | grep MASQUERADE
```

Частые причины:

- не сохранён NAT (`netfilter-persistent save`);
- нет policy-rule или `awg-rules.service` не запущен;
- в таблице 100 нет `default dev awg1`;
- клиентский DNS недоступен (в конфиге `DNS = 1.1.1.1`).

### 4.7. Российские сайты идут через VPN

```bash
tail -20 /var/log/ru-routes-update.log
ip route show table 100 | grep -c 'via 192.168.89.1'
```

Если маршрутов мало/нет — обновите вручную:

```bash
sudo flock -n /run/update-ru-routes.lock /usr/local/bin/update-ru-routes.sh
```

Причина может быть в недоступности `ipdeny.com`; проверьте
`curl -I https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone`.
Обновление инкрементальное: неизменённые маршруты не удаляются, поэтому
RU-трафик не проваливается в VPN. Обычно 1–3 с; полная заливка — только на
чистой системе. В логе смотрите строку
`Added N RU routes, removed M, unchanged K`.

### 4.8. После обновления ядра пропал VPN

DKMS-модуль не собрался под новое ядро.

```bash
dkms status
sudo systemctl status amneziawg-ensure-module.service --no-pager
sudo dkms autoinstall
sudo modprobe amneziawg
```

Если не помогает — установите заголовки под текущее ядро и перезагрузитесь:

```bash
sudo apt install linux-headers-$(uname -r)
sudo reboot
```

### 4.9. QR не открывается (500)

```bash
command -v qrencode || sudo apt install -y qrencode
```

### 4.10. Переименование отклонено

Имя должно соответствовать `^[\w-]{1,32}$`: буквы (включая кириллицу), цифры,
`_`, `-`, до 32 символов. Имя не должно совпадать с существующим.

### 4.11. Панель медленно открывается

Первый запрос после старта может занять ~0.6 с: панель определяет внешний IP.
Далее ~0.2 с. Если `ifconfig.me` недоступен, используется последний известный
IP из `/var/lib/awg-web/last-external-ip`.

### 4.12. Растёт journal/логи

```bash
sudo journalctl --disk-usage
sudo journalctl --vacuum-time=14d
```

`/var/log/ru-routes-update.log` и `/var/log/amneziawg-ensure-module.log`
ротируются (второй — через logrotate). При необходимости добавьте logrotate
для RU-лога.

### 4.13. После входа панель снова просит пароль (iOS/Safari)

Симптом: пароль принят, страница открылась, но сразу появляется второе окно.

Причина: Safari на iOS запрашивает `/favicon.ico` и `/apple-touch-icon*.png`
отдельным процессом (`NetworkingExtension`) без Basic-кредов. Если ответить
`401` с `WWW-Authenticate`, браузер показывает второе окно пароля.

Проверка:

```bash
curl -sk -D - -o /dev/null https://192.168.89.245:51821/favicon.ico \
  | tr -d '\r' | head -5
```

Должно быть `204 No Content` и **не** должно быть `WWW-Authenticate`.
В актуальной `app.py` эти пути публичные; если у вас старый файл — обновите
панель:

```bash
sudo bash scripts/deploy-panel.sh panel/app.py
```

---

## 5. Бэкапы

Что важно сохранить:

```bash
sudo tar czf /root/awg-router-backup-$(date +%F).tgz \
  /etc/amnezia/amneziawg \
  /etc/systemd/system/awg-web.service \
  /etc/systemd/system/awg-rules.service \
  /etc/systemd/system/amneziawg-ensure-module.service \
  /etc/iptables/rules.v4 \
  /etc/sysctl.d/99-amneziawg-security.conf \
  /usr/local/bin/update-ru-routes.sh \
  /usr/local/sbin/amneziawg-ensure-module \
  /home/pavelilyushin/awg-migration/web/app.py \
  /home/pavelilyushin/awg-migration/web/web.pass \
  /home/pavelilyushin/awg-migration/web/certs
```

Восстановление:

```bash
sudo tar xzf /root/awg-router-backup-YYYY-MM-DD.tgz -C /
sudo systemctl daemon-reload
sudo sysctl --system
sudo netfilter-persistent reload
sudo systemctl restart awg-quick@awg1 awg-quick@awg0 awg-rules.service awg-web.service
```

> В архиве лежат приватные ключи и пароль панели. Храните его с правами `600`
> и не выкладывайте в git/облако без шифрования.

---

## 6. Обновление панели

```bash
# локально: проверка синтаксиса и деплой
sudo bash scripts/deploy-panel.sh panel/app.py
```

Скрипт:

1. делает бэкап текущего `app.py` → `app.py.bak.<timestamp>`;
2. проверяет новый файл через `python3 -m py_compile`;
3. устанавливает с правами `600` и владельцем `pavelilyushin`;
4. перезапускает `awg-web.service` и проверяет `401` без пароля и `200`
   с паролем; при неудаче откатывает бэкап.

Ручной откат:

```bash
sudo cp -a /home/pavelilyushin/awg-migration/web/app.py.bak.<timestamp> \
          /home/pavelilyushin/awg-migration/web/app.py
sudo systemctl restart awg-web.service
```

После обновления прогоните `sudo bash scripts/verify.sh`.

---

## 7. Смена пароля панели

```bash
printf '%s\n' 'НОВЫЙ_ПАРОЛЬ' | sudo tee /home/pavelilyushin/awg-migration/web/web.pass >/dev/null
sudo chown pavelilyushin:pavelilyushin /home/pavelilyushin/awg-migration/web/web.pass
sudo chmod 600 /home/pavelilyushin/awg-migration/web/web.pass
sudo systemctl restart awg-web.service
```

Рестарт также сбрасывает rate-limit. CSRF-токен изменится автоматически
(он выводится из пароля), старые открытые формы нужно обновить.

---

## 8. Замена TLS-сертификата

```bash
cd /home/pavelilyushin/awg-migration/web/certs
sudo openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout server.key -out server.crt \
  -subj "/CN=awg-router" \
  -addext "subjectAltName=IP:192.168.89.245,DNS:awg-router.local"
sudo chown pavelilyushin:pavelilyushin server.key server.crt
sudo chmod 600 server.key
sudo chmod 644 server.crt
sudo systemctl restart awg-web.service
```

Если меняете IP роутера — обновите SAN и юнит/конфиги.

---

## 9. Обновление системы

```bash
sudo apt update
sudo apt full-upgrade -y
sudo reboot
```

После перезагрузки проверьте:

```bash
systemctl is-active awg-quick@awg0 awg-quick@awg1 awg-rules.service awg-web.service
awg show
sudo bash scripts/verify.sh
```

`amneziawg-ensure-module.service` пересоберёт DKMS-модуль под новое ядро,
apt-хук сделает это заранее при установке пакетов ядра.

---

## 10. Мониторинг (опционально)

Установите health-check и добавьте его в cron:

```bash
sudo install -m 0755 scripts/verify.sh /usr/local/bin/verify.sh
```

```cron
*/15 * * * * /usr/local/bin/verify.sh >/dev/null 2>&1 || logger -t awg-verify "health check failed"
```

Скрипт только читает состояние и не меняет конфигурацию.

---

## 11. Безопасность

- Панель не публикуйте в интернет; доступ — из LAN или через VPN.
- Пароль — длинный, уникальный; файл `web.pass` — `600`.
- TLS самоподписанный: это защищает канал от пассивного прослушивания,
  но не от подмены. Для строгой проверки добавьте свой CA в доверенные.
- Приватные ключи (`awg0.conf`, `awg1.conf`, `clients/*.conf`,
  `certs/server.key`) — только `600`, владелец `root`/`pavelilyushin`.
- Регулярно обновляйте систему и AmneziaWG.
- Бэкапы содержат секреты — храните их зашифрованными.
