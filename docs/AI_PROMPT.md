# Промт для ИИ: воссоздать AWG Router с нуля

Ниже — готовый промт, который можно передать ИИ-агенту с доступом к серверу
(SSH/shell) или к репозиторию. Он описывает цель, ограничения, порядок работ
и критерии приёмки.

Скопируйте текст из блока ниже целиком.

````text
Ты — senior Linux/network engineer. Воссоздай проект «AWG Router» на чистой
Raspberry Pi 4 с Debian 13 (trixie) arm64: VPN-роутер на AmneziaWG с
split-routing по России и собственной веб-панелью управления.

====================================================================
1. ЦЕЛЬ
====================================================================
Получить работающий домашний VPN-роутер:
- клиенты (телефоны/ноутбуки) подключаются к awg0 (UDP 51820, 10.8.0.0/24);
- их трафик уходит в upstream-туннель awg1 к VPN-провайдеру;
- адреса из RU-списка идут напрямую через домашний шлюз;
- веб-панель на HTTPS :51821 управляет клиентами, QR/конфигами,
  интерфейсами, upstream и RU-маршрутами.

====================================================================
2. ВХОДНЫЕ ДАННЫЕ — УТОЧНИ У ПОЛЬЗОВАТЕЛЯ
====================================================================
Не начинай установку, пока не получишь/не подтвердишь:
1. Параметры LAN: подсеть, шлюз, интерфейс, IP роутера.
   Пример этой инсталляции: 192.168.89.0/24, gw 192.168.89.1, eth0,
   роутер 192.168.89.245.
2. Полный конфиг upstream от VPN-провайдера (AmneziaWG/WireGuard):
   Address, PrivateKey, PublicKey, Endpoint, обфускация Jc/Jmin/Jmax/
   S1-S4/H1-H4/i1 (если есть).
3. Логин панели и пароль (пароль не придумывай сам, если пользователь
   хочет свой; сохрани в файл, не в юнит).
4. Доступ по SSH и sudo. Не меняй SSH-порт и не блокируй доступ.
5. Можно ли перезагружать устройство (спроси перед reboot).

====================================================================
3. АРТЕФАКТЫ ПРОЕКТА
====================================================================
Если у тебя есть этот репозиторий, используй файлы КАК ЕСТЬ:
- panel/app.py                         — исходник панели (эталон)
- systemd/awg-web.service              — systemd-юнит панели (gunicorn)
- panel/web.pass.example               — пример файла пароля
- systemd/awg-rules.service            — policy-rule + маршруты
- systemd/amneziawg-ensure-module.service
- scripts/amneziawg-ensure-module      — пересборка DKMS после ядра
- scripts/update-ru-routes.sh          — обновление RU-маршрутов
- scripts/deploy-panel.sh              — безопасное обновление панели
- scripts/verify.sh                    — read-only health check
- config/99-amneziawg-security.conf    — sysctl
- config/rt_tables                     — именованная таблица 100
- config/rules.v4.example              — NAT + MSS
- config/awg0.conf.example             — шаблон серверного интерфейса
- config/awg1.conf.example             — шаблон upstream
- docs/INSTALL.md                      — подробная ручная инструкция
- docs/OPERATIONS.md                   — эксплуатация и диагностика

Если файлов нет — восстанови их по спецификации в разделе 9.

====================================================================
4. ПРАВИЛА БЕЗОПАСНОСТИ (ОБЯЗАТЕЛЬНО)
====================================================================
- Перед изменением любого файла делай бэкап с timestamp.
- Никогда не меняй маршрут по умолчанию и не включай Table = auto
  на awg1: это ломает LAN/SSH. На awg1 обязателен `Table = off`.
- Не блокируй SSH и не включай firewall, который отрежет текущую сессию.
- Не перезагружай устройство без явного подтверждения.
- Не печатай в отчёт приватные ключи, пароли и содержимое web.pass.
- Все команды выполняй с `set -euo pipefail` в скриптах; проверяй коды
  возврата. Секреты — только в файлах с правами 600.
- После каждого этапа — проверка, а не «надеюсь, сработало».

====================================================================
5. ПЛАН РАБОТ
====================================================================
Этап 0. Инвентаризация
- Зафиксируй: uname -a, /etc/os-release, ip -4 addr, ip route, свободное
  место, версии python3/flask/gunicorn/qrencode/awg.
- Проверь, не заняты ли порты 51820/udp и 51821/tcp.

Этап 1. Базовые пакеты
- apt update && apt install: python3, python3-flask, python3-werkzeug,
  gunicorn, qrencode, iptables, iptables-persistent, netfilter-persistent,
  dkms, build-essential, linux-headers-rpi-v8 (или подходящие под ядро).

Этап 2. AmneziaWG
- Подключи Amnezia PPA (Ubuntu noble) с ключом
  75C9DD72C799870E310542E2466F2C257290828 в /etc/apt/keyrings/.
- Установи amneziawg, amneziawg-tools, amneziawg-dkms.
- modprobe amneziawg; проверь lsmod и `awg --version`.
- Установи amneziawg-ensure-module + unit + apt-hook + logrotate,
  включи unit. Это пересобирает DKMS после обновления ядра.

Этап 3. Sysctl
- Установи config/99-amneziawg-security.conf, выполни sysctl --system.
- Проверь net.ipv4.ip_forward=1 и rp_filter=2.

Этап 4. Интерфейсы
- Создай /etc/amnezia/amneziawg (0750 root:pavelilyushin) и clients (0700).
- awg0.conf: Address 10.8.0.1/24, ListenPort 51820, PrivateKey,
  MTU 1280. Без Table = off.
- awg1.conf: полный конфиг провайдера + `Table = off`.
- Права 600 root:root на оба файла.
- systemctl enable --now awg-quick@awg1, затем awg-quick@awg0.
- Проверь `awg show`.

Этап 5. Маршрутизация и NAT
- Добавь `100 awg_foreign` в /etc/iproute2/rt_tables (если нет).
- Установи awg-rules.service, enable --now.
- Проверь: ip rule (priority 400), default dev awg1 в table 100,
  `ip route get 77.88.8.8` → via LAN-шлюз (маршрут без via не работает).
- NAT: MASQUERADE 10.8.0.0/24 в eth0 и awg1; MSS 1240 на awg1.
- Сохрани: netfilter-persistent save.

Этап 6. RU-маршруты
- Установи update-ru-routes.sh в /usr/local/bin, запусти вручную.
- Скрипт инкрементальный: добавляет только новые сети, удаляет только
  исчезнувшие, неизменённые маршруты не перестраивает.
- Проверь /var/log/ru-routes-update.log и количество маршрутов в table 100;
  второй запуск должен дать added 0, removed 0 за 1–3 с.
- Добавь cron 0 4 * * * с flock -n /run/update-ru-routes.lock.

Этап 7. Панель
- Создай /home/<user>/awg-migration/web (0700).
- Установи app.py (0600), создай web.pass (0600) с паролем пользователя.
- Сгенерируй self-signed сертификат (RSA 4096, 10 лет, SAN IP+DNS),
  server.key 600, server.crt 644.
- Установи awg-web.service, daemon-reload, enable --now.
- Панель должна слушать 0.0.0.0:51821 через gunicorn:
  --workers 1 --threads 8 --worker-class gthread,
  --timeout 180, TLS certfile/keyfile, Restart=always.
  Один worker обязателен: rate-limit, кэш MAC и статус RU — в памяти.

Этап 8. Проверка
- Запусти scripts/verify.sh (read-only).
- Дополнительно проверь вручную:
  * без auth / → 401, с auth → 200;
  * /favicon.ico и /apple-touch-icon* без auth → 204, без WWW-Authenticate;
  * Server: gunicorn без версии, nosniff, X-Frame-Options, CSP, no-store;
  * /api/status, /api/peers, /api/ru отдают валидный JSON;
  * create → rename → QR → ZIP(2 файла) → delete;
  * локальный конфиг нового клиента: Endpoint = LAN-адрес, не 10.71.x;
  * RU-скрипт дважды: второй запуск added 0/removed 0, 1–3 с;
  * после теста число пиров в awg0.conf = числу live-пиров,
    клиентских файлов чётное;
  * 16 параллельных запросов к /api/status → 200;
  * rate-limit: 11 неверных логинов → 429 + Retry-After;
    после restart awg-web снова 200;
  * в journal нет traceback.
- Удали тестовых пиров и временные файлы.

====================================================================
6. КРИТЕРИИ ПРИЁМКИ
====================================================================
- awg-quick@awg0, awg-quick@awg1, awg-rules, awg-web — active и enabled.
- `awg show` показывает оба интерфейса; у awg1 есть handshake с провайдером.
- `ip rule` содержит правило 400; table 100 содержит default dev awg1
  и тысячи RU-маршрутов via LAN-шлюз.
- ip_forward=1, NAT MASQUERADE для 10.8.0.0/24, MSS 1240.
- Панель: 401 без пароля, 200 с паролем, HTTPS, gunicorn, один worker.
- `GET /favicon.ico` и `/apple-touch-icon*` без пароля → 204 и НЕТ заголовка
  `WWW-Authenticate`; `/`, `/api/*` без пароля → 401 с challenge.
- CRUD клиента, QR-страница с двумя кодами, ZIP с двумя конфигами.
- Новый клиент: внешний конфиг → внешний IP, локальный → LAN-адрес
  (192.168.89.245), НЕ 10.71.107.82 и НЕ 0.0.0.0.
- После создания и удаления тестового клиента число пиров в awg0.conf,
  live-пиров и клиентских файлов возвращается к исходному.
- RU-обновление работает вручную и по cron; лог пишется.
- Повторный запуск RU-скрипта без изменений в списке: added 0, removed 0,
  unchanged ~8600, 1–3 с; таблица не перестраивается.
- Перезагрузка RPi не ломает VPN и панель (спроси разрешение перед reboot).
- Нет ошибок в journal; секреты не попали в отчёт и в git.

====================================================================
7. ФОРМАТ ОТЧЁТА
====================================================================
В конце выдай:
1. Что установлено (пакеты/версии).
2. Какие файлы созданы/изменены (пути, права).
3. Результаты проверок (список ok/fail).
4. Что осталось сделать или требует решения пользователя.
5. Команды для отката/бэкапа.
Не вставляй в отчёт приватные ключи и пароли.

====================================================================
8. ЕСЛИ ЧТО-ТО ПОШЛО НЕ ТАК
====================================================================
- Не оставляй систему в полу-рабочем состоянии: если этап не удался,
  откати изменения и сообщи.
- При потере SSH-доступа: не перезагружай, проверь ip route/ip rule,
  верни Table = off на awg1, удали конфликтующие правила.
- При падении панели: journalctl -u awg-web, py_compile app.py,
  проверь права на server.key и web.pass, затем restart.
- При отсутствии handshake awg1: проверь Endpoint, ключи, обфускацию,
  UDP до провайдера, статус провайдера.

====================================================================
9. СПЕЦИФИКАЦИЯ, ЕСЛИ ФАЙЛОВ ПРОЕКТА НЕТ
====================================================================
Восстанови файлы по этому описанию.

9.1. Сеть
- awg0: сервер, 10.8.0.1/24, UDP 51820, MTU 1280, пиры 10.8.0.2-254/32.
- awg1: upstream, Table = off, default dev awg1 в table 100.
- policy: ip rule from 10.8.0.0/24 lookup awg_foreign priority 400.
- host routes: 1.1.1.1/32 и 8.8.8.8/32 dev awg1; 77.88.8.8/32
  via LAN-шлюз dev eth0 (без `via` маршрут не работает — ARP на eth0
  не найдёт 77.88.8.8).
- NAT: MASQUERADE 10.8.0.0/24 out eth0 и awg1.
- MSS: TCPMSS --set-mss 1240 для awg1.
- RU: table 100, маршруты via LAN-шлюз, обновление из
  https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone
  инкрементально (diff: add new / del gone, без полной перестройки).

9.2. Панель (Flask, один файл app.py)
Конфиг:
- CONFIG_DIR=/etc/amnezia/amneziawg, AWG_CONF=awg0.conf,
  AWG1_CONF=awg1.conf, CLIENTS_DIR=clients.
- WEB_PORT=51821, WEB_USER, WEB_PASSWORD или WEB_PASSWORD_FILE,
  WEB_TLS_CERT/KEY, AWG_LISTEN_PORT, EXTERNAL_ENDPOINT, INTERNAL_ENDPOINT.
- CSRF-токен = HMAC-SHA256(пароль, "awg-web-csrf-v1").
- Rate-limit: 10 неудач за 600 с на IP → 429 + Retry-After.

Безопасность:
- HTTP Basic, compare_digest.
- CSRF на всех POST.
- CSP, X-Frame-Options DENY, nosniff, no-store.
- Валидация имён ^[\w-]{1,32}$, IP через ipaddress.
- Атомарная запись конфигов (temp + os.replace, 600).
- subprocess с таймаутами, без shell=True.

Маршруты:
- GET / — дашборд: карточки awg0/awg1, карточка RU, таблица клиентов.
- GET /api/status, /api/peers, /api/ru — JSON для автообновления.
- POST /create — новый пир + два конфига (внешний/локальный).
- POST /delete/<name>, /rename/<old>, /restart/<iface>,
  /update-ru, /reboot.
- GET /qr/<name> — страница с двумя QR; /qr/<name>/<external|local> — PNG.
- GET /config/<name> — ZIP с двумя .conf; /config/<name>/<kind> — один файл.
- GET /favicon.ico и /apple-touch-icon* — публично, 204 без
  WWW-Authenticate (иначе iOS Safari после входа показывает второе окно
  пароля: он запрашивает иконки отдельным процессом без Basic-кредов).
- GET/POST /upstream — редактор awg1.conf: проверка awg-quick strip,
  автодобавление Table = off, бэкап, рестарт, ожидание handshake 25 с,
  откат при неудаче.

Handshake-цвета: ≤180 с — зелёный, ≤86400 с — оранжевый,
>86400 с — красный, нет — серый. В карточках — рамка/фон, в таблице —
  текст и точка.

Клиентский конфиг:
[Interface]
Address = 10.8.0.X/32
PrivateKey = <client>
DNS = 1.1.1.1
MTU = 1280
[Peer]
PublicKey = <server>
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
Endpoint = <external|internal>:51820

- external = внешний IP (ifconfig.me, кэш 60 с, fallback в файл);
- internal = LAN-адрес роутера. Функция detect_internal() обязана
  ИСКЛЮЧАТЬ адреса awg0/awg1: при policy-routing `ip route get 1.1.1.1`
  возвращает src 10.71.107.82 (адрес awg1), и такой endpoint бесполезен
  клиенту, который ещё не подключён к туннелю. Переопределение —
  переменная INTERNAL_ENDPOINT.

9.3. Юнит панели
- gunicorn, --workers 1 --threads 8 --worker-class gthread,
  --bind 0.0.0.0:51821, TLS, --timeout 180, --graceful-timeout 30,
  --keep-alive 5, access/error log в journal, Restart=always.
- Пароль — через WEB_PASSWORD_FILE, не через Environment.

9.4. Эксплуатация
- Бэкап: tar с /etc/amnezia/amneziawg, юнитами, rules.v4, sysctl,
  скриптами, app.py, web.pass, certs.
- Обновление панели: бэкап → py_compile → install 600 → restart →
  проверка active; при падении — откат.
- Диагностика: journalctl -u awg-web/awg-quick@*, /var/log/ru-routes-update.log,
  dkms status, awg show, ip rule, ip route table 100, iptables -t nat -S.
````

---

## Как пользоваться промтом

1. Скопируйте блок выше в чат ИИ-агенту, у которого есть SSH-доступ к
   Raspberry Pi (или к репозиторию).
2. Приложите репозиторий/файлы, если они есть: так ИИ возьмёт `app.py` и
   юниты как есть, а не будет писать заново.
3. Ответьте на вопросы из раздела 2 (сеть, конфиг провайдера, пароль).
4. Попросите ИИ сначала выполнить «Этап 0» и показать план, затем — установку
   по этапам с проверками.
5. Приёмка — по разделу 6 и `scripts/verify.sh`.

> Если восстанавливаете на **другой** сети, замените IP/шлюз/интерфейс
> и константы `app.py` (`RU_GATEWAY`, `next_ip`, `IFACE_SERVICES` и т.д.).
