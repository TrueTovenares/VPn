import os, re, json, secrets, subprocess, fcntl, hmac, hashlib, time, threading, io, zipfile
import ipaddress, shutil, tempfile
from collections import defaultdict, deque
from flask import Flask, request, redirect, url_for, send_file, Response, abort, render_template_string
from werkzeug.serving import WSGIRequestHandler

os.umask(0o077)

CONFIG_DIR = "/etc/amnezia/amneziawg"
AWG_CONF = os.path.join(CONFIG_DIR, "awg0.conf")
CLIENTS_DIR = os.path.join(CONFIG_DIR, "clients")

WEB_USER = os.environ.get("WEB_USER", "admin")
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
WEB_PASSWORD_FILE = os.environ.get("WEB_PASSWORD_FILE", "")
if not WEB_PASSWORD and WEB_PASSWORD_FILE and os.path.exists(WEB_PASSWORD_FILE):
    with open(WEB_PASSWORD_FILE, "r", encoding="utf-8") as f:
        WEB_PASSWORD = f.read().strip()
if not WEB_PASSWORD:
    raise SystemExit("FATAL: WEB_PASSWORD or WEB_PASSWORD_FILE is required")

WEB_PORT = int(os.environ.get("WEB_PORT", "51821"))
WEB_BIND = os.environ.get("WEB_BIND", "0.0.0.0")
TLS_CERT = os.environ.get("WEB_TLS_CERT", "")
TLS_KEY = os.environ.get("WEB_TLS_KEY", "")
if TLS_CERT or TLS_KEY:
    if not (TLS_CERT and TLS_KEY and os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY)):
        raise SystemExit("FATAL: WEB_TLS_CERT/WEB_TLS_KEY set but certificate files are missing")

LISTEN_PORT = os.environ.get("AWG_LISTEN_PORT", "")
EXTERNAL_ENDPOINT = os.environ.get("EXTERNAL_ENDPOINT", "")
INTERNAL_ENDPOINT = os.environ.get("INTERNAL_ENDPOINT", "")

CSRF_TOKEN = hmac.new(WEB_PASSWORD.encode("utf-8"), b"awg-web-csrf-v1", hashlib.sha256).hexdigest()

FAIL_WINDOW = 600
FAIL_MAX = 10
_fails = defaultdict(deque)
_fails_lock = threading.Lock()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

def _client_ip():
    return request.remote_addr or "unknown"

def _rate_limited(ip):
    now = time.time()
    with _fails_lock:
        dq = _fails.get(ip)
        if not dq:
            return False
        while dq and now - dq[0] > FAIL_WINDOW:
            dq.popleft()
        if not dq:
            _fails.pop(ip, None)
            return False
        return len(dq) >= FAIL_MAX

def _record_fail(ip):
    now = time.time()
    with _fails_lock:
        dq = _fails[ip]
        while dq and now - dq[0] > FAIL_WINDOW:
            dq.popleft()
        dq.append(now)

def _clear_fails(ip):
    with _fails_lock:
        _fails.pop(ip, None)

def get_listen_port():
    global LISTEN_PORT
    if LISTEN_PORT:
        return LISTEN_PORT
    if os.path.exists(AWG_CONF):
        with open(AWG_CONF, encoding="utf-8") as f:
            for line in f:
                m = re.match(r'ListenPort\s*=\s*(\d+)', line.strip())
                if m:
                    LISTEN_PORT = m.group(1)
                    return LISTEN_PORT
    return "51820"

def _tunnel_addrs():
    """IPv4-адреса туннельных интерфейсов — их нельзя выдавать как LAN-endpoint."""
    addrs = set()
    for iface in ('awg0', 'awg1'):
        try:
            out = subprocess.check_output(['ip', '-4', '-o', 'addr', 'show', iface], timeout=3).decode()
            addrs.update(re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', out))
        except Exception:
            pass
    return addrs

def detect_internal():
    if INTERNAL_ENDPOINT:
        return INTERNAL_ENDPOINT
    # Адреса туннелей (awg0/awg1) не годятся: клиент до них не достучится,
    # пока не поднят VPN. При policy-routing `ip route get 1.1.1.1` может
    # вернуть src из awg1 — такой ответ нужно отбросить.
    skip = _tunnel_addrs()
    # 1) адрес-источник для внешнего трафика, если это не туннель
    try:
        out = subprocess.check_output(['ip', '-4', 'route', 'get', '1.1.1.1'], timeout=3).decode()
        m = re.search(r'\bsrc\s+(\d+\.\d+\.\d+\.\d+)', out)
        if m and not m.group(1).startswith('127.') and m.group(1) not in skip:
            return m.group(1)
    except Exception:
        pass
    # 2) адрес на интерфейсе default-маршрута (кроме туннелей)
    try:
        route = subprocess.check_output(['ip', 'route', 'show', 'default'], timeout=3).decode()
        m = re.search(r'dev\s+(\S+)', route)
        if m and m.group(1) not in ('awg0', 'awg1'):
            out = subprocess.check_output(['ip', '-4', 'addr', 'show', m.group(1)], timeout=3).decode()
            m2 = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', out)
            if m2 and not m2.group(1).startswith('127.'):
                return m2.group(1)
    except Exception:
        pass
    # 3) резерв: первый глобальный адрес, кроме адресов туннелей
    try:
        out = subprocess.check_output(['ip', '-4', '-o', 'addr', 'show', 'scope', 'global'],
                                      timeout=3).decode()
        for line in out.splitlines():
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/', line)
            if m:
                ip = m.group(1)
                if ip not in skip and not ip.startswith('127.'):
                    return ip
    except Exception:
        pass
    return "127.0.0.1"

EXT_IP_CACHE_FILE = "/var/lib/awg-web/last-external-ip"
EXT_IP_TTL = 60
_ext_cache = {"value": None, "ts": 0.0}
_ext_lock = threading.Lock()

def _valid_ip(s):
    """Строгая проверка IPv4-адреса."""
    try:
        ipaddress.IPv4Address(s or "")
        return True
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return False

def _atomic_write(path, text, mode=0o600):
    """Атомарная запись: временный файл в том же каталоге + os.replace."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix="-" + os.path.basename(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def _remember_ext(ip):
    with _ext_lock:
        _ext_cache.update({"value": ip, "ts": time.time()})
    try:
        os.makedirs(os.path.dirname(EXT_IP_CACHE_FILE), mode=0o700, exist_ok=True)
        with open(EXT_IP_CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(ip)
    except Exception:
        pass

def detect_external():
    if EXTERNAL_ENDPOINT: return EXTERNAL_ENDPOINT
    now = time.time()
    with _ext_lock:
        if _ext_cache["value"] and now - _ext_cache["ts"] < EXT_IP_TTL:
            return _ext_cache["value"]
    try:
        out = subprocess.check_output(['curl', '-s', '--max-time', '3', 'ifconfig.me'], timeout=5).decode().strip()
        if _valid_ip(out):
            _remember_ext(out)
            return out
    except Exception:
        pass
    # fallback: последний известный внешний IP (чтобы не отдавать 0.0.0.0 в конфигах)
    with _ext_lock:
        if _ext_cache["value"]:
            return _ext_cache["value"]
    try:
        with open(EXT_IP_CACHE_FILE, encoding="utf-8") as f:
            ip = f.read().strip()
        if _valid_ip(ip):
            with _ext_lock: _ext_cache.update({"value": ip, "ts": time.time()})
            return ip
    except Exception:
        pass
    return "0.0.0.0"

def parse_peers():
    if not os.path.exists(AWG_CONF):
        return []
    with open(AWG_CONF, encoding="utf-8") as f:
        lines = f.readlines()

    peers = []
    i, n = 0, len(lines)
    while i < n:
        s = lines[i].strip()
        name = None
        if s.startswith('# Name = '):
            name = s[len('# Name = '):]
            j = i + 1
            while j < n and lines[j].strip() == '':
                j += 1
            if j < n and lines[j].strip() == '[Peer]':
                i = j
            else:
                i += 1
                continue
        elif s != '[Peer]':
            i += 1
            continue

        peer = {'name': name, 'public_key': None, 'allowed_ips': None}
        i += 1
        while i < n:
            s2 = lines[i].strip()
            if s2 == '' or s2.startswith('# Name = ') or s2 == '[Peer]':
                break
            if s2.startswith('PublicKey = '):
                peer['public_key'] = s2[len('PublicKey = '):]
            elif s2.startswith('AllowedIPs = '):
                peer['allowed_ips'] = s2[len('AllowedIPs = '):]
            i += 1
        if peer['public_key']:
            peers.append(peer)
    return peers

def rewrite_peers(peers):
    with open(AWG_CONF, encoding="utf-8") as f:
        content = f.read()
    m = re.search(r'(?:^|\n)(?:# Name = \S+\n)?\[Peer\]', content)
    interface = content[:m.start()].rstrip() if m else content.rstrip()
    out = [interface]
    for p in peers:
        out.append("")
        if p.get("name"):
            out.append(f"# Name = {p['name']}")
        out.append("[Peer]")
        out.append(f"PublicKey = {p['public_key']}")
        out.append(f"AllowedIPs = {p['allowed_ips']}")
    _atomic_write(AWG_CONF, "\n".join(out) + "\n")

def get_server_public():
    with open(AWG_CONF, encoding="utf-8") as f:
        content = f.read()
    m = re.search(r'\[Interface\][^\[]*?PrivateKey\s*=\s*(\S+)', content, re.DOTALL)
    if not m:
        return None
    r = subprocess.run(['awg', 'pubkey'], input=m.group(1).encode(),
                       capture_output=True, timeout=10)
    return r.stdout.decode().strip() if r.returncode == 0 else None

def gen_keypair():
    priv = subprocess.check_output(['awg', 'genkey'], timeout=10).decode().strip()
    r = subprocess.run(['awg', 'pubkey'], input=priv.encode(),
                       capture_output=True, timeout=10)
    if r.returncode != 0:
        raise RuntimeError("awg pubkey завершился с ошибкой")
    return priv, r.stdout.decode().strip()

def next_ip(peers):
    used = set()
    for p in peers:
        if p.get('allowed_ips'):
            for aip in p['allowed_ips'].split(','):
                mm = re.match(r'10\.8\.0\.(\d+)/32', aip.strip())
                if mm:
                    used.add(int(mm.group(1)))
    for i in range(2, 255):
        if i not in used:
            return i
    return None

def write_client_confs(name, priv, ip32):
    server_pub = get_server_public()
    if not server_pub:
        raise RuntimeError("не удалось получить публичный ключ сервера")
    port = get_listen_port()
    ext = detect_external()
    loc = detect_internal()
    if not _valid_ip(ext) or ext == "0.0.0.0":
        raise RuntimeError("не удалось определить внешний IP")
    base = f"""[Interface]
Address = {ip32}
PrivateKey = {priv}
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = {server_pub}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    os.chmod(CLIENTS_DIR, 0o700)
    for suffix, endpoint in (("", ext), ("-local", loc)):
        path = os.path.join(CLIENTS_DIR, f"{name}{suffix}.conf")
        _atomic_write(path, base + f"Endpoint = {endpoint}:{port}\n")

# ================== INTERFACES STATUS ==================
IFACE_SERVICES = {"awg0": "awg-quick@awg0", "awg1": "awg-quick@awg1"}
RULES_SERVICE = "awg-rules.service"

def _run(cmd, timeout=6):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        return None

def _svc_state(iface):
    r = _run(["systemctl", "is-active", IFACE_SERVICES[iface]])
    if not r: return "unknown"
    return (r.stdout or b"").decode(errors="ignore").strip() or "unknown"

def _svc_uptime(iface):
    r = _run(["systemctl", "show", IFACE_SERVICES[iface], "-p", "ActiveEnterTimestampMonotonic", "--value"])
    if not r: return None
    try:
        start_us = int((r.stdout or b"0").decode().strip() or 0)
        if start_us <= 0: return None
        with open("/proc/uptime", encoding="ascii") as f:
            up = float(f.read().split()[0])
        sec = up - start_us / 1e6
        return sec if sec >= 0 else None
    except Exception:
        return None

def _parse_ago(text):
    mult = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "week": 604800}
    total, found = 0, False
    for n, u in re.findall(r"(\d+)\s+(second|minute|hour|day|week)s?", text):
        total += int(n) * mult[u]
        found = True
    return total if found else None

def _to_bytes(v, unit):
    mult = {"B": 1, "KIB": 1024, "MIB": 1024**2, "GIB": 1024**3, "TIB": 1024**4,
            "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4}
    return int(v * mult.get(unit.upper(), 1))

def _human(n):
    n = float(n)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or u == "TiB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TiB"

def _ru_dur(sec):
    sec = int(sec)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d: parts.append(f"{d} дн")
    if h: parts.append(f"{h} ч")
    if m and not d: parts.append(f"{m} мин")
    if s and not d and not h: parts.append(f"{s} сек")
    return " ".join(parts) or "0 сек"

def _parse_iface(iface):
    info = {"port": None, "pubkey": None, "peers": []}
    r = _run(["awg", "show", iface])
    if not r or r.returncode != 0: return info
    cur = None
    for line in (r.stdout or b"").decode(errors="ignore").splitlines():
        s = line.strip()
        if s.startswith("interface:"):
            cur = None
        elif s.startswith("public key:"):
            info["pubkey"] = s.split(":", 1)[1].strip()
        elif s.startswith("listening port:"):
            info["port"] = s.split(":", 1)[1].strip()
        elif s.startswith("peer:"):
            cur = {"handshake": None, "rx": 0, "tx": 0}
            info["peers"].append(cur)
        elif cur is not None and s.startswith("latest handshake:"):
            cur["handshake"] = _parse_ago(s.split(":", 1)[1])
        elif cur is not None and s.startswith("transfer:"):
            m = re.search(r"([\d.]+)\s+(\w+) received,\s+([\d.]+)\s+(\w+) sent", s)
            if m:
                cur["rx"] = _to_bytes(float(m.group(1)), m.group(2))
                cur["tx"] = _to_bytes(float(m.group(3)), m.group(4))
    return info

def _peer_stats(iface):
    """Точные данные по пирам из `awg show <iface> dump`."""
    stats = {}
    r = _run(["awg", "show", iface, "dump"])
    if not r or r.returncode != 0: return stats
    for line in (r.stdout or b"").decode(errors="ignore").splitlines()[1:]:
        f = line.split("\t")
        if len(f) < 8: continue
        ep = f[2]
        try:
            hs = int(f[4])
        except ValueError:
            hs = 0
        try:
            rx, tx = int(f[5]), int(f[6])
        except ValueError:
            rx, tx = 0, 0
        stats[f[0]] = {
            "endpoint": None if ep in ("(none)", "") else ep,
            "handshake_ts": hs,
            "rx": rx,
            "tx": tx,
        }
    return stats

# ================== MAC ПИРОВ ==================
# WireGuard — L3-туннель, MAC в нём не передаётся. Но клиенты из локальной сети
# видны в ARP-таблице eth0, поэтому для них MAC получить можно.
PEER_INFO_FILE = "/var/lib/awg-web/peer-info.json"
PEER_MAC_TTL = 120     # MAC — раз в 2 минуты (может быть рандомизирован)
_peer_info = {}
_peer_info_lock = threading.Lock()
_peer_info_loaded = False
_peer_info_thread = None
_peer_info_thread_lock = threading.Lock()

def _load_peer_info():
    global _peer_info_loaded
    with _peer_info_lock:
        if _peer_info_loaded:
            return
        _peer_info_loaded = True
    try:
        with open(PEER_INFO_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            with _peer_info_lock:
                _peer_info.update({
                    k: {kk: vv for kk, vv in v.items() if kk in ("mac", "mac_ts")}
                    for k, v in data.items() if isinstance(v, dict)
                })
    except Exception:
        pass

def _save_peer_info():
    try:
        with _peer_info_lock:
            data = json.dumps(_peer_info, ensure_ascii=False)
        _atomic_write(PEER_INFO_FILE, data, mode=0o600)
    except Exception:
        pass

def _endpoint_ip(endpoint):
    if not endpoint: return ""
    ep = endpoint.strip()
    if ep.startswith("["):
        m = re.match(r'^\[([0-9a-fA-F:]+)\]', ep)
        return m.group(1) if m else ""
    ip = ep.rsplit(":", 1)[0]
    return ip if _valid_ip(ip) else ""

def _is_lan_ip(ip):
    try:
        return ipaddress.IPv4Address(ip).is_private
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return False

def _neigh_mac(ip):
    try:
        r = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, timeout=3)
        m = re.search(r'lladdr ([0-9a-fA-F:]{17})', r.stdout.decode(errors="ignore"))
        return m.group(1).lower() if m else ""
    except Exception:
        return ""

def lookup_peer_info(ip, force=False):
    """MAC устройства по IP из локальной сети (с кэшем)."""
    _load_peer_info()
    if not _is_lan_ip(ip):
        return ""
    now = time.time()
    with _peer_info_lock:
        cur = dict(_peer_info.get(ip) or {})
    if force or not cur.get("mac") or now - cur.get("mac_ts", 0) > PEER_MAC_TTL:
        mac = _neigh_mac(ip)
        cur["mac_ts"] = now
        changed = bool(mac) and mac != cur.get("mac")
        if mac:
            cur["mac"] = mac
        with _peer_info_lock:
            _peer_info[ip] = cur
        if changed:
            _save_peer_info()
    return cur.get("mac", "")

def cached_peer_mac(endpoint):
    ip = _endpoint_ip(endpoint)
    if not ip or not _is_lan_ip(ip): return ""
    _load_peer_info()
    with _peer_info_lock:
        cur = _peer_info.get(ip) or {}
    return cur.get("mac", "")

def refresh_peer_info(force=False):
    stats = _peer_stats("awg0")
    seen = []
    for s in stats.values():
        ip = _endpoint_ip(s.get("endpoint"))
        if ip and _is_lan_ip(ip) and ip not in seen:
            seen.append(ip)
    for ip in seen:
        try: lookup_peer_info(ip, force=force)
        except Exception: pass

def _peer_info_loop():
    time.sleep(2)
    while True:
        try: refresh_peer_info()
        except Exception: pass
        time.sleep(45)

def _ensure_peer_info_thread():
    global _peer_info_thread
    with _peer_info_thread_lock:
        if _peer_info_thread and _peer_info_thread.is_alive(): return
        _peer_info_thread = threading.Thread(target=_peer_info_loop, daemon=True)
        _peer_info_thread.start()

HS_OK_AGE = 180        # handshake не старше 3 минут — интерфейс/пир на связи
HS_ERR_AGE = 86400     # handshake старше суток — явно нет связи

def _hs_state(age):
    """Цвет handshake: (класс текста, класс точки, класс карточки)."""
    if age is None: return "hs-none", "", ""
    if age <= HS_OK_AGE: return "hs-ok", "on", ""
    if age <= HS_ERR_AGE: return "hs-warn", "warn", "stale-warn"
    return "hs-err", "err", "stale-err"

def peer_view(stats, public_key, now=None):
    s = stats.get(public_key or "")
    now = time.time() if now is None else now
    if not s:
        return {"endpoint": "—", "handshake": "нет", "online": False,
                "rx": "0 B", "tx": "0 B", "mac": "—",
                "hs_cls": "hs-none", "dot_cls": ""}
    age = max(0, int(now - s["handshake_ts"])) if s["handshake_ts"] else None
    hs_cls, dot_cls, _ = _hs_state(age)
    return {
        "endpoint": s["endpoint"] or "—",
        "handshake": "нет" if age is None else _ru_dur(age) + " назад",
        "online": age is not None and age <= HS_OK_AGE,
        "rx": _human(s["rx"]),
        "tx": _human(s["tx"]),
        "mac": cached_peer_mac(s["endpoint"]) or "—",
        "hs_cls": hs_cls,
        "dot_cls": dot_cls,
    }

def iface_status(iface):
    state = _svc_state(iface)
    info = _parse_iface(iface) if state == "active" else {"port": None, "peers": []}
    peers = info["peers"]
    hs = [p["handshake"] for p in peers if p.get("handshake") is not None]
    best_age = min(hs) if hs else None
    hs_cls, _, hs_card_cls = _hs_state(best_age)
    up = _svc_uptime(iface)
    return {
        "name": iface,
        "state": state,
        "state_ru": {"active": "работает", "inactive": "остановлен", "failed": "ошибка",
                     "activating": "запускается", "deactivating": "останавливается"}.get(state, state),
        "cls": "ok" if state == "active" else ("err" if state == "failed" else "warn"),
        "port": info.get("port") or "—",
        "peers": len(peers),
        "peers_active": sum(1 for p in peers if p.get("handshake") is not None and p["handshake"] <= HS_OK_AGE),
        "handshake": "нет" if best_age is None else _ru_dur(best_age) + " назад",
        "hs_cls": hs_cls,
        "hs_card_cls": hs_card_cls,
        "rx": _human(sum(p["rx"] for p in peers)),
        "tx": _human(sum(p["tx"] for p in peers)),
        "uptime": _ru_dur(up) if up is not None else "—",
    }

# ================== RU ROUTES ==================
RU_SCRIPT = "/usr/local/bin/update-ru-routes.sh"
RU_LOCK = "/run/update-ru-routes.lock"
RU_TABLE = "100"
RU_GATEWAY = "192.168.89.1"
RU_LIST_FILE = "/tmp/ru-aggregated.zone"
RU_LOG = "/var/log/ru-routes-update.log"

_ru_lock = threading.Lock()
_ru_state = {"running": False, "ok": None, "msg": None, "finished": None}

def ru_routes_info():
    count = 0
    r = _run(["ip", "route", "show", "table", RU_TABLE])
    if r and r.returncode == 0:
        count = sum(1 for l in (r.stdout or b"").decode(errors="ignore").splitlines()
                    if f"via {RU_GATEWAY}" in l)
    updated = "—"
    try:
        updated = time.strftime("%d.%m %H:%M", time.localtime(os.path.getmtime(RU_LIST_FILE)))
    except OSError:
        pass
    last_log = "—"
    try:
        with open(RU_LOG, encoding="utf-8", errors="replace") as f:
            lines = [x.strip() for x in f.read().splitlines() if x.strip()]
        if lines:
            pick = next((x for x in reversed(lines) if "Added" in x or "ERROR" in x), lines[-1])
            last_log = pick.split(": ", 1)[-1]
    except Exception:
        pass
    return {"count": count, "updated": updated, "last_log": last_log}

def ru_state_view():
    with _ru_lock:
        st = dict(_ru_state)
    info = ru_routes_info()
    info.update({"running": st["running"], "ok": st["ok"], "finished": st["finished"]})
    return info

def _run_ru_update():
    ok, out = False, ""
    try:
        r = subprocess.run(["flock", "-n", RU_LOCK, RU_SCRIPT], capture_output=True, timeout=600)
        ok = r.returncode == 0
        out = (r.stdout + r.stderr).decode(errors="ignore").strip()
        if r.returncode == 1 and not out:
            out = "скрипт уже выполняется (flock)"
    except Exception as e:
        ok, out = False, str(e)
    with _ru_lock:
        _ru_state.update({"running": False, "ok": ok, "msg": out[-500:], "finished": time.time()})

def _public_asset(path):
    """Служебные иконки, которые iOS/Safari запрашивает без Basic-кредов."""
    return path == "/favicon.ico" or path.startswith("/apple-touch-icon")

@app.before_request
def auth():
    # Safari на iOS тянет favicon/apple-touch-icon отдельным процессом
    # (NetworkingExtension) без Authorization. Ответ 401 с WWW-Authenticate
    # вызывает второе окно пароля сразу после успешного входа. Отдаём 204.
    if request.method == "GET" and _public_asset(request.path):
        return Response(status=204)
    ip = _client_ip()
    if _rate_limited(ip):
        return Response("Too many failed login attempts. Try again later.\n", 429,
                        {'Retry-After': str(FAIL_WINDOW), 'Content-Type': 'text/plain'})
    a = request.authorization
    if a is not None:
        user_ok = hmac.compare_digest((a.username or "").encode("utf-8"), WEB_USER.encode("utf-8"))
        pass_ok = hmac.compare_digest((a.password or "").encode("utf-8"), WEB_PASSWORD.encode("utf-8"))
        if user_ok and pass_ok:
            _clear_fails(ip)
            return None
        _record_fail(ip)
    return Response('Auth required', 401, {'WWW-Authenticate': 'Basic realm="AWG", charset="UTF-8"'})

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("csrf", "")
        if not hmac.compare_digest(token.encode("utf-8"), CSRF_TOKEN.encode("utf-8")):
            abort(400)

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return resp

TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>AWG Router</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:1000px;margin:20px auto;padding:0 15px}
h1{border-bottom:2px solid #333;padding-bottom:5px}
table{width:100%;border-collapse:collapse;margin:20px 0}
.table-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
.table-scroll table{margin:0}
th,td{border:1px solid #ccc;padding:8px;text-align:left;font-size:14px}
th{background:#f0f0f0}
.btn{display:inline-block;padding:8px 14px;background:#007bff;color:white;text-decoration:none;border-radius:4px;border:none;cursor:pointer;font-size:14px}
.btn:hover{background:#0056b3}.btn-danger{background:#dc3545}.btn-danger:hover{background:#a71d2a}
.btn-sm{padding:4px 10px;font-size:12px}
.info{background:#e7f3ff;padding:12px;border-left:4px solid #007bff;margin:15px 0;font-size:14px}
.info code{background:rgba(0,0,0,0.05);padding:2px 5px;border-radius:3px}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin:10px 0 20px}
.card{flex:1 1 320px;border:1px solid #ccc;border-radius:8px;padding:12px 14px;background:#fafafa}
.card-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.card-name{font-size:16px}
table.kv{width:100%;border:0;margin:0 0 8px}
table.kv th,table.kv td{border:0;padding:3px 0;font-size:13px;vertical-align:top}
table.kv th{background:none;color:#666;font-weight:500;width:105px;text-align:left}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}
.badge.ok{background:#dcfce7;color:#166534}
.badge.err{background:#fee2e2;color:#991b1b}
.badge.warn{background:#fef9c3;color:#713f12}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#bbb;margin-right:6px;vertical-align:middle}
.dot.on{background:#22c55e}
.dot.warn{background:#f59e0b}
.dot.err{background:#dc2626}
.hs-ok{color:#15803d;font-weight:600}
.hs-warn{color:#b45309;font-weight:600}
.hs-err{color:#dc2626;font-weight:600}
.hs-none{color:#999}
.card.stale-warn{border-color:#f59e0b;background:#fffdf5}
.card.stale-err{border-color:#dc2626;background:#fff5f5}
td code{background:rgba(0,0,0,0.05);padding:1px 4px;border-radius:3px;font-size:12px}
.btn-ghost{background:#e9ecef;color:#333;padding:2px 7px;font-size:12px}
.btn-ghost:hover{background:#d3d8dd}
.rename-form{display:none;gap:4px;align-items:center;margin:0}
.rename-form input{width:120px;padding:2px 5px;font-size:13px;border:1px solid #bbb;border-radius:4px}
.msgbar{padding:10px 14px;border-radius:8px;margin:10px 0;font-size:14px}
.msgbar.ok{background:#dcfce7;color:#166534;border:1px solid #86efac}
.msgbar.err{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}
</style></head><body>
<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
<h1 style="flex:1;margin:0 0 5px">AWG Router — Управление клиентами</h1>
<form method="post" action="/reboot" style="margin:0"
      onsubmit="return confirm('Перезагрузить Raspberry Pi? VPN будет недоступен 1–2 минуты.')">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button type="submit" class="btn btn-danger">⟳ Перезагрузить RPi</button>
</form>
</div>
<p style="margin:10px 0 15px"><a href="/upstream" style="color:#2563eb">⚙️ Настройки upstream (awg1.conf)</a></p>
{% if msg %}<div class="msgbar {{ 'ok' if ok else 'err' }}">{{ msg }}</div>{% endif %}
<h2 style="font-size:1.15rem;margin:20px 0 6px">Интерфейсы</h2>
<div class="cards">
{% for i in ifaces %}
<div class="card {{ i.hs_card_cls }}" id="if-{{ i.name }}">
<div class="card-top"><b class="card-name">{{ i.name }}</b><span class="badge {{ i.cls }}" data-f="state">{{ i.state_ru }}</span></div>
<table class="kv">
<tr><th>Порт</th><td data-f="port">{{ i.port }}</td></tr>
<tr><th>Пиры</th><td data-f="peers">{{ i.peers }} (активных {{ i.peers_active }})</td></tr>
<tr><th>Handshake</th><td><span class="{{ i.hs_cls }}" data-f="hs" title="зелёный — на связи, оранжевый — был недавно, красный — нет связи больше суток">{{ i.handshake }}</span></td></tr>
<tr><th>Трафик</th><td><span data-f="rx">{{ i.rx }}</span> ↓ / <span data-f="tx">{{ i.tx }}</span> ↑</td></tr>
<tr><th>Uptime</th><td data-f="uptime">{{ i.uptime }}</td></tr>
</table>
<form method="post" action="/restart/{{ i.name }}" style="margin:0"
      onsubmit="return confirm('Перезапустить {{ i.name }}? Соединения через этот интерфейс кратковременно прервутся.')">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button type="submit" class="btn btn-sm btn-danger">↻ Перезапустить {{ i.name }}</button>
</form>
</div>
{% endfor %}
<div class="card" id="ru-card">
<div class="card-top"><b class="card-name">RU-маршруты</b><span class="badge {{ ru.badge_cls }}" data-f="ru-badge">{{ ru.badge_text }}</span></div>
<table class="kv">
<tr><th>Сетей</th><td data-f="ru-count">{{ ru.count }}</td></tr>
<tr><th>Список от</th><td data-f="ru-updated">{{ ru.updated }}</td></tr>
<tr><th>Лог</th><td data-f="ru-log" style="font-size:12px;color:#555">{{ ru.last_log }}</td></tr>
</table>
<form method="post" action="/update-ru" style="margin:0"
      onsubmit="return confirm('Обновить таблицу российских адресов? Маршруты будут перестроены, это может занять до минуты.')">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button type="submit" class="btn btn-sm">↻ Обновить RU-маршруты</button>
</form>
</div>
</div>
<div class="info">
<b>External endpoint:</b> <code>{{ ext }}:{{ port }}</code><br>
<b>Internal endpoint:</b> <code>{{ loc }}:{{ port }}</code><br>
<b>Peers:</b> {{ peers|length }}
</div>
<form method="post" action="/create"><input type="hidden" name="csrf" value="{{ csrf }}"><button type="submit" class="btn">+ Создать клиента</button></form>
<div class="table-scroll">
<table>
<tr><th>#</th><th>Имя</th><th>IP</th><th>Endpoint</th><th>MAC</th><th>Handshake</th><th>Трафик</th><th>QR</th><th>Конфиги</th><th></th></tr>
{% for p in peers %}
<tr data-pk="{{ p.public_key }}">
<td>{{ loop.index }}</td>
<td style="white-space:nowrap"><span data-p="name">{{ p.display }}</span>{% if p.name %} <button type="button" class="btn btn-sm btn-ghost" title="Переименовать" onclick="showRename(this)">✎</button>
<form method="post" action="/rename/{{ p.name|urlencode }}" class="rename-form">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input name="name" value="{{ p.name }}" maxlength="32" required title="Буквы, цифры, _ и -, до 32 символов">
<button type="submit" class="btn btn-sm" title="Сохранить">✓</button>
</form>{% endif %}</td>
<td>{{ p.ip }}</td>
<td><code data-p="endpoint">{{ p.endpoint }}</code></td>
<td><code data-p="mac" title="MAC из ARP-таблицы (только для клиентов локальной сети)">{{ p.mac }}</code></td>
<td style="white-space:nowrap"><span class="dot {{ p.dot_cls }}" data-p="dot"></span><span class="{{ p.hs_cls }}" data-p="hs" title="зелёный — на связи, оранжевый — был недавно, красный — нет связи больше суток">{{ p.handshake }}</span></td>
<td style="white-space:nowrap"><span data-p="rx">{{ p.rx }}</span> ↓ / <span data-p="tx">{{ p.tx }}</span> ↑</td>
{% if p.has_client %}
<td><a href="/qr/{{ p.name|urlencode }}" class="btn btn-sm">QR</a></td>
<td><a href="/config/{{ p.name|urlencode }}" class="btn btn-sm">.conf ×2</a></td>
<td><form method="post" action="/delete/{{ p.name|urlencode }}" style="margin:0"><input type="hidden" name="csrf" value="{{ csrf }}"><button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Удалить пира?')">×</button></form></td>
{% else %}
<td colspan="3" style="color:#888">— внешний пир (без QR) —</td>
{% endif %}
</tr>
{% endfor %}
</table>
</div>
<script>
function showRename(btn){
  const form = btn.nextElementSibling;
  if(!form) return;
  form.style.display = 'inline-flex';
  btn.style.display = 'none';
  const inp = form.querySelector('input[name="name"]');
  if(inp){ inp.focus(); inp.select(); }
}
async function refreshStatus(){
  try{
    const r = await fetch('/api/status', {cache:'no-store'});
    if(!r.ok) return;
    const d = await r.json();
    for(const n in d){
      const card = document.getElementById('if-'+n);
      if(!card) continue;
      const v = d[n];
      const set = (f, val) => { const el = card.querySelector('[data-f="'+f+'"]'); if(el) el.textContent = val; };
      const st = card.querySelector('[data-f="state"]');
      if(st){ st.textContent = v.state_ru; st.className = 'badge ' + v.cls; }
      set('port', v.port);
      set('peers', v.peers + ' (активных ' + v.peers_active + ')');
      const hsEl = card.querySelector('[data-f="hs"]');
      if(hsEl){ hsEl.textContent = v.handshake; hsEl.className = v.hs_cls || ''; }
      card.className = 'card' + (v.hs_card_cls ? ' ' + v.hs_card_cls : '');
      set('rx', v.rx); set('tx', v.tx);
      set('uptime', v.uptime);
    }
  }catch(e){}
}
async function refreshPeers(){
  try{
    const r = await fetch('/api/peers', {cache:'no-store'});
    if(!r.ok) return;
    const d = await r.json();
    document.querySelectorAll('tr[data-pk]').forEach(tr => {
      const v = d[tr.dataset.pk];
      if(!v) return;
      const q = f => tr.querySelector('[data-p="'+f+'"]');
      const ep = q('endpoint'); if(ep) ep.textContent = v.endpoint;
      const mac = q('mac'); if(mac) mac.textContent = v.mac;
      const hs = q('hs'); if(hs){ hs.textContent = v.handshake; hs.className = v.hs_cls || ''; }
      const rx = q('rx'); if(rx) rx.textContent = v.rx;
      const tx = q('tx'); if(tx) tx.textContent = v.tx;
      const dot = q('dot'); if(dot) dot.className = 'dot' + (v.dot_cls ? ' ' + v.dot_cls : '');
    });
  }catch(e){}
}
async function refreshRu(){
  try{
    const r = await fetch('/api/ru', {cache:'no-store'});
    if(!r.ok) return;
    const v = await r.json();
    const card = document.getElementById('ru-card');
    if(!card) return;
    const set = (f, val) => { const el = card.querySelector('[data-f="'+f+'"]'); if(el) el.textContent = val; };
    set('ru-count', v.count);
    set('ru-updated', v.updated);
    set('ru-log', v.last_log || '—');
    const b = card.querySelector('[data-f="ru-badge"]');
    if(b){
      if(v.running){ b.textContent = 'обновляется…'; b.className = 'badge warn'; }
      else if(v.ok === false){ b.textContent = 'ошибка'; b.className = 'badge err'; }
      else { b.textContent = 'актуально'; b.className = 'badge ok'; }
    }
  }catch(e){}
}
setInterval(refreshStatus, 10000);
setInterval(refreshPeers, 10000);
setInterval(refreshRu, 10000);
</script>
</body></html>"""

@app.route('/')
def index():
    _ensure_peer_info_thread()
    peers = parse_peers()
    stats = _peer_stats('awg0')
    now = time.time()
    for p in peers:
        p['ip'] = (p.get('allowed_ips') or '').split(',')[0].strip() or '—'
        p['display'] = p.get('name') or f"({(p.get('public_key') or '')[:12]}…)"
        p['has_client'] = bool(p.get('name') and os.path.exists(os.path.join(CLIENTS_DIR, f"{p['name']}.conf")))
        p.update(peer_view(stats, p.get('public_key'), now))
    ru = ru_state_view()
    ru["badge_cls"] = "warn" if ru["running"] else ("err" if ru["ok"] is False else "ok")
    ru["badge_text"] = "обновляется…" if ru["running"] else ("ошибка" if ru["ok"] is False else "актуально")
    return render_template_string(TEMPLATE, peers=peers, ext=detect_external(), loc=detect_internal(),
                                  port=get_listen_port(), csrf=CSRF_TOKEN,
                                  ifaces=[iface_status(n) for n in IFACE_SERVICES], ru=ru,
                                  msg=request.args.get('msg'), ok=request.args.get('ok') == '1')

@app.route('/api/status')
def api_status():
    return Response(json.dumps({n: iface_status(n) for n in IFACE_SERVICES}, ensure_ascii=False),
                    mimetype='application/json')

@app.route('/api/ru')
def api_ru():
    return Response(json.dumps(ru_state_view(), ensure_ascii=False), mimetype='application/json')

@app.post('/update-ru')
def update_ru():
    with _ru_lock:
        if _ru_state["running"]:
            return redirect(url_for('index', msg='Обновление RU-маршрутов уже выполняется', ok=0))
        _ru_state.update({"running": True, "ok": None, "msg": None})
    threading.Thread(target=_run_ru_update, daemon=True).start()
    return redirect(url_for('index', msg='Обновление RU-маршрутов запущено — это займёт до минуты', ok=1))

@app.route('/api/peers')
def api_peers():
    _ensure_peer_info_thread()
    stats = _peer_stats('awg0')
    now = time.time()
    return Response(json.dumps({pk: peer_view(stats, pk, now) for pk in stats}, ensure_ascii=False),
                    mimetype='application/json')

@app.post('/restart/<iface>')
def restart_iface(iface):
    if iface not in IFACE_SERVICES: abort(404)
    msg, ok = f"{iface} перезапущен", True
    try:
        r = subprocess.run(["systemctl", "restart", IFACE_SERVICES[iface]],
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            ok = False
            err = (r.stderr or r.stdout or b"").decode(errors="ignore").strip()
            msg = f"Не удалось перезапустить {iface}: {err[:300] or 'код ' + str(r.returncode)}"
        else:
            subprocess.run(["systemctl", "restart", RULES_SERVICE], capture_output=True, timeout=60)
    except Exception as e:
        ok, msg = False, f"Не удалось перезапустить {iface}: {e}"
    return redirect(url_for('index', msg=msg, ok=1 if ok else 0))

@app.post('/create')
def create():
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    if detect_external() == "0.0.0.0":
        return redirect(url_for('index', msg='Не удалось определить внешний IP — клиент не создан', ok=0))
    with open(AWG_CONF + '.lock', 'w', encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            peers = parse_peers()
            ip_last = next_ip(peers)
            if ip_last is None:
                return "Все IP в подсети 10.8.0.0/24 заняты", 400
            try:
                priv, pub = gen_keypair()
            except Exception as e:
                return redirect(url_for('index', msg=f'Не удалось сгенерировать ключи: {e}', ok=0))
            existing = {p.get('name') for p in peers}
            while True:
                name = "peer_" + secrets.token_hex(3)
                if name not in existing:
                    break
            ip32 = f"10.8.0.{ip_last}/32"
            with open(AWG_CONF, 'a', encoding="utf-8") as f:
                f.write(f"\n# Name = {name}\n[Peer]\nPublicKey = {pub}\nAllowedIPs = {ip32}\n")
            os.chmod(AWG_CONF, 0o600)
            subprocess.run(['awg', 'set', 'awg0', 'peer', pub, 'allowed-ips', ip32],
                           check=False, timeout=10)
            try:
                write_client_confs(name, priv, ip32)
            except Exception as e:
                # откат: пир не должен остаться без конфигов
                rewrite_peers(peers)
                subprocess.run(['awg', 'set', 'awg0', 'peer', pub, 'remove'],
                               check=False, timeout=10)
                return redirect(url_for('index', msg=f'Не удалось записать конфиги клиента: {e}', ok=0))
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)
    return redirect(url_for('index'))

NAME_RE = re.compile(r'^[\w-]{1,32}$')

@app.post('/delete/<name>')
def delete(name):
    if not NAME_RE.match(name): abort(400)
    with open(AWG_CONF + '.lock', 'w', encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            peers = parse_peers()
            target = next((p for p in peers if p.get('name') == name), None)
            if target and target.get('public_key'):
                ep = (_peer_stats('awg0').get(target['public_key']) or {}).get('endpoint')
                ip = _endpoint_ip(ep)
                subprocess.run(['awg', 'set', 'awg0', 'peer', target['public_key'], 'remove'],
                               check=False, timeout=10)
                if ip:
                    with _peer_info_lock:
                        _peer_info.pop(ip, None)
                    _save_peer_info()
            peers = [p for p in peers if p.get('name') != name]
            rewrite_peers(peers)
            for suffix in ('', '-local'):
                fp = os.path.join(CLIENTS_DIR, f"{name}{suffix}.conf")
                if os.path.exists(fp): os.remove(fp)
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)
    return redirect(url_for('index'))

@app.post('/rename/<old>')
def rename(old):
    if not NAME_RE.match(old): abort(400)
    new = (request.form.get('name') or '').strip()
    if not NAME_RE.match(new):
        return redirect(url_for('index', msg='Недопустимое имя: буквы, цифры, _ и -, до 32 символов', ok=0))
    if new == old:
        return redirect(url_for('index', msg='Имя не изменилось', ok=1))
    with open(AWG_CONF + '.lock', 'w', encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            peers = parse_peers()
            if not any(p.get('name') == old for p in peers):
                return redirect(url_for('index', msg=f'Пир {old} не найден', ok=0))
            if any(p.get('name') == new for p in peers):
                return redirect(url_for('index', msg=f'Имя «{new}» уже занято', ok=0))
            with open(AWG_CONF, encoding="utf-8") as f:
                lines = f.readlines()
            marker = f'# Name = {old}'
            idx = next((i for i, line in enumerate(lines) if line.strip() == marker), None)
            if idx is None:
                return redirect(url_for('index', msg='Не нашёл имя в конфиге', ok=0))
            lines[idx] = f'# Name = {new}\n'
            _atomic_write(AWG_CONF, "".join(lines))
            for suffix in ('', '-local'):
                src = os.path.join(CLIENTS_DIR, f"{old}{suffix}.conf")
                dst = os.path.join(CLIENTS_DIR, f"{new}{suffix}.conf")
                if os.path.exists(src):
                    os.replace(src, dst)
                    os.chmod(dst, 0o600)
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)
    return redirect(url_for('index', msg=f'Пир «{old}» переименован в «{new}»', ok=1))

@app.route('/qr/<name>/<kind>')
def qr(name, kind):
    if kind not in ('external', 'local'):
        abort(404)
    if not NAME_RE.match(name):
        abort(400)
    path = os.path.join(CLIENTS_DIR, f"{name}{'-local' if kind == 'local' else ''}.conf")
    if not os.path.exists(path):
        abort(404)
    with open(path, encoding="utf-8") as f:
        content = f.read()
    try:
        png = subprocess.check_output(
            ['qrencode', '-t', 'PNG', '-o', '-', '-s', '6', content], timeout=15)
    except (OSError, subprocess.SubprocessError):
        abort(500)
    return Response(png, mimetype='image/png')

@app.route('/config/<name>/<kind>')
def config(name, kind):
    if kind not in ('external', 'local'):
        abort(404)
    if not NAME_RE.match(name):
        abort(400)
    fname = f"{name}{'-local' if kind == 'local' else ''}.conf"
    path = os.path.join(CLIENTS_DIR, fname)
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=fname, mimetype='text/plain')

QR_TEMPLATE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QR — {{ name }}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#222}
h1{font-size:20px;border-bottom:2px solid #333;padding-bottom:6px}
.qrs{display:flex;gap:20px;flex-wrap:wrap}
.qr{flex:1 1 320px;border:1px solid #ddd;border-radius:8px;padding:14px;text-align:center;background:#fff}
.qr h2{font-size:15px;margin:4px 0 10px}
.qr img{width:100%;max-width:320px;height:auto}
.note{color:#666;font-size:12px;margin-top:8px}
.btn{display:inline-block;padding:8px 14px;background:#007bff;color:#fff;text-decoration:none;border-radius:4px;margin:16px 8px 0 0}
</style></head><body>
<h1>QR — {{ name }}</h1>
<div class="qrs">
<div class="qr"><h2>Внешний</h2><img src="/qr/{{ name|urlencode }}/external" alt="QR внешний"><div class="note">Endpoint — внешний IP</div></div>
<div class="qr"><h2>Локальный</h2><img src="/qr/{{ name|urlencode }}/local" alt="QR локальный"><div class="note">Endpoint — адрес в локальной сети</div></div>
</div>
<p><a class="btn" href="/config/{{ name|urlencode }}">Скачать оба конфига (.zip)</a>
<a class="btn" style="background:#6c757d" href="/">← Назад</a></p>
</body></html>"""

@app.route('/qr/<name>')
def qr_page(name):
    if not NAME_RE.match(name): abort(400)
    if not os.path.exists(os.path.join(CLIENTS_DIR, f"{name}.conf")): abort(404)
    return render_template_string(QR_TEMPLATE, name=name)

@app.route('/config/<name>')
def config_zip(name):
    if not NAME_RE.match(name): abort(400)
    files = [os.path.join(CLIENTS_DIR, f"{name}{s}") for s in (".conf", "-local.conf")]
    files = [p for p in files if os.path.exists(p)]
    if not files: abort(404)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in files:
            z.write(p, os.path.basename(p))
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f"{name}-awg.zip",
                     mimetype="application/zip")


# ================== UPSTREAM (awg1.conf) ==================
AWG1_CONF = os.path.join(CONFIG_DIR, "awg1.conf")
UPSTREAM_SERVICE = "awg-quick@awg1"

UPSTREAM_TEMPLATE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>AWG Router — Upstream</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}
h1{font-size:1.6rem}
textarea{width:100%;min-height:480px;font-family:ui-monospace,monospace;font-size:13px;padding:10px;border:1px solid #ccc;border-radius:8px;box-sizing:border-box}
button{padding:10px 18px;background:#2563eb;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:15px}
button:hover{background:#1d4ed8}
.msg{padding:10px 14px;border-radius:8px;margin:10px 0}
.msg.ok{background:#dcfce7;color:#166534;border:1px solid #86efac}
.msg.err{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}
.note{background:#fef9c3;border:1px solid #fde047;padding:10px 14px;border-radius:8px;color:#713f12;font-size:14px;line-height:1.45}
a{color:#2563eb}
</style></head><body>
<p><a href="/">← назад к клиентам</a></p>
<h1>Upstream (awg1.conf)</h1>
<div class="note">
  <b>Внимание:</b> вставляй <b>полный</b> конфиг от VPN-провайдера (секции <code>[Interface]</code> и <code>[Peer]</code>).
  После сохранения сервис <code>awg-quick@awg1</code> перезапустится. Если handshake не появится за 25 сек — конфиг откатится к бэкапу.
  <br>Строка <code>Table = off</code> добавляется автоматически (защита от поломки RPi).
</div>
{% if msg %}<div class="msg {{ 'ok' if ok else 'err' }}">{{ msg }}</div>{% endif %}
<form method="post" action="/upstream">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <p><textarea name="config" spellcheck="false">{{ current }}</textarea></p>
  <button type="submit">Сохранить и перезапустить awg1</button>
</form>
{% if backup_path %}<p>Бэкап: <code>{{ backup_path }}</code></p>{% endif %}
</body></html>
"""

def _is_valid_upstream(text):
    t = text.strip()
    if not t: return False, "пустой конфиг"
    for marker in ("[Interface]", "[Peer]", "PrivateKey", "PublicKey", "Endpoint"):
        if marker not in t: return False, f"в конфиге нет {marker}"
    return True, ""

def _test_upstream(text):
    fd, tmp = tempfile.mkstemp(prefix="awg1-test-", suffix=".conf")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        r = subprocess.run(["awg-quick", "strip", tmp], capture_output=True, timeout=10)
        return r.returncode == 0, (r.stderr or r.stdout).decode(errors="ignore")
    except Exception as e:
        return False, str(e)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

def _wait_handshake(max_sec=25):
    deadline = time.time() + max_sec
    while time.time() < deadline:
        try:
            out = subprocess.check_output(["awg", "show", "awg1"], timeout=5, stderr=subprocess.DEVNULL).decode()
            if any("latest handshake" in l and "ago" in l for l in out.splitlines()):
                return True
        except Exception: pass
        time.sleep(2)
    return False

@app.route("/upstream", methods=["GET", "POST"])
def upstream():
    # Авторизация и CSRF уже проверены в before_request.
    msg, ok, backup_path = None, True, None
    if request.method == "POST":
        text = (request.form.get("config") or "").replace("\r\n", "\n").strip()

        # Защита от человеческого фактора: принудительно добавляем Table = off
        if "Table = off" not in text:
            text = text.replace("[Interface]", "[Interface]\nTable = off")

        valid, err = _is_valid_upstream(text)
        if not valid:
            msg, ok = f"Не сохранено: {err}", False
        else:
            syntax_ok, syntax_err = _test_upstream(text)
            if not syntax_ok:
                msg, ok = f"Не сохранено: awg-quick strip ругается — {syntax_err[:300]}", False
            else:
                ts = time.strftime("%Y%m%d-%H%M%S")
                backup_path = f"{AWG1_CONF}.bak.{ts}"
                try:
                    if os.path.exists(AWG1_CONF):
                        shutil.copy2(AWG1_CONF, backup_path)
                    _atomic_write(AWG1_CONF, text + "\n")
                    subprocess.run(["systemctl", "restart", UPSTREAM_SERVICE],
                                   check=True, timeout=30)
                    subprocess.run(["systemctl", "restart", RULES_SERVICE], timeout=30)
                    time.sleep(2)
                    if _wait_handshake(25):
                        msg, ok = "Конфиг сохранён, awg1 перезапущен, handshake есть.", True
                    else:
                        raise RuntimeError("handshake не появился за 25 сек")
                except Exception as e:
                    ok = False
                    if os.path.exists(backup_path):
                        try:
                            shutil.copy2(backup_path, AWG1_CONF)
                            os.chmod(AWG1_CONF, 0o600)
                            subprocess.run(["systemctl", "restart", UPSTREAM_SERVICE],
                                           timeout=30)
                            subprocess.run(["systemctl", "restart", RULES_SERVICE],
                                           timeout=30)
                            msg = f"Не сохранено ({e}) — конфиг откачен к бэкапу."
                        except Exception as e2:
                            msg = f"Ошибка ({e}); откат не удался: {e2}"
                    else:
                        msg = f"Ошибка при сохранении: {e}"

    try:
        with open(AWG1_CONF, encoding="utf-8") as f:
            current = f.read()
    except Exception as e:
        current = f"# не удалось прочитать {AWG1_CONF}: {e}"

    html = render_template_string(UPSTREAM_TEMPLATE, current=current, msg=msg, ok=ok, backup_path=backup_path, csrf=CSRF_TOKEN)
    return Response(html, mimetype="text/html")


# ================== REBOOT ==================
REBOOT_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5;url=/">
<title>AWG Router — Перезагрузка</title>
<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:4rem auto;padding:0 1rem;color:#222;text-align:center}
.box{background:#fef9c3;border:1px solid #fde047;padding:20px;border-radius:10px;color:#713f12;font-size:16px;line-height:1.5}
</style></head><body>
<h1>⟳ Raspberry Pi перезагружается…</h1>
<div class="box">Команда перезагрузки отправлена. VPN будет недоступен около 1–2 минут.<br>
Страница обновится автоматически.</div>
</body></html>"""

@app.post('/reboot')
def reboot():
    def _do_reboot():
        time.sleep(1.5)
        try:
            subprocess.call(["systemctl", "reboot", "--no-block"], timeout=10)
        except Exception:
            pass
    threading.Thread(target=_do_reboot, daemon=True).start()
    return Response(REBOOT_PAGE, mimetype="text/html")


class QuietHandler(WSGIRequestHandler):
    # Не светим версию Werkzeug/Python в заголовке Server
    def version_string(self):
        return "awg"

if __name__ == '__main__':
    ssl_ctx = None
    if TLS_CERT and TLS_KEY:
        ssl_ctx = (TLS_CERT, TLS_KEY)
        scheme = "https"
    else:
        scheme = "http"
        print("WARNING: TLS is not configured — serving plain HTTP", flush=True)
    print(f"Serving on {scheme}://{WEB_BIND}:{WEB_PORT} (auth user: {WEB_USER})", flush=True)
    app.run(host=WEB_BIND, port=WEB_PORT, threaded=True, debug=False, ssl_context=ssl_ctx,
            request_handler=QuietHandler)
