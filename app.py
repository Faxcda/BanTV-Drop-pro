#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, hashlib, hmac, ipaddress, json, os, platform, re, secrets, shutil, socket, subprocess, sys, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
import urllib.request
try: import webview
except Exception: webview=None
try: import qrcode
except Exception: qrcode=None

MAGIC, VERSION = "BANTV-DROP", "10.21"
HOST_ALIAS = "host"
if getattr(sys,"frozen",False):                      # запаковано в EXE
    RES = Path(sys._MEIPASS)                         # ресурсы (index.html, иконка)
else:
    RES = Path(__file__).resolve().parent
# Данные никогда не хранятся рядом с исходниками или EXE.
DATA = Path(os.environ.get("APPDATA") or str(Path.home()))/"BanTV Drop"
DATA.mkdir(parents=True, exist_ok=True)
SETTINGS_F, PAIRED_F = DATA/"bantv_settings.json", DATA/"bantv_paired.json"
DEVICES_F, LINKS_F   = DATA/"bantv_devices.json",  DATA/"bantv_links.json"
LOG_F, INDEX_F       = DATA/"bantv_log.txt",       RES/"index.html"
TEMP_DIR, SHARED_DIR = DATA/".bantv_temp",         DATA/"BanTV Shared"
MAX_BODY, JSON_CAP   = 8*1024**3, 1024*1024
RATE_MAX, UDP_PORT   = 120, 8445
LOCK = threading.RLock(); UDP_OK=False; HTTP_PORT=8420
JOIN_RATE={}; PAIR_RATE={}; PKG_BYTES={}

def load_j(p,d):
    try:
        if p.exists(): return json.loads(p.read_text("utf-8"))
    except Exception: pass
    return d
def save_j(p,d):
    """Атомарная запись: сбой не оставляет повреждённый JSON."""
    tmp=p.with_suffix(p.suffix+".tmp")
    try:
        tmp.write_text(json.dumps(d,ensure_ascii=False,indent=1),encoding="utf-8")
        tmp.replace(p)
    except OSError as e:
        # log() ещё может быть не объявлен во время начальной загрузки.
        print("BanTV Drop: не удалось сохранить",p.name,":",e,file=sys.stderr)
        try: tmp.unlink(missing_ok=True)
        except OSError: pass

SETTINGS = load_j(SETTINGS_F,{})
SELF_ID   = SETTINGS.setdefault("self_id", secrets.token_hex(8))
SELF_NAME = SETTINGS.setdefault("self_name",(platform.node() or "PC")[:24])
SETTINGS.setdefault("save_dir", str(DATA/"BanTV Received"))   # ✅ исправлено: DATA, не BASE
SETTINGS.setdefault("auto_accept", False)
SETTINGS.setdefault("speed_limit", 0)
SETTINGS.setdefault("blocked", [])
save_j(SETTINGS_F, SETTINGS)
SAVE_DIR = Path(SETTINGS["save_dir"])
for _d in (SAVE_DIR, SHARED_DIR, TEMP_DIR):
    try: _d.mkdir(parents=True, exist_ok=True)
    except Exception: pass

PAIRED  = load_j(PAIRED_F,{})
DEVICES = load_j(DEVICES_F,{})
LINKS   = load_j(LINKS_F,{"pairs":[],"groups":[]})
LINKS.setdefault("pairs",[]); LINKS.setdefault("groups",[])
SESSIONS, PACKAGES, FILE_REG = {},[],{}
PAIRING = {"active":False,"code":None,"expires":0.0,"url":""}
PAIR_INVITES, PAIR_REQUESTS, GROUP_INVITES = [],[],[]
PEERS, SPEED, LOGS, RATE = {},[0.0]*70,[],{}
BYTES = {"v":0}

def log(m):
    t=time.strftime("%H:%M:%S")
    with LOCK:
        LOGS.append({"time":t,"message":m})
        if len(LOGS)>200: del LOGS[:len(LOGS)-200]
    try:
        if LOG_F.exists() and LOG_F.stat().st_size>2*1024**2:
            LOG_F.replace(LOG_F.with_name("bantv_log.old.txt"))
        open(LOG_F,"a",encoding="utf-8").write(f"{t} {m}\n")
    except Exception: pass

def now(): return time.time()
def new_id(p): return p+"_"+secrets.token_hex(6)
def sanitize(n):
    n=re.sub(r"[^\w. \-]+","_",str(n or "")).strip()[:120]
    if n.startswith("."): n="_"+n
    return n or "file.bin"
def unique_path(d,n):
    p=d/n
    if not p.exists(): return p
    i=1
    while True:
        q=d/f"{p.stem}_{i}{p.suffix}"
        if not q.exists(): return q
        i+=1
def in_dir(path, root):
    """Проверка принадлежности пути разрешённому каталогу без path traversal."""
    try:
        return Path(path).resolve().is_relative_to(Path(root).resolve())
    except Exception:
        return False
def in_save_dir(path): return in_dir(path, SAVE_DIR)
def in_temp_dir(path): return in_dir(path, TEMP_DIR)
def in_shared_dir(path): return in_dir(path, SHARED_DIR)
def sha256_file(path,chunk=1024*1024):
    h=hashlib.sha256()
    try:
        with open(path,"rb") as f:
            while True:
                c=f.read(chunk)
                if not c: break
                h.update(c)
        return h.hexdigest()
    except Exception: return ""
def join_ok(ip, bucket=JOIN_RATE, limit=3):
    """Ограничение подбора кодов: не более трёх попыток за минуту с IP."""
    t=now(); a=bucket.setdefault(ip,[])
    while a and t-a[0]>60: a.pop(0)
    a.append(t); return len(a)<=limit
def _private_ipv4(value):
    try:
        ip=ipaddress.ip_address(value)
        return ip.version==4 and ip.is_private and not ip.is_loopback
    except ValueError: return False
def my_addresses():
    """Возвращает только реальные LAN-адреса, не маршрут VPN по умолчанию.

    Последний выбранный LAN-IP сохраняется, поэтому QR не прыгает при
    подключении VPN, пока прежний адаптер остаётся подключённым.
    """
    ips=[]
    for host in (socket.gethostname(), socket.getfqdn()):
        try:
            for item in socket.getaddrinfo(host,None,socket.AF_INET):
                ip=item[4][0]
                if _private_ipv4(ip) and ip not in ips: ips.append(ip)
        except OSError: pass
    saved=SETTINGS.get("lan_ip")
    if saved in ips:
        ips.remove(saved); ips.insert(0,saved)
    elif ips:
        SETTINGS["lan_ip"]=ips[0]; save_j(SETTINGS_F,SETTINGS)
    return ips or ["127.0.0.1"]
def my_url(): return f"http://{my_addresses()[0]}:{HTTP_PORT}"
def session_ok(c):
    s=SESSIONS.get(c); return bool(s and now()-s["last"]<30)
def can_act(cid,tok=""):
    """Хост — только loopback; остальные — только с выданным токеном пары."""
    if cid==SELF_ID: return True
    if cid in PAIRED and tok and PAIRED[cid]["token"]==tok: return True
    return False
def members_of(p):
    t,i=p["target_type"],p["target_id"]
    if i==HOST_ALIAS: i=SELF_ID
    if t=="device": return {i}
    if t=="pair":
        for x in LINKS["pairs"]:
            if x["id"]==i: return set(x["members"])
    if t=="group":
        for g in LINKS["groups"]:
            if g["id"]==i: return {m["id"] for m in g["members"]}
    return set()
def visible(p,c): return p["sender_id"]==c or c in members_of(p)
def rate_ok(ip):
    t=now(); a=RATE.setdefault(ip,[])
    while a and t-a[0]>10: a.pop(0)
    a.append(t); return len(a)<=RATE_MAX
def peer_post(url,path,data=None,raw=None,hdr=None,timeout=60):
    # Magic — лишь маркер протокола; реальная проверка выполняется по паре и IP.
    h={"X-BanTV-Magic":MAGIC,"X-BanTV-Peer":SELF_ID}
    body=json.dumps(data).encode() if raw is None else raw
    if raw is None: h["Content-Type"]="application/json"
    h.update(hdr or {})
    rq=urllib.request.Request(url.rstrip("/")+path,data=body,headers=h,method="POST")
    with urllib.request.urlopen(rq,timeout=timeout) as r: return json.loads(r.read() or b"{}")
def save_links(): save_j(LINKS_F,LINKS)
def probe_peers(path,payload,timeout=2):
    with LOCK: peers=list(PEERS.items())
    for pid,pv in peers:
        if not pv.get("online"): continue
        try:
            r=peer_post(pv["url"],path,payload,timeout=timeout)
            if r.get("ok") and r.get("found"): return r
        except Exception: pass
    return None
def url_points_to(url, ip):
    try: return urlparse(str(url)).hostname==ip
    except ValueError: return False
def known_peer(fid, ip):
    """Принимаем команды peer только от уже сопряжённого ПК с ожидаемого IP."""
    if not fid: return False
    with LOCK:
        for pair in LINKS["pairs"]:
            if SELF_ID in pair.get("members",[]) and fid in pair.get("members",[]) \
               and url_points_to(pair.get("remote_url",""),ip):
                return True
    return False
def pending_peer(req_id, ip):
    with LOCK:
        return any(r.get("id")==req_id and url_points_to(r.get("remote_to",""),ip)
                   for r in PAIR_REQUESTS)

def discovery_sender():
    while True:
        try:
            msg=json.dumps({"magic":MAGIC,"id":SELF_ID,"name":SELF_NAME,
                "url":my_url(),"port":HTTP_PORT,"ts":now()}).encode()
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
            s.sendto(msg,("<broadcast>",UDP_PORT)); s.close()
        except Exception: pass
        time.sleep(2)
def discovery_listener():
    global UDP_OK
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    try:
        s.bind(("",UDP_PORT)); UDP_OK=True
    except Exception: return
    while True:
        try:
            d,_=s.recvfrom(2048); d=json.loads(d.decode("utf-8","ignore"))
            if d.get("magic")!=MAGIC: continue
            if d.get("id")==SELF_ID: continue
            if d.get("url")==my_url(): continue
            if d["id"] in SETTINGS["blocked"]: continue
            with LOCK: PEERS[d["id"]]={"name":d.get("name","PC"),"url":d.get("url",""),"last":now(),"online":True}
        except Exception: time.sleep(.5)
def speed_loop():
    last=BYTES["v"]
    while True:
        time.sleep(1)
        with LOCK:
            v=BYTES["v"]; SPEED.append(float(v-last)); last=v
            while len(SPEED)>70: SPEED.pop(0)
def cleanup_loop():
    while True:
        time.sleep(15); t=now()
        with LOCK:
            if PAIRING["active"] and t>PAIRING["expires"]: PAIRING.update(active=False,code=None)
            for a in (PAIR_INVITES,GROUP_INVITES): a[:]=[x for x in a if x["expires"]>t]
            PAIR_REQUESTS[:]=[x for x in PAIR_REQUESTS if x.get("expires",1e18)>t]
            for p in PACKAGES:
                if p["status"]=="offering" and t-p["created"]>600: p["status"]="canceled"
            LINKS["pairs"]=[p for p in LINKS["pairs"] if p.get("permanent") or p.get("expires",1e18)>t]
            save_links()
def peer_watchdog():
    while True:
        time.sleep(5)
        with LOCK:
            for p in PEERS.values(): p["online"]=(now()-p["last"])<10

def push_file_to_peer(pkg,fi,path,url):
    try:
        data=Path(path).read_bytes()
        peer_post(url,
                  f"/api/peer/push?package_id={pkg.get('peer_pkg_id') or pkg['id']}&file_id={fi['id']}",
                  raw=data,hdr={"X-File-Name":fi["name"],"X-File-Sha":fi.get("sha256","")})
    except Exception as e:
        log("push error: "+str(e))

class WinApi:
    _max=False; _geo=None
    def minimize(self):
        try: webview.windows[0].minimize()
        except Exception: pass
    def toggle_max(self):
        w=webview.windows[0]
        if not WinApi._max:
            try: WinApi._geo=(w.x,w.y,w.width,w.height)
            except Exception: WinApi._geo=None
            try: w.maximize()
            except Exception: pass
            WinApi._max=True
        else:
            try: w.restore()
            except Exception: pass
            if WinApi._geo:
                try:
                    x,y,wd,ht=WinApi._geo
                    w.move(x,y); w.resize(wd,ht)
                except Exception: pass
            WinApi._max=False
    def close(self):
        try: webview.windows[0].destroy()
        except Exception: pass

class H(BaseHTTPRequestHandler):
    server_version="BanTVDrop/"+VERSION; protocol_version="HTTP/1.1"
    def log_message(self,*a): pass
    def _send(self,code,body,ct="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type",ct); self.send_header("Content-Length",str(len(body)))
        self.send_header("Cache-Control","no-store")
        self.end_headers()
        try: self.wfile.write(body)
        except Exception: pass
    def _json(self,d,code=200): self._send(code,json.dumps(d,ensure_ascii=False).encode())
    def _drain(self,n):
        while n>0:
            c=self.rfile.read(min(65536,n))
            if not c: break
            n-=len(c)
    def _body(self):
        n=int(self.headers.get("Content-Length") or 0)
        if n>JSON_CAP: self._drain(n); return {}
        raw=self.rfile.read(n) if n else b""
        try: return json.loads(raw or b"{}")
        except Exception: return {}
    def _q(self): return parse_qs(urlparse(self.path).query)
    def _cid(self,b=None):
        """C1: хост ТОЛЬКО loopback. Удалённый клиент не может выдать себя за хоста."""
        ip=self.client_address[0]
        if ip in ("127.0.0.1","::1") or ip.startswith("127."):
            return SELF_ID
        q=self._q()
        claimed=str((b or {}).get("client") or q.get("client",[""])[0] or "")
        if claimed in (SELF_ID,HOST_ALIAS):
            # попытка выдать себя за хоста -> анонимный стабильный id по IP+UA
            ua=self.headers.get("User-Agent","")
            claimed="anon_"+hashlib.sha256((ip+ua).encode()).hexdigest()[:12]
        return claimed
    def _token(self,b=None):
        h=self.headers.get("X-BanTV-Token")
        if h: return h
        q=self._q()
        return str((b or {}).get("token") or q.get("token",[""])[0] or "")
    def _qr(self,text):
        if not qrcode: return self._json({"error":"qrcode not installed"},404)
        import io; buf=io.BytesIO(); qrcode.make(text).save(buf,"PNG")
        self._send(200,buf.getvalue(),"image/png")

    def do_GET(self):
        p=urlparse(self.path).path
        if p in ("/","/index.html"):
            try: data=INDEX_F.read_bytes()
            except Exception:
                data="<h1>BanTV Drop</h1><p>index.html not found next to app.py</p>".encode("utf-8")
            return self._send(200,data,"text/html; charset=utf-8")
        if p=="/api/ping": return self._json({"ok":True})
        if p=="/api/qr/address": return self._qr(f"{my_url()}/")
        if p=="/api/qr/pairing":
            with LOCK:
                if not PAIRING["active"]: return self._json({"error":"none"},404)
                return self._qr(PAIRING["url"])
        if p=="/api/state": return self._state()
        if p.startswith("/api/download/"): return self._download(unquote(p[len("/api/download/"):]))
        return self._json({"error":"nf"},404)

    def _state(self):
        cid=self._cid(); tok=self._token()
        authorized=can_act(cid,tok)
        # До сопряжения не раскрываем список устройств, группы, историю и файлы.
        # Этого минимального состояния достаточно, чтобы открыть QR/ссылку и пройти pair.
        if cid!=SELF_ID and not authorized:
            return self._json({"ok":True,"authorized":False,"now":now(),"version":VERSION,
                "status":"Требуется сопряжение","server":{"url":my_url(),"port":HTTP_PORT,
                "addresses":my_addresses(),"ip":my_addresses()[0]},"self":{"id":HOST_ALIAS,
                "name":SELF_NAME,"platform":"pc"},"settings":{"auto_accept":False,"speed_limit":0},
                "devices":[],"packages":[],"files":{"shared":[]},"logs":[],"speed_history":SPEED,
                "pairs":[],"groups":[],"pair_requests":[],"pair_invites":[],"group_invites":[],
                "paired_ids":[],"pairing":{"active":False,"code":None,"url":"","expires_in":0}})
        if cid and cid!=SELF_ID:
            with LOCK:
                s=SESSIONS.setdefault(cid,{"name":DEVICES.get(cid,"Device"),"platform":"phone","last":now()})
                s["last"]=now()
        host = cid==SELF_ID
        def mask(x): return HOST_ALIAS if (not host and x==SELF_ID) else x
        with LOCK:
            dev=[{"id":(SELF_ID if host else HOST_ALIAS),"name":SELF_NAME,"platform":"pc",
                  "online":True,"paired":True,"is_self":host,"remote":False}]
            for k,v in SESSIONS.items():
                if k==SELF_ID: continue
                dev.append({"id":k,"name":v.get("name","Device"),"platform":v.get("platform","phone"),
                            "online":session_ok(k),"paired":k in PAIRED,"is_self":False,"remote":False})
            pkgs=[dict(p, progress=PKG_BYTES.get(p["id"],0)) for p in PACKAGES if (cid and visible(p,cid))]
            pairing=({"active":PAIRING["active"],"code":PAIRING["code"],"url":PAIRING["url"],
                      "expires_in":max(0,int(PAIRING["expires"]-now()))} if host
                     else {"active":False,"code":None,"url":"","expires_in":0})
            pairs_out=[]
            for pr in LINKS["pairs"]:
                cpr=dict(pr)
                if not host:
                    cpr["members"]=[mask(m) for m in pr["members"]]
                    cpr["names"]={mask(k):v for k,v in (pr.get("names") or {}).items()}
                pairs_out.append(cpr)
            self._json({
             "ok":True,"authorized":True,"now":now(),"version":VERSION,"status":"Активен",
             "settings":{"save_dir":str(SAVE_DIR) if host else "","auto_accept":SETTINGS.get("auto_accept",False),
                         "speed_limit":int(SETTINGS.get("speed_limit",0) or 0)},
             "server":{"url":my_url(),"port":HTTP_PORT,"addresses":my_addresses(),"ip":my_addresses()[0]},
             "self":{"id":(SELF_ID if host else HOST_ALIAS),"name":SELF_NAME,"platform":"pc"},
             "devices":dev,
             "packages":pkgs,
             "files":{"shared":[{"id":"sh_"+f.name,"name":f.name,"size":f.stat().st_size}
                                for f in sorted(SHARED_DIR.iterdir()) if f.is_file()] if SHARED_DIR.exists() else []},
             "logs":LOGS[-80:],"speed_history":SPEED,
             "pairs":pairs_out,
             "pair_requests":[r for r in PAIR_REQUESTS if cid in (r.get("to"),r.get("from"))],
             "pair_invites":[i for i in PAIR_INVITES if i["owner"]==cid],
             "group_invites":[i for i in GROUP_INVITES if self._g_owner(i)==cid],
             "groups":LINKS["groups"],
             "paired_ids":list(PAIRED.keys()) if host else [],
             "pairing":pairing})
    def _g_owner(self,inv):
        g=next((x for x in LINKS["groups"] if x["id"]==inv.get("group_id")),None)
        return g["owner"] if g else None

    def _download(self,fid):
        cid=self._cid(); tok=self._token()
        if not can_act(cid,tok): return self._json({"error":"auth"},403)
        with LOCK:
            if fid.startswith("sh_"):
                path=(SHARED_DIR/sanitize(fid[3:])).resolve()
                if not in_shared_dir(path): return self._json({"error":"deny"},403)
            else:
                m=FILE_REG.get(fid)
                if not m: return self._json({"error":"nf"},404)
                pkg=next((p for p in PACKAGES if p["id"]==m["package_id"]),None)
                if not (cid==SELF_ID or m.get("by")==cid or (pkg and visible(pkg,cid))):
                    return self._json({"error":"deny"},403)
                path,name=Path(m["path"]),m["name"]
        valid_root=in_shared_dir(path) if fid.startswith("sh_") else in_save_dir(path)
        if not path.is_file() or not valid_root: return self._json({"error":"gone"},404)
        self.send_response(200)
        self.send_header("Content-Type","application/octet-stream")
        self.send_header("Content-Length",str(path.stat().st_size))
        self.send_header("Content-Disposition",f'attachment; filename="{name}"')
        self.end_headers()
        with open(path,"rb") as f:
            while True:
                c=f.read(1024*1024)
                if not c: break
                try: self.wfile.write(c)
                except Exception: break

    def do_POST(self):
        p=urlparse(self.path).path
        if p!="/api/upload" and not rate_ok(self.client_address[0]):
            return self._json({"error":"rate"},429)
        if p=="/api/upload": return self._upload()
        body=self._body(); cid=self._cid(body); tok=self._token(body)

        if p.startswith("/api/peer/"):
            if self.headers.get("X-BanTV-Magic")!=MAGIC: return self._json({"error":"magic"},403)
            return self._peer(p,body)

        if p=="/api/pair" and not cid: return self._json({"error":"client"},400)
        if p!="/api/pair" and not can_act(cid,tok): return self._json({"error":"auth"},403)
        host_only = cid!=SELF_ID

        if p in ("/api/heartbeat","/api/register"):
            if cid==SELF_ID: return self._json({"ok":True,"paired":True})
            with LOCK:
                nm=sanitize(body.get("name") or DEVICES.get(cid,"Device"))[:24] or "Device"
                SESSIONS[cid]={"name":nm,"platform":body.get("platform","phone"),"last":now()}
                DEVICES[cid]=nm; save_j(DEVICES_F,DEVICES)
            return self._json({"ok":True,"paired":cid in PAIRED})

        if p=="/api/settings":
            if host_only: return self._json({"error":"host"},403)
            if "auto_accept" in body: SETTINGS["auto_accept"]=bool(body["auto_accept"])
            if "speed_limit" in body:
                try: SETTINGS["speed_limit"]=max(0,int(body["speed_limit"]))
                except Exception: pass
            save_j(SETTINGS_F,SETTINGS)
            log("Настройки изменены"); return self._json({"ok":True})

        if p=="/api/choose-folder":
            if host_only: return self._json({"error":"host"},403)
            d=None
            try:
                import tkinter as tk
                from tkinter import filedialog
                r=tk.Tk(); r.withdraw(); d=filedialog.askdirectory(); r.destroy()
            except Exception: pass
            if d:
                global SAVE_DIR
                SETTINGS["save_dir"]=d; save_j(SETTINGS_F,SETTINGS)
                SAVE_DIR=Path(d); SAVE_DIR.mkdir(parents=True,exist_ok=True); log(f"Папка: {d}")
            return self._json({"ok":bool(d),"dir":d or ""})

        if p=="/api/open-folder":
            if host_only: return self._json({"error":"host"},403)
            try:
                d=str(SAVE_DIR)
                if sys.platform=="win32": subprocess.Popen(["explorer",d])
                elif sys.platform=="darwin": subprocess.Popen(["open",d])
                else: subprocess.Popen(["xdg-open",d])
                return self._json({"ok":True})
            except Exception as e: return self._json({"error":str(e)},500)

        if p=="/api/firewall-allow":
            if host_only: return self._json({"error":"host"},403)
            if sys.platform!="win32":
                return self._json({"ok":False,"error":"не Windows: настройте файрвол вручную"})
            try:
                CF=0x08000000
                subprocess.run(["netsh","advfirewall","firewall","add","rule","name=BanTV Drop HTTP",
                    "dir=in","action=allow","protocol=TCP","localport",str(HTTP_PORT)],
                    check=True,creationflags=CF,timeout=15)
                subprocess.run(["netsh","advfirewall","firewall","add","rule","name=BanTV Drop UDP",
                    "dir=in","action=allow","protocol=UDP","localport",str(UDP_PORT)],
                    check=True,creationflags=CF,timeout=15)
                log("Порт открыт в брандмауэре"); return self._json({"ok":True})
            except Exception as e:
                return self._json({"ok":False,"error":"нужны права администратора: "+str(e)})

        if p=="/api/net-test":
            lan=my_addresses(); selected=lan[0]
            res=[{"name":"HTTP‑сервер","ok":True,"info":f"работает, порт {HTTP_PORT}"},
                 {"name":"LAN‑адрес для QR","ok":selected!="127.0.0.1",
                  "info":selected if selected!="127.0.0.1" else "LAN-адаптер не найден; QR доступен только на этом ПК"},
                 {"name":"VPN‑устойчивый адрес","ok":bool(SETTINGS.get("lan_ip")),
                  "info":"закреплён "+str(SETTINGS.get("lan_ip",selected))+"; VPN не меняет QR, пока LAN подключён"}]
            ip=my_addresses()[0]
            try:
                s=socket.create_connection((ip,HTTP_PORT),timeout=2); s.close()
                res.append({"name":"LAN‑адрес доступен","ok":True,"info":f"{ip}:{HTTP_PORT} отвечает"})
            except Exception as e:
                res.append({"name":"LAN‑адрес доступен","ok":False,"info":f"{ip} не отвечает ({e})"})
            res.append({"name":"UDP discovery","ok":UDP_OK,"info":f"порт {UDP_PORT}: "+("открыт" if UDP_OK else "нет")})
            wr=os.access(str(SAVE_DIR),os.W_OK)
            res.append({"name":"Папка приёма","ok":wr,"info":str(SAVE_DIR) if wr else "нет прав записи"})
            try:
                free=shutil.disk_usage(SAVE_DIR).free
                res.append({"name":"Свободное место","ok":free>256*1024**2,"info":f"{free/1024**3:.1f} ГБ"})
            except OSError as e: res.append({"name":"Свободное место","ok":False,"info":str(e)})
            res.append({"name":"Безопасность","ok":True,"info":"для передачи нужен токен сопряжённого устройства"})
            return self._json({"ok":True,"checks":res,"addresses":lan,"selected_address":selected})

        if p=="/api/pairing/create":
            if host_only: return self._json({"error":"host"},403)
            with LOCK:
                # QR-код и ручной код: 100 млн вариантов вместо 10 тыс.
                code=f"{secrets.randbelow(100_000_000):08d}"
                PAIRING.update(active=True,code=code,expires=now()+300,url=f"{my_url()}/?pair={code}")
                log(f"Код подключения {code}")
                return self._json({"ok":True,"code":code,"url":PAIRING["url"],"expires_in":300})

        if p=="/api/pair":
            if not join_ok(self.client_address[0],PAIR_RATE,3): return self._json({"error":"rate"},429)
            code=str(body.get("code") or "")
            with LOCK:
                if not (PAIRING["active"] and PAIRING["code"]==code and now()<PAIRING["expires"]):
                    return self._json({"error":"code"},403)
                tok_new=secrets.token_urlsafe(24)
                PAIRED[cid]={"token":tok_new,"name":sanitize(body.get("name") or "Device")[:24],"at":now()}
                save_j(PAIRED_F,PAIRED); log("QR‑авторизация устройства")
            return self._json({"ok":True,"token":tok_new})

        if p=="/api/device/rename":
            with LOCK:
                tid=body.get("id") or cid
                if tid==HOST_ALIAS: tid=SELF_ID
                if tid!=cid and cid!=SELF_ID: return self._json({"error":"deny"},403)
                nm=sanitize(body.get("name"))[:24] or "Device"
                if tid==SELF_ID: SETTINGS["self_name"]=nm; save_j(SETTINGS_F,SETTINGS)
                else:
                    DEVICES[tid]=nm; save_j(DEVICES_F,DEVICES)
                    if tid in SESSIONS: SESSIONS[tid]["name"]=nm
            return self._json({"ok":True})

        if p=="/api/device/forget":
            if host_only: return self._json({"error":"host"},403)
            with LOCK: PAIRED.pop(body.get("id"),None); save_j(PAIRED_F,PAIRED)
            return self._json({"ok":True})

        if p=="/api/package/create":
            tt,tid=body.get("target_type","device"),body.get("target_id","")
            if tid==HOST_ALIAS: tid=SELF_ID
            with LOCK:
                if tt=="device":
                    if tid==SELF_ID and cid!=SELF_ID: return self._json({"error":"self"},400)
                    if tid not in SESSIONS and tid not in PEERS and tid!=SELF_ID:
                        return self._json({"error":"offline"},404)
                if tt=="pair" and tid not in [x["id"] for x in LINKS["pairs"]]: return self._json({"error":"pair"},403)
                if tt=="group" and tid not in [g["id"] for g in LINKS["groups"]]: return self._json({"error":"group"},403)
                if tt in ("pair","group") and cid not in members_of({"target_type":tt,"target_id":tid}):
                    return self._json({"error":"deny"},403)
                remotes=[]
                if tt=="pair":
                    pr=next((x for x in LINKS["pairs"] if x["id"]==tid),None)
                    if pr:
                        for m in pr["members"]:
                            if m!=SELF_ID and m in PEERS: remotes.append(PEERS[m]["url"])
                if tt=="group":
                    g=next((x for x in LINKS["groups"] if x["id"]==tid),None)
                    if g:
                        for m in g["members"]:
                            if m["id"]!=SELF_ID and m["id"] in PEERS: remotes.append(PEERS[m["id"]]["url"])
                pkg={"id":new_id("pkg"),"sender_id":cid,
                     "sender_name":SELF_NAME if cid==SELF_ID else DEVICES.get(cid,"Device"),
                     "target_type":tt,"target_id":tid,"status":"offering","remotes":remotes,
                     "files":[{"id":sanitize(f.get("id")) or new_id("f"),"name":sanitize(f.get("name")),
                               "size":max(0,min(int(f.get("size") or 0),MAX_BODY)),
                               "status":"pending","received":0,"expected_sha":(f.get("sha256") or "").lower()} for f in body.get("files",[])],
                     "created":now()}
                if not pkg["files"]: return self._json({"error":"empty"},400)
                if tt=="device" and tid==SELF_ID and SETTINGS.get("auto_accept"):
                    pkg["status"]="accepted"; log("Автоприём хостом")
                if remotes:
                    def _offer(rs=remotes):
                        for u in rs:
                            try:
                                peer_post(u,"/api/peer/package-offer",
                                          {"pkg":{"id":pkg["id"],"files":pkg["files"]},
                                           "from":SELF_ID,"from_name":SELF_NAME,"from_url":my_url()})
                            except Exception as e: log("offer error: "+str(e))
                    threading.Thread(target=_offer,daemon=True).start()
                    log("Пакет → удалённые ПК (ждёт подтверждения)")
                else:
                    log("Пакет → получатель (ждёт подтверждения)")
                PACKAGES.append(pkg); PKG_BYTES[pkg["id"]]=0
            return self._json({"ok":True,"package":pkg})

        if p=="/api/package/accept":
            with LOCK:
                pkg=next((x for x in PACKAGES if x["id"]==body.get("id")),None)
                if not pkg or cid==pkg["sender_id"] or cid not in members_of(pkg): return self._json({"error":"deny"},403)
                sel=body.get("files"); remotes=pkg.get("remotes",[])
                if pkg["status"]=="offering":
                    if sel is not None:
                        sset=set(sel)
                        if not sset: pkg["status"]="declined"; log("Пакет отклонён")
                        else:
                            for f in pkg["files"]:
                                if f["id"] not in sset: f["status"]="skipped"
                            pkg["status"]="accepted"; log(f"Принято файлов: {len(sset)}")
                    else: pkg["status"]="accepted"; log("Пакет принят")
            if remotes and pkg["status"]=="accepted":
                def _acc(rs=remotes):
                    for u in rs:
                        try: peer_post(u,"/api/peer/package-accept",{"pkg_id":pkg["id"],"files":sel})
                        except Exception as e: log("accept fwd error: "+str(e))
                threading.Thread(target=_acc,daemon=True).start()
            return self._json({"ok":True})
        if p=="/api/package/decline":
            with LOCK:
                pkg=next((x for x in PACKAGES if x["id"]==body.get("id")),None)
                if not pkg or cid==pkg["sender_id"] or cid not in members_of(pkg): return self._json({"error":"deny"},403)
                if pkg["status"]=="offering": pkg["status"]="declined"; log("Пакет отклонён")
            return self._json({"ok":True})
        if p=="/api/package/cancel":
            with LOCK:
                pkg=next((x for x in PACKAGES if x["id"]==body.get("id")),None)
                if not pkg or pkg["sender_id"]!=cid: return self._json({"error":"deny"},403)
                pkg["status"]="canceled"
            return self._json({"ok":True})

        if p=="/api/pair-invite/create":
            inv={"id":new_id("pinv"),"code":f"{secrets.randbelow(100_000_000):08d}","owner":cid,
                 "owner_name":SELF_NAME if cid==SELF_ID else DEVICES.get(cid,"Device"),
                 "expires":now()+600,"temporary":bool(body.get("temporary"))}
            with LOCK: PAIR_INVITES.append(inv)
            return self._json({"ok":True,"invite":inv})
        if p=="/api/pair-invite/join":
            if not join_ok(self.client_address[0]): return self._json({"error":"rate"},429)
            code=str(body.get("code") or "")
            with LOCK:
                inv=next((i for i in PAIR_INVITES if i["code"]==code and i["expires"]>now()),None)
            if inv:
                if inv["owner"]==cid: return self._json({"error":"self"},400)
                req={"id":new_id("preq"),"a":inv["owner"],"a_name":inv["owner_name"],
                     "b":cid,"b_name":DEVICES.get(cid,"Device"),"conf_a":False,"conf_b":False,
                     "temporary":inv["temporary"],"to":inv["owner"],"from":cid,"expires":now()+600}
                with LOCK:
                    PAIR_REQUESTS.append(req); PAIR_INVITES.remove(inv)
                return self._json({"ok":True,"request":req})
            found=probe_peers("/api/peer/pair-invite-probe",{"code":code})
            if not found: return self._json({"error":"code"},404)
            try:
                r=peer_post(found["owner_url"],"/api/peer/pair-join",
                            {"code":code,"from_id":SELF_ID,"from_name":SELF_NAME,"from_url":my_url()})
            except Exception: return self._json({"error":"code"},404)
            if not r.get("ok"): return self._json({"error":"code"},404)
            req=r["request"]
            with LOCK: PAIR_REQUESTS.append(req)
            return self._json({"ok":True,"request":req})
        if p in ("/api/pair-request/confirm","/api/pair-request/decline"):
            ok=p.endswith("confirm")
            with LOCK:
                r=next((x for x in PAIR_REQUESTS if x["id"]==body.get("id")),None)
                if not r or cid not in (r["a"],r["b"]): return self._json({"error":"deny"},403)
                remote_to=r.get("remote_to")
                if not ok:
                    PAIR_REQUESTS.remove(r)
                    if remote_to:
                        threading.Thread(target=lambda u=remote_to: peer_post(u,"/api/peer/pair-declined",
                            {"req_id":r["id"]}),daemon=True).start()
                    return self._json({"ok":True})
                if cid==r["a"]: r["conf_a"]=True
                else: r["conf_b"]=True
                if r["conf_a"] and r["conf_b"]:
                    PAIR_REQUESTS.remove(r)
                    pair={"id":r["id"],"members":[r["a"],r["b"]],
                          "names":{r["a"]:r["a_name"],r["b"]:r["b_name"]},
                          "permanent":not r["temporary"],
                          "expires":now()+600 if r["temporary"] else 1e18,
                          "remote_url":remote_to}
                    LINKS["pairs"].append(pair); save_links(); log("Пара создана")
                    if remote_to:
                        threading.Thread(target=lambda u=remote_to,pr=pair: peer_post(u,
                            "/api/peer/pair-established",{"pair":pr,"req_id":r["id"],"owner_url":my_url()}),daemon=True).start()
            return self._json({"ok":True})
        if p=="/api/pair/forget":
            with LOCK:
                pr=next((x for x in LINKS["pairs"] if x["id"]==body.get("id")),None)
                if not pr or cid not in pr["members"]: return self._json({"error":"deny"},403)
                LINKS["pairs"]=[x for x in LINKS["pairs"] if x["id"]!=body.get("id")]; save_links()
            return self._json({"ok":True})

        if p=="/api/group/create":
            g={"id":new_id("grp"),"name":sanitize(body.get("name") or "Группа")[:24],"owner":cid,
               "members":[{"id":cid,"name":SELF_NAME if cid==SELF_ID else DEVICES.get(cid,"Device")}]}
            with LOCK: LINKS["groups"].append(g); save_links()
            return self._json({"ok":True,"group":g})
        if p=="/api/group/leave":
            with LOCK:
                g=next((x for x in LINKS["groups"] if x["id"]==body.get("id")),None)
                if not g: return self._json({"error":"nf"},404)
                if cid not in [m["id"] for m in g["members"]]: return self._json({"error":"deny"},403)
                if g["owner"]==cid: LINKS["groups"].remove(g)
                else: g["members"]=[m for m in g["members"] if m["id"]!=cid]
                save_links()
            return self._json({"ok":True})
        if p=="/api/group-invite/create":
            with LOCK:
                g=next((x for x in LINKS["groups"] if x["id"]==body.get("group_id")),None)
                if not g or g["owner"]!=cid: return self._json({"error":"deny"},403)
                inv={"id":new_id("ginv"),"code":f"{secrets.randbelow(100_000_000):08d}","group_id":g["id"],"expires":now()+600}
                GROUP_INVITES.append(inv)
            return self._json({"ok":True,"invite":inv})
        if p=="/api/group-invite/join":
            if not join_ok(self.client_address[0]): return self._json({"error":"rate"},429)
            code=str(body.get("code") or "")
            with LOCK:
                inv=next((i for i in GROUP_INVITES if i["code"]==code and i["expires"]>now()),None)
            if inv:
                g=next((x for x in LINKS["groups"] if x["id"]==inv["group_id"]),None)
                if not g: return self._json({"error":"code"},404)
                with LOCK:
                    if cid not in [m["id"] for m in g["members"]]:
                        g["members"].append({"id":cid,"name":DEVICES.get(cid,"Device")})
                    GROUP_INVITES.remove(inv); save_links()
                return self._json({"ok":True,"group":g})
            found=probe_peers("/api/peer/group-invite-probe",{"code":code})
            if not found: return self._json({"error":"code"},404)
            try:
                r=peer_post(found["owner_url"],"/api/peer/group-join",
                            {"code":code,"from_id":SELF_ID,"from_name":SELF_NAME,"from_url":my_url()})
            except Exception: return self._json({"error":"code"},404)
            if not r.get("ok"): return self._json({"error":"code"},404)
            g=r["group"]
            with LOCK:
                if not any(x["id"]==g["id"] for x in LINKS["groups"]):
                    LINKS["groups"].append(g); save_links()
            return self._json({"ok":True,"group":g})
        return self._json({"error":"nf"},404)

    def _upload(self):
        q=self._q(); pkg_id=q.get("package_id",[""])[0]; file_id=q.get("file_id",[""])[0]
        off_s=q.get("offset",[None])[0]; final=q.get("final",["0"])[0]=="1"
        cid=self._cid(); tok=self._token(); n=int(self.headers.get("Content-Length") or 0)
        if n<0 or n>MAX_BODY: self._drain(max(n,0)); return self._json({"error":"big"},413)
        if not can_act(cid,tok): self._drain(n); return self._json({"error":"auth"},403)
        with LOCK:
            pkg=next((x for x in PACKAGES if x["id"]==pkg_id),None)
            fi=next((f for f in pkg["files"] if f["id"]==file_id),None) if pkg else None
            bad = not pkg or not fi or pkg["sender_id"]!=cid \
                  or pkg["status"] not in ("accepted","transferring") or fi["status"]!="pending"
            if bad:
                self._drain(n); return self._json({"error":"deny"},403)
            pkg["status"]="transferring"
            path=unique_path(SAVE_DIR,fi["name"])
            if not in_save_dir(path): return self._json({"error":"deny"},403)
        if off_s is None:
            if n!=fi["size"]:
                self._drain(n); return self._json({"error":"size"},400)
            try:
                with open(path,"wb") as f:
                    left=n
                    while left>0:
                        c=self.rfile.read(min(1024*1024,left))
                        if not c: break
                        f.write(c); left-=len(c)
                        with LOCK:
                            BYTES["v"]+=len(c); PKG_BYTES[pkg_id]=PKG_BYTES.get(pkg_id,0)+len(c)
            except Exception:
                return self._json({"error":"io"},500)
            if left: return self._json({"error":"incomplete"},400)
            with LOCK:
                fi["received"]=n; self._finish(pkg,fi,path,cid,file_id,pkg_id)
            return self._json({"ok":True,"saved_as":path.name})
        try: off=int(off_s)
        except (TypeError,ValueError): self._drain(n); return self._json({"error":"offset"},400)
        part=TEMP_DIR/(pkg_id+"_"+file_id+".part")
        if not in_temp_dir(part): return self._json({"error":"deny"},403)
        with LOCK:
            if off!=fi.get("received",0) or off+n>fi["size"]:
                self._drain(n); return self._json({"error":"offset"},409)
        try:
            with open(part,"ab" if off>0 else "wb") as f:
                left=n
                while left>0:
                    c=self.rfile.read(min(1024*1024,left))
                    if not c: break
                    f.write(c); left-=len(c)
                    with LOCK:
                        BYTES["v"]+=len(c); PKG_BYTES[pkg_id]=PKG_BYTES.get(pkg_id,0)+len(c)
        except Exception:
            return self._json({"error":"io"},500)
        if left: return self._json({"error":"incomplete"},400)
        with LOCK: fi["received"]=off+n
        if final:
            with LOCK:
                if fi["received"]!=fi["size"]:
                    return self._json({"error":"size"},400)
                path=unique_path(SAVE_DIR,fi["name"])
                if not in_save_dir(path): return self._json({"error":"deny"},403)
                part.replace(path)
                self._finish(pkg,fi,path,cid,file_id,pkg_id)
            return self._json({"ok":True,"saved_as":path.name})
        return self._json({"ok":True,"part":True})

    def _finish(self,pkg,fi,path,cid,file_id,pkg_id):
        sha=sha256_file(path)
        fi["sha256"]=sha
        exp=(fi.get("expected_sha") or "").lower()
        integ=(not exp) or (exp==sha)
        fi["integrity"]=bool(integ)
        fi["status"]="completed" if integ else "corrupted"
        if not integ: log("⚠ Целостность НАРУШЕНА: "+fi["name"])
        FILE_REG[file_id]={"path":str(path),"name":fi["name"],"size":path.stat().st_size,
                           "package_id":pkg_id,"by":cid,"at":now(),"sha256":sha,"integrity":bool(integ)}
        st=[f["status"] for f in pkg["files"]]
        if any(s=="corrupted" for s in st):
            pkg["status"]="error"; log("Пакет с ошибкой целостности")
        elif all(s in ("completed","skipped") for s in st):
            pkg["status"]="completed"; log("Пакет завершён")
        for u in pkg.get("remotes",[]):
            threading.Thread(target=push_file_to_peer,args=(pkg,fi,path,u),daemon=True).start()

    def _peer(self,p,b):
        fid=b.get("from") or b.get("id") or self.headers.get("X-BanTV-Peer","")
        if fid in SETTINGS["blocked"]: return self._json({"error":"blocked"},403)
        public=("/api/peer/pair-invite-probe","/api/peer/pair-join",
                "/api/peer/group-invite-probe","/api/peer/group-join")
        if p not in public and not known_peer(fid,self.client_address[0]):
            if p not in ("/api/peer/pair-established","/api/peer/pair-declined") \
               or not pending_peer(b.get("req_id"),self.client_address[0]):
                return self._json({"error":"peer auth"},403)
        if p=="/api/peer/pair-invite-probe":
            code=b.get("code")
            with LOCK:
                inv=next((i for i in PAIR_INVITES if i["code"]==code and i["expires"]>now()),None)
            if inv:
                return self._json({"ok":True,"found":True,"owner_id":SELF_ID,
                                   "owner_name":SELF_NAME,"owner_url":my_url()})
            return self._json({"ok":True,"found":False})
        if p=="/api/peer/pair-join":
            code=b.get("code")
            with LOCK:
                inv=next((i for i in PAIR_INVITES if i["code"]==code and i["expires"]>now()),None)
                if not inv: return self._json({"ok":False})
                req={"id":new_id("preq"),"a":inv["owner"],"a_name":inv["owner_name"],
                     "b":b.get("from_id"),"b_name":b.get("from_name","PC"),
                     "conf_a":False,"conf_b":True,"temporary":inv["temporary"],
                     "to":inv["owner"],"from":b.get("from_id"),
                     "remote_to":b.get("from_url"),"expires":now()+600}
                PAIR_REQUESTS.append(req); PAIR_INVITES.remove(inv)
            # У присоединившегося ПК remote_to — адрес владельца приглашения.
            response=dict(req); response["remote_to"]=my_url()
            return self._json({"ok":True,"request":response})
        if p=="/api/peer/pair-established":
            pr=dict(b.get("pair") or {})
            pr["remote_url"]=b.get("owner_url") or pr.get("remote_url","")
            with LOCK:
                PAIR_REQUESTS[:]=[x for x in PAIR_REQUESTS if x["id"]!=b.get("req_id")]
                if not any(x["id"]==pr.get("id") for x in LINKS["pairs"]):
                    LINKS["pairs"].append(pr); save_links(); log("Пара установлена (ПК)")
            return self._json({"ok":True})
        if p=="/api/peer/pair-declined":
            with LOCK:
                PAIR_REQUESTS[:]=[x for x in PAIR_REQUESTS if x["id"]!=b.get("req_id")]
            return self._json({"ok":True})
        if p=="/api/peer/group-invite-probe":
            code=b.get("code")
            with LOCK:
                inv=next((i for i in GROUP_INVITES if i["code"]==code and i["expires"]>now()),None)
            if inv:
                return self._json({"ok":True,"found":True,"owner_id":SELF_ID,
                                   "owner_name":SELF_NAME,"owner_url":my_url()})
            return self._json({"ok":True,"found":False})
        if p=="/api/peer/group-join":
            code=b.get("code")
            with LOCK:
                inv=next((i for i in GROUP_INVITES if i["code"]==code and i["expires"]>now()),None)
                if not inv: return self._json({"ok":False})
                g=next((x for x in LINKS["groups"] if x["id"]==inv["group_id"]),None)
                if not g: return self._json({"ok":False})
                if b.get("from_id") not in [m["id"] for m in g["members"]]:
                    g["members"].append({"id":b.get("from_id"),"name":b.get("from_name","PC")})
                GROUP_INVITES.remove(inv); save_links()
            return self._json({"ok":True,"group":g})
        if p=="/api/peer/package-offer":
            pb=b.get("pkg") or {}
            # C2: санитизируем имена и размеры на входе
            files=[]
            for f in (pb.get("files") or []):
                files.append({"id":sanitize(f.get("id")) or new_id("f"),
                              "name":sanitize(f.get("name")),
                              "size":max(0,min(int(f.get("size") or 0),MAX_BODY)),
                              "status":"pending","expected_sha":(f.get("sha256") or "").lower()})
            with LOCK:
                if any(x["id"]==pb.get("id") for x in PACKAGES): return self._json({"ok":True})
                pkg={"id":sanitize(pb.get("id")) or new_id("pkg"),"sender_id":fid,
                     "sender_name":sanitize(b.get("from_name","PC"))[:24],"target_type":"device","target_id":SELF_ID,
                     "status":"offering","files":files,"created":now(),
                     "peer_url":b.get("from_url"),"peer_pkg_id":pb.get("id"),"remotes":[b.get("from_url")]}
                if pkg["files"]:
                    PACKAGES.append(pkg); PKG_BYTES[pkg["id"]]=0; log("Входящий пакет от ПК (ждёт подтверждения)")
            return self._json({"ok":True})
        if p=="/api/peer/package-accept":
            pid=b.get("pkg_id"); sel=b.get("files")
            with LOCK:
                pkg=next((x for x in PACKAGES if x["id"]==pid),None)
                if pkg and pkg["status"]=="offering":
                    if sel is not None:
                        sset=set(sel)
                        for f in pkg["files"]:
                            if f["id"] not in sset: f["status"]="skipped"
                        pkg["status"]="accepted" if sset else "declined"
                    else: pkg["status"]="accepted"
                    log("Удалённый ПК принял пакет")
            return self._json({"ok":True})
        if p=="/api/peer/push":
            q=self._q(); ppid=q.get("package_id",[None])[0]; pfid=q.get("file_id",[None])[0]
            exp_sha=(self.headers.get("X-File-Sha") or "").lower()
            n=int(self.headers.get("Content-Length") or 0)
            if n>MAX_BODY: return self._json({"error":"big"},413)
            if ppid and pfid:
                with LOCK:
                    pkg=next((x for x in PACKAGES if x["id"]==ppid),None)
                    fi=next((f for f in pkg["files"] if f["id"]==pfid),None) if pkg else None
                    # H1 + C2: только от отправителя и только после принятия
                    if not pkg or not fi or pkg["sender_id"]!=fid \
                       or pkg["status"] not in ("accepted","transferring") or fi["status"]!="pending":
                        self._drain(n); return self._json({"error":"deny"},403)
                    if exp_sha: fi["expected_sha"]=exp_sha
                    name=sanitize(fi["name"])
                    path=unique_path(SAVE_DIR,name)
                    if not in_save_dir(path):
                        self._drain(n); return self._json({"error":"deny"},403)
                    pkg["status"]="transferring"
                try:
                    with open(path,"wb") as f:
                        left=n
                        while left>0:
                            c=self.rfile.read(min(1024*1024,left))
                            if not c: break
                            f.write(c); left-=len(c)
                            with LOCK:
                                BYTES["v"]+=len(c); PKG_BYTES[ppid]=PKG_BYTES.get(ppid,0)+len(c)
                except Exception:
                    return self._json({"error":"io"},500)
                with LOCK:
                    sha=sha256_file(path); fi["sha256"]=sha
                    integ=(not fi.get("expected_sha")) or (fi["expected_sha"]==sha)
                    fi["integrity"]=bool(integ)
                    fi["status"]="completed" if integ else "corrupted"
                    FILE_REG[pfid]={"path":str(path),"name":fi["name"],"size":path.stat().st_size,
                                   "package_id":ppid,"by":fid,"at":now(),"sha256":sha,"integrity":bool(integ)}
                    st=[f["status"] for f in pkg["files"]]
                    if any(s=="corrupted" for s in st): pkg["status"]="error"
                    elif all(s in ("completed","skipped") for s in st):
                        pkg["status"]="completed"; log("Пакет от ПК завершён")
                return self._json({"ok":True})
            self._drain(n); return self._json({"error":"pair"},403)
        return self._json({"error":"nf"},404)

def main():
    global HTTP_PORT
    ap=argparse.ArgumentParser(); ap.add_argument("--no-window",action="store_true")
    ap.add_argument("--port",type=int,default=8420); a=ap.parse_args()
    srv=None
    for port in range(a.port,a.port+6):
        try:
            ThreadingHTTPServer.allow_reuse_address=True
            srv=ThreadingHTTPServer(("0.0.0.0",port),H); srv.daemon_threads=True
            HTTP_PORT=port; break
        except OSError:
            continue
    if srv is None:
        print("Ports 8420-8425 busy. Close another BanTV Drop instance.",file=sys.stderr)
        return
    threading.Thread(target=srv.serve_forever,daemon=True).start()
    for fn in (discovery_sender,discovery_listener,speed_loop,cleanup_loop,peer_watchdog):
        threading.Thread(target=fn,daemon=True).start()
    log(f"Сервер :{HTTP_PORT}")
    print(f"BanTV Drop v{VERSION} -> {my_url()}")
    if not a.no_window and webview:
        webview.create_window("BanTV Drop",f"http://127.0.0.1:{HTTP_PORT}",
                              width=1180,height=840,frameless=True,easy_drag=False,
                              js_api=WinApi(),background_color='#0a0e13')
        webview.start()
    else:
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt: srv.shutdown()

if __name__=="__main__":
    main()
