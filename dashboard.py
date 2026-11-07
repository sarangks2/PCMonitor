"""대시보드 웹서버 (127.0.0.1 전용, 읽기 전용)."""
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import config
import intrusion
import ai_explain
import winutil
from procinfo import PROCINFO

log = logging.getLogger("pcmon.web")
HTML_PATH = os.path.join(config.RES_DIR, "dashboard.html")
ALLOWED_HOSTS = {f"127.0.0.1:{config.HTTP_PORT}", f"localhost:{config.HTTP_PORT}"}
NO_ACCESS_HTML = """<!doctype html><meta charset="utf-8"><title>PC 모니터</title>
<body style="font-family:'Malgun Gothic',sans-serif;padding:40px;background:#f6f7f9;color:#1d2330">
<h2>접근 권한이 없습니다</h2>
<p>보안 정보가 들어 있어서 PC 모니터를 설치한 계정(또는 관리자)만 볼 수 있습니다.</p>
<p>바탕화면이나 시작 메뉴의 <b>PC 모니터</b> 아이콘으로 열어 주세요.</p></body>"""


def annotate(rows):
    for r in rows:
        pid = r.get("pid")
        if pid:
            try:
                info = PROCINFO.describe(pid, r.get("name"), exe=r.get("path"))
            except Exception:
                info = PROCINFO.by_name_only(r.get("name"))
        else:
            info = PROCINFO.by_name_only(r.get("name"))
        if info.get("display_name"):
            r["display_name"] = info["display_name"]
        r.setdefault("desc", info["desc"])
        r.setdefault("cat", info["cat"])
        r.setdefault("company", info["company"])
        r.setdefault("path", info["path"])
    return rows



def pub_actions(mon, acts):
    """화면에는 버튼 표시에 필요한 것만 (실제 명령·경로는 서버에만)."""
    return [{"id": a["id"], "label": a["label"], "confirm": a.get("confirm", ""), "kind": a["kind"],
             "job": mon.rem.status(a["id"])} for a in (acts or [])]


CAT_KO = {"intrusion": "침입", "security": "보안", "defender": "백신", "network": "네트워크", "process": "프로그램", "persistence": "자동실행"}
SEC_CATS = ("intrusion", "security", "defender", "network", "process", "persistence")


def event_key(title):
    """이벤트 '무시' 규칙 키: 숫자만 다른 같은 경고는 같은 것으로 (예: '로그인 실패 3회' = '5회')."""
    return "evt|" + re.sub(r"[0-9][0-9,.:]*", "#", re.sub(r"\s+\(\d+회\)$", "", title or ""))


class IgnoreStore:
    """무시한 항목 목록 (kv 'ignored'). 언제·무엇을 무시했는지 기록하고 '다시 표시'로 되살린다.
    type: finding(흔적 점검 항목, 계속 무시) · event_rule(같은 제목 경고 계속 무시) · event_once(이번 경고만 확인함)"""

    def __init__(self, db):
        self.db = db
        old = db.get("acked_events")  # 이전 버전의 '확인함' 기록을 옮겨 옴
        if old:
            lst = db.get("ignored") or []
            lst.append({"id": secrets.token_hex(4), "type": "event_once", "title": f"이전에 확인함 처리한 경고 {len(old)}건",
                        "check": "이전 기록", "ts": int(time.time()), "eids": [int(i) for i in old if str(i).isdigit()][-3000:]})
            db.set("ignored", lst)
            db.set("acked_events", None)

    def list(self):
        return self.db.get("ignored") or []

    def state(self):
        fk, rk, once = set(), set(), set()
        for x in self.list():
            if x["type"] == "finding":
                fk.add(x["key"])
            elif x["type"] == "event_rule":
                rk.add(x["key"])
                once.update(x.get("eids") or [])
            else:
                once.update(x.get("eids") or [])
        return fk, rk, once

    def add(self, typ, title, check, key=None, eids=None):
        if typ not in ("finding", "event_rule", "event_once"):
            return {"ok": False, "msg": "잘못된 요청"}
        title, check = str(title)[:300], str(check)[:40]
        lst = self.list()
        if key and any(x.get("key") == key for x in lst):
            return {"ok": True, "msg": "이미 무시 중입니다"}
        lst.append({"id": secrets.token_hex(4), "type": typ, "title": title, "check": check, "ts": int(time.time()),
                    "key": key, "eids": [int(i) for i in (eids or []) if str(i).isdigit()][:500]})
        self.db.set("ignored", lst[-500:])
        label = {"finding": "무시함", "event_rule": "같은 경고 계속 무시", "event_once": "확인함"}[typ]
        self.db.add_event(time.time(), "action", "info", "pcmon", 0, f"{label}: {title}", {"구분": check})
        return {"ok": True}

    def restore(self, iid):
        lst = self.list()
        hit = [x for x in lst if x["id"] == iid]
        if not hit:
            return {"ok": False, "msg": "항목을 찾을 수 없습니다"}
        self.db.set("ignored", [x for x in lst if x["id"] != iid])
        self.db.add_event(time.time(), "action", "info", "pcmon", 0, f"다시 표시: {hit[0]['title']}", {"구분": hit[0]["check"]})
        return {"ok": True, "msg": f"'{hit[0]['title']}' 을 다시 표시합니다"}


def serve(mon):
    db = mon.db
    risk_cache = {"ts": 0, "data": None}
    ign = IgnoreStore(db)
    mon.ignore = ign

    def build_risks(force=False):
        """아직 해결되지 않은 위험·주의 항목 (흔적 점검 결과 + '확인함' 안 누른 위험 이벤트 24시간)."""
        if not force and time.time() - risk_cache["ts"] < 8 and risk_cache["data"]:
            return risk_cache["data"]
        items = []
        fkeys, rkeys, acked = ign.state()
        scan = db.get("trace_scan") or {}
        for f in scan.get("findings") or []:
            fk = f.get("key") or intrusion.finding_key(f["check"], f["title"])
            if fk in fkeys:
                continue
            if f["sev"] in ("crit", "warn") and not all(mon.rem.status(a["id"]).get("state") == "ok" for a in f.get("actions") or [{"id": "-"}]):
                items.append({"type": "finding", "key": fk, "sev": f["sev"], "ts": scan.get("ts"), "title": f["title"], "raw_title": f["title"],
                              "check": f["check"], "detail": f["detail"] if isinstance(f["detail"], list) else ([f["detail"]] if f["detail"] else []),
                              "what": "흔적 점검에서 발견된 항목입니다.", "how": "아래 버튼으로 바로 조치하거나, 괜찮은 항목이면 '무시'를 누르세요 (무시한 항목 목록에서 다시 표시 가능).",
                              "actions": pub_actions(mon, f.get("actions"))})
        evs = db.query("SELECT * FROM events WHERE severity='crit' AND ts>? AND category IN (%s) AND title NOT LIKE '침입 흔적 점검 완료%%' "
                       "ORDER BY ts DESC LIMIT 100" % ",".join("?" * len(SEC_CATS)), (int(time.time()) - 86400,) + SEC_CATS)
        groups = {}
        for e in evs:  # 같은 제목은 한 줄로 묶음 (최신 것 기준, 확인함은 묶음 전체에)
            if e["id"] in acked or event_key(e["title"]) in rkeys:
                continue
            g = groups.get(e["title"])
            if g:
                g["ids"].append(e["id"])
                continue
            groups[e["title"]] = {"e": e, "ids": [e["id"]]}
        for g in groups.values():
            e = g["e"]
            what, how, acts = mon.rem.event_help(e)
            try:
                d = json.loads(e["detail"] or "{}")
                det = [f"{k}: {v}" for k, v in d.items()][:8] if isinstance(d, dict) else [str(d)]
            except Exception:
                det = [e["detail"]] if e["detail"] else []
            items.append({"type": "event", "eid": e["id"], "eids": g["ids"], "count": len(g["ids"]), "sev": "crit", "ts": e["ts"],
                          "raw_title": e["title"], "key": event_key(e["title"]),
                          "title": e["title"] + (f"  ({len(g['ids'])}회)" if len(g["ids"]) > 1 else ""), "check": CAT_KO.get(e["category"], e["category"]),
                          "detail": [str(x)[:300] for x in det], "what": what, "how": how, "actions": pub_actions(mon, acts)})
        data = {"crit": sum(1 for i in items if i["sev"] == "crit"), "warn": sum(1 for i in items if i["sev"] == "warn"), "items": items,
                "ignored": len(ign.list())}
        risk_cache.update(ts=time.time(), data=data)
        return data

    mon.build_risks = build_risks

    def about():
        """PC 모니터 자신의 자원 사용량과 외부 통신 여부 (안전성 확인용)."""
        import psutil
        me = mon.me
        with me.oneshot():
            mi = me.memory_info()
            kids = me.children(recursive=True)
            try:
                handles = me.num_handles()
            except Exception:
                handles = None
            conns = []
            try:
                conns = (me.net_connections if hasattr(me, "net_connections") else me.connections)(kind="inet")
            except Exception:
                pass
        ext = [c for c in conns if c.raddr and not c.raddr.ip.startswith("127.") and c.raddr.ip != "::1"]
        listen = sorted({f"{c.laddr.ip}:{c.laddr.port}" for c in conns if c.status == psutil.CONN_LISTEN})

        def dsize(p):
            t = 0
            for r, _d, fs in os.walk(p):
                for f in fs:
                    try:
                        t += os.path.getsize(os.path.join(r, f))
                    except OSError:
                        pass
            return t
        return {
            "version": config.VERSION, "github": config.GITHUB_URL, "exe": me.exe(), "pid": me.pid,
            "started": int(me.create_time()), "admin": mon.sec.status.get("admin"), "system": mon.os.get("system"),
            "cpu": round(getattr(mon, "self_cpu", 0.0), 2), "mem_mb": round(getattr(mi, "private", mi.rss) / 1048576, 1),
            "rss_mb": round(mi.rss / 1048576, 1), "threads": me.num_threads(), "handles": handles,
            "children": [k.name() for k in kids if k.is_running()],
            "data_dir": config.DATA_DIR, "data_mb": round(dsize(config.DATA_DIR) / 1e6, 2), "db_mb": round(db.size_mb(), 2),
            "db_max_mb": config.DB_MAX_MB, "keep": {"raw": config.KEEP_RAW_DAYS, "agg": config.KEEP_5MIN_DAYS, "events": config.KEEP_EVENT_DAYS},
            "listen": listen, "external_conns": len(ext), "conns": len(conns),
        }

    def with_acts(rows):
        out = []
        for r in rows:
            r2 = dict(r)
            try:
                r2["actions"] = pub_actions(mon, mon.rem.proc_actions(r))
            except Exception:
                r2["actions"] = []
            out.append(r2)
        return out

    def api(path, q):
        now = int(time.time())
        if path == "/api/ping":
            return {"app": "pcmon", "admin": mon.sec.status.get("admin")}
        if path == "/api/live":
            L = intrusion.live_snapshot(db, mon.fw, mon.sec.status, server=mon.os.get("server"))
            for k in ("inbound", "outbound", "listening"):
                for r in L[k]:
                    r["desc"] = PROCINFO.by_name_only(r["proc"]).get("desc", "")
            return L
        if path == "/api/trace":
            r = mon.trace.result()
            fkeys = ign.state()[0]
            # 화면에는 버튼 표시에 필요한 것만 (실제 명령·경로는 서버에만 보관)
            for f in r.get("findings") or []:
                f["key"] = f.get("key") or intrusion.finding_key(f["check"], f["title"])
                f["ignored"] = f["key"] in fkeys
                f["actions"] = [{"id": a["id"], "label": a["label"], "confirm": a.get("confirm", ""), "kind": a["kind"],
                                 "job": mon.rem.status(a["id"])} for a in (f.get("actions") or [])]
            return r
        if path == "/api/find":
            r = mon.finder.find(q.get("q", [""])[0][:60])
            for k in ("running", "installed", "files"):
                for row in r.get(k) or []:
                    row["actions"] = pub_actions(mon, row.get("actions"))
            return r
        if path == "/api/notes":
            return mon.notes.list()
        if path == "/api/banking":
            return mon.bank.status()
        if path == "/api/settings":
            return {"lang": mon.db.get("ui_lang") or "ko", "close_action": mon.db.get("close_action") or "tray",
                    "alert_level": mon.db.get("alert_level") or "crit",
                    "notify_mode": mon.db.get("notify_mode") or "instant"}
        if path == "/api/ai/explain":
            target = q.get("target", [""])[0][:120]
            k = q.get("type", ["process"])[0][:30]
            return ai_explain.explain_item(name=target, kind=k)
        if path == "/api/ignored":
            names = {"finding": "점검 항목 무시", "event_rule": "같은 경고 계속 무시", "event_once": "이번 경고만 확인함"}
            return [{**x, "type_name": names.get(x["type"], x["type"]), "count": len(x.get("eids") or [])}
                    for x in sorted(ign.list(), key=lambda x: -x["ts"])]
        if path == "/api/about":
            return about()
        if path == "/api/risks":
            return build_risks()
        if path == "/api/maint":
            return {"defender": mon.upd.defender_scan(), "wu": mon.upd.wu_status(), "admin": mon.sec.status.get("admin")}
        if path == "/api/action/status":
            return mon.rem.status(q.get("id", [""])[0])
        if path == "/api/quarantine":
            return mon.rem.quarantine_list()
        if path == "/api/summary":
            import psutil
            last_inc = db.query("SELECT ts,kind,bugcheck,last_heartbeat FROM incidents ORDER BY ts DESC LIMIT 1")
            counts = db.query("SELECT category, severity, COUNT(*) n FROM events WHERE ts>? GROUP BY 1,2", (now - 86400,))
            drives = []
            try:
                excluded = set(getattr(config, "EXCLUDE_DRIVES", ("F:",)))
                db_ex = mon.db.get("excluded_drives") or []
                if isinstance(db_ex, (list, tuple)):
                    excluded.update(d.strip().upper() for d in db_ex if d)
                min_gb = getattr(config, "MIN_DRIVE_TOTAL_GB", 1.0)

                for ptn in psutil.disk_partitions(all=False):
                    drv = ptn.mountpoint[:2].upper()
                    if drv in excluded or ptn.mountpoint.upper().startswith("F:"):
                        continue
                    if ("fixed" in ptn.opts or "rw" in ptn.opts) and not ptn.mountpoint.startswith(("\\\\", "/")):
                        try:
                            du = psutil.disk_usage(ptn.mountpoint)
                            total_gb = du.total / 1e9
                            # 시스템 예약(100MB), 복구 파티션 등 1GB 미만 특수 파티션 자동 배제
                            if total_gb < min_gb:
                                continue
                            drives.append({
                                "mount": ptn.mountpoint,
                                "drive": drv,
                                "free_gb": round(du.free / 1e9, 1),
                                "total_gb": round(total_gb, 1),
                                "used_gb": round((du.total - du.free) / 1e9, 1),
                                "pct": round(du.percent, 1)
                            })
                        except Exception:
                            pass
            except Exception:
                pass
            return {
                "now": now, "latest": mon.latest, "disk_free_gb": round(mon.latest_disk, 1),
                "drives": drives,
                "top_cpu": with_acts(mon.top_now[:6]), "top_mem": with_acts(getattr(mon, "mem_top", [])[:6]),
                "risks": {k: v for k, v in build_risks().items() if k != "items"},
                "status": mon.sec.status, "last_incident": last_inc[0] if last_inc else None,
                "counts24h": counts, "db_mb": round(db.size_mb(), 2), "uptime_since": mon.db.get("boot_time"),
                "os": mon.os, "drive": config.SYSTEM_DRIVE[:2],
                "alerts": db.query("SELECT ts,severity,title,body FROM alerts ORDER BY ts DESC LIMIT 15"),
            }
        if path == "/api/metrics":
            hours = min(float(q.get("hours", ["24"])[0]), 24 * config.KEEP_5MIN_DAYS)
            since = now - int(hours * 3600)
            if hours <= 24:
                rows = db.query("SELECT ts,cpu,mem,commit_pct,disk_busy,net_rx,net_tx FROM metrics WHERE ts>=? ORDER BY ts",
                                (since,))
                # 화면에 600점 정도만
                step = max(1, len(rows) // 600)
                out = []
                for i in range(0, len(rows), step):
                    chunk = rows[i:i + step]
                    out.append({"ts": chunk[-1]["ts"], "cpu": sum(r["cpu"] for r in chunk) / len(chunk),
                                "cpu_max": max(r["cpu"] for r in chunk),
                                "mem": max(r["mem"] for r in chunk), "commit": max(r["commit_pct"] for r in chunk),
                                "disk": max(r["disk_busy"] for r in chunk),
                                "net_rx": sum(r["net_rx"] for r in chunk) / len(chunk),
                                "net_tx": sum(r["net_tx"] for r in chunk) / len(chunk)})
                return out
            rows = db.query('SELECT ts,cpu_avg cpu,cpu_max,mem_max mem,commit_max "commit",disk_busy_max disk,net_rx,net_tx '
                            "FROM metrics_5m WHERE ts>=? ORDER BY ts", (since,))
            return rows
        if path == "/api/procs":
            try:
                ts = int(q.get("ts", [now])[0])
            except (ValueError, TypeError):
                ts = int(now)
            return annotate(db.query("SELECT * FROM procs WHERE ts=(SELECT ts FROM procs ORDER BY ABS(ts-?) LIMIT 1) "
                                     "ORDER BY kind, rank", (ts,)))
        if path == "/api/events":
            try:
                days = float(q.get("days", ["7"])[0])
            except (ValueError, TypeError):
                days = 7.0
            cats = q.get("cat", [""])[0]
            sql = "SELECT * FROM events WHERE ts>=?"
            args = [now - int(days * 86400)]
            if cats:
                cl = cats.split(",")
                sql += " AND category IN (%s)" % ",".join("?" * len(cl))
                args += cl
            return db.query(sql + " ORDER BY ts DESC LIMIT 500", args)
        if path == "/api/mem/breakdown":
            import procinfo
            return procinfo.get_memory_breakdown()
        if path == "/api/incidents":
            rows = db.query("SELECT * FROM incidents ORDER BY ts DESC LIMIT 50")
            for r in rows:
                r["snapshot"] = json.loads(r["snapshot"] or "{}")
                annotate(r["snapshot"].get("procs") or [])
            return rows
        return None

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype):
            try:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()
                self.wfile.write(body)
            except (ConnectionError, OSError):
                pass  # 화면 쪽에서 먼저 연결을 끊은 경우 (창 닫음/시간 초과)

        def _authed(self):
            c = SimpleCookie(self.headers.get("Cookie", ""))
            v = c.get("pcmon_t")
            return bool(mon.token) and v is not None and hmac.compare_digest(v.value, mon.token)

        def do_GET(self):
            # DNS 리바인딩 방지: 로컬 호스트 이름으로 온 요청만 허용
            if self.headers.get("Host", "") not in ALLOWED_HOSTS:
                return self._send(403, b"forbidden", "text/plain")
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/api/ping":
                return self._send(200, json.dumps({"app": "pcmon"}).encode(), "application/json")
            if u.path == "/i18n_en.json":
                with open(os.path.join(config.RES_DIR, "i18n_en.json"), "rb") as f:
                    return self._send(200, f.read(), "application/json; charset=utf-8")
            if u.path == "/favicon.ico":
                with open(os.path.join(config.RES_DIR, "pcmon.ico"), "rb") as f:
                    return self._send(200, f.read(), "image/x-icon")
            # 접근 열쇠: 런처가 ?t=열쇠 로 한 번 열면 쿠키로 저장
            t = q.get("t", [""])[0]
            if t and mon.token and hmac.compare_digest(t, mon.token):
                self.send_response(302)
                self.send_header("Set-Cookie", f"pcmon_t={mon.token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000")
                self.send_header("Location", "/")
                self.end_headers()
                return
            if not self._authed():
                if u.path.startswith("/api/"):
                    return self._send(401, b"unauthorized", "text/plain")
                return self._send(401, NO_ACCESS_HTML.encode("utf-8"), "text/html; charset=utf-8")
            try:
                if u.path in ("/", "/index.html"):
                    with open(HTML_PATH, "rb") as f:
                        return self._send(200, f.read(), "text/html; charset=utf-8")
                data = api(u.path, q)
                if data is None:
                    return self._send(404, b"not found", "text/plain")
                return self._send(200, json.dumps(data, ensure_ascii=False, default=str).encode("utf-8"),
                                  "application/json; charset=utf-8")
            except Exception as e:
                log.exception("api")
                return self._send(500, str(e).encode(), "text/plain")

    def do_POST(self):
        # 다른 사이트가 몰래 요청하지 못하게: 로컬 Host + 사용자 정의 헤더(브라우저가 교차 출처로는 못 붙임)
        if self.headers.get("Host", "") not in ALLOWED_HOSTS or self.headers.get("X-PCMon") != "1" or not self._authed():
            return self._send(403, b"forbidden", "text/plain")
        p = urlparse(self.path).path
        try:
            n = min(int(self.headers.get("Content-Length") or 0), 65536)
            body = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except Exception:
            body = {}
        try:
            if p == "/api/trace/run":
                res = {"started": mon.trace.start()}
            elif p == "/api/action/run":
                res = mon.rem.run(str(body.get("id", ""))[:32])
            elif p == "/api/quarantine/restore":
                res = mon.rem.restore(str(body.get("qid", ""))[:40])
            elif p == "/api/ignore":
                typ = str(body.get("type", ""))
                title, check = str(body.get("title", ""))[:300], str(body.get("check", ""))[:40]
                if typ == "finding":
                    key = intrusion.finding_key(check, title)   # 키는 서버에서 다시 계산
                elif typ == "event_rule":
                    key = event_key(title)
                else:
                    key = None
                ids = body.get("eids") if isinstance(body.get("eids"), list) else []
                res = mon.ignore.add(typ, title, check, key=key, eids=ids)
                mon.build_risks(force=True)
            elif p == "/api/settings":
                if "lang" in body:
                    lang = str(body.get("lang", "ko"))
                    mon.db.set("ui_lang", lang if lang in ("ko", "en") else "ko")
                if "close_action" in body:
                    ca = str(body.get("close_action", "tray"))
                    if ca in ("tray", "exit"):
                        mon.db.set("close_action", ca)
                if "alert_level" in body:
                    al = str(body.get("alert_level", "crit"))
                    if al in ("crit", "all", "mute"):
                        mon.db.set("alert_level", al)
                if "notify_mode" in body:
                    nm = str(body.get("notify_mode", "instant"))
                    if nm in ("instant", "silent", "digest"):
                        mon.db.set("notify_mode", nm)
                res = {"ok": True}
            elif p == "/api/proc/kill":
                import psutil
                pname = str(body.get("name", "")).strip().lower()
                pid = body.get("pid")
                PROTECTED = {"system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe"}
                if pname in PROTECTED:
                    res = {"ok": False, "msg": f"'{pname}'은(는) Windows 핵심 시스템 프로세스로 종료할 수 없습니다."}
                else:
                    killed = 0
                    if pid:
                        try:
                            p = psutil.Process(int(pid))
                            if p.name().lower() not in PROTECTED:
                                p.kill()
                                killed += 1
                        except Exception:
                            pass
                    if not killed and pname:
                        for p in psutil.process_iter(["name"]):
                            try:
                                if p.info.get("name", "").lower() == pname:
                                    p.kill()
                                    killed += 1
                            except Exception:
                                pass
                    if killed:
                        res = {"ok": True, "msg": f"'{pname or pid}' 프로세스 {killed}개를 즉시 강제 종료했습니다."}
                    else:
                        res = {"ok": False, "msg": f"종료할 '{pname or pid}' 프로세스를 찾을 수 없거나 이미 종료되었습니다."}
            elif p == "/api/proc/test_spawn":
                import subprocess
                try:
                    proc = subprocess.Popen(["notepad.exe"])
                    res = {"ok": True, "pid": proc.pid, "name": "notepad.exe",
                           "msg": f"테스트 프로세스 'notepad.exe' (PID: {proc.pid})가 실행되었습니다! 이제 '즉시 종료'를 눌러보세요."}
                except Exception as e:
                    res = {"ok": False, "msg": f"테스트 프로세스 실행 실패: {e}"}
            elif p in ("/api/mem/trim", "/api/mem/optimize"):
                import procinfo
                res = procinfo.optimize_memory()
                try:
                    db.add_event(int(time.time()), "system", "info", "pcmon", 0,
                                 f"안전 메모리 최적화 수행: {res.get('saved_mb', 0)}MB 회수 (프로세스 {res.get('count', 0)}개)", "")
                except Exception:
                    pass
            elif p == "/api/shutdown":
                threading.Timer(0.3, mon.shutdown).start()
                res = {"ok": True, "msg": "PC 모니터 백그라운드를 종료합니다"}
            elif p == "/api/ai/explain":
                name = str(body.get("name") or body.get("target") or "")[:120]
                path_val = str(body.get("path", ""))[:300]
                details = str(body.get("details", ""))[:1000]
                kind = str(body.get("kind") or body.get("type") or "process")[:30]
                res = ai_explain.explain_item(name=name, path=path_val, details=details, kind=kind)
            elif p == "/api/tray/balloon":
                title = str(body.get("title", "PC 모니터"))[:60]
                msg = str(body.get("msg", ""))[:250]
                if getattr(mon, "tray", None):
                    mon.tray.show_balloon(title, msg)
                else:
                    winutil.toast(title, msg)
                res = {"ok": True}
            elif p == "/api/ui_closed":
                ca = mon.db.get("close_action") or "tray"
                if ca == "exit":
                    threading.Timer(0.3, mon.shutdown).start()
                elif getattr(mon, "tray", None):
                    mon.tray.show_balloon("PC 모니터", "백그라운드 감시가 트레이에서 계속 실행 중입니다.")
                else:
                    winutil.toast("PC 모니터", "백그라운드 감시가 트레이에서 계속 실행 중입니다.")
                res = {"ok": True}
            elif p == "/api/banking":
                act = str(body.get("action", ""))
                B = mon.bank
                if not mon.sec.status.get("admin"):
                    res = {"ok": False, "msg": "관리자 권한으로 실행 중이 아니라 바꿀 수 없습니다"}
                elif act in ("block", "unblock"):
                    res = B.set_block_external(act == "block")
                elif act == "on":
                    res = B.turn_on("수동")
                elif act == "off":
                    res = B.turn_off("수동")
                elif act == "kick_all":
                    res = B.kick_all()
                elif act == "apply_recommended":
                    res = B.apply_recommended()
                elif act == "mode":
                    kws = body.get("keywords") if isinstance(body.get("keywords"), list) else None
                    res = B.set_mode(str(body.get("mode", "")), [str(k) for k in kws] if kws is not None else None, body.get("idle_min"))
                elif act == "restore":
                    B.cfg["mode"] = "always"
                    res = B.restore_original()
                else:
                    res = {"ok": False, "msg": "잘못된 요청"}
            elif p == "/api/notes":
                res = mon.notes.set(str(body.get("name", "")), str(body.get("note", "")), str(body.get("verdict", "")))
                mon.rem._pa_cache.clear()
            elif p == "/api/ignore/restore":
                res = mon.ignore.restore(str(body.get("id", ""))[:16])
                mon.build_risks(force=True)
            elif p == "/api/risks/ack":  # 이전 화면 호환
                ids = body.get("ids") if isinstance(body.get("ids"), list) else [body.get("id")]
                res = mon.ignore.add("event_once", str(body.get("title", "경고")), "보안", eids=ids)
                mon.build_risks(force=True)
            elif p in ("/api/wu/start", "/api/wu/refresh", "/api/defender/start", "/api/defender/cancel"):
                if not mon.sec.status.get("admin"):
                    res = {"ok": False, "msg": "관리자 권한으로 실행 중이 아니라 할 수 없습니다"}
                elif p == "/api/wu/start":
                    res = mon.upd.start_wu()
                elif p == "/api/wu/refresh":
                    threading.Thread(target=mon.upd.refresh_wu, daemon=True).start()
                    res = {"ok": True, "msg": "업데이트 목록을 다시 확인합니다 (최대 1~2분)"}
                elif p == "/api/defender/start":
                    res = mon.upd.defender_start(str(body.get("kind", "")))
                else:
                    res = mon.upd.defender_cancel()
            else:
                return self._send(404, b"not found", "text/plain")
            return self._send(200, json.dumps(res, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")
        except Exception as e:
            log.exception("do_POST error")
            return self._send(500, str(e).encode(), "text/plain")

    def db_ack_get():
        return mon.db.get("acked_events") or []

    H.do_POST = do_POST
    try:
        srv = ThreadingHTTPServer((config.HTTP_HOST, config.HTTP_PORT), H)
    except OSError as e:
        log.error("대시보드 포트 %d 를 열 수 없음 (다른 프로그램이 사용 중?): %s  → 환경변수 PCMON_PORT 로 변경 가능",
                  config.HTTP_PORT, e)
        return
    log.info("대시보드 http://%s:%d", config.HTTP_HOST, config.HTTP_PORT)
    srv.serve_forever()
