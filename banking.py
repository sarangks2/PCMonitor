"""인터넷뱅킹 보안 프로그램 관리.

국내 인터넷뱅킹·공공기관 사이트용 보안 프로그램(nProtect, CrossEX, TouchEn, Wizvera, IPinside, 공동인증서 도구 등)은
PC가 켜지면 항상 실행되고, 일부는 다른 기기에서도 접속할 수 있는 포트를 연다.
사이트(URL) 단위로 제한하는 설정은 이 프로그램들에 없으므로, 효과가 같은 두 가지를 제공한다.

1. 외부 접속 차단: 방화벽 '들어오는 연결 차단' 규칙 → 다른 기기는 접속 불가, 이 PC 브라우저(127.0.0.1)는 그대로 사용
   (Windows 방화벽은 같은 PC 안의 연결(loopback)은 막지 않으므로 뱅킹에는 영향 없음)
2. 실행 방식
   - always : 원래대로 항상 켜 둠
   - auto   : 평소엔 꺼 두고, 은행·공공기관 사이트 창(창 제목의 키워드)이 열리면 켜고, 닫힌 뒤 N분 지나면 끔
   - off    : 꺼 둠 (필요할 때 '지금 켜기')
   끄기 = 서비스 '수동 시작'으로 바꾸고 중지 + 로그인 시 자동 실행 항목을 보관 후 제거 + 프로그램 종료
   원래대로 = 보관해 둔 시작 방식·자동 실행 항목 복구
"""
import ctypes
import logging
import os
import re
import subprocess
import threading
import time
import winreg
from ctypes import wintypes

import psutil

import winutil

log = logging.getLogger("pcmon.banking")

VENDOR_RE = re.compile(r"INCAInternet|nProtect|AhnLab\\Safe Transaction|ASTx|TouchEn|RaonSecure|Wizvera|Veraport|IPinside|Interezen|"
                       r"iniLINE|CrossEX|\\initech\\|INISAFE|Delfino|MagicLine|DreamSecurity|AnySign|SoftForum|KSign|Yettiesoft|"
                       r"vestcert|nxKey|XecureWeb|SignKorea|UniSign|CrossCert|Kings\\|KICA", re.I)
DEFAULT_KEYWORDS = ["은행", "뱅킹", "Bank", "농협", "NH", "IBK", "새마을금고", "신협", "우체국", "수협", "카카오뱅크", "케이뱅크", "토스뱅크",
                    "홈택스", "손택스", "위택스", "정부24", "민원24", "국민건강보험", "국민연금", "건강보험", "전자소송", "인터넷등기소", "대법원",
                    "증권", "공동인증서", "금융인증서", "인증서", "카드", "보험", "나이스평가", "NICE"]
RUN_KEYS = [(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU")]
SC_START = {"automatic": "auto", "manual": "demand", "disabled": "disabled"}
FW_GROUP = "PCMonitor 뱅킹 외부차단"


def _exe(cmd):
    c = (cmd or "").strip()
    if c.startswith('"'):
        return c[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.(exe|npe))\b", c, re.I)
    return m.group(1) if m else c


def window_titles():
    """보이는 창들의 제목 (같은 사용자 세션에서만 볼 수 있음)."""
    titles = []
    proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    u = ctypes.windll.user32

    def cb(h, _l):
        if u.IsWindowVisible(h):
            n = u.GetWindowTextLengthW(h)
            if n:
                b = ctypes.create_unicode_buffer(n + 1)
                u.GetWindowTextW(h, b, n + 1)
                titles.append(b.value)
        return True
    u.EnumWindows(proc(cb), 0)
    return titles


class Banking:
    def __init__(self, mon):
        self.mon = mon
        self.db = mon.db
        self.lock = threading.Lock()
        self.cfg = self.db.get("banking") or {}
        self.cfg.setdefault("mode", "always")
        self.cfg.setdefault("block_external", False)
        self.cfg.setdefault("keywords", DEFAULT_KEYWORDS)
        self.cfg.setdefault("idle_min", 10)
        self.cfg.setdefault("saved", {"services": {}, "run": []})   # 꺼 두기 전 원래 설정
        self.cfg.setdefault("state", "on")
        self.last_seen = 0
        self.last_match = ""
        self.busy = ""

    def save(self):
        self.db.set("banking", self.cfg)

    # ---------------------------------------------------------------- 찾기
    def inventory(self):
        svcs, runs, procs, ports, exes = [], [], [], [], set()
        try:
            for s in psutil.win_service_iter():
                try:
                    d = s.as_dict()
                except Exception:
                    continue
                if VENDOR_RE.search(f"{d.get('binpath', '')} {d.get('display_name', '')}"):
                    svcs.append({"name": d["name"], "display": d.get("display_name") or d["name"], "status": d.get("status"),
                                 "start": d.get("start_type"), "exe": _exe(d.get("binpath", ""))})
                    exes.add(_exe(d.get("binpath", "")).lower())
        except Exception:
            pass
        for hive, key, hn in RUN_KEYS:
            try:
                with winreg.OpenKey(hive, key) as k:
                    i = 0
                    while True:
                        try:
                            n, v, t = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        if VENDOR_RE.search(str(v)):
                            runs.append({"hive": hn, "key": key, "name": n, "value": str(v), "type": t, "exe": _exe(str(v))})
                            exes.add(_exe(str(v)).lower())
                        i += 1
            except OSError:
                pass
        for s in self.cfg["saved"]["run"]:   # 꺼 둔 동안 보관 중인 자동 실행
            exes.add(_exe(s["value"]).lower())
        pid_exe = {}
        for p in psutil.process_iter(["pid", "name", "exe"]):
            e = p.info.get("exe") or ""
            if e and (VENDOR_RE.search(e) or e.lower() in exes):
                procs.append({"pid": p.info["pid"], "name": p.info["name"], "exe": e})
                pid_exe[p.info["pid"]] = p.info["name"]
                exes.add(e.lower())
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == psutil.CONN_LISTEN and c.pid in pid_exe:
                    ports.append({"proc": pid_exe[c.pid], "port": c.laddr.port, "addr": c.laddr.ip,
                                  "external": c.laddr.ip in ("0.0.0.0", "::")})
        except Exception:
            pass
        return {"services": svcs, "runs": runs, "procs": procs, "ports": ports, "exes": sorted(exes)}

    # ---------------------------------------------------------------- 외부 접속 차단
    def set_block_external(self, on):
        inv = self.inventory()
        winutil.run_ps(f"Remove-NetFirewallRule -Group '{FW_GROUP}' -ErrorAction SilentlyContinue")
        n = 0
        if on:
            for e in inv["exes"]:
                if os.path.isfile(e):
                    b = winutil._b64(e)
                    winutil.run_ps(
                        "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));"
                        "New-NetFirewallRule -DisplayName ('PCMonitor 뱅킹 외부차단 - ' + [IO.Path]::GetFileName($p)) -Group '%s' "
                        "-Direction Inbound -Action Block -Program $p -Profile Any | Out-Null" % (b, FW_GROUP))
                    n += 1
        self.cfg["block_external"] = bool(on)
        self.save()
        self.db.add_event(time.time(), "action", "info", "pcmon", 0,
                          f"뱅킹 프로그램 외부 접속 차단 {'켬' if on else '끔'}" + (f" ({n}개 프로그램)" if on else ""), "")
        return {"ok": True, "msg": (f"뱅킹 프로그램 {n}개의 외부 접속을 막았습니다. 이 PC 브라우저에서는 그대로 쓸 수 있습니다." if on
                                    else "외부 접속 차단 규칙을 지웠습니다.")}

    # ---------------------------------------------------------------- 켜기 / 끄기
    def turn_off(self, reason="수동"):
        with self.lock:
            self.busy = "끄는 중"
            try:
                inv = self.inventory()
                saved = self.cfg["saved"]
                for s in inv["services"]:
                    saved["services"].setdefault(s["name"], s["start"] or "automatic")
                    if s["start"] == "automatic":
                        subprocess.run(["sc.exe", "config", s["name"], "start=", "demand"], capture_output=True, creationflags=winutil.CREATE_NO_WINDOW)
                    subprocess.run(["sc.exe", "stop", s["name"]], capture_output=True, creationflags=winutil.CREATE_NO_WINDOW)
                for r in inv["runs"]:   # 로그인 시 자동 실행 → 보관 후 제거
                    hive = winreg.HKEY_LOCAL_MACHINE if r["hive"] == "HKLM" else winreg.HKEY_CURRENT_USER
                    try:
                        with winreg.OpenKey(hive, r["key"], 0, winreg.KEY_SET_VALUE) as k:
                            winreg.DeleteValue(k, r["name"])
                        saved["run"].append({k2: r[k2] for k2 in ("hive", "key", "name", "value", "type")})
                    except OSError:
                        pass
                killed = 0
                time.sleep(2)
                for p in self.inventory()["procs"]:
                    try:
                        psutil.Process(p["pid"]).kill()
                        killed += 1
                    except Exception:
                        pass
                self.cfg["state"] = "off"
                self.save()
                self._refresh_baseline()
                left = self.inventory()["procs"]
                self.db.add_event(time.time(), "action", "info", "pcmon", 0, f"뱅킹 보안 프로그램 끔 ({reason})",
                                  {"종료": killed, "남은 프로세스": [p["name"] for p in left]})
                return {"ok": True, "msg": "뱅킹 보안 프로그램을 껐습니다." + (f" (스스로 보호 중이라 남은 것: {', '.join(sorted({p['name'] for p in left}))})" if left else "")}
            finally:
                self.busy = ""

    def turn_on(self, reason="수동"):
        with self.lock:
            self.busy = "켜는 중"
            try:
                inv = self.inventory()
                for s in inv["services"]:
                    if s["start"] != "disabled" or s["name"] in self.cfg["saved"]["services"]:
                        subprocess.run(["sc.exe", "start", s["name"]], capture_output=True, creationflags=winutil.CREATE_NO_WINDOW)
                started = 0
                if not winutil.is_system():
                    for r in self.cfg["saved"]["run"]:   # 로그인 시 실행되던 것들을 일반 권한으로 실행
                        e = _exe(r["value"])
                        if os.path.isfile(e) and not any(p["exe"].lower() == e.lower() for p in inv["procs"]):
                            subprocess.Popen(["explorer.exe", e], creationflags=winutil.CREATE_NO_WINDOW)
                            started += 1
                self.cfg["state"] = "on"
                self.save()
                self.db.add_event(time.time(), "action", "info", "pcmon", 0, f"뱅킹 보안 프로그램 켬 ({reason})", "")
                return {"ok": True, "msg": "뱅킹 보안 프로그램을 켰습니다. 사이트가 '설치 필요'라고 하면 새로고침(F5) 하세요."}
            finally:
                self.busy = ""

    def restore_original(self):
        """원래 설정으로: 서비스 시작 방식·로그인 시 자동 실행 복구 후 켬."""
        with self.lock:
            for name, start in self.cfg["saved"]["services"].items():
                subprocess.run(["sc.exe", "config", name, "start=", SC_START.get(start, "auto")], capture_output=True, creationflags=winutil.CREATE_NO_WINDOW)
            for r in self.cfg["saved"]["run"]:
                hive = winreg.HKEY_LOCAL_MACHINE if r["hive"] == "HKLM" else winreg.HKEY_CURRENT_USER
                try:
                    with winreg.CreateKey(hive, r["key"]) as k:
                        winreg.SetValueEx(k, r["name"], 0, r.get("type", winreg.REG_SZ), r["value"])
                except OSError:
                    pass
            self.cfg["saved"] = {"services": {}, "run": []}
            self.save()
        res = self.turn_on("원래대로")
        self._refresh_baseline()
        return res

    def kick_all(self):
        """실행 중인 모든 뱅킹 보안 프로그램을 지금 즉시 강제 종료 (원클릭 차기/Kick)."""
        inv = self.inventory()
        procs = inv.get("procs", [])
        total_rss = sum(p.get("rss", 0) for p in procs)
        killed_names = []
        for p in procs:
            try:
                psutil.Process(p["pid"]).kill()
                killed_names.append(p.get("name") or str(p["pid"]))
            except Exception:
                pass
        stopped_svcs = 0
        for s in inv.get("services", []):
            try:
                r = subprocess.run(["sc.exe", "stop", s["name"]], capture_output=True, creationflags=winutil.CREATE_NO_WINDOW)
                if r.returncode == 0:
                    stopped_svcs += 1
            except Exception:
                pass
        freed_mb = round(total_rss / 1048576, 1)
        self.cfg["state"] = "off"
        self.save()
        self._refresh_baseline()
        self.db.add_event(time.time(), "action", "info", "pcmon", 0,
                          f"뱅킹 보안 프로그램 즉시 차기 (종료 {len(killed_names)}개, {freed_mb}MB 확보)",
                          {"종료목록": killed_names, "중지된 서비스수": stopped_svcs})
        return {
            "ok": True,
            "killed_count": len(killed_names),
            "freed_mb": freed_mb,
            "stopped_services": stopped_svcs,
            "names": killed_names,
            "msg": f"⚡ 뱅킹 보안 프로그램 {len(killed_names)}개를 즉시 강제 종료(Kick)하여 약 {freed_mb}MB 메모리를 확보했습니다."
        }

    def apply_recommended(self):
        """인터넷 보안 프로그램 권장 설정 원클릭 적용: 사이트 열 때만 켜기(auto) + 외부 차단(True) + 5분 후 동면."""
        self.set_block_external(True)
        self.set_mode("auto", idle_min=5)
        self.db.add_event(time.time(), "action", "info", "pcmon", 0, "뱅킹 보안 프로그램 권장 설정 적용 (사이트 열 때만 켜기, 외부차단 켬, 5분 후 종료)", "")
        return {
            "ok": True,
            "msg": "🌟 인터넷 보안 프로그램 권장 설정이 적용되었습니다!\n- 은행·공공기관 사이트 열 때만 자동 기동\n- 사이트 닫은 후 5분 뒤 자동 동면/종료\n- 방화벽 외부 접속 완벽 차단"
        }


    def set_mode(self, mode, keywords=None, idle_min=None):
        if mode not in ("always", "auto", "off"):
            return {"ok": False, "msg": "잘못된 요청"}
        if keywords is not None:
            self.cfg["keywords"] = [k.strip()[:30] for k in keywords if k.strip()][:100]
        if idle_min is not None:
            self.cfg["idle_min"] = max(1, min(240, int(idle_min)))
        prev = self.cfg["mode"]
        self.cfg["mode"] = mode
        self.save()
        if mode == "always" and prev != "always":
            r = self.restore_original()
            return {"ok": True, "msg": "원래대로 항상 켜 두도록 바꿨습니다. " + r["msg"]}
        if mode in ("auto", "off") and self.cfg["state"] == "on" and not self._bank_window():
            r = self.turn_off("평소 꺼 두기")
            extra = " 은행·공공기관 사이트 창이 열리면 자동으로 켭니다." if mode == "auto" else " 필요할 때 '지금 켜기'를 누르세요."
            return {"ok": True, "msg": r["msg"] + extra}
        return {"ok": True, "msg": "설정을 저장했습니다."}

    # ---------------------------------------------------------------- 자동 모드 (3초마다)
    def _bank_window(self):
        if winutil.is_system():
            return ""
        kws = [k.lower() for k in self.cfg["keywords"]]
        for t in window_titles():
            tl = t.lower()
            if any(k in tl for k in kws) and "pc 모니터" not in tl:
                return t
        return ""

    def tick(self):
        if self.cfg["mode"] != "auto" or self.busy:
            return
        w = self._bank_window()
        if w:
            self.last_seen = time.time()
            self.last_match = w
            if self.cfg["state"] == "off":
                threading.Thread(target=self._auto_on, args=(w,), daemon=True).start()
        elif self.cfg["state"] == "on" and time.time() - self.last_seen > self.cfg["idle_min"] * 60:
            threading.Thread(target=self.turn_off, args=(f"뱅킹 창 닫힌 지 {self.cfg['idle_min']}분",), daemon=True).start()

    def _auto_on(self, title):
        r = self.turn_on(f"자동: {title[:40]}")
        winutil.toast("뱅킹 보안 프로그램을 켰습니다", f"'{title[:40]}' 창이 열려서 켰습니다. 사이트가 설치를 요구하면 새로고침(F5) 하세요.")
        return r

    def _refresh_baseline(self):
        """우리가 바꾼 자동 실행 변화가 '새 자동실행' 경고로 뜨지 않게 기준 목록 갱신."""
        try:
            self.db.set("persist_baseline", self.mon.sec._snapshot_persistence())
        except Exception:
            pass

    def status(self):
        inv = self.inventory()
        return {**{k: self.cfg[k] for k in ("mode", "block_external", "keywords", "idle_min", "state")},
                "busy": self.busy, "saved_services": len(self.cfg["saved"]["services"]), "saved_runs": len(self.cfg["saved"]["run"]),
                "last_match": self.last_match, "last_seen": int(self.last_seen), "auto_available": not winutil.is_system(),
                "inventory": {k: inv[k] for k in ("services", "runs", "procs", "ports")}}
