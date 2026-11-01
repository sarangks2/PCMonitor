"""Windows 업데이트 · Windows 보안(백신) 검사 진행 상황.

백신 검사: Windows는 진행률(%)을 알려 주지 않는다. 대신
  - 시작/끝 기록(Defender 이벤트 1000/1001/1002/1005)
  - 백신 엔진(MsMpEng)이 지금까지 읽은 데이터 양 ÷ 디스크 사용량  → 전체 검사 진행률 추정
  - 지난번 같은 종류 검사에 걸린 시간 → 빠른 검사 진행률 추정
Windows 업데이트: 업데이트 에이전트(COM)로 대기 목록·다운로드 여부·설치 기록, 이벤트로 다운로드/설치 진행.
"""
import logging
import os
import subprocess
import threading
import time

import psutil

import winutil

log = logging.getLogger("pcmon.sysupdate")
DEF_CH = "Microsoft-Windows-Windows Defender/Operational"
WU_CH = "Microsoft-Windows-WindowsUpdateClient/Operational"
SCAN_KIND = {"1": "빠른 검사", "2": "전체 검사", "3": "사용자 지정 검사"}

WU_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$o=@{}
$s=New-Object -ComObject Microsoft.Update.Session
$sr=$s.CreateUpdateSearcher(); $sr.Online=$false
$r=$sr.Search("IsInstalled=0 and IsHidden=0")
$o.pending=@($r.Updates | % { @{t=$_.Title; dl=[bool]$_.IsDownloaded; kb=(@($_.KBArticleIDs) -join ','); sev=[string]$_.MsrcSeverity;
  cat=(@($_.Categories | % { $_.Name }) -join ',')} })
$n=$sr.GetTotalHistoryCount(); $h=@()
if($n -gt 0){ $h=@($sr.QueryHistory(0,[Math]::Min($n,30)) | % { @{t=$_.Title; d=$_.Date.ToLocalTime().ToString('yyyy-MM-dd HH:mm'); rc=[int]$_.ResultCode} }) }
$o.history=$h
$au=(New-Object -ComObject Microsoft.Update.AutoUpdate).Results
$o.lastsearch=$(if($au.LastSearchSuccessDate){$au.LastSearchSuccessDate.ToLocalTime().ToString('yyyy-MM-dd HH:mm')}else{''})
$o.lastinstall=$(if($au.LastInstallationSuccessDate){$au.LastInstallationSuccessDate.ToLocalTime().ToString('yyyy-MM-dd HH:mm')}else{''})
$o.reboot=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$ux=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$o.paused=[string]$ux.PauseUpdatesExpiryTime
$o.svc=[string](Get-Service wuauserv).StartType
$o | ConvertTo-Json -Depth 4 -Compress
"""


class SysUpdate:
    def __init__(self, db):
        self.db = db
        self.mp_samples = []        # (시각, MsMpEng 누적 읽기 바이트)
        self.wu = db.get("wu_status") or {}
        self.wu_running = False
        self.disk_used = 0

    # ------------------------------------------------------------------ 주기 작업
    def sample(self):
        """30초마다: 백신 엔진이 읽은 양 기록 (진행률 추정용)."""
        for p in psutil.process_iter(["name"]):
            if p.info["name"] == "MsMpEng.exe":
                try:
                    self.mp_samples.append((time.time(), p.io_counters().read_bytes, p.create_time()))
                except Exception:
                    pass
                break
        self.mp_samples = self.mp_samples[-3000:]   # 약 25시간
        if not self.disk_used or len(self.mp_samples) % 60 == 1:
            used = 0
            for d in psutil.disk_partitions(all=False):
                if "fixed" in d.opts or d.fstype in ("NTFS", "ReFS"):
                    try:
                        used += psutil.disk_usage(d.mountpoint).used
                    except OSError:
                        pass
            self.disk_used = used

    def refresh_wu(self):
        if self.wu_running:
            return
        self.wu_running = True
        try:
            r = winutil.run_ps_json(WU_PS, timeout=300)
            if r:
                r["checked"] = int(time.time())
                for k in ("pending", "history"):
                    if isinstance(r.get(k), dict):
                        r[k] = [r[k]]
                self.wu = r
                self.db.set("wu_status", r)
        finally:
            self.wu_running = False

    # ------------------------------------------------------------------ 백신 검사 상태
    def defender_scan(self):
        try:
            evs = winutil.query_events(DEF_CH, "*[System[(EventID=1000 or EventID=1001 or EventID=1002 or EventID=1005)]]",
                                       max_events=40, reverse=True)
        except Exception:
            return {"available": False}
        evs.sort(key=lambda e: e["ts"])
        scans = {}
        for e in evs:
            d = e["data"]
            sid = d.get("Scan ID", "")
            s = scans.setdefault(sid, {"id": sid, "kind": SCAN_KIND.get(d.get("Scan Parameters Index", ""), d.get("Scan Parameters", "")),
                                       "kidx": d.get("Scan Parameters Index", ""), "who": d.get("User", ""), "start": None, "end": None, "result": ""})
            if e["id"] == 1000:
                s["start"] = e["ts"]
                s["trigger"] = d.get("Scan Trigger", "").lstrip("흝흞에걖")
            else:
                s["end"] = e["ts"]
                s["result"] = {1001: "완료", 1002: "취소됨", 1005: "실패"}[e["id"]]
                if e["id"] == 1001:
                    try:
                        s["secs"] = int(d.get("Scan Time Hours", 0)) * 3600 + int(d.get("Scan Time Minutes", 0)) * 60 + int(d.get("Scan Time Seconds", 0))
                    except ValueError:
                        pass
        lst = sorted([s for s in scans.values() if s["start"]], key=lambda s: s["start"])
        mpcmd = any(p.info["name"] == "MpCmdRun.exe" for p in psutil.process_iter(["name"]))
        running = [s for s in lst if not s["end"] and time.time() - s["start"] < 3 * 86400]
        cur = running[-1] if running else None
        out = {"available": True, "running": bool(cur), "mpcmdrun": mpcmd,
               "recent": [{k: s.get(k) for k in ("kind", "start", "end", "result", "secs", "trigger")} for s in lst if s["end"]][-4:][::-1]}
        if cur:
            el = time.time() - cur["start"]
            cur_out = {"kind": cur["kind"], "start": cur["start"], "elapsed": int(el), "trigger": cur.get("trigger", ""), "who": cur["who"]}
            prev = [s for s in lst if s["end"] and s.get("secs") and s["kidx"] == cur["kidx"]]
            if cur["kidx"] == "2" and self.mp_samples and self.disk_used:
                # 전체 검사: 백신 엔진이 읽은 양 ÷ 디스크 사용량
                now_t, now_b, ct = self.mp_samples[-1]
                base = None
                for t, b, c in self.mp_samples:
                    if t >= cur["start"] - 60 and c == ct:
                        base = b
                        break
                done = None
                if base is not None and self.mp_samples[0][0] <= cur["start"] + 120:
                    done = max(0, now_b - base)
                elif ct >= cur["start"] - 1800:
                    done = now_b  # 백신 엔진이 검사 직전에 시작됨 → 누적 읽기량 ≈ 검사한 양
                else:
                    # 모니터가 검사 도중부터 지켜봄 → 지켜본 구간의 속도로 시작 이후 전체량 추정
                    same = [(t, b) for t, b, c in self.mp_samples if c == ct and t >= cur["start"]]
                    cur_out["observed"] = int(same[-1][0] - same[0][0]) if len(same) >= 2 else 0
                    if len(same) >= 2 and same[-1][0] - same[0][0] >= 600:  # 10분 이상 지켜본 뒤에만 추정
                        r = (same[-1][1] - same[0][1]) / (same[-1][0] - same[0][0])
                        done = r * el
                if done is not None:
                    pct = min(99.0, 100.0 * done / self.disk_used)
                    rate = done / el if el > 60 else 0
                    eta = int((self.disk_used - done) / rate) if rate > 0 else None
                    cur_out.update(pct=round(pct, 1), read_gb=round(done / 1e9, 1), total_gb=round(self.disk_used / 1e9),
                                   eta=eta if eta is not None and eta < 3 * 86400 else None, method="bytes",
                                   slow=eta is None or eta >= 3 * 86400)
            elif prev:
                avg = sum(s["secs"] for s in prev[-3:]) / len(prev[-3:])
                cur_out.update(pct=round(min(99.0, 100 * el / max(avg, 1)), 1), eta=max(0, int(avg - el)), method="time")
            cur_out["idle_only"] = self._idle_only()
            out["current"] = cur_out
        return out

    def _idle_only(self):
        """'PC를 안 쓸 때만 검사' 설정 여부 (켜져 있으면 사용 중엔 검사가 거의 멈춤)."""
        if not hasattr(self, "_idle"):
            self._idle = (None, 0)
        if time.time() - self._idle[1] > 1800:
            self._idle = (self._idle[0], time.time())  # 화면 요청을 막지 않도록 백그라운드에서 확인

            def chk():
                out = winutil.run_ps("(Get-MpPreference).ScanOnlyIfIdleEnabled", timeout=60).strip()
                self._idle = (out == "True" if out in ("True", "False") else None, time.time())
            threading.Thread(target=chk, daemon=True).start()
        return self._idle[0]

    # ------------------------------------------------------------------ Windows 업데이트 상태
    def wu_status(self):
        w = dict(self.wu or {})
        w["refreshing"] = self.wu_running
        # 최근 1시간 다운로드·설치 진행 (이벤트)
        try:
            evs = winutil.query_events(WU_CH, "*[System[(EventID=19 or EventID=20 or EventID=43 or EventID=44) and "
                                              "TimeCreated[timediff(@SystemTime) <= 7200000]]]", max_events=200)
        except Exception:
            evs = []
        started = {}
        for e in evs:
            t = e["data"].get("updateTitle", "")
            st = started.setdefault(t, {"t": t, "state": "", "ts": e["ts"]})
            st["state"] = {44: "다운로드 중", 43: "설치 중", 19: "설치 완료", 20: "설치 실패"}[e["id"]]
            st["ts"] = e["ts"]
            if e["id"] == 20:
                st["err"] = e["data"].get("errorCode", "")
        act = sorted(started.values(), key=lambda x: x["ts"])
        busy = any(p.info["name"] in ("TiWorker.exe", "TrustedInstaller.exe") and (p.info.get("cpu_percent") or 0) > 3
                   for p in psutil.process_iter(["name", "cpu_percent"]))
        w["activity"] = act[-10:]
        done = sum(1 for a in act if a["state"] in ("설치 완료", "설치 실패"))
        w["active"] = bool([a for a in act if a["state"] in ("다운로드 중", "설치 중")]) or busy
        w["progress"] = {"done": done, "total": len(act)} if act else None
        w["installing_now"] = busy
        pend = w.get("pending") or []
        w["pending_security"] = [p for p in pend if "보안" in p.get("t", "") or "Security" in p.get("cat", "") or p.get("sev")]
        hist_ok = [h for h in (w.get("history") or []) if h.get("rc") == 2 and "Defender" not in h.get("t", "") and "보안 인텔리전스" not in h.get("t", "")]
        w["last_os_update"] = hist_ok[0] if hist_ok else None
        return w

    # ------------------------------------------------------------------ 버튼
    def start_wu(self):
        """업데이트 확인 → 다운로드 → 설치 (설정 앱과 같은 동작). 끝나면 목록 다시 확인."""
        uso = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "UsoClient.exe")
        for arg in ("StartInteractiveScan", "StartDownload", "StartInstall"):
            try:
                subprocess.Popen([uso, arg], creationflags=winutil.CREATE_NO_WINDOW)
            except OSError:
                pass
            time.sleep(2)
        threading.Timer(120, self.refresh_wu).start()
        return {"ok": True, "msg": "업데이트 확인·다운로드·설치를 시작했습니다. 진행 상황은 아래에 표시됩니다 (몇 분 뒤부터)."}

    def defender_start(self, kind):
        exe = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")
        st = {"quick": "1", "full": "2"}.get(kind)
        if not st:
            return {"ok": False, "msg": "잘못된 요청"}
        subprocess.Popen([exe, "-Scan", "-ScanType", st], creationflags=winutil.CREATE_NO_WINDOW)
        return {"ok": True, "msg": ("빠른" if st == "1" else "전체") + " 검사를 시작했습니다"}

    def defender_cancel(self):
        exe = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")
        r = subprocess.run([exe, "-Cancel"], capture_output=True, timeout=60, creationflags=winutil.CREATE_NO_WINDOW)
        for p in psutil.process_iter(["name"]):
            if p.info["name"] == "MpCmdRun.exe":
                try:
                    p.kill()
                except Exception:
                    pass
        return {"ok": True, "msg": "검사를 중지했습니다"}
