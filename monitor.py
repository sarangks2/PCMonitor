"""PC 모니터 본체. pythonw monitor.py 로 백그라운드 실행.

- 10초마다 CPU/메모리/디스크/네트워크 기록 + 생존신호(heartbeat)
- 재부팅 후 직전 비정상 종료를 찾아 '멈추기 직전 5분' 기록을 장애 보고서로 남김
- 보안 감시 (security.py)
- 대시보드 http://127.0.0.1:8765
"""
import logging
import logging.handlers
import os
import sys
import threading
import time
import traceback

import psutil

import config
import i18n
import winutil
from db import DB
from intrusion import FirewallWatcher, TraceScanner
from procinfo import PROCINFO
from remediate import Remediator
from sysupdate import SysUpdate
from finder import Finder, Notes
from banking import Banking
from security import SecurityMonitor

os.makedirs(config.DATA_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[logging.handlers.RotatingFileHandler(config.LOG_PATH, maxBytes=config.LOG_MAX_BYTES,
                                                   backupCount=1, encoding="utf-8")])
log = logging.getLogger("pcmon")


class Monitor:
    def __init__(self):
        self.db = DB()
        self.cooldown = {}
        self.sec = SecurityMonitor(self.db, self.alert)
        self.fw = FirewallWatcher(self.db, self.alert)
        self.trace = TraceScanner(self.db, self)
        self.rem = Remediator(self.db, self)
        self.upd = SysUpdate(self.db)
        self.notes = Notes(self.db)
        self.finder = Finder(self)
        self.bank = Banking(self)
        self.latest = {}          # 현재 값 (대시보드용)
        self.top_now = []         # 현재 상위 프로세스
        self.proc_cache = {}      # pid -> psutil.Process
        self.cpu_acc = {}         # pid -> [cpu합, 횟수, 이름]
        self.high = {"cpu": 0, "mem": 0, "commit": 0}
        self.started = time.time()
        self.ncpu = psutil.cpu_count() or 1
        self.os = winutil.os_info()
        self.me = psutil.Process()
        self.me.cpu_percent(None)
        self.self_cpu = 0.0
        self.token = ""
        self.stop = threading.Event()

    # ------------------------------------------------------------------ 알림
    def alert(self, key, severity, title, body):
        now = time.time()
        if now - self.cooldown.get(key, 0) < config.ALERT_COOLDOWN_SECS:
            return
        self.cooldown[key] = now
        self.db.execute("INSERT INTO alerts(ts,key,severity,title,body) VALUES(?,?,?,?,?)",
                        (int(now), key, severity, title, body))
        log.warning("ALERT [%s] %s - %s", severity, title, body.replace("\n", " "))
        if not self.popup_allowed(severity, now):
            return  # 기록은 남기고 팝업만 생략 (앱의 이벤트 화면에서 볼 수 있음)
        lang = self.db.get("ui_lang") or "ko"
        winutil.toast(("⚠ " if severity == "crit" else "") + i18n.tr(title, lang), i18n.tr(body, lang),
                      app_name="PC Monitor" if lang == "en" else "PC 모니터")

    def notify_settings(self):
        n = self.db.get("notify") or {}
        return {"level": n.get("level") if n.get("level") in ("all", "crit", "off") else "all",
                "mute_until": int(n.get("mute_until") or 0)}

    def popup_allowed(self, severity, now=None):
        """알림 설정: all=모두 · crit=위험만 · off=끄기, mute_until=그때까지 잠시 끄기."""
        n = self.notify_settings()
        if n["mute_until"] > (now or time.time()) or n["level"] == "off":
            return False
        return n["level"] == "all" or severity == "crit"

    def shutdown(self, reason="사용자가 끔"):
        """모니터 본체를 정상 종료 (종료 코드 0 → 예약 작업이 '실패 후 다시 시작'을 하지 않음).
        다음 로그인/부팅 때나 PC 모니터 아이콘을 열면 다시 켜진다."""
        log.info("종료: %s", reason)
        self.db.set("stopped_at", time.time())
        self.stop.set()

    # ------------------------------------------------------------------ 장애 감지
    def detect_incident(self):
        """이전 실행의 마지막 생존신호 이후 재부팅됐고, 그 사이 비정상 종료 이벤트가 있으면 기록."""
        last_hb = self.db.get("heartbeat")
        boot = psutil.boot_time()
        self.db.set("boot_time", boot)
        stopped = self.db.get("stopped_at")
        if stopped:
            self.db.set("stopped_at", 0)
        if not last_hb or last_hb >= boot:
            return
        if stopped and stopped >= last_hb:
            return  # 사용자가 모니터를 끈 뒤라 '멈추기 직전' 기록이 없다
        if self.db.query("SELECT 1 FROM incidents WHERE boot_time=?", (int(boot),)):
            return
        since_ms = int((time.time() - last_hb + 600) * 1000)
        try:
            evs = winutil.query_events(
                "System", f"*[System[(EventID=41 or EventID=6008 or EventID=1001 or EventID=1074 or EventID=13) "
                          f"and TimeCreated[timediff(@SystemTime) <= {since_ms}]]]")
        except Exception:
            evs = []
        evs = [e for e in evs if e["ts"] >= last_hb - 120]
        k41 = [e for e in evs if e["id"] == 41]
        if not k41 and not any(e["id"] == 6008 for e in evs):
            return  # 정상 종료/재시작
        bc, kind = "", "갑작스런 꺼짐"
        if k41:
            d = k41[-1]["data"]
            code = int(d.get("BugcheckCode", "0") or 0)
            if code:
                bc, kind = f"0x{code:X}", "블루스크린"
            elif d.get("PowerButtonTimestamp", "0") not in ("0", ""):
                kind = "멈춤 → 전원 버튼 강제 종료"
            else:
                kind = "갑작스런 전원 차단/리셋"
        hb = int(last_hb)
        metrics = self.db.query("SELECT * FROM metrics WHERE ts BETWEEN ? AND ? ORDER BY ts", (hb - 300, hb))
        procs = self.db.query("SELECT * FROM procs WHERE ts=(SELECT MAX(ts) FROM procs WHERE ts<=?)", (hb,))
        events = self.db.query("SELECT ts,category,severity,title FROM events WHERE ts BETWEEN ? AND ? ORDER BY ts",
                               (hb - 1800, hb + 600))
        summary = self._summarize(metrics, procs)
        import json
        self.db.execute(
            "INSERT INTO incidents(ts,last_heartbeat,boot_time,kind,bugcheck,summary,snapshot) VALUES(?,?,?,?,?,?,?)",
            (int(time.time()), hb, int(boot), kind, bc, summary,
             json.dumps({"metrics": metrics, "procs": procs, "events": events}, ensure_ascii=False)))
        when = time.strftime("%m/%d %H:%M:%S", time.localtime(hb))
        self.alert(f"incident:{int(boot)}", "crit", f"직전 비정상 종료 감지: {kind} {bc}".strip(),
                   f"마지막 기록 {when}. {summary}")
        log.warning("incident: %s %s / %s", kind, bc, summary)

    @staticmethod
    def _summarize(metrics, procs):
        if not metrics:
            return "직전 기록 없음 (모니터가 실행 중이 아니었음)"
        mx = lambda k: max((m[k] or 0) for m in metrics)
        parts = [f"직전 5분 최대 CPU {mx('cpu'):.0f}%", f"메모리 {mx('mem'):.0f}%", f"커밋 {mx('commit_pct'):.0f}%",
                 f"디스크 사용률 {mx('disk_busy'):.0f}%"]
        top = [p for p in procs if p["kind"] == "cpu"][:2] + [p for p in procs if p["kind"] == "mem"][:1]
        if top:
            parts.append("상위: " + ", ".join(f"{p['name']}({p['cpu']:.0f}%/{p['mem_mb']:.0f}MB)" for p in top))
        hint = []
        if mx("mem") >= 90 or mx("commit_pct") >= 90:
            hint.append("메모리 부족 의심")
        if mx("cpu") >= 95:
            hint.append("CPU 과부하")
        if mx("disk_busy") >= 95:
            hint.append("디스크 과부하")
        if not hint:
            hint.append("자원 사용은 정상 → 드라이버/하드웨어 쪽 의심")
        return ", ".join(parts) + " → " + ", ".join(hint)

    # ------------------------------------------------------------------ 수집
    def sample_processes(self):
        seen, new_exes = set(), []
        rows = []
        for p in psutil.process_iter(["pid", "name"]):
            pid = p.info["pid"]
            if pid in (0, 4):
                continue
            seen.add(pid)
            proc = self.proc_cache.get(pid)
            if proc is None:
                self.proc_cache[pid] = proc = p
                try:
                    proc.cpu_percent(None)
                    if self.started + 30 < time.time():
                        new_exes.append((pid, p.info["name"], proc.exe()))
                except Exception:
                    pass
                continue
            try:
                with proc.oneshot():
                    cpu = proc.cpu_percent(None) / self.ncpu
                    mi = proc.memory_info()
                    mem = getattr(mi, "private", mi.rss) / 1048576
                rows.append({"pid": pid, "name": p.info["name"], "cpu": cpu, "mem_mb": mem})
                a = self.cpu_acc.setdefault(pid, [0.0, 0, p.info["name"]])
                a[0] += cpu
                a[1] += 1
            except Exception:
                pass
        for pid in list(self.proc_cache):
            if pid not in seen:
                self.proc_cache.pop(pid, None)
                self.cpu_acc.pop(pid, None)
        self.top_now = sorted(rows, key=lambda r: -r["cpu"])[:8]
        self.mem_top = sorted(rows, key=lambda r: -r["mem_mb"])[:8]
        for r in {id(r): r for r in self.top_now + self.mem_top}.values():
            try:
                r.update(PROCINFO.describe(r["pid"], r["name"]))
            except Exception:
                pass
        for r in self.mem_top[:1]:
            if r["mem_mb"] > config.PROC_MEM_ALERT_MB:
                self.alert(f"procmem:{r['name']}", "warn", "프로세스 메모리 과다",
                           f"{r['name']} 가 {r['mem_mb']:.0f}MB 사용 중")
        return new_exes

    def snapshot_top(self, ts):
        cpu_avg = sorted(((a[0] / a[1], pid, a[2]) for pid, a in self.cpu_acc.items() if a[1]), reverse=True)[:5]
        memd = {r["pid"]: r["mem_mb"] for r in getattr(self, "mem_top", [])}
        rows = [{"kind": "cpu", "rank": i, "pid": pid, "name": n, "cpu": c, "mem_mb": memd.get(pid, 0)}
                for i, (c, pid, n) in enumerate(cpu_avg)]
        cpud = {pid: a[0] / a[1] for pid, a in self.cpu_acc.items() if a[1]}
        rows += [{"kind": "mem", "rank": i, "pid": r["pid"], "name": r["name"], "cpu": cpud.get(r["pid"], 0),
                  "mem_mb": r["mem_mb"]} for i, r in enumerate(getattr(self, "mem_top", [])[:5])]
        self.db.add_procs(ts, rows)
        self.cpu_acc.clear()

    def check_thresholds(self, m):
        dt = config.SAMPLE_INTERVAL
        for key, val, lim, secs, title in (
                ("cpu", m["cpu"], config.CPU_ALERT_PCT, config.CPU_ALERT_SECS, "CPU 사용률 높음"),
                ("mem", m["mem"], config.MEM_ALERT_PCT, config.MEM_ALERT_SECS, "메모리 부족"),
                ("commit", m["commit_pct"], config.COMMIT_ALERT_PCT, config.MEM_ALERT_SECS, "가상 메모리(커밋) 부족")):
            self.high[key] = self.high[key] + dt if val >= lim else 0
            if self.high[key] >= secs:
                top = (self.top_now if key == "cpu" else getattr(self, "mem_top", []))[:3]
                who = ", ".join(f"{t['name']}({t['cpu']:.0f}%)" if key == "cpu" else f"{t['name']}({t['mem_mb']:.0f}MB)"
                                for t in top)
                self.alert(f"thr:{key}", "warn", title, f"{val:.0f}% 상태가 {self.high[key]}초 지속. 상위: {who}")
                self.db.add_event(m["ts"], "resource", "warn", "pcmon", 0, f"{title} {val:.0f}%", {"상위": who})
                self.high[key] = -config.ALERT_COOLDOWN_SECS  # 바로 다시 기록하지 않도록

    def _arm_watchdog(self):
        """수집이 2분 넘게 멈추면 모든 스레드의 실행 위치를 data/hang.txt 에 남긴다.
        (파이썬이 멈춰 있어도 동작하는 faulthandler 의 별도 감시 스레드 사용)"""
        import faulthandler
        try:
            if not hasattr(self, "_wd_file"):
                self._wd_file = open(os.path.join(config.DATA_DIR, "hang.txt"), "a", encoding="utf-8")
            faulthandler.dump_traceback_later(120, repeat=False, file=self._wd_file)
        except Exception:
            pass

    def run_sampler(self):
        self._arm_watchdog()
        psutil.cpu_percent(None)
        io0, net0, t0 = psutil.disk_io_counters(), psutil.net_io_counters(), time.time()
        last_tick = time.time()
        last_snap = 0
        last_disk = 0
        self.sample_processes()
        while not self.stop.wait(config.SAMPLE_INTERVAL - (time.time() - last_tick) % config.SAMPLE_INTERVAL):
            try:
                now = time.time()
                gap = now - last_tick
                if gap > config.STALL_SECS:
                    self.db.add_event(now, "stall", "warn", "pcmon", 0, f"수집 {gap:.0f}초 끊김 (응답 없음 또는 절전)",
                                      {"from": last_tick})
                last_tick = now
                self._arm_watchdog()
                vm = psutil.virtual_memory()
                pi = winutil.perf_info()
                io, net = psutil.disk_io_counters(), psutil.net_io_counters()
                dt = max(now - t0, 1)
                busy = 0.0
                if io and io0:
                    busy = min(100.0, ((io.read_time - io0.read_time) + (io.write_time - io0.write_time)) / (dt * 10))
                m = {
                    "ts": int(now), "cpu": psutil.cpu_percent(None), "mem": vm.percent,
                    "mem_used_mb": int((vm.total - vm.available) / 1048576), "commit_pct": round(pi["commit_pct"], 1),
                    "disk_busy": round(busy, 1),
                    "disk_r": round((io.read_bytes - io0.read_bytes) / dt / 1048576, 2) if io else 0,
                    "disk_w": round((io.write_bytes - io0.write_bytes) / dt / 1048576, 2) if io else 0,
                    "net_rx": round((net.bytes_recv - net0.bytes_recv) / dt / 1024, 1),
                    "net_tx": round((net.bytes_sent - net0.bytes_sent) / dt / 1024, 1),
                    "procs": pi["procs"], "handles": pi["handles"], "threads": pi["threads"],
                }
                io0, net0, t0 = io, net, now
                new_exes = self.sample_processes()
                try:  # PC 모니터 자신이 쓰는 자원 (정보 화면)
                    self.self_cpu = self.me.cpu_percent(None) / self.ncpu
                except Exception:
                    pass
                self.db.add_metric(m, int(now))
                self.latest = m
                self.check_thresholds(m)
                if new_exes:
                    self.new_exe_queue.extend(new_exes)
                if now - last_snap >= config.PROC_SNAPSHOT_INTERVAL:
                    last_snap = now
                    self.snapshot_top(int(now))
                if now - last_disk >= 600:
                    last_disk = now
                    free = psutil.disk_usage(config.SYSTEM_DRIVE).free / 1e9
                    self.latest_disk = free
                    if free < config.DISK_FREE_ALERT_GB:
                        self.alert("diskfree", "warn", f"{config.SYSTEM_DRIVE[:2]} 드라이브 공간 부족", f"남은 공간 {free:.1f}GB")
            except Exception:
                log.exception("sampler")

    def _loop(self, tasks, extra=None):
        """tasks = [(이름, 주기초, 함수)] 를 5초마다 확인해서 주기가 된 것만 실행."""
        while not self.stop.wait(5):
            now = time.time()
            for k, every, fn in tasks:
                if now - self._last.get(k, 0) >= every:
                    self._last[k] = now
                    try:
                        fn()
                    except Exception:
                        log.exception(k)
            if extra:
                extra()

    def run_background(self):
        """빠른 작업(이벤트 로그·네트워크·방화벽 기록·정리)과 느린 작업(PowerShell 점검)을
        두 스레드로 나눠, PC가 바빠 PowerShell이 늦어져도 감시가 멈추지 않게 한다."""
        self._last = {}

        def auto_trace():
            prev = (self.db.get("trace_scan") or {}).get("ts", 0)
            if time.time() - prev >= config.TRACE_SCAN_HOURS * 3600 and time.time() - self.started > 120:
                self.trace.start()

        def newproc():
            if self.new_exe_queue:
                batch, self.new_exe_queue = self.new_exe_queue[:], []
                try:
                    self.sec.check_new_processes(batch)
                except Exception:
                    log.exception("newproc")

        slow = [("fwinit", 300, lambda: self.fw.status != "ok" and self.fw.ensure_logging()),
                ("def", config.DEFENDER_INTERVAL, self._defender),
                ("persist", config.PERSISTENCE_INTERVAL, self.sec.check_persistence),
                ("trace", 600, auto_trace),
                ("wu", 1800, self.upd.refresh_wu)]
        fast = [("evt", config.EVENTLOG_INTERVAL, self.sec.poll_eventlogs),
                ("net", 30, self.sec.check_network),
                ("fw", 5, self.fw.poll),
                ("mpsample", 30, self.upd.sample),
                ("bank", 3, self.bank.tick),
                ("agg", 300, self.db.aggregate),
                ("clean", 3600, self.db.cleanup)]
        threading.Thread(target=self._loop, args=(slow, newproc), daemon=True).start()
        self._loop(fast)

    def _ensure_token(self):
        """대시보드 접근 열쇠. data 폴더 권한(설치한 사용자·관리자)으로 보호되므로
        다른 사용자(서버의 원격 접속 사용자 등)는 대시보드를 볼 수 없다."""
        import secrets
        try:
            with open(config.TOKEN_PATH, encoding="ascii") as f:
                self.token = f.read().strip()
        except OSError:
            self.token = ""
        if len(self.token) < 32:
            self.token = secrets.token_urlsafe(32)
            with open(config.TOKEN_PATH, "w", encoding="ascii") as f:
                f.write(self.token)

    def _defender(self):
        if self.sec.check_defender() is False:
            # Defender가 재시작 중이면 응답이 없다 → 2분 뒤 다시 시도
            self._last["def"] = time.time() - config.DEFENDER_INTERVAL + 120
        self.sec.check_firewall_profiles()
        self.sec.check_audit()

    def main(self):
        log.info("시작 (관리자=%s)", winutil.is_admin())
        self.new_exe_queue = []
        self.latest_disk = psutil.disk_usage(config.SYSTEM_DRIVE).free / 1e9
        log.info("OS: %s", self.os)
        self._ensure_token()
        try:
            self.detect_incident()
        except Exception:
            log.exception("incident")
        import dashboard
        threading.Thread(target=dashboard.serve, args=(self,), daemon=True).start()
        threading.Thread(target=self.run_background, daemon=True).start()
        self.run_sampler()
        try:
            import faulthandler
            faulthandler.cancel_dump_traceback_later()
        except Exception:
            pass
        log.info("수집 중지됨")


URL = f"http://127.0.0.1:{config.HTTP_PORT}/"


def _monitor_up(timeout=5):
    import urllib.request
    try:
        with urllib.request.urlopen(URL + "api/ping", timeout=timeout) as r:
            return b"pcmon" in r.read()
    except Exception:
        return False


def _monitor_process_exists():
    """모니터 본체가 떠 있는지 (응답이 느려도). 관리자 프로세스의 뮤텍스는 일반 권한에서도 '있음'은 알 수 있다."""
    import ctypes
    h = ctypes.windll.kernel32.OpenMutexW(0x00100000, False, "Global\\pcmon_single_instance")  # SYNCHRONIZE
    if h:
        ctypes.windll.kernel32.CloseHandle(h)
        return True
    return ctypes.windll.kernel32.GetLastError() == 5  # 접근 거부 = 존재함


LOADING_HTML = """<!doctype html><meta charset="utf-8"><title>PC 모니터</title>
<style>body{font-family:'Segoe UI','Malgun Gothic',sans-serif;background:#f6f7f9;color:#1d2330;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
@media(prefers-color-scheme:dark){body{background:#0f1218;color:#e6e9ef}}.b{text-align:center;max-width:460px;padding:20px}
.s{width:36px;height:36px;border:4px solid #8884;border-top-color:#2f6fde;border-radius:50%;animation:r 1s linear infinite;margin:0 auto 16px}
@keyframes r{to{transform:rotate(360deg)}}.m{color:#667085;font-size:13px;line-height:1.6}</style>
<div class="b"><div class="s"></div><h3 style="margin:0 0 8px">PC 모니터를 시작하는 중…</h3>
<div class="m" id="m">준비되면 자동으로 화면이 열립니다.</div></div>
<script>
const go="__URL__",t0=Date.now();
function tick(){fetch("__PING__",{mode:"no-cors",cache:"no-store"}).then(()=>location.replace(go)).catch(()=>{
 const s=Math.round((Date.now()-t0)/1000),m=document.getElementById("m");
 if(s>20)m.innerHTML="PC가 바빠서 시간이 걸리고 있습니다 ("+s+"초).<br>백신 전체 검사·업데이트 설치 중이면 몇 분 걸릴 수 있습니다.";
 if(s>600)m.innerHTML+="<br><br>10분이 지나도 열리지 않으면 PC를 다시 시작하거나<br>C:\\\\ProgramData\\\\PCMonitor\\\\pcmon.log 를 확인해 주세요.";
 setTimeout(tick,2000)})}
tick();
</script>"""


def open_app_window(wait_page=False):
    """주소창 없는 독립 앱 창으로 대시보드를 연다 (Edge/Chrome 앱 모드, 없으면 기본 브라우저).
    wait_page=True 이면 '시작 중' 화면을 먼저 띄우고, 모니터가 준비되면 자동으로 넘어간다."""
    import subprocess
    import webbrowser
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    la = os.environ.get("LOCALAPPDATA", "")
    cands = [os.path.join(pf86, r"Microsoft\Edge\Application\msedge.exe"), os.path.join(pf, r"Microsoft\Edge\Application\msedge.exe"),
             os.path.join(pf, r"Google\Chrome\Application\chrome.exe"), os.path.join(pf86, r"Google\Chrome\Application\chrome.exe"),
             os.path.join(la, r"Google\Chrome\Application\chrome.exe")]
    try:  # 접근 열쇠 (설치한 사용자·관리자만 읽을 수 있음)
        with open(config.TOKEN_PATH, encoding="ascii") as f:
            url = URL + "?t=" + f.read().strip()
    except OSError:
        url = URL
    base = os.path.join(la or os.environ.get("TEMP", "."), "PCMonitor")
    profile = os.path.join(base, "appwindow")  # 평소 브라우저와 분리된 전용 프로필
    if wait_page:
        os.makedirs(base, exist_ok=True)
        page = os.path.join(base, "loading.html")  # 본인 사용자 폴더 (다른 사용자는 못 읽음)
        with open(page, "w", encoding="utf-8") as f:
            f.write(LOADING_HTML.replace("__URL__", url).replace("__PING__", URL + "api/ping"))
        url = "file:///" + page.replace("\\", "/")
    for c in cands:
        if c and os.path.exists(c):
            subprocess.Popen([c, f"--app={url}", f"--user-data-dir={profile}", "--window-size=1320,900",
                              "--no-first-run", "--no-default-browser-check", "--disable-sync"],
                             creationflags=winutil.CREATE_NO_WINDOW)
            return
    webbrowser.open(url)


def launcher():
    """사용자가 실행했을 때 (기다리지 않고 바로 창을 띄움):
    - 모니터가 응답하면 → 대시보드 창
    - 모니터가 떠 있지만 느리면 → '시작 중' 창 (준비되면 자동 전환)
    - 모니터가 없으면 → 자동실행 작업(관리자)을 깨우고 '시작 중' 창
    - 자동실행 작업도 없으면 False → 이 프로세스가 직접 모니터 실행"""
    import subprocess
    if _monitor_up(timeout=3):
        open_app_window()
        return True
    if not _monitor_process_exists():
        r = subprocess.run(["schtasks", "/run", "/tn", "PCMonitor"], capture_output=True, creationflags=winutil.CREATE_NO_WINDOW)
        if r.returncode != 0:
            return False
    open_app_window(wait_page=True)
    return True


def _single_instance():
    import ctypes
    h = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\pcmon_single_instance")
    if ctypes.windll.kernel32.GetLastError() in (183, 5):  # 이미 실행 중
        sys.exit(0)
    return h


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    # 관리자 권한(자동 실행 작업) 또는 --background → 모니터 본체
    # 일반 실행(더블클릭/바로가기) → 앱 창 띄우기
    if not winutil.is_admin() and "--background" not in sys.argv:
        if launcher():
            sys.exit(0)
        # 자동 실행 작업이 없으면 이 프로세스가 직접 모니터 실행 (일부 보안 기록은 못 읽음)
        open_app_window(wait_page=True)
    _mutex = _single_instance()
    try:
        Monitor().main()
    except Exception:
        log.error("치명적 오류\n%s", traceback.format_exc())
        raise
