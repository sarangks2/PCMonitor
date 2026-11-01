"""보안/장애 감시: 이벤트 로그, 자동실행 변경, 열린 포트, 외부 접속, 의심 실행파일, Defender 상태."""
import ipaddress
import logging
import os
import re
import time
import winreg

import psutil

import config
import winutil

log = logging.getLogger("pcmon.security")

ADMIN_SID = "S-1-5-32-544"
LOGON_TYPES = {"2": "콘솔", "3": "네트워크", "4": "배치", "5": "서비스", "7": "잠금 해제", "8": "평문 네트워크",
               "9": "새 자격증명", "10": "원격 데스크톱", "11": "캐시된 로그인"}

# (채널, 이벤트ID 목록) - 읽을 대상
CHANNELS = {
    "System": [41, 6008, 1001, 7045, 104, 17, 18, 19, 47, 7031, 7034, 4101, 14, 7, 51, 153],
    "Security": [4625, 4624, 4720, 4722, 4724, 4732, 4728, 4740, 1102],
    "Application": [1000, 1002],
    "Microsoft-Windows-Windows Defender/Operational":
        [1006, 1015, 1116, 1117, 1118, 1119, 2001, 2003, 5001, 5007, 5010, 5012],
    "Microsoft-Windows-PowerShell/Operational": [4104],
}


# 악성 스크립트에서 흔한 패턴 (소문자). 정상 관리 스크립트에는 거의 안 나온다.
PS_ATTACK_PATTERNS = [
    "downloadstring(", "downloadfile(", "downloaddata(", "net.webclient", "start-bitstransfer",
    "invoke-mimikatz", "invoke-shellcode", "invoke-reflectivepeinjection", "amsiutils", "amsiinitfailed",
    "virtualalloc", "createremotethread", "writeprocessmemory", "reflection.assembly]::load(",
    "add-mppreference -exclusion", "set-mppreference -disable",
    "-encodedcommand", "frombase64string(", "iex(", "iex (", "invoke-expression",
    "certutil -urlcache", "bitsadmin /transfer", "vssadmin delete shadows", "wevtutil cl",
    "new-object net.sockets.tcpclient", "system.net.sockets.tcpclient",
]
# 이 PC에서 정상적으로 쓰는 것 (pcmon 자신, Claude Code 셸, Windows 내장 모듈)
PS_BENIGN_MARKERS = ["toastnotificationmanager", "get-authenticodesignature", "function write-result",
                     "__cmdletization", "microsoft.powershell.core\\set-strictmode",
                     "$psdefaultparametervalues['out-file:encoding'] = 'utf8'"]  # Claude Code 셸 도구


def _is_external(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast)
    except ValueError:
        return False


def _is_loopback(ip):
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return False


def _is_local(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        return a.is_loopback or a.is_unspecified
    except ValueError:
        return ip in ("", "-")


class SecurityMonitor:
    def __init__(self, db, alert):
        self.db = db
        self.alert = alert            # alert(key, severity, title, body)
        self.status = {"eventlog": {}, "defender": None, "firewall": None, "admin": winutil.is_admin(),
                       "audit": None}
        self.sig_cache = db.get("sig_cache", {})
        self.known_inbound = set()

    # ====================================================== 이벤트 로그
    def poll_eventlogs(self):
        first_run = self.db.get("evt_bookmarks") is None
        marks = self.db.get("evt_bookmarks", {})
        for ch, ids in CHANNELS.items():
            idq = " or ".join(f"EventID={i}" for i in ids)
            last = marks.get(ch)
            if last is None:
                # 처음에는 최근 7일만 훑는다 (팝업 없이 기록만)
                xp = f"*[System[({idq}) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"
            else:
                xp = f"*[System[({idq}) and EventRecordID > {last}]]"
            try:
                evs = winutil.query_events(ch, xp)
                self.status["eventlog"][ch] = "ok"
            except winutil.EventLogAccessDenied:
                self.status["eventlog"][ch] = "권한 없음 (관리자 권한 필요)"
                continue
            except Exception as e:
                self.status["eventlog"][ch] = f"오류: {e}"
                continue
            if evs:
                marks[ch] = max(e["record"] for e in evs)
            elif last is None:
                # 최근 7일 이벤트가 없으면 현재 최신 레코드를 기준점으로
                marks[ch] = self._latest_record(ch)
            quiet = last is None  # 첫 수집(과거분)은 팝업 생략
            self._handle(ch, evs, quiet)
        self.db.set("evt_bookmarks", marks)
        if first_run:
            log.info("이벤트 로그 기준점 설정 완료")

    def _latest_record(self, ch):
        try:
            h = winutil.query_events(ch, "*", max_events=1, reverse=True)
            return h[0]["record"] if h else 0
        except Exception:
            return 0

    def _handle(self, ch, evs, quiet):
        failed = {}
        for e in evs:
            try:
                if ch == "Security" and e["id"] == 4625:
                    d = e["data"]
                    k = (d.get("IpAddress", "-"), d.get("TargetUserName", "?"), LOGON_TYPES.get(d.get("LogonType"), d.get("LogonType")))
                    f = failed.setdefault(k, [0, e["ts"]])
                    f[0] += 1
                    continue
                self._one(ch, e, quiet)
            except Exception:
                log.exception("이벤트 처리 실패 %s %s", ch, e.get("id"))
        # 로그인 실패는 묶어서 기록
        total = sum(v[0] for v in failed.values())
        for (ip, user, lt), (n, ts) in failed.items():
            ext = _is_external(ip)
            self.db.add_event(ts, "security", "crit" if ext or n >= config.FAILED_LOGON_ALERT else "warn",
                              "Security", 4625, f"로그인 실패 {n}회: 계정 {user}",
                              {"IP": ip, "계정": user, "방식": lt, "외부IP": ext})
            if not quiet and (ext or total >= config.FAILED_LOGON_ALERT):
                self.alert(f"logonfail:{ip}", "crit", "로그인 실패 반복 감지",
                           f"{ip} 에서 계정 '{user}' 로그인 실패 {n}회 ({lt})")

    def _one(self, ch, e, quiet):
        i, d, ts = e["id"], e["data"], e["ts"]
        add = self.db.add_event

        def alert(key, sev, title, body):
            if not quiet:
                self.alert(key, sev, title, body)

        if ch == "System":
            if i == 41:
                bc = int(d.get("BugcheckCode", "0") or 0)
                pb = d.get("PowerButtonTimestamp", "0") not in ("0", "")
                why = f"블루스크린 0x{bc:X}" if bc else ("전원 버튼 강제 종료" if pb else "갑작스런 전원 차단")
                add(ts, "crash", "crit", "Kernel-Power", 41, f"비정상 종료 ({why})", d)
            elif i == 6008:
                add(ts, "crash", "warn", "EventLog", 6008, "예기치 않은 종료 기록", d)
            elif i == 1001:
                add(ts, "crash", "crit", e["provider"], 1001, "블루스크린 보고서", d)
            elif i in (17, 18, 19, 47) and "WHEA" in e["provider"]:
                add(ts, "hardware", "crit" if i == 18 else "warn", "WHEA", i, "하드웨어 오류 보고 (CPU/메모리/PCIe)", d)
                alert(f"whea:{i}", "crit", "하드웨어 오류 감지", f"WHEA 이벤트 {i} - CPU/메모리/메인보드 점검 필요")
            elif i == 7045:
                name, path = d.get("ServiceName", "?"), d.get("ImagePath", "")
                add(ts, "persistence", "warn", "Service Control Manager", 7045, f"새 서비스 설치: {name}", d)
                alert(f"svc:{name}", "warn", "새 서비스가 설치됨", f"{name}\n{path}")
            elif i == 104:
                add(ts, "security", "crit", "EventLog", 104, "시스템 로그가 지워짐", d)
                alert("logclear:sys", "crit", "이벤트 로그 삭제 감지", "시스템 로그가 지워졌습니다. 흔적 지우기일 수 있습니다.")
            elif i in (7031, 7034):
                add(ts, "system", "info", "Service Control Manager", i, f"서비스 비정상 종료: {d.get('param1', '')}", d)
            elif i in (7, 51, 153) and any(x in e["provider"].lower() for x in ("disk", "stor", "ntfs", "nvme")):
                add(ts, "hardware", "warn", e["provider"], i, "디스크 입출력 오류", d)
                alert(f"disk:{i}", "warn", "디스크 오류 감지", f"이벤트 {i} ({e['provider']}) - 디스크 상태 점검 필요")
            elif i in (4101, 14) and ("nvlddmkm" in e["provider"] or "Display" in e["provider"]):
                add(ts, "crash", "warn", e["provider"], i, "그래픽 드라이버 오류/복구", d)

        elif ch == "Security":
            if i == 4624:
                lt = d.get("LogonType")
                ip = d.get("IpAddress", "-")
                if lt in ("3", "10") and not _is_local(ip) and not d.get("TargetUserName", "").endswith("$"):
                    ext = _is_external(ip)
                    add(ts, "security", "crit" if ext or lt == "10" else "warn", "Security", 4624,
                        f"원격 로그인 성공: {d.get('TargetUserName')} ({LOGON_TYPES.get(lt)})", d)
                    alert(f"logon:{ip}", "crit" if ext else "warn", "원격 로그인 성공",
                          f"{ip} 에서 '{d.get('TargetUserName')}' 로그인 ({LOGON_TYPES.get(lt)})")
            elif i == 4720:
                add(ts, "security", "crit", "Security", i, f"새 사용자 계정 생성: {d.get('TargetUserName')}", d)
                alert(f"user:{d.get('TargetUserName')}", "crit", "새 사용자 계정 생성", d.get("TargetUserName", ""))
            elif i in (4732, 4728):
                admin = d.get("TargetSid") == ADMIN_SID
                add(ts, "security", "crit" if admin else "warn", "Security", i,
                    f"그룹에 계정 추가: {d.get('TargetUserName')} ← {d.get('MemberName') or d.get('MemberSid')}", d)
                if admin:
                    alert("admingrp", "crit", "관리자 그룹에 계정 추가됨", str(d.get("MemberName") or d.get("MemberSid")))
            elif i in (4722, 4724):
                add(ts, "security", "warn", "Security", i,
                    ("계정 활성화: " if i == 4722 else "비밀번호 재설정: ") + d.get("TargetUserName", ""), d)
            elif i == 4740:
                add(ts, "security", "crit", "Security", i, f"계정 잠김(로그인 실패 누적): {d.get('TargetUserName')}", d)
                alert("lockout", "crit", "계정 잠김", f"{d.get('TargetUserName')} - 로그인 실패가 누적되었습니다")
            elif i == 1102:
                add(ts, "security", "crit", "Security", i, "보안 로그가 지워짐", d)
                alert("logclear:sec", "crit", "보안 로그 삭제 감지", "보안 로그가 지워졌습니다. 흔적 지우기일 수 있습니다.")

        elif ch == "Application":
            app = d.get("p0") or d.get("AppName") or "?"
            add(ts, "app", "info", e["provider"], i, ("앱 충돌: " if i == 1000 else "앱 응답 없음: ") + app, d)

        elif ch.startswith("Microsoft-Windows-Windows Defender"):
            name = d.get("Threat Name") or d.get("Threat name") or ""
            path = d.get("Path", "")
            if i in (1006, 1015, 1116):
                add(ts, "defender", "crit", "Defender", i, f"악성코드 탐지: {name}", d)
                alert(f"threat:{name}:{path}", "crit", "악성코드 탐지", f"{name}\n{path}")
            elif i == 1117:
                add(ts, "defender", "warn", "Defender", i, f"악성코드 조치 완료: {name} ({d.get('Action Name', '')})", d)
            elif i in (1118, 1119):
                add(ts, "defender", "crit", "Defender", i, f"악성코드 조치 실패: {name}", d)
                alert(f"threatfail:{name}", "crit", "악성코드 조치 실패", f"{name}\n{path}")
            elif i in (5001, 5010, 5012):
                add(ts, "defender", "crit", "Defender", i, "Defender 보호 기능이 꺼짐", d)
                alert(f"defoff:{i}", "crit", "Defender 보호 꺼짐", "실시간 보호/검사 기능이 비활성화되었습니다")
            elif i in (2001, 2003):
                add(ts, "defender", "warn", "Defender", i, "바이러스 정의 업데이트 실패", d)
            elif i == 5007:
                nv = d.get("New Value", "")
                if "Exclusions" in nv:
                    add(ts, "defender", "crit", "Defender", i, "Defender 검사 예외 추가/변경", d)
                    alert("defexcl", "crit", "Defender 예외 설정 변경", nv[:200])

        elif ch.startswith("Microsoft-Windows-PowerShell") and i == 4104 and e["level"] == 3:
            # 레벨 3(경고) 4104 = PowerShell이 '의심 키워드'를 본 스크립트. 내장 모듈도 자주 걸리므로
            # 실제 공격 패턴이 있을 때만 경고한다.
            full = d.get("ScriptBlockText", "")
            low = full.lower()
            hits = [k for k in PS_ATTACK_PATTERNS if k in low]
            if re.search(r"-disable\w+\s+(\$true|1)\b", low):
                hits.append("Defender 기능 끄기")
            if not hits or any(b in low for b in PS_BENIGN_MARKERS):
                return
            add(ts, "security", "crit", "PowerShell", i, "위험한 PowerShell 스크립트 실행: " + ", ".join(hits[:3]),
                {"script": full[:1500], "path": d.get("Path", "")})
            alert("ps4104", "crit", "위험한 PowerShell 실행", ", ".join(hits[:3]) + "\n" + full[:120])

    # ====================================================== 자동실행(지속성) 변경
    def _snapshot_persistence(self):
        snap = {}
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        for hive, path in run_keys:
            try:
                with winreg.OpenKey(hive, path) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        snap[f"run:{'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{path}\\{name}"] = str(val)
                        i += 1
            except OSError:
                pass
        for folder in (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                       os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp")):
            try:
                for f in os.listdir(folder):
                    if f.lower() != "desktop.ini":
                        snap[f"startup:{folder}\\{f}"] = ""
            except OSError:
                pass
        try:
            for s in psutil.win_service_iter():
                try:
                    snap[f"service:{s.name()}"] = s.binpath()
                except Exception:
                    snap[f"service:{s.name()}"] = ""
        except Exception:
            pass
        tasks_root = os.path.expandvars(r"%SystemRoot%\System32\Tasks")
        for root, _dirs, files in os.walk(tasks_root):
            for f in files:
                snap["task:" + os.path.relpath(os.path.join(root, f), tasks_root)] = ""
        return snap

    def check_persistence(self):
        # 관리자 권한이 없으면 시스템 예약 작업·서비스 일부가 안 보여서 '제거/추가' 오탐이 난다 → 건너뜀
        if not winutil.is_admin():
            return
        snap = self._snapshot_persistence()
        base = self.db.get("persist_baseline")
        if base is None:
            self.db.set("persist_baseline", snap)
            log.info("자동실행 기준선 저장: %d개", len(snap))
            return
        added = [k for k in snap if k not in base]
        removed = [k for k in base if k not in snap]
        if len(added) > 20 or len(removed) > 20:
            # 한꺼번에 대량 변경 = 권한/환경 변화(또는 대형 업데이트). 개별 팝업 대신 기준선만 갱신
            self.db.add_event(time.time(), "persistence", "info", "pcmon", 0,
                              f"자동실행 기준 목록 갱신 (추가 {len(added)} · 제거 {len(removed)})", {"예시": (added + removed)[:10]})
            self.db.set("persist_baseline", snap)
            return
        kinds = {"run": "레지스트리 자동실행", "startup": "시작프로그램 폴더", "service": "서비스", "task": "예약 작업"}
        now = time.time()
        for k, v in snap.items():
            kind, name = k.split(":", 1)
            if k not in base:
                # Windows 기본 예약 작업(업데이트 때 자주 생김)은 기록만, 팝업은 생략.
                # 악성 작업이 이 폴더에 숨는 경우는 '흔적 점검'이 실행 파일 위치·서명으로 따로 잡는다.
                ms_task = kind == "task" and name.lower().startswith("microsoft\\windows\\")
                self.db.add_event(now, "persistence", "info" if ms_task else "warn", "pcmon", 0, f"새 {kinds[kind]}: {name}", {"값": v})
                if not ms_task:
                    self.alert(f"persist:{k}", "warn", f"새 {kinds[kind]} 추가됨", f"{name}\n{v}"[:250])
            elif base[k] != v and kind in ("run", "service"):
                self.db.add_event(now, "persistence", "warn", "pcmon", 0, f"{kinds[kind]} 경로 변경: {name}",
                                  {"이전": base[k], "현재": v})
                self.alert(f"persistchg:{k}", "warn", f"{kinds[kind]} 경로 변경", f"{name}\n{v}"[:250])
        for k in base:
            if k not in snap:
                kind, name = k.split(":", 1)
                self.db.add_event(now, "persistence", "info", "pcmon", 0, f"{kinds[kind]} 제거: {name}", "")
        self.db.set("persist_baseline", snap)

    # ====================================================== 네트워크
    def check_network(self):
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return
        names = {}

        def pname(pid):
            if pid not in names:
                try:
                    names[pid] = psutil.Process(pid).name()
                except Exception:
                    names[pid] = f"pid{pid}"
            return names[pid]

        listening = {}
        for c in conns:
            if c.status == psutil.CONN_LISTEN and c.laddr and not _is_loopback(c.laddr.ip):
                listening.setdefault(pname(c.pid), set()).add(c.laddr.port)
        known = self.db.get("listen_baseline")
        cur = {k: sorted(v) for k, v in listening.items()}
        if known is None:
            self.db.set("listen_baseline", cur)
        else:
            changed = False
            for proc, ports in cur.items():
                if proc not in known:
                    self.db.add_event(time.time(), "network", "warn", "pcmon", 0,
                                      f"새 프로그램이 외부 접속 대기 시작: {proc}", {"포트": ports})
                    self.alert(f"listen:{proc}", "warn", "새 포트 열림", f"{proc} 가 포트 {ports} 에서 접속 대기")
                    known[proc] = ports
                    changed = True
            if changed:
                self.db.set("listen_baseline", known)

        # 내 PC의 열린 포트로 외부(인터넷) IP가 접속해 온 경우
        lports = {p for ports in listening.values() for p in ports}
        for c in conns:
            if c.status == psutil.CONN_ESTABLISHED and c.raddr and c.laddr and c.laddr.port in lports:
                if _is_external(c.raddr.ip):
                    key = (c.raddr.ip, c.laddr.port)
                    if key not in self.known_inbound:
                        self.known_inbound.add(key)
                        self.db.add_event(time.time(), "network", "crit", "pcmon", 0,
                                          f"외부에서 내 PC로 접속: {c.raddr.ip} → 포트 {c.laddr.port}",
                                          {"프로세스": pname(c.pid)})
                        self.alert(f"inbound:{c.raddr.ip}", "crit", "외부에서 접속 감지",
                                   f"{c.raddr.ip} → 포트 {c.laddr.port} ({pname(c.pid)})")

    # ====================================================== 의심 위치 실행파일
    SUSPICIOUS_DIRS = [os.path.normcase(os.path.expandvars(p)) for p in (
        r"%TEMP%", r"%LOCALAPPDATA%\Temp", r"%USERPROFILE%\Downloads", r"%PUBLIC%", r"%APPDATA%",
        r"%LOCALAPPDATA%", r"%ProgramData%", r"%SystemRoot%\Temp")]

    def check_new_processes(self, new_exes):
        """새로 시작된 프로세스 중 사용자 쓰기 가능 폴더에서 실행된 서명 없는 파일을 경고."""
        todo = []
        for pid, name, exe in new_exes:
            if not exe:
                continue
            ne = os.path.normcase(exe)
            if not any(ne.startswith(d + os.sep) for d in self.SUSPICIOUS_DIRS):
                continue
            try:
                key = f"{exe}|{int(os.path.getmtime(exe))}"
            except OSError:
                continue
            if key in self.sig_cache:
                continue
            todo.append((key, exe, name, pid))
        if not todo:
            return
        res = winutil.signature_status([t[1] for t in todo[:20]])
        for key, exe, name, pid in todo[:20]:
            r = res.get(exe) or {"s": "Error", "n": ""}
            self.sig_cache[key] = r["s"]
            if r["s"] != "Valid":
                self.db.add_event(time.time(), "process", "crit", "pcmon", 0,
                                  f"서명 없는 프로그램 실행: {name}", {"경로": exe, "서명": r["s"], "pid": pid})
                self.alert(f"unsigned:{exe}", "crit", "서명 없는 프로그램 실행", f"{name}\n{exe}")
        if len(self.sig_cache) > 3000:
            self.sig_cache = dict(list(self.sig_cache.items())[-1500:])
        self.db.set("sig_cache", self.sig_cache)

    # ====================================================== Defender / 방화벽
    def check_defender(self):
        # Defender가 없는 서버/다른 백신을 쓰는 PC도 고려
        r = winutil.run_ps_json(
            "$ErrorActionPreference='SilentlyContinue';$o=@{};"
            "$s=Get-Service WinDefend;$o.svc=[string]$s.Status;"
            "try{$m=Get-MpComputerStatus -ErrorAction Stop;$o.rtp=[bool]$m.RealTimeProtectionEnabled;$o.av=[bool]$m.AntivirusEnabled;"
            "$o.sigdays=[int]$m.AntivirusSignatureAge;$o.sigdate=$m.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm');"
            "$o.quickscan=[int]$m.QuickScanAge;$o.mode=[string]$m.AMRunningMode}catch{$o.err=$_.Exception.Message};"
            "$o.other=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct|?{$_.displayName -notmatch 'Defender'}|%{$_.displayName});"
            "$o.fw=@(Get-NetFirewallProfile|%{@{n=$_.Name;e=[bool]$_.Enabled}});$o.fwsvc=[string](Get-Service mpssvc).Status;"
            "$o|ConvertTo-Json -Compress -Depth 3", timeout=180)
        if not r:
            return False
        if r.get("err") and r.get("svc") == "Running":
            return False  # Defender가 재시작/업데이트 중 → 잠시 후 다시
        other = [x for x in (r.get("other") or []) if x]
        d = {k: r.get(k) for k in ("rtp", "av", "sigdays", "sigdate", "quickscan", "mode")}
        d["installed"] = bool(r.get("svc"))
        d["other"] = other
        # 다른 백신이 주 백신이면 Defender는 수동(Passive) 모드 → Defender 경고는 하지 않음
        d["passive"] = bool(other) or (r.get("mode") or "").lower() in ("passive mode", "edr block mode", "sxs passive mode")
        self.status["defender"] = d
        self.status["firewall"] = r.get("fw")
        self.status["fwsvc"] = r.get("fwsvc")
        if not d["installed"] or r.get("err"):
            if not other and not winutil.os_info()["server"]:
                self.alert("def:none", "crit", "백신이 동작하지 않음", "Windows 보안(Defender)도 다른 백신도 확인되지 않습니다")
            return True
        if d["passive"]:
            return True
        if not r.get("rtp") or not r.get("av"):
            self.alert("def:rtp", "crit", "Defender 실시간 보호 꺼짐", "바이러스 실시간 보호가 꺼져 있습니다")
        if (r.get("sigdays") or 0) > config.DEFENDER_SIG_MAX_DAYS:
            self.alert("def:sig", "warn", "바이러스 정의가 오래됨",
                       f"마지막 업데이트 {r.get('sigdate')} ({r.get('sigdays')}일 전)")
        return True

    def check_firewall_profiles(self):
        r = self.status.get("firewall") or []
        if self.status.get("fwsvc") and self.status["fwsvc"] != "Running":
            self.alert("fw:svc", "warn", "Windows 방화벽 서비스가 꺼져 있음", "다른 방화벽을 쓰는 게 아니라면 위험합니다")
            return
        for p in r:
            if not p.get("e"):
                self.alert(f"fw:{p.get('n')}", "crit", "방화벽 꺼짐", f"{p.get('n')} 프로필 방화벽이 꺼져 있습니다")

    def check_audit(self):
        """로그인 실패 감사가 켜져 있는지 확인 (관리자만 가능)."""
        if not self.status["admin"]:
            return
        out = winutil.run_ps("auditpol /get /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /r | ConvertFrom-Csv | "
                             "Select-Object -Expand 'Inclusion Setting'")
        self.status["audit"] = out or None
