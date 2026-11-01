"""침입 감시: 방화벽 차단 기록(접속 시도/포트 스캔), 실시간 연결 현황, 침입 흔적 점검."""
import ipaddress
import json
import logging
import os
import re
import threading
import time
from datetime import datetime

import psutil

import winutil

log = logging.getLogger("pcmon.intrusion")

SENSITIVE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB(파일공유)",
                   1433: "MSSQL", 3306: "MySQL", 3389: "원격 데스크톱", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}

# 원격 제어 프로그램 (프로세스/서비스 이름 소문자 일부)
REMOTE_TOOLS = {
    "teamviewer": "TeamViewer", "anydesk": "AnyDesk", "rustdesk": "RustDesk", "remoting_host": "Chrome 원격 데스크톱",
    "tvnserver": "TightVNC", "winvnc": "VNC", "vncserver": "VNC", "screenconnect": "ScreenConnect",
    "splashtop": "Splashtop", "srservice": "Splashtop", "radmin": "Radmin", "rserver3": "Radmin", "logmein": "LogMeIn",
    "ammyy": "Ammyy Admin", "supremo": "Supremo", "ultraviewer": "UltraViewer", "dwagent": "DWService",
    "meshagent": "MeshCentral", "zohoassist": "Zoho Assist", "remotecall": "RemoteCall", "anysupport": "AnySupport",
    "helpu": "HelpU", "parsec": "Parsec", "nomachine": "NoMachine", "nxserver": "NoMachine",
}
# '앱 제거' 목록에서 찾을 정확한 이름 (일반 단어로 찾으면 엉뚱한 프로그램이 걸릴 수 있음. 예: Chrome 브라우저)
UNINSTALL_HINT = {"Chrome 원격 데스크톱": "chrome remote desktop host", "DWService": "dwagent", "MeshCentral": "mesh agent",
                  "Splashtop": "splashtop streamer", "Radmin": "radmin server", "VNC": "vnc server", "Ammyy Admin": "ammyy"}
LOLBINS = ("mshta", "wscript", "cscript", "regsvr32", "certutil", "bitsadmin", "msbuild", "installutil")


def ip_kind(ip):
    """'ext' 인터넷 / 'lan' 내부망 / 'local' 내 PC·루프백 / 'mcast' 브로드캐스트·멀티캐스트."""
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "local"
    if a.is_loopback or a.is_unspecified:
        return "local"
    if a.is_multicast or (a.version == 4 and (str(a).endswith(".255"))):
        return "mcast"
    if a.is_private or a.is_link_local:
        return "lan"
    return "ext"


def finding_key(check, title):
    """'무시' 규칙용 키: 숫자는 바뀌어도 같은 항목으로 본다 (예: 'Defender 검사 예외 6개' = '… 7개')."""
    return f"{check}|{re.sub(r'[0-9][0-9,.:]*', '#', title or '')}"


def _loopback(ip):
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return False


_USERS_DIR = os.path.dirname(os.environ.get("PUBLIC", os.environ.get("SystemDrive", "C:") + "\\Users\\Public")).lower() + "\\"
_PROGRAMDATA = os.environ.get("ProgramData", os.environ.get("SystemDrive", "C:") + "\\ProgramData").lower() + "\\"
_WINTEMP = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Temp").lower() + "\\"


def user_writable(p):
    """일반 사용자가 파일을 써넣을 수 있는 위치 (악성코드가 주로 숨는 곳)."""
    p = (p or "").lower()
    return p.startswith(_USERS_DIR) or p.startswith(_PROGRAMDATA) or p.startswith(_WINTEMP) or "\\temp\\" in p


def exe_from_cmd(cmd):
    """명령줄에서 실행파일 경로만 추출."""
    if not cmd:
        return ""
    c = os.path.expandvars(cmd.strip())
    if c.startswith('"'):
        return c[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.(exe|com|bat|cmd|scr|dll))\b", c, re.I)
    return m.group(1) if m else c.split(" ")[0]


# ============================================================ 방화벽 차단 기록
class FirewallWatcher:
    """pfirewall.log 의 DROP(수신) 기록을 읽어 '나에게 들어오려던 접속 시도'를 집계."""

    def __init__(self, db, alert):
        self.db = db
        self.alert = alert
        self.path = os.path.expandvars(r"%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log")
        self.status = "확인 전"
        self.offset = None
        self.last_ts = db.get("fw_last_ts", 0)
        self.minute = {}       # (분, src) -> {n, ports, proto}
        self.lock = threading.Lock()

    def ensure_logging(self):
        """차단 기록이 꺼져 있으면 켠다 (관리자 필요)."""
        if not winutil.is_admin():
            self.status = "권한 없음 (관리자 권한 필요)"
            return
        r = winutil.run_ps_json("$o=@{svc=[string](Get-Service mpssvc).Status; p=@(Get-NetFirewallProfile | % { @{n=$_.Name; b=[string]$_.LogBlocked; f=$_.LogFileName} })}; $o | ConvertTo-Json -Compress -Depth 3",
                                timeout=180)
        if r is None:
            self.status = "확인 중 (PC가 바빠서 5분 뒤 다시 시도)"
            return
        if r.get("svc") and r["svc"] != "Running":
            self.status = "Windows 방화벽이 꺼져 있어 차단 기록 없음 (다른 방화벽 사용 중?)"
            return
        r = r.get("p") or []
        r = r if isinstance(r, list) else [r]
        if any(p.get("b") != "True" for p in r):
            winutil.run_ps("Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 4096")
            self.db.add_event(time.time(), "network", "info", "pcmon", 0, "방화벽 차단 기록 켬 (접속 시도 감시용)", "")
            log.info("방화벽 차단 기록 켬")
        for p in r:
            if p.get("f"):
                self.path = os.path.expandvars(p["f"])
                break
        self.status = "ok"

    def poll(self):
        if self.status != "ok":
            return
        try:
            size = os.path.getsize(self.path)
        except OSError:
            self.status_detail = "기록 파일 없음 (아직 차단된 접속 없음)"
            return
        if self.offset is None or size < self.offset:
            self.offset = 0  # 처음 또는 파일 교체됨 → 처음부터 (last_ts 로 중복 제거)
        if size == self.offset:
            self._flush()
            return
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read(size - self.offset)
        except OSError as e:
            self.status = f"읽기 실패: {e}"
            return
        cut = data.rfind(b"\n") + 1
        self.offset += cut
        quiet = self.last_ts == 0  # 처음 읽는 과거분은 팝업 없이
        for line in data[:cut].decode("ascii", "replace").splitlines():
            self._line(line, quiet)
        self._flush(force_old=True)

    def _line(self, line, quiet):
        if not line or line[0] == "#":
            return
        f = line.split()
        # date time action protocol src dst sport dport size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path [pid]
        if len(f) < 17 or f[2] != "DROP" or f[16] != "RECEIVE":
            return
        try:
            ts = datetime.strptime(f[0] + " " + f[1], "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            return
        if ts < self.last_ts:
            return
        proto, src, dst, sport, dport, flags = f[3], f[4], f[5], f[6], f[7], f[9]
        if ip_kind(dst) == "mcast" or ip_kind(src) in ("local", "mcast"):
            return
        # 실제 '접속 시도'만: TCP SYN, ICMP 에코 요청, 응답이 아닌 UDP
        if proto == "TCP":
            if flags != "S":
                return  # 이미 끊긴 연결의 늦은 응답 등
        elif proto == "UDP":
            if sport in ("53", "123", "443", "5353", "1900", "3702", "137", "138") or (dport.isdigit() and int(dport) >= 49152):
                return
        elif proto == "ICMP":
            if f[13] != "8":
                return
            dport = "ping"
        else:
            return
        self.last_ts = ts
        key = (int(ts) // 60 * 60, src)
        with self.lock:
            m = self.minute.setdefault(key, {"n": 0, "ports": set(), "proto": set(), "quiet": quiet})
            m["n"] += 1
            m["ports"].add(dport)
            m["proto"].add(proto)

    def _flush(self, force_old=False):
        now_min = int(time.time()) // 60 * 60
        with self.lock:
            done = [k for k in self.minute if k[0] < now_min]
            items = [(k, self.minute.pop(k)) for k in done]
        for (ts, src), m in items:
            kind = ip_kind(src)
            ports = sorted(m["ports"], key=lambda p: (not p.isdigit(), int(p) if p.isdigit() else 0))
            self.db.execute("INSERT INTO fw_drops(ts,src,n,ports,kind,proto) VALUES(?,?,?,?,?,?)",
                            (ts, src, m["n"], json.dumps(ports[:30]), kind, ",".join(sorted(m["proto"]))))
            nports = len([p for p in ports if p.isdigit()])
            sens = [f"{p}({SENSITIVE_PORTS[int(p)]})" for p in ports if p.isdigit() and int(p) in SENSITIVE_PORTS]
            if nports >= 10:
                title = f"포트 스캔 감지: {src} ({'인터넷' if kind == 'ext' else '내부망'})"
                self.db.add_event(ts, "intrusion", "crit", "Firewall", 0, title, {"포트 수": nports, "시도": m["n"], "포트": ports[:30]})
                if not m["quiet"]:
                    self.alert(f"scan:{src}", "crit", "포트 스캔 감지", f"{src} 가 1분 동안 포트 {nports}개를 두드림 (방화벽이 차단)")
            elif kind == "ext":
                self.db.add_event(ts, "intrusion", "crit", "Firewall", 0, f"인터넷에서 접속 시도 차단: {src}",
                                  {"포트": ports, "횟수": m["n"]})
                if not m["quiet"]:
                    self.alert(f"extdrop:{src}", "crit", "인터넷에서 접속 시도 (차단됨)",
                               f"{src} → 포트 {', '.join(ports[:5])} ({m['n']}회). 공유기 포트포워딩/DMZ 설정 확인 필요")
            elif sens and m["n"] >= 20:
                self.db.add_event(ts, "intrusion", "warn", "Firewall", 0, f"내부망 기기의 반복 접속 시도: {src}",
                                  {"포트": sens, "횟수": m["n"]})
                if not m["quiet"]:
                    self.alert(f"landrop:{src}", "warn", "내부망 기기가 반복 접속 시도",
                               f"{src} → {', '.join(sens)} {m['n']}회/분. 그 기기의 감염 여부 확인 필요")
        if items:
            self.db.set("fw_last_ts", self.last_ts)

    def pending(self):
        with self.lock:
            return [{"ts": k[0], "src": k[1], "n": m["n"], "ports": sorted(m["ports"]), "kind": ip_kind(k[1])}
                    for k, m in self.minute.items()]


# ============================================================ 실시간 현황
def live_snapshot(db, fw, sec_status, server=False):
    """server=True 이면 내부망 원격 접속·파일공유 연결은 업무상 정상으로 보고 '주의'로 올리지 않는다."""
    now = int(time.time())
    names = {}

    def pname(pid):
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name()
            except Exception:
                names[pid] = f"pid {pid}" if pid else "System"
        return names[pid]

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []
    listening, lports = [], set()
    for c in conns:
        if c.status == psutil.CONN_LISTEN and c.laddr and not _loopback(c.laddr.ip):
            lports.add(c.laddr.port)
            listening.append({"proc": pname(c.pid), "port": c.laddr.port, "addr": c.laddr.ip,
                              "svc": SENSITIVE_PORTS.get(c.laddr.port, "")})
    inbound, outbound = [], {}
    for c in conns:
        if not c.raddr or ip_kind(c.raddr.ip) == "local":
            continue
        kind = ip_kind(c.raddr.ip)
        if c.laddr and c.laddr.port in lports and c.status in (psutil.CONN_ESTABLISHED, "SYN_RECV"):
            inbound.append({"proc": pname(c.pid), "lport": c.laddr.port, "rip": c.raddr.ip, "rport": c.raddr.port,
                            "kind": kind, "state": c.status, "svc": SENSITIVE_PORTS.get(c.laddr.port, "")})
        elif c.status == psutil.CONN_ESTABLISHED and kind == "ext":
            o = outbound.setdefault(c.pid, {"proc": pname(c.pid), "pid": c.pid, "n": 0, "ips": set()})
            o["n"] += 1
            o["ips"].add(f"{c.raddr.ip}:{c.raddr.port}")
    outbound = sorted(({**o, "ips": sorted(o["ips"])[:6]} for o in outbound.values()), key=lambda o: -o["n"])

    sessions = []
    try:
        for u in psutil.users():
            sessions.append({"name": u.name, "host": u.host or "", "started": u.started, "remote": bool(u.host)})
    except Exception:
        pass

    # 방화벽 차단 시도
    fw_rows = db.query("SELECT ts,src,n,ports,kind FROM fw_drops WHERE ts>=? ORDER BY ts", (now - 86400,))
    fw_rows += fw.pending()
    by_src = {}
    for r in fw_rows:
        s = by_src.setdefault(r["src"], {"src": r["src"], "kind": r["kind"], "n": 0, "ports": set(), "last": 0, "n1h": 0})
        s["n"] += r["n"]
        s["n1h"] += r["n"] if r["ts"] >= now - 3600 else 0
        s["last"] = max(s["last"], r["ts"])
        ports = r["ports"] if isinstance(r["ports"], list) else json.loads(r["ports"] or "[]")
        s["ports"].update(ports)
    fw_src = sorted(({**s, "ports": sorted(s["ports"], key=lambda p: (not str(p).isdigit(), int(p) if str(p).isdigit() else 0))[:12],
                      "nports": len(s["ports"])} for s in by_src.values()), key=lambda s: -s["last"])[:50]
    series = {}
    for r in fw_rows:
        b = r["ts"] // 600 * 600
        series[b] = series.get(b, 0) + r["n"]
    fw_series = [{"ts": t, "n": series.get(t, 0)} for t in range((now - 86400) // 600 * 600, now + 1, 600)]

    # 로그인 기록 (이벤트 테이블에서)
    failed = db.query("SELECT ts,title,detail FROM events WHERE event_id=4625 AND ts>=? ORDER BY ts DESC LIMIT 100", (now - 86400,))
    fl = {}
    for r in failed:
        try:
            d = json.loads(r["detail"])
        except Exception:
            d = {}
        k = (d.get("IP", "-"), d.get("계정", "?"))
        n = int(re.search(r"(\d+)회", r["title"]).group(1)) if re.search(r"(\d+)회", r["title"]) else 1
        e = fl.setdefault(k, {"ip": k[0], "user": k[1], "n": 0, "last": r["ts"], "how": d.get("방식", ""), "kind": ip_kind(k[0]) if k[0] not in ("-", "") else "local"})
        e["n"] += n
    remote_ok = db.query("SELECT ts,title,detail FROM events WHERE event_id=4624 AND ts>=? ORDER BY ts DESC LIMIT 50", (now - 7 * 86400,))
    remote_ok = [{"ts": r["ts"], "title": r["title"], "ip": (json.loads(r["detail"]) if r["detail"].startswith("{") else {}).get("IpAddress", "")}
                 for r in remote_ok]
    intr_events = db.query("SELECT ts,severity,title FROM events WHERE category='intrusion' AND ts>=? ORDER BY ts DESC LIMIT 30", (now - 86400,))

    # 원격 제어 프로그램 실행 중?
    tools = set()
    for p in psutil.process_iter(["name"]):
        n = (p.info["name"] or "").lower()
        for k, label in REMOTE_TOOLS.items():
            if k in n:
                tools.add(label)

    # 판정
    crit, warn = [], []
    ext_in = [i for i in inbound if i["kind"] == "ext"]
    if ext_in:
        crit.append(f"인터넷에서 내 PC로 연결됨: " + ", ".join(f"{i['rip']}→{i['lport']}" for i in ext_in[:3]))
    if any(s["remote"] and ip_kind(s["host"]) == "ext" for s in sessions):
        crit.append("인터넷에서 원격 접속한 세션이 있음")
    if any(s["kind"] == "ext" and s["n1h"] for s in fw_src):
        crit.append("최근 1시간 인터넷에서 접속 시도 (방화벽이 차단함)")
    if any(s["nports"] >= 10 and s["last"] >= now - 3600 for s in fw_src):
        crit.append("최근 1시간 포트 스캔 감지")
    if any(e["kind"] == "ext" for e in fl.values()):
        crit.append("인터넷 IP의 로그인 실패 기록")
    if any(r["ip"] and ip_kind(r["ip"]) == "ext" and r["ts"] >= now - 86400 for r in remote_ok):
        crit.append("24시간 내 인터넷에서 원격 로그인 성공")
    if fl:
        warn.append(f"24시간 로그인 실패 {sum(e['n'] for e in fl.values())}회")
    if not server and [i for i in inbound if i["kind"] == "lan" and i["svc"]]:
        warn.append("내부망 기기가 " + ", ".join(sorted({i['svc'] for i in inbound if i['kind'] == 'lan' and i['svc']})) + " 로 연결 중")
    if any(s["remote"] for s in sessions) and not server:
        warn.append("원격 접속 세션 있음")
    if tools:
        warn.append("원격 제어 프로그램 실행 중: " + ", ".join(sorted(tools)))
    if any(s["kind"] == "lan" and s["n1h"] >= 20 for s in fw_src):
        warn.append("최근 1시간 내부망 기기의 반복 접속 시도")
    level = "crit" if crit else "warn" if warn else "ok"

    return {
        "now": now, "level": level, "reasons": crit + warn,
        "inbound": inbound, "outbound": outbound[:15], "listening": sorted(listening, key=lambda x: x["port"]),
        "sessions": sessions, "remote_tools": sorted(tools),
        "fw": {"status": fw.status, "sources": fw_src, "series": fw_series,
               "total24h": sum(r["n"] for r in fw_rows), "total1h": sum(r["n"] for r in fw_rows if r["ts"] >= now - 3600)},
        "failed": sorted(fl.values(), key=lambda e: -e["last"]), "remote_ok": remote_ok,
        "events": intr_events, "seclog": (sec_status.get("eventlog") or {}).get("Security"), "server": bool(server),
    }


# ============================================================ 침입 흔적 점검
COLLECT_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$o=@{}
if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
  $o.users=@(Get-LocalUser | % { @{n=$_.Name;e=[bool]$_.Enabled;sid=$_.SID.Value;ll=$(if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd HH:mm')}else{''});pw=$(if($_.PasswordLastSet){$_.PasswordLastSet.ToString('yyyy-MM-dd')}else{''})} })
} else {
  $o.users=@(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | % { @{n=$_.Name;e=(-not $_.Disabled);sid=$_.SID;ll='';pw=''} })
}
try { $o.admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | % { @{n=$_.Name;t=[string]$_.ObjectClass} }) }
catch { $g=Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'"; $o.admins=@($g | Get-CimAssociatedInstance -Association Win32_GroupUser | % { @{n="$($_.Domain)\$($_.Name)";t=$_.CimClass.CimClassName} }) }
$o.server=((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)
$o.rdp=((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0)
$o.ra=((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Remote Assistance').fAllowToGetHelp -eq 1)
$o.svcs=@(Get-Service WinRM,sshd,RemoteRegistry,TlntSvr | % { @{n=$_.Name;s=[string]$_.Status;st=[string]$_.StartType} })
$o.shares=@(Get-SmbShare | ? { $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$|print\$)$' } | % { @{n=$_.Name;p=$_.Path} })
$o.smb1=[bool](Get-SmbServerConfiguration).EnableSMB1Protocol
$p=Get-MpPreference
$o.excl=@{path=@($p.ExclusionPath);proc=@($p.ExclusionProcess);ext=@($p.ExclusionExtension)}
$tn=@{}; Get-MpThreat | % { $tn[[string]$_.ThreatID]=$_.ThreatName }
$o.threats=@(Get-MpThreatDetection | % { @{t=$_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm');name=$tn[[string]$_.ThreatID];res=(@($_.Resources) -join '; ');ok=[bool]$_.ActionSuccess} })
$o.hosts=@(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | ? { $_ -match '^\s*[^#\s]' })
$is=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$o.proxy=@{en=[int]$is.ProxyEnable;srv=[string]$is.ProxyServer;pac=[string]$is.AutoConfigURL}
$o.wmi=@(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | % { @{n=$_.Name;c=$_.CimClass.CimClassName;cmd=[string]("$($_.CommandLineTemplate) $($_.ScriptFileName)")} })
$o.tasks=@(Get-ScheduledTask | ? { $_.State -ne 'Disabled' } | % { $t=$_; @($t.Actions) | ? { $_.Execute } | % { @{n=$t.TaskPath+$t.TaskName;tp=$t.TaskPath;tn=$t.TaskName;a=[string]$t.Author;x=[string]$_.Execute;g=[string]$_.Arguments} } })
$af=@{}; Get-NetFirewallApplicationFilter | % { $af[$_.InstanceID]=$_.Program }
$o.fwrules=@(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | % { @{n=$_.DisplayName;p=[string]$af[$_.InstanceID];prof=[string]$_.Profile} } | ? { $_.p -and $_.p -ne 'Any' -and $_.p -ne 'System' })
$o.ifeo=@(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | % { $q=Get-ItemProperty $_.PSPath; if($q.Debugger -or $q.VerifierDlls){ @{n=$_.PSChildName;d=[string]$q.Debugger;v=[string]$q.VerifierDlls} } })
$sp=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
$o.kms=@{host=[string]$sp.KeyManagementServiceName;port=[string]$sp.KeyManagementServicePort}
$o.access=@('sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe') | % { @{n=$_;s=[string](Get-AuthenticodeSignature "$env:SystemRoot\System32\$_").Status} }
$w=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$o.winlogon=@{shell=[string]$w.Shell;userinit=[string]$w.Userinit}
$o | ConvertTo-Json -Depth 5 -Compress
"""


class TraceScanner:
    def __init__(self, db, sec):
        self.db = db
        self.sec = sec
        self.running = False
        self.lock = threading.Lock()

    def start(self):
        with self.lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def result(self):
        r = self.db.get("trace_scan") or {}
        r["running"] = self.running
        r["admin"] = winutil.is_admin()
        return r

    def _run(self):
        t0 = time.time()
        try:
            findings = self.scan()
            crit = sum(1 for f in findings if f["sev"] == "crit")
            warn = sum(1 for f in findings if f["sev"] == "warn")
            self.db.set("trace_scan", {"ts": int(time.time()), "secs": round(time.time() - t0, 1),
                                       "findings": findings, "crit": crit, "warn": warn})
            # 점검 요약은 '정보'로만 기록 (점검 결과 자체가 위험 목록에 들어가므로 중복 집계 방지)
            self.db.add_event(time.time(), "intrusion", "info", "pcmon", 0,
                              f"침입 흔적 점검 완료: 위험 {crit}, 주의 {warn}", "")
            if crit:
                self.sec.alert("trace", "crit", "침입 흔적 점검: 위험 항목 발견", f"위험 {crit}건, 주의 {warn}건 - 앱에서 확인하세요")
        except Exception:
            log.exception("trace scan")
        finally:
            self.running = False

    # --------------------------------------------------------------
    def scan(self):
        F = []

        R = getattr(self.sec, "rem", None)  # 바로 정리 기능 (Monitor.rem)

        def add(check, sev, title, detail="", actions=None):
            F.append({"check": check, "sev": sev, "title": title, "detail": detail, "actions": (actions or []) if R else [],
                      "key": finding_key(check, title)})

        raw = winutil.run_ps_json(COLLECT_PS, timeout=240) or {}
        if not raw:
            add("수집", "warn", "시스템 정보 수집 실패 (관리자 권한 필요할 수 있음)")

        # 1. 계정
        users = raw.get("users") or []
        admins = raw.get("admins") or []
        enabled = [u for u in users if u.get("e")]
        guest = [u for u in enabled if u.get("sid", "").endswith("-501")]
        builtin_admin = [u for u in enabled if u.get("sid", "").endswith("-500")]
        if guest:
            add("계정", "crit", "Guest(손님) 계정이 켜져 있음", "누구나 로그인할 수 있는 상태입니다",
                R and [R.action_setting("guest_off", "Guest 끄기", "Guest(손님) 계정을 사용 안 함으로 바꿉니다.")])
        if builtin_admin:
            add("계정", "warn", "기본 Administrator 계정이 켜져 있음", "공격자가 가장 먼저 노리는 계정입니다")
        add("계정", "info", f"사용 중인 계정 {len(enabled)}개 · 관리자 {len(admins)}개",
            [f"{u['n']}  (마지막 로그인 {u.get('ll') or '-'}, 비밀번호 변경 {u.get('pw') or '-'})" for u in enabled]
            + ["관리자: " + ", ".join(a["n"] for a in admins)])

        # 2. 원격 접속 경로
        open_paths = []
        if raw.get("rdp"):
            open_paths.append("원격 데스크톱 켜짐")
        if raw.get("ra"):
            open_paths.append("원격 지원 허용")
        for s in raw.get("svcs") or []:
            if s.get("s") == "Running":
                open_paths.append(f"{ {'WinRM': '원격 관리(WinRM)', 'sshd': 'SSH 서버', 'RemoteRegistry': '원격 레지스트리', 'TlntSvr': 'Telnet'}.get(s['n'], s['n'])} 실행 중")
        tools = {}
        for p in psutil.process_iter(["name", "exe"]):
            n = (p.info["name"] or "").lower()
            for k, label in REMOTE_TOOLS.items():
                if k in n:
                    tools[label] = p.info.get("exe") or ""
        try:
            for s in psutil.win_service_iter():
                n = s.name().lower()
                for k, label in REMOTE_TOOLS.items():
                    if k in n and label not in tools:
                        tools[label] = s.binpath() if hasattr(s, "binpath") else ""
        except Exception:
            pass
        for label, where in tools.items():
            exe = exe_from_cmd(where) if where else ""
            acts = []
            if R:
                acts = R.action_uninstall(UNINSTALL_HINT.get(label, label.lower()), exe) or \
                    ((R.action_quarantine(exe) + R.action_delete(exe)) if exe and os.path.isfile(exe) else [])
            add("원격 제어", "warn", f"원격 제어 프로그램 발견: {label}",
                f"{where or label} — 직접 설치한 것이 아니라면 즉시 삭제하세요" + ("" if acts else " (자동 제거 방법을 찾지 못함: 앱 및 기능에서 제거)"), acts)
        if open_paths and raw.get("server"):
            add("원격 접속", "info", "원격 접속 기능 (서버 관리용이면 정상)", open_paths +
                ["※ 인터넷에 직접 노출되지 않았는지, 강한 암호·계정 잠금 정책이 있는지 확인하세요"])
        elif open_paths:
            acts = []
            if R and raw.get("ra"):
                acts.append(R.action_setting("remote_assist_off", "원격 지원 끄기", "원격 지원(다른 사람이 이 PC를 원격으로 도와주는 기능)을 끕니다."))
            if R and raw.get("rdp"):
                acts.append(R.action_setting("rdp_off", "원격 데스크톱 끄기", "원격 데스크톱 접속을 끕니다.\n이 PC에 원격으로 접속해서 쓰고 있다면 누르지 마세요."))
            add("원격 접속", "warn", "외부에서 들어올 수 있는 원격 접속 기능", open_paths, acts)
        elif not tools:
            add("원격 접속", "ok", "원격 데스크톱·원격 제어 프로그램 없음")

        # 3. 공유/SMB
        if raw.get("shares"):
            add("공유", "info" if raw.get("server") else "warn", f"공유 폴더 {len(raw['shares'])}개",
                [f"{s['n']} → {s['p']}" for s in raw["shares"]])
        if raw.get("smb1"):
            add("공유", "warn", "SMBv1(구형 파일공유) 켜짐", "랜섬웨어(WannaCry 등)가 쓰는 취약한 방식입니다",
                R and [R.action_setting("smb1_off", "SMBv1 끄기", "구형 파일공유(SMBv1)를 끕니다. 아주 오래된 NAS/복합기와 공유가 안 될 수 있습니다.")])
        if not raw.get("shares") and not raw.get("smb1"):
            add("공유", "ok", "공유 폴더 없음 · SMBv1 꺼짐")

        # 4. 백신 예외/탐지 이력
        ex = raw.get("excl") or {}
        exl = [x for k in ("path", "proc", "ext") for x in (ex.get(k) or []) if x and "N/A" not in str(x)]
        if exl:
            bad = [x for x in exl if user_writable(str(x)) or re.fullmatch(r"[a-z]:\\?", str(x), re.I)]
            add("백신", "crit" if bad else "warn", f"Defender 검사 예외 {len(exl)}개",
                [str(x) for x in exl] + (["※ 사용자 폴더/드라이브 전체 예외는 악성코드가 자주 쓰는 수법"] if bad else []),
                R and [R.action_setting("defender_excl_remove", f"예외 {len(exl)}개 모두 삭제", "Defender 검사 예외를 모두 지워서 이 위치들도 다시 검사하게 합니다.\n\n" + "\n".join(map(str, exl[:10])), items=[str(x) for x in exl])])
        th = raw.get("threats") or []
        if th:
            fails = [t for t in th if not t.get("ok")]
            add("백신", "crit" if fails else "warn", f"과거 악성코드 탐지 {len(th)}건" + (f" (조치 실패 {len(fails)}건)" if fails else " (모두 조치됨)"),
                [f"{t['t']}  {t.get('name') or '?'}  {t.get('res', '')[:150]}" for t in th[:15]])
        if not exl and not th:
            add("백신", "ok", "Defender 예외 없음 · 악성코드 탐지 이력 없음")

        # 5. 네트워크 변조 (hosts, 프록시)
        hosts = [h for h in (raw.get("hosts") or []) if not re.match(r"\s*(127\.0\.0\.1|::1)\s+localhost", h)]
        if hosts:
            add("네트워크 변조", "warn", f"hosts 파일에 항목 {len(hosts)}개 (사이트 주소 바꿔치기 가능)", hosts[:20])
        px = raw.get("proxy") or {}
        if px.get("en") or px.get("pac"):
            add("네트워크 변조", "warn", "프록시 설정됨 (인터넷 트래픽 가로채기 가능)", [px.get("srv") or "", px.get("pac") or ""])
        if not hosts and not (px.get("en") or px.get("pac")):
            add("네트워크 변조", "ok", "hosts 파일·프록시 정상")

        # 6. 숨은 자동실행 (WMI, Winlogon, 접근성 백도어)
        wmi = [w for w in (raw.get("wmi") or []) if w.get("c") != "NTEventLogEventConsumer" and w.get("n") != "SCM Event Log Consumer"]
        if wmi:
            add("숨은 자동실행", "crit", f"WMI 이벤트 구독 {len(wmi)}개 (파일 없는 악성코드가 쓰는 방식)",
                [f"{w['n']} [{w['c']}] {w.get('cmd', '')[:200]}" for w in wmi],
                R and [R.action_setting("wmi_remove", f"'{w['n']}' 삭제", f"WMI 이벤트 구독 '{w['n']}' 을 지웁니다.", name=w["n"]) for w in wmi[:5]])
        wl = raw.get("winlogon") or {}
        if wl and wl.get("shell", "explorer.exe").strip().lower() not in ("explorer.exe", "explorer.exe,"):
            add("숨은 자동실행", "crit", "Winlogon Shell 변조", wl.get("shell"))
        if wl and not re.fullmatch(r"([a-z]:\\windows\\system32\\)?userinit\.exe,?", (wl.get("userinit") or "userinit.exe").strip().lower()):
            add("숨은 자동실행", "crit", "Winlogon Userinit 변조", wl.get("userinit"))
        acc = {"sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe"}
        for i in raw.get("ifeo") or []:
            if i.get("d"):
                sev = "crit" if i["n"].lower() in acc else "warn"
                add("숨은 자동실행", sev, f"실행 가로채기(IFEO): {i['n']} → {i['d']}",
                    "로그인 화면 백도어(고정키/접근성 바꿔치기) 수법" if sev == "crit" else "다른 프로그램으로 대체 실행되도록 설정됨",
                    R and [R.action_setting("ifeo_remove", "가로채기 설정 삭제", f"{i['n']} 실행 가로채기 설정을 지웁니다.", exe=i["n"])])
            if i.get("v"):
                add("숨은 자동실행", "crit", f"DLL 주입(VerifierDlls): {i['n']} ← {i['v']}",
                    "프로그램이 켜질 때마다 이 DLL이 강제로 들어갑니다 (불법 인증 도구·악성코드 수법)",
                    R and [R.action_setting("ifeo_remove", "DLL 주입 설정 삭제", f"{i['n']} 의 DLL 주입 설정을 지웁니다.", exe=i["n"])])
        kms = raw.get("kms") or {}
        if kms.get("host"):
            add("불법 인증 흔적", "warn", f"KMS 인증 서버가 수동 지정됨: {kms['host']}:{kms.get('port') or 1688}",
                "회사 KMS 서버가 아니라면 불법 인증 도구(KMSAuto 등)의 흔적입니다",
                R and [R.action_setting("kms_clear", "KMS 설정 삭제", "수동으로 지정된 KMS 인증 서버 설정을 지웁니다.\n회사에서 쓰는 KMS 서버라면 누르지 마세요.")])
        for e in [x for k in ("path", "proc") for x in ((raw.get("excl") or {}).get(k) or [])]:
            if re.search(r"kms|aact|autopico|sppextcomobj|activat|crack|keygen", str(e), re.I):
                add("불법 인증 흔적", "crit", "백신 예외에 불법 인증 도구가 등록돼 있음", str(e))
                break
        for a in raw.get("access") or []:
            if a.get("s") != "Valid":
                add("숨은 자동실행", "crit", f"접근성 프로그램 {a['n']} 서명 이상 ({a.get('s')})", "로그인 화면 백도어 의심")
        if not any(f["check"] == "숨은 자동실행" for f in F):
            add("숨은 자동실행", "ok", "WMI 구독·Winlogon·로그인 화면 백도어 흔적 없음")

        # 7. 예약 작업 / 시작프로그램 / 서비스 / 방화벽 허용 규칙 → 사용자 폴더의 서명 없는 실행파일
        cands = {}   # path -> [설명]
        lol, lol_tasks = [], []
        for t in raw.get("tasks") or []:
            x = exe_from_cmd(t.get("x", ""))
            args = (t.get("g") or "").lower()
            base = os.path.basename(x).lower().replace(".exe", "")
            if base in LOLBINS or (base in ("powershell", "pwsh") and re.search(r"-(e|en|enc|encodedcommand)\s|hidden|downloadstring|iwr |invoke-webrequest", args)) \
                    or (base == "rundll32" and ("javascript:" in args or "http" in args)) or (base == "cmd" and "powershell" in args and "-e" in args):
                lol.append(f"{t['n']}: {t.get('x')} {t.get('g', '')[:160]}")
                lol_tasks.append(t)
            if user_writable(x):
                cands.setdefault(x, []).append(f"예약 작업 {t['n']}")
        for k, v in (self.db.get("persist_baseline") or {}).items():
            kind, name = k.split(":", 1)
            if kind in ("run", "service"):
                x = exe_from_cmd(v)
                if user_writable(x):
                    cands.setdefault(x, []).append(("시작프로그램 " if kind == "run" else "서비스 ") + name.split("\\")[-1])
            elif kind == "startup":
                if name.lower().endswith((".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".scr")):
                    lol.append(f"시작프로그램 폴더에 스크립트/실행파일 직접 있음: {name}")
        for r in raw.get("fwrules") or []:
            x = os.path.expandvars(r.get("p", ""))
            if user_writable(x):
                cands.setdefault(x, []).append(f"방화벽 허용 규칙 '{r['n']}'")
        procs_user = {}
        for p in psutil.process_iter(["pid", "name", "exe"]):
            x = p.info.get("exe") or ""
            if user_writable(x):
                procs_user.setdefault(x, []).append(p.info["pid"])
                cands.setdefault(x, []).append("실행 중")
        paths = [p for p in cands if os.path.exists(p)][:80]
        sigs = {}
        for i in range(0, len(paths), 20):
            sigs.update(winutil.signature_status(paths[i:i + 20]))
        unsigned = [(p, cands[p]) for p in paths if (sigs.get(p) or {}).get("s") not in ("Valid",)]
        # 서명 없는 프로그램의 외부 통신
        ext_comm = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == psutil.CONN_ESTABLISHED and c.raddr and ip_kind(c.raddr.ip) == "ext":
                    for p, pids in procs_user.items():
                        if c.pid in pids:
                            ext_comm.setdefault(p, set()).add(c.raddr.ip)
        except Exception:
            pass
        for p, where in unsigned:
            persist = [w for w in where if w != "실행 중"]
            sev = "crit" if (persist or p in ext_comm) else "warn"
            det = [f"경로: {p}", "위치: " + ", ".join(sorted(set(where))), f"서명: {(sigs.get(p) or {}).get('s', '?')}"]
            if p in ext_comm:
                det.append("외부 통신 중: " + ", ".join(sorted(ext_comm[p])[:5]))
            acts = (R.action_uninstall(None, p) + R.action_quarantine(p) + R.action_delete(p)) if R else []
            add("의심 프로그램", sev, f"서명 없는 프로그램: {os.path.basename(p)}", det, acts)
        if lol:
            add("의심 프로그램", "crit", f"의심스러운 방식의 자동 실행 {len(lol)}개 (스크립트 실행기/인코딩 명령)", lol[:20],
                R and [R.action_setting("task_disable", f"작업 끄기: {t['tn']}", f"예약 작업 {t['n']} 을 사용 안 함으로 바꿉니다.\n\n{t.get('x')} {t.get('g', '')[:200]}",
                                        tp=t["tp"], tn=t["tn"]) for t in lol_tasks[:5]])
        if not unsigned and not lol:
            add("의심 프로그램", "ok", f"사용자 폴더의 실행파일 {len(paths)}개 모두 서명 정상 · 의심 자동실행 없음")

        # 8. 이벤트 로그 이력 (로그 보존 기간 전체)
        def q(ch, ids, maxn=3000):
            try:
                return winutil.query_events(ch, "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + ")]]", max_events=maxn)
            except winutil.EventLogAccessDenied:
                return None
            except Exception:
                return []

        oldest = None
        try:
            o = winutil.query_events("Security", "*", max_events=1)
            oldest = o[0]["ts"] if o else None
        except Exception:
            pass
        span = f" (보안 로그 보존: {datetime.fromtimestamp(oldest):%Y-%m-%d} 이후)" if oldest else ""
        fmt = lambda ts: datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
        clr = (q("Security", [1102]) or []) + (q("System", [104]) or [])
        if clr:
            add("로그 기록", "crit", f"이벤트 로그가 지워진 기록 {len(clr)}건 (흔적 지우기 의심)",
                [f"{fmt(e['ts'])} {'보안' if e['id'] == 1102 else '시스템'} 로그 삭제 by {e['data'].get('SubjectUserName', '')}" for e in clr[-10:]])
        acct = q("Security", [4720, 4732, 4728])
        if acct is None:
            add("로그 기록", "warn", "보안 로그를 읽을 수 없음 (관리자 권한 필요)")
        else:
            if acct:
                add("로그 기록", "warn", f"계정 생성/관리자 그룹 변경 기록 {len(acct)}건{span}",
                    [f"{fmt(e['ts'])} {'계정 생성' if e['id'] == 4720 else '그룹 추가'}: {e['data'].get('TargetUserName', '')} "
                     f"{e['data'].get('MemberName', '') or ''} (by {e['data'].get('SubjectUserName', '')})" for e in acct[-15:]])
            logons = q("Security", [4624], 20000) or []
            rem = {}
            for e in logons:
                d = e["data"]
                ip = d.get("IpAddress", "-")
                if d.get("LogonType") in ("3", "10") and ip_kind(ip) in ("ext", "lan") and not d.get("TargetUserName", "").endswith("$") \
                        and d.get("TargetUserName") != "ANONYMOUS LOGON":
                    k = (ip, d.get("TargetUserName"), "원격 데스크톱" if d.get("LogonType") == "10" else "네트워크")
                    r = rem.setdefault(k, [0, e["ts"]])
                    r[0] += 1
                    r[1] = e["ts"]
            if rem:
                ext = any(ip_kind(k[0]) == "ext" for k in rem)
                add("로그 기록", "crit" if ext else "warn", f"다른 기기에서 로그인 성공한 기록{span}",
                    [f"{ip} → {u} ({how}) {n}회, 마지막 {fmt(t)}{'  ← 인터넷 IP!' if ip_kind(ip) == 'ext' else ''}" for (ip, u, how), (n, t) in rem.items()])
            fails = q("Security", [4625], 20000) or []
            fl = {}
            for e in fails:
                k = (e["data"].get("IpAddress", "-"), e["data"].get("TargetUserName", "?"))
                fl[k] = fl.get(k, 0) + 1
            if fl:
                ext = any(ip_kind(k[0]) == "ext" for k in fl)
                add("로그 기록", "crit" if ext or sum(fl.values()) >= 50 else "warn", f"로그인 실패 {sum(fl.values())}회{span}",
                    [f"{ip} / {u}: {n}회" for (ip, u), n in sorted(fl.items(), key=lambda x: -x[1])[:15]])
            if not clr and not acct and not rem and not fl:
                add("로그 기록", "ok", f"로그 삭제·계정 생성·원격 로그인·로그인 실패 기록 없음{span}")

        order = {"crit": 0, "warn": 1, "info": 2, "ok": 3}
        F.sort(key=lambda f: order[f["sev"]])
        return F
