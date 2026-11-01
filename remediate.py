"""위험 항목 바로 정리: 프로그램 제거, 실행파일 격리(되돌리기 가능), 위험 설정 끄기.

보안 원칙
- 화면(브라우저)은 '조치 번호(id)'만 보낼 수 있다. 실제 대상·명령은 점검 때 서버가 만든 목록에서만 꺼낸다.
- Windows 폴더의 파일, Microsoft 서명 파일, PC 모니터 자신은 격리하지 않는다.
- 모든 조치는 events 테이블에 기록된다.
"""
import ctypes
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
import winreg

import psutil

import config
import winutil

log = logging.getLogger("pcmon.remediate")
QUAR_DIR = os.path.join(config.DATA_DIR, "quarantine")
UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]
# 조용히 제거하는 옵션을 알고 있는 제거 프로그램 (제작사 문서 기준)
KNOWN_SILENT = {"teamviewer": "/S", "anydesk": "--remove", "rustdesk": "--uninstall", "ultraviewer": "/VERYSILENT",
                "supremo": "/S", "tightvnc": "/qn", "ammyy": ""}
SYSROOT = os.environ.get("SystemRoot", r"C:\Windows").lower() + "\\"


def exe_from(cmd):
    c = (cmd or "").strip()
    if c.startswith('"'):
        return c[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.exe)\b", c, re.I)
    return m.group(1) if m else ""


# ------------------------------------------------------------------ 내려받은 프로그램 폴더 / 휴지통
# 사용자 폴더 아래 '이 프로그램만의 폴더'를 찾기 위한 기준 위치들
def _user_roots():
    up = os.environ.get("USERPROFILE", "")
    roots = [os.path.join(up, d) for d in ("Downloads", "Desktop", "Documents")]
    roots += [os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", ""), os.environ.get("TEMP", ""),
              os.environ.get("PUBLIC", ""), os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")]
    return [r.rstrip("\\").lower() for r in roots if r]


# 이 이름의 하위 폴더는 여러 프로그램이 함께 쓰므로 한 단계 더 들어간다
_SHARED_SUB = {"programs", "microsoft", "packages", "temp", "google", "mozilla", "apps", "local", "roaming", "common files"}


def app_folder(path):
    """...\\Downloads\\srt-macro-win32-ia32\\...\\srt-macro.exe → ...\\Downloads\\srt-macro-win32-ia32"""
    p = os.path.abspath(path)
    low = p.lower()
    for root in sorted(_user_roots(), key=len, reverse=True):
        if low.startswith(root + "\\"):
            parts = p[len(root) + 1:].split("\\")
            i = 0
            while i < len(parts) - 1 and parts[i].lower() in _SHARED_SUB:
                i += 1
            if i >= len(parts) - 1:
                return ""  # 실행파일이 기준 폴더 바로 아래에 있음 → 폴더째 삭제 안 함
            return os.path.join(p[:len(root)], *parts[:i + 1])
    return ""


def _folder_stats(folder):
    n = size = 0
    for r, _d, files in os.walk(folder):
        for f in files:
            n += 1
            try:
                size += os.path.getsize(os.path.join(r, f))
            except OSError:
                pass
            if n > 50000:
                return n, size
    return n, size


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [("hwnd", ctypes.c_void_p), ("wFunc", ctypes.c_uint), ("pFrom", ctypes.c_wchar_p), ("pTo", ctypes.c_wchar_p),
                ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", ctypes.c_int), ("hNameMappings", ctypes.c_void_p),
                ("lpszProgressTitle", ctypes.c_wchar_p)]


def recycle(path):
    """휴지통으로 이동. SYSTEM 계정 등 휴지통이 없으면 완전 삭제."""
    if not winutil.is_system():
        op = SHFILEOPSTRUCTW(None, 3, path + "\0", None, 0x40 | 0x10 | 0x4 | 0x400, 0, None, None)  # 삭제·되돌리기 허용·묻지 않음
        if ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op)) == 0 and not op.fAnyOperationsAborted and not os.path.exists(path):
            return "휴지통으로 이동"
    if os.path.isdir(path):
        shutil.rmtree(path)
    else:
        os.remove(path)
    return "완전 삭제"


# ------------------------------------------------------------------ 설치 프로그램 찾기
def find_installed(name_hint=None, exe_path=None):
    """'앱 제거' 목록에서 이름 또는 설치 위치로 찾기."""
    hint = (name_hint or "").lower()
    if hint and len(hint) < 4:
        hint = ""  # 너무 짧은 이름은 엉뚱한 프로그램과 겹칠 수 있음
    exe_dir = os.path.dirname(exe_path or "").lower()
    # 여러 프로그램이 함께 쓰는 폴더는 '설치 위치'로 비교하지 않는다
    shared = {SYSROOT.rstrip("\\"), os.path.join(SYSROOT, "system32").rstrip("\\"), os.path.join(SYSROOT, "syswow64").rstrip("\\"),
              os.environ.get("ProgramFiles", "").lower(), os.environ.get("ProgramFiles(x86)", "").lower(),
              os.environ.get("ProgramData", "").lower(), os.environ.get("LOCALAPPDATA", "").lower(),
              os.environ.get("APPDATA", "").lower(), os.environ.get("USERPROFILE", "").lower()}
    if exe_dir in shared or exe_dir.startswith(SYSROOT) or exe_dir.endswith("\\downloads") or exe_dir.endswith("\\desktop"):
        exe_dir = ""
    hits = []
    for hive, path in UNINSTALL_KEYS:
        try:
            root = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                try:
                    sub = winreg.EnumKey(root, i)
                    with winreg.OpenKey(root, sub) as k:
                        def val(n):
                            try:
                                return str(winreg.QueryValueEx(k, n)[0])
                            except OSError:
                                return ""
                        dn = val("DisplayName")
                        if not dn or val("SystemComponent") == "1":
                            continue
                        loc = val("InstallLocation").strip('"').rstrip("\\").lower()
                        if len(loc) <= 3 or loc in shared or loc.startswith(SYSROOT):
                            loc = ""  # 드라이브 루트(C:\)나 공용 폴더로 등록된 프로그램은 위치 비교 제외 (예: 영웅문4 → C:\)
                        un = val("UninstallString")
                        un_dir = os.path.dirname(exe_from(un)).lower()
                        match = (hint and hint in dn.lower()) or (exe_dir and loc and (exe_dir == loc or exe_dir.startswith(loc + "\\"))) \
                            or (exe_dir and un_dir and un_dir not in shared and exe_dir == un_dir)
                        if match and un:
                            hits.append({"name": dn, "version": val("DisplayVersion"), "publisher": val("Publisher"),
                                         "uninstall": un, "quiet": val("QuietUninstallString"), "key": sub,
                                         "hive": "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"})
                except OSError:
                    continue
    return hits


def _uninstall_cmd(entry):
    """조용히 제거할 수 있으면 조용한 명령, 아니면 원래 제거 명령 + silent=False."""
    if entry.get("quiet"):
        return entry["quiet"], True
    un = entry["uninstall"]
    m = re.search(r"msiexec(\.exe)?\s+/[ix]\s*(\{[0-9a-f-]+\})", un, re.I)
    if m:
        return f"msiexec.exe /x {m.group(2)} /qn /norestart", True
    low = entry["name"].lower()
    for k, flag in KNOWN_SILENT.items():
        if k in low and flag:
            return f"{un} {flag}", True
    return un, False


# ------------------------------------------------------------------ 조치 목록 만들기 (점검 결과에 붙임)
class Remediator:
    def __init__(self, db, mon):
        self.db = db
        self.mon = mon
        self.jobs = {}          # id -> {state, msg, ts}
        self.extra = {}         # 프로세스 목록에서 만든 조치 (id -> 조치)
        self._pa_cache = {}
        self.lock = threading.Lock()
        os.makedirs(QUAR_DIR, exist_ok=True)

    @staticmethod
    def new_id(*key):
        """대상이 같으면 항상 같은 번호 → 다시 점검해도 화면의 버튼이 그대로 동작."""
        import hashlib
        return hashlib.sha1("|".join(map(str, key)).encode("utf-8")).hexdigest()[:12]

    def action_uninstall(self, label, exe=None):
        acts = []
        hits = find_installed(label, exe)
        if len(hits) > 1 and label:
            hits = [h for h in hits if label.lower() in h["name"].lower()]
        if len(hits) != 1:
            return []  # 정확히 하나로 특정되지 않으면 제거 버튼을 만들지 않음 (엉뚱한 프로그램 제거 방지)
        for e in hits:
            cmd, silent = _uninstall_cmd(e)
            acts.append({"id": self.new_id("uninstall", e["hive"], e["key"]), "kind": "uninstall", "label": f"'{e['name']}' 제거",
                         "confirm": f"{e['name']} {e['version']} ({e['publisher']}) 를 제거합니다." +
                                    ("" if silent else "\n제거 창이 뜨면 안내에 따라 진행하세요."),
                         "cmd": cmd, "silent": silent, "entry": e})
        return acts

    def action_quarantine(self, path, why=""):
        if not self._quarantine_allowed(path):
            return []
        return [{"id": self.new_id("quarantine", path.lower()), "kind": "quarantine", "label": "격리 (되돌리기 가능)",
                 "confirm": f"{os.path.basename(path)} 를 끄고 격리 폴더로 옮깁니다.\n관련 방화벽 허용 규칙과 자동실행 등록도 지웁니다.\n"
                            "필요하면 '격리 보관함'에서 되돌릴 수 있습니다.\n\n{path}", "path": path}]

    def action_delete(self, path):
        """바로 삭제 (휴지통으로). 내려받은 프로그램 폴더가 따로 있으면 '폴더째 삭제'도."""
        if not self._quarantine_allowed(path):
            return []
        acts = [{"id": self.new_id("delete", path.lower()), "kind": "delete", "label": "삭제",
                 "confirm": f"{os.path.basename(path)} 를 끄고 삭제(휴지통으로 이동)합니다.\n관련 방화벽 허용 규칙과 자동실행 등록도 지웁니다.\n\n{path}",
                 "path": path}]
        folder = app_folder(path)
        if folder:
            n, size = _folder_stats(folder)
            if n and size < 3e9:
                acts.append({"id": self.new_id("delete", folder.lower()), "kind": "delete", "label": "폴더째 삭제",
                             "confirm": f"프로그램 폴더 전체를 삭제(휴지통으로 이동)합니다.\n파일 {n}개 · {size / 1e6:.0f}MB\n"
                                        f"폴더 안에서 실행 중인 프로그램은 먼저 종료합니다.\n\n{folder}",
                             "path": folder, "folder": True})
        return acts

    def action_setting(self, what, label, confirm, **kw):
        key = ("setting", what) + tuple(str(v) for _, v in sorted(kw.items()))
        return {"id": self.new_id(*key), "kind": "setting", "what": what, "label": label, "confirm": confirm, **kw}

    def _quarantine_allowed(self, path):
        p = (path or "").lower()
        if not p or not os.path.isfile(path) or p.startswith(SYSROOT):
            return False
        if os.path.basename(p) in ("pcmonitor.exe", "python.exe", "pythonw.exe"):
            return False
        return True

    # ------------------------------------------------------------------ 프로세스 목록의 종료/제거 버튼
    CRITICAL = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
                "svchost.exe", "dwm.exe", "explorer.exe", "msmpeng.exe", "memory compression", "pcmonitor.exe", "pythonw.exe",
                "python.exe", "fontdrvhost.exe", "lsaiso.exe", "secure system"}

    def proc_actions(self, row):
        """권장 등급에 따라 [종료] [제거] [삭제] 버튼. 결과는 10분간 캐시."""
        adv, name, exe = row.get("advice"), (row.get("name") or "").lower(), row.get("path") or ""
        if adv not in ("close", "remove", "remove_rec", "check") or name in self.CRITICAL:
            return []
        if not hasattr(self, "_pa_cache"):
            self._pa_cache, self.extra = {}, {}
        key = (name, exe.lower(), adv)
        hit = self._pa_cache.get(key)
        if hit and time.time() - hit[0] < 600:
            return hit[1]
        acts = [{"id": self.new_id("kill", exe.lower() or name), "kind": "kill", "label": "종료", "name": row.get("name"), "exe": exe,
                 "confirm": f"{row.get('name')} 를 지금 종료합니다.\n저장하지 않은 작업이 있으면 사라질 수 있습니다."}]
        if adv in ("remove", "remove_rec", "check") and exe:
            acts += self.action_uninstall(None, exe)
            if adv == "check" and not any(a["kind"] == "uninstall" for a in acts):
                acts += self.action_delete(exe)
        for a in acts:
            self.extra[a["id"]] = a
        self._pa_cache[key] = (time.time(), acts)
        return acts

    # ------------------------------------------------------------------ 위험 이벤트 → 설명 + 조치 버튼
    def event_help(self, e):
        """events 행 하나에 대해 (무슨 일인지, 어떻게 하면 되는지, [조치])."""
        import ipaddress
        title, cat = e.get("title") or "", e.get("category")
        try:
            d = json.loads(e.get("detail") or "{}")
            if not isinstance(d, dict):
                d = {}
        except Exception:
            d = {}
        acts = []

        def ip_block(ip):
            try:
                a = ipaddress.ip_address(str(ip).split("%")[0])
            except ValueError:
                return
            if a.is_loopback or a.is_unspecified:
                return
            acts.append(self.action_setting("block_ip", f"{ip} 차단", f"{ip} 에서 이 PC로 들어오는 모든 접속을 방화벽으로 막습니다.\n"
                                            "(같은 집/회사 기기라면 그 기기의 파일공유·원격 접속도 막힙니다)", ip=str(a)))

        ip = d.get("IP") or d.get("IpAddress") or ""
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{6,})", title)
        if not ip and m and cat in ("intrusion", "network"):
            ip = m.group(1)
        if "서명 없는 프로그램 실행" in title and d.get("경로"):
            what = "사용자 폴더(다운로드·임시 폴더 등)에서 디지털 서명이 없는 프로그램이 실행됐습니다. 악성코드가 흔히 이런 방식으로 실행됩니다."
            how = "직접 받은 프로그램이 확실하면 '확인함'. 모르는 프로그램이면 격리하거나 삭제하세요."
            acts += self.action_quarantine(d["경로"]) + self.action_delete(d["경로"])
        elif "포트 스캔" in title:
            what = "한 기기가 1분 동안 이 PC의 여러 포트를 차례로 두드렸습니다. 침입할 틈을 찾는 전형적인 행동입니다. 방화벽이 막았습니다."
            how = "인터넷 IP라면 공유기의 포트포워딩·DMZ 설정을 끄세요. 내부망 기기라면 그 기기의 악성코드 감염을 의심하세요. 아래 버튼으로 차단할 수 있습니다."
            ip_block(ip)
        elif "인터넷에서 접속 시도" in title or "외부에서 내 PC로 접속" in title:
            what = "인터넷의 다른 컴퓨터가 이 PC에 직접 접속하려고 했습니다. 보통 공유기가 막아 주므로 이런 시도가 보이면 공유기 설정에 구멍이 있다는 뜻입니다."
            how = "공유기의 포트포워딩·DMZ·UPnP 설정을 확인하세요. 아래 버튼으로 이 IP를 차단할 수 있습니다."
            ip_block(ip)
        elif e.get("event_id") == 4625 or "로그인 실패" in title:
            what = "누군가 이 PC 계정으로 로그인하려다 비밀번호가 틀렸습니다. 반복되면 비밀번호를 맞히려는 공격(무차별 대입)입니다."
            how = "본인이 틀린 게 아니라면 그 IP를 차단하고, 계정 비밀번호를 길고 복잡하게 바꾸세요."
            ip_block(ip)
        elif e.get("event_id") == 4624 or "원격 로그인 성공" in title:
            what = "다른 기기에서 이 PC 계정으로 로그인에 성공했습니다."
            how = "본인(또는 아는 사람)이 아니라면 즉시 해당 IP를 차단하고 비밀번호를 바꾸세요."
            ip_block(ip)
        elif "새 서비스 설치" in title:
            name = title.split(":", 1)[-1].strip()
            what = "새 Windows 서비스(백그라운드 프로그램)가 설치됐습니다. 정상 프로그램도 설치하지만 악성코드도 자주 씁니다."
            how = "방금 설치한 프로그램 것이면 '확인함'. 모르는 서비스면 중지하고 사용 안 함으로 바꾸세요."
            acts.append(self.action_setting("svc_disable", "서비스 중지·사용 안 함", f"'{name}' 서비스를 중지하고 자동 시작을 끕니다.", svc=name))
        elif cat == "persistence" and ("레지스트리 자동실행" in title or "시작프로그램" in title):
            what = "PC가 켜질 때 자동으로 실행되는 프로그램이 새로 등록됐습니다."
            how = "아는 프로그램이면 '확인함', 모르면 자동실행에서 빼세요."
            m2 = re.search(r"(HKLM|HKCU)\\(.+)\\([^\\]+)$", title.split(": ", 1)[-1])
            if m2:
                acts.append(self.action_setting("run_remove", "자동실행에서 빼기", f"자동실행 항목 '{m2.group(3)}' 을 지웁니다.",
                                                hive=m2.group(1), key=m2.group(2), name=m2.group(3)))
        elif cat == "persistence" and "예약 작업" in title:
            full = title.split(": ", 1)[-1].strip().replace("/", "\\")
            what = "새 예약 작업이 등록됐습니다. 정해진 시간마다 프로그램을 실행합니다."
            how = "아는 프로그램 것이면 '확인함', 모르면 사용 안 함으로 바꾸세요."
            tp = "\\" + (full.rsplit("\\", 1)[0] + "\\" if "\\" in full else "")
            acts.append(self.action_setting("task_disable", "예약 작업 끄기", f"예약 작업 '{full}' 을 사용 안 함으로 바꿉니다.",
                                            tp=tp, tn=full.rsplit("\\", 1)[-1]))
        elif "새 사용자 계정" in title or "관리자 그룹에 계정" in title or ("그룹에 계정 추가" in title and "Admin" in json.dumps(d)):
            name = d.get("TargetUserName") if "새 사용자" in title else (d.get("MemberName") or "")
            what = "새 계정이 생겼거나 관리자 권한이 주어졌습니다. 침입자가 뒷문용 계정을 만드는 대표적인 방법입니다."
            how = "본인이 한 작업이 아니면 그 계정을 즉시 사용 안 함으로 바꾸고 비밀번호를 모두 바꾸세요."
            if name and "\\" not in name and not name.startswith("CN="):
                acts.append(self.action_setting("user_disable", f"'{name}' 계정 사용 안 함", f"'{name}' 계정을 로그인할 수 없게 합니다.", user=name))
        elif cat == "defender" and ("탐지" in title or "조치 실패" in title):
            what = "Windows 보안(백신)이 악성코드를 찾았습니다."
            how = "'조치 완료'면 이미 처리됐습니다. 조치 실패면 빠른 검사를 다시 하고, 그래도 남으면 오프라인 검사를 하세요."
            acts.append(self.action_setting("defender_quick", "빠른 검사 시작", "Windows 보안 빠른 검사를 시작합니다 (몇 분 걸림)."))
        elif cat == "defender" and ("꺼짐" in title or "예외" in title):
            what = "백신의 보호 기능이 꺼졌거나 검사 예외가 추가됐습니다. 악성코드가 자신을 숨기려고 자주 하는 일입니다."
            how = "직접 바꾼 게 아니면 실시간 보호를 다시 켜고, 흔적 점검에서 예외 목록을 확인하세요."
            acts.append(self.action_setting("rtp_on", "실시간 보호 켜기", "Windows 보안 실시간 보호를 켭니다."))
        elif "로그가 지워짐" in title:
            what = "Windows 이벤트 기록이 지워졌습니다. 침입자가 흔적을 지울 때 하는 행동입니다."
            how = "본인이 지운 게 아니라면 흔적 점검을 하고, 비밀번호를 바꾸고, 전체 검사를 하세요."
        elif "PowerShell" in title:
            what = "PowerShell(명령 실행 도구)로 해킹에 자주 쓰이는 형태의 명령이 실행됐습니다."
            how = "관리 도구나 설치 프로그램이 정상적으로 쓰기도 합니다(예: PC 모니터 설치 명령). 짐작 가는 게 없으면 흔적 점검과 빠른 검사를 하세요."
            acts.append(self.action_setting("defender_quick", "빠른 검사 시작", "Windows 보안 빠른 검사를 시작합니다 (몇 분 걸림)."))
        else:
            what = title
            how = "자세한 내용을 확인하고, 문제 없으면 '확인함'을 누르세요."
        for a in acts:
            self.extra[a["id"]] = a
        return what, how, acts

    def _kill(self, a):
        name, exe = (a.get("name") or "").lower(), (a.get("exe") or "").lower()
        if name in self.CRITICAL:
            return False, "Windows 필수 프로세스는 종료하지 않습니다"
        n = 0
        for p in psutil.process_iter(["name", "exe"]):
            try:
                if (exe and (p.info.get("exe") or "").lower() == exe) or (not exe and (p.info.get("name") or "").lower() == name):
                    p.kill()
                    n += 1
            except Exception:
                pass
        return (n > 0), (f"{a.get('name')} 종료됨 ({n}개)" if n else "이미 종료되어 있거나 권한이 없어 종료하지 못했습니다")

    # ------------------------------------------------------------------ 실행
    def find_action(self, aid):
        extra = getattr(self, "extra", {})
        if aid in extra:
            return extra[aid]
        scan = self.db.get("trace_scan") or {}
        for f in scan.get("findings", []):
            for a in f.get("actions") or []:
                if a.get("id") == aid:
                    return a
        return None

    def run(self, aid):
        a = self.find_action(aid)
        if not a:
            return {"ok": False, "msg": "조치를 찾을 수 없습니다 (점검을 다시 해 주세요)"}
        if not winutil.is_admin():
            return {"ok": False, "msg": "관리자 권한으로 실행 중이 아니라 조치할 수 없습니다"}
        with self.lock:
            if self.jobs.get(aid, {}).get("state") == "running":
                return {"ok": True, "msg": "이미 진행 중"}
            self.jobs[aid] = {"state": "running", "msg": "진행 중…", "ts": time.time()}
        threading.Thread(target=self._run, args=(aid, a), daemon=True).start()
        return {"ok": True}

    def status(self, aid):
        return self.jobs.get(aid) or {"state": "none"}

    def _done(self, aid, ok, msg, a):
        self.jobs[aid] = {"state": "ok" if ok else "fail", "msg": msg, "ts": time.time()}
        self.db.add_event(time.time(), "action", "info" if ok else "warn", "pcmon", 0,
                          ("조치 완료: " if ok else "조치 실패: ") + a["label"], {"결과": msg, "대상": a.get("path") or a.get("cmd") or a.get("what")})
        log.info("action %s %s: %s", a["kind"], "ok" if ok else "fail", msg)
        if ok and a["kind"] != "kill":
            # 결과 반영을 위해 다시 점검
            threading.Timer(3, self.mon.trace.start).start()
            getattr(self, "_pa_cache", {}).clear()

    def _run(self, aid, a):
        try:
            if a["kind"] == "uninstall":
                ok, msg = self._uninstall(a)
            elif a["kind"] == "quarantine":
                ok, msg = self.quarantine(a["path"])
            elif a["kind"] == "delete":
                ok, msg = self.delete(a)
            elif a["kind"] == "kill":
                ok, msg = self._kill(a)
            elif a["kind"] == "setting":
                ok, msg = self._setting(a)
            else:
                ok, msg = False, "알 수 없는 조치"
        except Exception as e:
            log.exception("action")
            ok, msg = False, f"오류: {e}"
        self._done(aid, ok, msg, a)

    def _uninstall(self, a):
        e = a["entry"]
        if a["silent"] or not winutil.is_system():
            p = subprocess.Popen(a["cmd"], creationflags=0 if not a["silent"] else winutil.CREATE_NO_WINDOW)
        else:
            return False, "로그인 없이 실행 중(SYSTEM)이라 제거 창을 띄울 수 없습니다. '앱 및 기능'에서 직접 제거해 주세요."
        self.jobs[a["id"]]["msg"] = "제거 프로그램 실행 중…" + ("" if a["silent"] else " (열린 제거 창에서 진행하세요)")
        try:
            p.wait(timeout=900)
        except subprocess.TimeoutExpired:
            return False, "제거가 15분 넘게 끝나지 않았습니다"
        # 일부 제거 프로그램은 자신을 복사해 따로 실행하고 바로 끝나므로 잠시 기다리며 확인
        for _ in range(60):
            if not find_installed(e["name"]):
                return True, f"{e['name']} 제거됨"
            time.sleep(5)
        return False, f"제거 프로그램은 끝났지만 '{e['name']}' 가 아직 목록에 있습니다 (취소했거나 재부팅 필요)"

    # ---------------------------------------------------------- 공통: 프로세스 종료 + 방화벽 규칙·자동실행 제거
    def _stop_and_unhook(self, target, folder):
        """target(파일 또는 폴더)에 해당하는 프로세스 종료, 방화벽 허용 규칙·레지스트리 자동실행 삭제."""
        t = target.lower().rstrip("\\")

        def hit(p):
            p = os.path.expandvars((p or "").strip('"')).lower()
            return p.startswith(t + "\\") if folder else p == t

        killed = 0
        for _ in range(3):  # 자식 프로세스가 다시 뜨는 경우 대비
            n = 0
            for p in psutil.process_iter(["pid", "exe"]):
                try:
                    if hit(p.info.get("exe")):
                        p.kill()
                        n += 1
                except Exception:
                    pass
            killed += n
            if not n:
                break
            time.sleep(1)
        removed = {"fw": [], "run": []}
        out = winutil.run_ps_json(
            ("$p=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('B64PATH'))).ToLower(); $f=FOLDER;"
             "$r=@(Get-NetFirewallApplicationFilter | Where-Object { $x=[Environment]::ExpandEnvironmentVariables([string]$_.Program).ToLower();"
             " if($f){ $x.StartsWith($p + '\\') } else { $x -eq $p } } | Get-NetFirewallRule);"
             "$n=@($r | ForEach-Object { @{n=$_.DisplayName;d=[string]$_.Direction;a=[string]$_.Action;"
             " prog=[string]($_ | Get-NetFirewallApplicationFilter).Program} }); $r | Remove-NetFirewallRule;"
             "ConvertTo-Json -InputObject $n -Compress")
            .replace("B64PATH", winutil._b64(t)).replace("FOLDER", "$true" if folder else "$false"), timeout=120)
        removed["fw"] = out or []
        for hive, key in ((winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                          (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
                          (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")):
            try:
                with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
                    i, names = 0, []
                    while True:
                        try:
                            n, v, ty = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        if t in os.path.expandvars(str(v)).lower():
                            names.append((n, v, ty))
                        i += 1
                    for n, v, ty in names:
                        winreg.DeleteValue(k, n)
                        removed["run"].append({"hive": "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU", "key": key, "n": n, "v": v, "t": ty})
            except OSError:
                pass
        return killed, removed

    # ---------------------------------------------------------- 바로 삭제 (휴지통)
    def delete(self, a):
        path, folder = a["path"], bool(a.get("folder"))
        if not os.path.exists(path):
            return True, "이미 삭제되어 없습니다"
        low = path.lower().rstrip("\\")
        if low.startswith(SYSROOT) or low in _user_roots() or len(low) <= 3:
            return False, "이 위치는 삭제할 수 없습니다"
        if not folder:
            sig = winutil.signature_status([path]).get(path) or {}
            if sig.get("s") == "Valid" and "microsoft" in (sig.get("n") or "").lower():
                return False, "Microsoft 서명 파일은 삭제하지 않습니다"
        killed, removed = self._stop_and_unhook(path, folder)
        try:
            how = recycle(path)
        except OSError as e:
            return False, f"삭제하지 못했습니다 (사용 중인 파일이 있을 수 있음): {e}"
        if os.path.exists(path):
            return False, "삭제하지 못했습니다 (사용 중인 파일이 있을 수 있음)"
        return True, (f"{os.path.basename(path)} {'폴더 ' if folder else ''}삭제됨 ({how}) · 프로세스 {killed}개 종료, "
                      f"방화벽 규칙 {len(removed['fw'])}개·자동실행 {len(removed['run'])}개 삭제")

    # ---------------------------------------------------------- 격리 / 되돌리기
    def quarantine(self, path):
        if not self._quarantine_allowed(path):
            return False, "격리할 수 없는 파일입니다 (시스템 파일이거나 이미 없음)"
        sig = winutil.signature_status([path]).get(path) or {}
        if sig.get("s") == "Valid" and "microsoft" in (sig.get("n") or "").lower():
            return False, "Microsoft 서명 파일은 격리하지 않습니다"
        killed, removed = self._stop_and_unhook(path, folder=False)
        qid = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        dst = os.path.join(QUAR_DIR, qid + "_" + os.path.basename(path) + ".quarantine")
        try:
            shutil.move(path, dst)
        except OSError as e:
            return False, f"파일을 옮기지 못했습니다: {e}"
        meta = {"qid": qid, "orig": path, "file": dst, "ts": int(time.time()), "sig": sig.get("s"), "removed": removed}
        with open(dst + ".json", "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False)
        msg = f"{os.path.basename(path)} 격리됨 (프로세스 {killed}개 종료, 방화벽 규칙 {len(removed['fw'])}개·자동실행 {len(removed['run'])}개 삭제)"
        return True, msg

    def quarantine_list(self):
        out = []
        for f in sorted(os.listdir(QUAR_DIR), reverse=True):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(QUAR_DIR, f), encoding="utf-8") as fh:
                        m = json.load(fh)
                    out.append({"qid": m["qid"], "orig": m["orig"], "ts": m["ts"], "sig": m.get("sig"),
                                "fw": len(m["removed"]["fw"]), "run": len(m["removed"]["run"])})
                except Exception:
                    pass
        return out

    def restore(self, qid):
        if not re.fullmatch(r"[0-9-]+-[0-9a-f]{6}", qid or ""):
            return {"ok": False, "msg": "잘못된 요청"}
        for f in os.listdir(QUAR_DIR):
            if f.startswith(qid + "_") and f.endswith(".json"):
                mp = os.path.join(QUAR_DIR, f)
                with open(mp, encoding="utf-8") as fh:
                    m = json.load(fh)
                if os.path.exists(m["orig"]):
                    return {"ok": False, "msg": "원래 위치에 같은 이름의 파일이 이미 있습니다"}
                os.makedirs(os.path.dirname(m["orig"]), exist_ok=True)
                shutil.move(m["file"], m["orig"])
                for r in m["removed"]["run"]:
                    hive = winreg.HKEY_LOCAL_MACHINE if r["hive"] == "HKLM" else winreg.HKEY_CURRENT_USER
                    try:
                        with winreg.CreateKey(hive, r["key"]) as k:
                            winreg.SetValueEx(k, r["n"], 0, r["t"], r["v"])
                    except OSError:
                        pass
                for r in m["removed"]["fw"]:
                    winutil.run_ps("New-NetFirewallRule -DisplayName ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))) "
                                   "-Direction %s -Action %s -Program ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))) | Out-Null"
                                   % (winutil._b64(r["n"]), r["d"] if r["d"] in ("Inbound", "Outbound") else "Inbound",
                                      r["a"] if r["a"] in ("Allow", "Block") else "Allow", winutil._b64(m["orig"])))
                os.remove(mp)
                self.db.add_event(time.time(), "action", "info", "pcmon", 0, f"격리 되돌림: {os.path.basename(m['orig'])}", {"경로": m["orig"]})
                threading.Timer(3, self.mon.trace.start).start()
                return {"ok": True, "msg": f"{os.path.basename(m['orig'])} 를 원래 위치로 되돌렸습니다"}
        return {"ok": False, "msg": "격리 기록을 찾을 수 없습니다"}

    # ---------------------------------------------------------- 설정 조치
    def _setting(self, a):
        w = a["what"]
        b64 = winutil._b64
        if w == "remote_assist_off":
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Remote Assistance", 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "fAllowToGetHelp", 0, winreg.REG_DWORD, 0)
            return True, "원격 지원을 껐습니다"
        if w == "rdp_off":
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Terminal Server", 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)
            return True, "원격 데스크톱을 껐습니다"
        if w == "defender_excl_remove":
            items = a.get("items") or []
            winutil.run_ps("$x=@(%s); foreach($i in $x){ Remove-MpPreference -ExclusionPath $i -ErrorAction SilentlyContinue; "
                           "Remove-MpPreference -ExclusionProcess $i -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionExtension $i -ErrorAction SilentlyContinue }"
                           % ",".join("[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))" % b64(i) for i in items), timeout=120)
            return True, f"Defender 검사 예외 {len(items)}개를 삭제했습니다"
        if w == "kms_clear":
            r = subprocess.run(["cscript.exe", "//nologo", os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "slmgr.vbs"), "/ckms"],
                               capture_output=True, timeout=120, creationflags=winutil.CREATE_NO_WINDOW)
            return r.returncode == 0, "KMS 인증 서버 설정을 지웠습니다 (정품 인증은 정식 라이선스로 다시 하세요)" if r.returncode == 0 else "실패: " + r.stdout.decode("mbcs", "replace")[-200:]
        if w == "guest_off":
            winutil.run_ps("Get-CimInstance Win32_UserAccount -Filter \"LocalAccount=True\" | ? { $_.SID -like '*-501' } | % { net user $_.Name /active:no }")
            return True, "Guest 계정을 껐습니다"
        if w == "smb1_off":
            winutil.run_ps("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force")
            return True, "SMBv1 을 껐습니다"
        if w == "task_disable":
            out = winutil.run_ps("$t=Disable-ScheduledTask -TaskPath ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))) "
                                 "-TaskName ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))); [string]$t.State"
                                 % (b64(a["tp"]), b64(a["tn"])))
            return out.strip() == "Disabled", f"예약 작업 '{a['tp']}{a['tn']}' 을 사용 안 함으로 바꿨습니다" if out.strip() == "Disabled" else "예약 작업을 끄지 못했습니다"
        if w == "ifeo_remove":
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + a["exe"],
                                0, winreg.KEY_SET_VALUE) as k:
                for v in ("Debugger", "VerifierDlls"):
                    try:
                        winreg.DeleteValue(k, v)
                    except OSError:
                        pass
            return True, f"{a['exe']} 의 실행 가로채기 설정을 지웠습니다"
        if w == "wmi_remove":
            winutil.run_ps(
                "$n=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));"
                "Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | ? { $_.Consumer.Name -eq $n } | Remove-CimInstance;"
                "Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | ? { $_.Name -eq $n } | Remove-CimInstance" % b64(a["name"]))
            return True, f"WMI 구독 '{a['name']}' 을 지웠습니다"
        if w == "block_ip":
            import ipaddress
            ip = str(ipaddress.ip_address(a["ip"]))  # 형식 검증
            out = winutil.run_ps(f"New-NetFirewallRule -DisplayName 'PCMonitor 차단 {ip}' -Direction Inbound -RemoteAddress {ip} -Action Block "
                                 f"-Profile Any | Out-Null; (Get-NetFirewallRule -DisplayName 'PCMonitor 차단 {ip}' | Measure-Object).Count")
            ok = out.strip() not in ("", "0")
            return ok, (f"{ip} 의 접속을 차단했습니다 (방화벽 규칙 'PCMonitor 차단 {ip}')" if ok else "차단 규칙을 만들지 못했습니다")
        if w == "svc_disable":
            name = a["svc"]
            svc = None
            for s in psutil.win_service_iter():
                if s.name().lower() == name.lower() or s.display_name().lower() == name.lower():
                    svc = s.name()
                    break
            if not svc:
                return False, "서비스를 찾을 수 없습니다 (이미 지워졌을 수 있음)"
            subprocess.run(["sc.exe", "stop", svc], capture_output=True, creationflags=winutil.CREATE_NO_WINDOW)
            r = subprocess.run(["sc.exe", "config", svc, "start=", "disabled"], capture_output=True, creationflags=winutil.CREATE_NO_WINDOW)
            return r.returncode == 0, f"'{svc}' 서비스를 중지하고 사용 안 함으로 바꿨습니다" if r.returncode == 0 else "서비스 설정을 바꾸지 못했습니다"
        if w == "run_remove":
            hive = winreg.HKEY_LOCAL_MACHINE if a["hive"] == "HKLM" else winreg.HKEY_CURRENT_USER
            if not re.fullmatch(r"Software\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(Once)?", a["key"], re.I):
                return False, "허용되지 않은 위치입니다"
            with winreg.OpenKey(hive, a["key"], 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, a["name"])
            return True, f"자동실행 '{a['name']}' 을 지웠습니다"
        if w == "user_disable":
            name = a["user"]
            if not re.fullmatch(r"[^\\/\"\[\]:;|=,+*?<>]{1,20}", name):
                return False, "잘못된 계정 이름"
            if name.lower() == os.environ.get("USERNAME", "").lower():
                return False, "지금 로그인한 본인 계정은 끌 수 없습니다"
            r = subprocess.run(["net", "user", name, "/active:no"], capture_output=True, creationflags=winutil.CREATE_NO_WINDOW)
            return r.returncode == 0, f"'{name}' 계정을 사용 안 함으로 바꿨습니다" if r.returncode == 0 else "계정을 바꾸지 못했습니다 (이름 확인)"
        if w == "defender_quick":
            subprocess.Popen([os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe"),
                              "-Scan", "-ScanType", "1"], creationflags=winutil.CREATE_NO_WINDOW)
            return True, "빠른 검사를 시작했습니다 (진행 상황은 개요 탭에 표시)"
        if w == "rtp_on":
            winutil.run_ps("Set-MpPreference -DisableRealtimeMonitoring $false")
            st = winutil.run_ps("(Get-MpComputerStatus).RealTimeProtectionEnabled")
            return st.strip() == "True", "실시간 보호를 켰습니다" if st.strip() == "True" else "켜지 못했습니다 (다른 백신이나 정책이 막고 있을 수 있음)"
        return False, "알 수 없는 설정"
