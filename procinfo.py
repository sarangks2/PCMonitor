"""프로세스가 무엇인지 사람이 알아볼 수 있게 설명을 붙인다.

1) 자주 보는 Windows/보안/앱 프로세스는 한국어 설명 사전
2) 그 밖에는 실행파일에 들어 있는 '파일 설명/회사명' (버전 정보)
3) svchost.exe 는 그 안에서 도는 서비스 이름
"""
import ctypes
import os
import threading
import time
from ctypes import wintypes

import psutil

# 이름(소문자) -> (설명, 분류)
KNOWN = {
    "system": ("Windows 커널 (드라이버·디스크·네트워크 처리)", "시스템"),
    "registry": ("레지스트리 저장소", "시스템"),
    "memory compression": ("메모리 압축 (RAM 절약용, 높아도 정상)", "시스템"),
    "secure system": ("보안 커널 (VBS)", "시스템"),
    "smss.exe": ("세션 관리자", "시스템"), "csrss.exe": ("Windows 하위 시스템", "시스템"),
    "wininit.exe": ("Windows 시작 관리", "시스템"), "winlogon.exe": ("로그인 화면 관리", "시스템"),
    "services.exe": ("서비스 관리자", "시스템"), "lsass.exe": ("로그인·암호 인증", "시스템"),
    "lsaiso.exe": ("격리된 인증 보호 (Credential Guard)", "시스템"),
    "svchost.exe": ("Windows 서비스 실행기", "시스템"),
    "dwm.exe": ("화면 그리기 (데스크톱 창 관리자)", "시스템"),
    "explorer.exe": ("작업 표시줄·바탕화면·파일 탐색기", "시스템"),
    "fontdrvhost.exe": ("글꼴 처리", "시스템"), "sihost.exe": ("셸 인프라 (알림·창)", "시스템"),
    "ctfmon.exe": ("입력기 (한글/영문 전환)", "시스템"), "taskhostw.exe": ("예약 작업 실행기", "시스템"),
    "runtimebroker.exe": ("앱 권한 관리", "시스템"), "dllhost.exe": ("COM 구성요소 실행기", "시스템"),
    "conhost.exe": ("콘솔 창 처리", "시스템"), "audiodg.exe": ("소리 처리", "시스템"),
    "spoolsv.exe": ("프린터 대기열", "시스템"), "searchindexer.exe": ("Windows 검색 색인 (파일 목록 만들기)", "시스템"),
    "searchhost.exe": ("작업 표시줄 검색", "시스템"), "searchprotocolhost.exe": ("검색 색인 보조", "시스템"),
    "startmenuexperiencehost.exe": ("시작 메뉴", "시스템"), "shellexperiencehost.exe": ("알림 센터·시계 화면", "시스템"),
    "textinputhost.exe": ("터치 키보드·이모지 입력", "시스템"), "widgets.exe": ("위젯", "시스템"),
    "compkgsrv.exe": ("구성요소 패키지 지원", "시스템"), "wmiprvse.exe": ("WMI 관리 정보 제공 (관리 도구가 정보 조회 중)", "시스템"),
    "trustedinstaller.exe": ("Windows 업데이트 설치 관리자", "업데이트"), "tiworker.exe": ("Windows 업데이트 설치 작업 (일시적으로 높음)", "업데이트"),
    "wuauclt.exe": ("Windows 업데이트", "업데이트"), "wuaucltcore.exe": ("Windows 업데이트 확인·다운로드", "업데이트"),
    "usoclient.exe": ("업데이트 예약 실행", "업데이트"), "musnotification.exe": ("업데이트 알림", "업데이트"),
    "msmpeng.exe": ("Windows 보안 백신 검사 엔진 (검사 중엔 CPU 높음 정상)", "보안"),
    "mpsigstub.exe": ("Windows 보안 바이러스 정의 업데이트", "보안"), "nissrv.exe": ("Windows 보안 네트워크 검사", "보안"),
    "mpdefendercoreservice.exe": ("Windows 보안 핵심 서비스", "보안"), "mpcmdrun.exe": ("Windows 보안 명령 실행 (검사·업데이트)", "보안"),
    "securityhealthservice.exe": ("Windows 보안 상태 서비스", "보안"), "securityhealthsystray.exe": ("Windows 보안 트레이 아이콘", "보안"),
    "smartscreen.exe": ("SmartScreen (위험 파일·사이트 차단)", "보안"),
    "msedge.exe": ("Microsoft Edge 브라우저", "앱"), "msedgewebview2.exe": ("앱 안에 들어간 웹 화면 (WebView2)", "앱"),
    "chrome.exe": ("Google Chrome 브라우저", "앱"), "firefox.exe": ("Firefox 브라우저", "앱"), "whale.exe": ("네이버 웨일 브라우저", "앱"),
    "claude.exe": ("Claude (AI 도우미)", "앱"), "windowsterminal.exe": ("Windows 터미널", "앱"),
    "powershell.exe": ("PowerShell 명령 창/스크립트", "앱"), "pwsh.exe": ("PowerShell 7", "앱"), "cmd.exe": ("명령 프롬프트", "앱"),
    "python.exe": ("Python 프로그램", "앱"), "pythonw.exe": ("Python 프로그램 (창 없음, PC BlackBox 포함)", "앱"),
    "pcblackbox.exe": ("PC BlackBox (이 프로그램)", "앱"), "pcmonitor.exe": ("PC BlackBox (이 프로그램)", "앱"), "code.exe": ("Visual Studio Code", "앱"),
    "onedrive.exe": ("OneDrive 동기화", "앱"), "googledrivefs.exe": ("Google 드라이브 동기화", "앱"),
    "kakaotalk.exe": ("카카오톡", "앱"), "ms-teams.exe": ("Microsoft Teams", "앱"), "teams.exe": ("Microsoft Teams", "앱"),
    "outlook.exe": ("Outlook 메일", "앱"), "winword.exe": ("Word", "앱"), "excel.exe": ("Excel", "앱"), "powerpnt.exe": ("PowerPoint", "앱"),
    "hwp.exe": ("한글(HWP)", "앱"), "teamviewer.exe": ("TeamViewer 원격 제어", "원격"), "teamviewer_service.exe": ("TeamViewer 원격 제어 서비스", "원격"),
    "anydesk.exe": ("AnyDesk 원격 제어", "원격"),
    "nosstarter.npe": ("nProtect Online Security (인터넷 뱅킹 보안)", "보안"),
    "sqlservr.exe": ("SQL Server 데이터베이스", "서버"), "w3wp.exe": ("IIS 웹사이트 작업자", "서버"),
    "inetinfo.exe": ("IIS 웹 서버", "서버"), "dns.exe": ("DNS 서버", "서버"), "ntfrs.exe": ("파일 복제", "서버"), "dfsrs.exe": ("DFS 복제", "서버"),
    "vmms.exe": ("Hyper-V 가상머신 관리", "서버"), "vmwp.exe": ("Hyper-V 가상머신 실행", "서버"),
    "scourtscanlauncher.exe": ("대법원 전자소송 스캔 프로그램", "앱"),
    "microsoft.photos.exe": ("사진 앱 (백그라운드에서 메모리 차지)", "앱"),
    "photos.exe": ("사진 앱", "앱"), "phoneexperiencehost.exe": ("휴대폰과 연결 앱", "앱"),
    "gamebar.exe": ("Xbox Game Bar", "앱"), "yourphone.exe": ("휴대폰과 연결 앱", "앱"),
    "acrord32.exe": ("Adobe Acrobat Reader", "앱"), "acrobat.exe": ("Adobe Acrobat", "앱"),
    "kmplayer.exe": ("KMPlayer 동영상 플레이어", "앱"), "potplayermini64.exe": ("팟플레이어", "앱"),
    "iniclientsvc_x64.exe": ("이니텍 공동인증서 관리 서비스 (뱅킹)", "보안"),
    "easysetup.app.exe": ("Brother 프린터 Easy Setup 설치 관리자", "설치"),
    "easysetup.exe": ("Brother 프린터 Easy Setup 설치 관리자", "설치"),
    "brctrlcntr.exe": ("Brother ControlCenter 프린터 제어", "앱"),
    "brsvc01a.exe": ("Brother 프린터 상태 감시 서비스", "시스템"),
    "brstmonw.exe": ("Brother 프린터 상태 모니터", "앱"),
}

# 권장: (등급, 안내)  등급: must 필수 · keep 그대로 · close 종료 가능 · remove 삭제 가능 · remove_rec 삭제 권장 · check 확인 필요
ADVICE_TEXT = {
    "must": "Windows 필수 구성요소 — 끄거나 지우지 마세요",
    "keep": "정상 동작 중 — 그대로 두세요",
    "close": "지금 안 쓰면 종료해도 됩니다",
    "remove": "인터넷 뱅킹·공공기관 사이트에서만 필요. 안 쓰면 제거해도 되고, 필요하면 사이트가 다시 설치합니다",
    "remove_rec": "직접 쓰는 게 아니라면 제거하세요 (원격 제어는 해킹 통로가 될 수 있음)",
    "check": "출처를 모르면 삭제를 권장합니다",
}
ADVICE_BY_NAME = {
    "pcblackbox.exe": ("keep", "PC BlackBox (이 프로그램)"), "pcmonitor.exe": ("keep", "PC BlackBox (이 프로그램)"), "pythonw.exe": ("keep", "PC BlackBox일 수 있음 — 그대로 두세요"),
    "claude.exe": ("keep", "지금 사용 중인 Claude"), "windowsterminal.exe": ("keep", "지금 사용 중인 터미널"),
    "microsoft.photos.exe": ("close", "종료해도 됩니다. 계속 뜨면: 설정 > 앱 > 설치된 앱 > 사진 > 고급 옵션 > 백그라운드 앱 권한 '안 함'"),
    "onedrive.exe": ("close", "OneDrive를 안 쓰면 종료하거나 제거해도 됩니다"),
    "googledrivefs.exe": ("keep", "Google 드라이브 동기화 — 쓰는 중이면 그대로 두세요"),
    "msmpeng.exe": ("must", "백신 — 절대 끄지 마세요. 검사 중엔 CPU가 높은 게 정상입니다"),
    "easysetup.app.exe": ("check", "Brother 프린터 드라이버 설치 도구입니다. USB 연결 시 충돌이 발생할 경우 Wi-Fi 무선 네트워크 설치를 권장합니다"),
    "easysetup.exe": ("check", "Brother 프린터 드라이버 설치 도구입니다. USB 연결 시 충돌이 발생할 경우 Wi-Fi 무선 네트워크 설치를 권장합니다"),
}

# 이름 일부로 알아보는 국내 인터넷 뱅킹·공공기관 보안 프로그램
KR_SECURITY = {
    "astx": "AhnLab Safe Transaction (뱅킹 보안)", "v3lite": "AhnLab V3 Lite 백신", "v3ltray": "AhnLab V3 Lite 백신", "delfino": "Delfino 공동인증서 전자서명",
    "veraport": "Veraport 보안 프로그램 설치 관리자", "ipinside": "IPinside 접속 단말 정보 수집 (뱅킹)",
    "touchen": "TouchEn 키보드 보안", "nprotect": "nProtect 키보드/온라인 보안", "magicline": "MagicLine 공동인증서",
    "anysign": "AnySign 전자서명", "crossex": "CrossEX 보안 확장", "kings": "Kings 보안", "wizvera": "WizVera 보안",
    "inisafe": "INISAFE 전자서명", "xecure": "XecureWeb 보안", "unisign": "UniSign 전자서명", "keysharp": "KeySharp 공동인증서",
    "tray_sign": "공동인증서 서명 도우미", "markany": "MarkAny 문서 보안(DRM)", "fasoo": "Fasoo 문서 보안(DRM)",
    "softcamp": "SoftCamp 문서 보안", "alyac": "알약 백신", "hauri": "ViRobot 백신", "naverwhale": "네이버 웨일",
}

_ver = ctypes.WinDLL("version.dll")
_ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
_ver.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
_ver.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]


def version_strings(path):
    """실행파일의 파일 설명/회사/제품명."""
    out = {}
    try:
        size = _ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return out
        buf = ctypes.create_string_buffer(size)
        if not _ver.GetFileVersionInfoW(path, 0, size, buf):
            return out
        p, n = ctypes.c_void_p(), wintypes.UINT()
        langs = []
        if _ver.VerQueryValueW(buf, r"\VarFileInfo\Translation", ctypes.byref(p), ctypes.byref(n)) and n.value >= 4:
            arr = ctypes.cast(p, ctypes.POINTER(wintypes.WORD * (n.value // 2))).contents
            langs = [f"{arr[i]:04x}{arr[i + 1]:04x}" for i in range(0, len(arr), 2)]
        langs += ["040904b0", "041204b0", "040904e4"]
        for key in ("FileDescription", "CompanyName", "ProductName"):
            for lc in langs:
                if _ver.VerQueryValueW(buf, f"\\StringFileInfo\\{lc}\\{key}", ctypes.byref(p), ctypes.byref(n)) and n.value:
                    s = ctypes.wstring_at(p, n.value).rstrip("\x00").strip()
                    if s:
                        out[key] = s
                        break
    except Exception:
        pass
    return out


def advice_for(key, info, kr_security=False):
    if key in ADVICE_BY_NAME:
        return ADVICE_BY_NAME[key]
    cat, co = info.get("cat"), (info.get("company") or "").lower()
    if cat in ("시스템", "업데이트") or (cat == "보안" and "microsoft" in co):
        return "must", ADVICE_TEXT["must"]
    if cat == "보안" or kr_security:
        return "remove", ADVICE_TEXT["remove"]
    if cat == "원격":
        return "remove_rec", ADVICE_TEXT["remove_rec"]
    if cat == "사용자 폴더":
        return "check", ADVICE_TEXT["check"]
    if cat == "서버":
        return "keep", ADVICE_TEXT["keep"]
    return "close", ADVICE_TEXT["close"]


class ProcInfo:
    def __init__(self):
        self.by_path = {}     # exe 경로 -> {desc, company}
        self.by_name = {}     # 이름(소문자) -> 마지막으로 본 정보 (과거 기록 표시용)
        self.svc_by_pid = {}
        self.svc_ts = 0
        self.lock = threading.Lock()

    def _services(self):
        if time.time() - self.svc_ts < 60:
            return self.svc_by_pid
        m = {}
        try:
            for s in psutil.win_service_iter():
                try:
                    d = s.as_dict()
                    if d.get("pid"):
                        m.setdefault(d["pid"], []).append(d.get("display_name") or d.get("name"))
                except Exception:
                    pass
        except Exception:
            pass
        self.svc_by_pid, self.svc_ts = m, time.time()
        return m

    def resolve_script_name(self, pid, name):
        """python/powershell/node/cmd 등 스크립트 실행기의 실제 실행 프로그램/스크립트명 및 설명 추출."""
        low_name = (name or "").lower()
        if low_name not in ("python.exe", "pythonw.exe", "powershell.exe", "pwsh.exe", "node.exe", "cmd.exe"):
            return None, None
        if not pid or pid <= 4:
            return None, None
        try:
            p = psutil.Process(pid)
            cmdline = p.cmdline()
        except Exception:
            return None, None
        if not cmdline:
            return None, None

        cmd_str = " ".join(cmdline)
        low_cmd = cmd_str.lower()

        # 1. Python
        if "python" in low_name:
            if "monitor.py" in low_cmd or "pcmon" in low_cmd:
                return "PC 모니터 (Python)", "PC 모니터 백그라운드 시스템 감시 데몬"
            if "antigravity" in low_cmd:
                return "Antigravity CLI (Python)", "Google Antigravity 지능형 개발 도우미"
            if "pytest" in low_cmd or "run_all_tests" in low_cmd or "test_" in low_cmd:
                return "테스트 러너 (Python)", "Python 자동화 테스트 스위트 실행기"
            if "pip" in low_cmd:
                return "pip 패키지 관리자", "Python 라이브러리 설치/관리 도구"
            for arg in cmdline[1:]:
                if arg.lower().endswith(".py"):
                    base = os.path.basename(arg)
                    return f"{base} (Python)", f"Python 스크립트: {base}"
            return "Python 작업 프로세스", "백그라운드에서 실행 중인 Python 프로그램"

        # 2. PowerShell
        if "powershell" in low_name or "pwsh" in low_name:
            if "antigravity" in low_cmd or "gemini" in low_cmd:
                return "Antigravity 터미널 (PowerShell)", "개발 도우미에서 호출한 PowerShell 세션"
            if "claude" in low_cmd:
                return "Claude 도구 세션 (PowerShell)", "Claude 데스크톱/CLI 터미널 세션"
            if "openconnect" in low_cmd or "vpn" in low_cmd:
                return "OpenConnect VPN (PowerShell)", "VPN 터널 연결 관리 스크립트"
            for i, arg in enumerate(cmdline):
                if arg.lower() in ("-file", "-f") and i + 1 < len(cmdline):
                    base = os.path.basename(cmdline[i + 1])
                    return f"{base} (PowerShell)", f"PowerShell 스크립트: {base}"
                if arg.lower().endswith(".ps1"):
                    base = os.path.basename(arg)
                    return f"{base} (PowerShell)", f"PowerShell 스크립트: {base}"
            return "PowerShell 명령 실행기", "명령어 및 관리 스크립트 실행 창"

        # 3. Node.js
        if "node" in low_name:
            if "claude" in low_cmd:
                return "Claude Desktop (Node.js)", "Anthropic Claude 데스크톱 백엔드"
            if "npm" in low_cmd:
                return "npm 패키지 도구", "Node.js 패키지 관리자"
            for arg in cmdline[1:]:
                if arg.lower().endswith(".js"):
                    base = os.path.basename(arg)
                    return f"{base} (Node.js)", f"Node.js 스크립트: {base}"
            return "Node.js 런타임", "Node.js 기반 백그라운드 프로그램"

        # 4. cmd.exe
        if "cmd.exe" in low_name:
            for arg in cmdline[1:]:
                if arg.lower().endswith((".bat", ".cmd")):
                    base = os.path.basename(arg)
                    return f"{base} (배치)", f"Windows 배치 파일: {base}"

        return None, None

    def describe(self, pid, name, exe=None):
        """{'desc','company','cat','path','services','display_name'}"""
        key = (name or "").lower()
        if exe is None:
            try:
                exe = psutil.Process(pid).exe()
            except Exception:
                exe = ""
        info = {"path": exe or "", "company": "", "desc": "", "cat": ""}

        # 스크립트 실행기(python, powershell, node 등) 세부 프로그램명 역추적
        disp_name, disp_desc = self.resolve_script_name(pid, name)
        if disp_name:
            info["display_name"] = disp_name
            if disp_desc:
                info["desc"] = disp_desc

        vs = {}
        if exe:
            with self.lock:
                vs = self.by_path.get(exe)
            if vs is None:
                vs = version_strings(exe)
                with self.lock:
                    self.by_path[exe] = vs
            info["company"] = vs.get("CompanyName", "")
            info["desc"] = vs.get("FileDescription") or vs.get("ProductName") or ""
        kr = next((v for k, v in KR_SECURITY.items() if k in key), None)
        if key in KNOWN:
            info["desc"], info["cat"] = KNOWN[key]
        elif kr:
            info["desc"], info["cat"] = kr, "보안"
        elif not info["cat"]:
            co = info["company"].lower()
            p = (exe or "").lower()
            if "microsoft" in co and ("\\windows\\" in p):
                info["cat"] = "시스템"
            elif "\\users\\" in p or "\\temp\\" in p:
                info["cat"] = "사용자 폴더"
            else:
                info["cat"] = "앱"
        if key == "svchost.exe":
            svcs = self._services().get(pid, [])
            if svcs:
                info["services"] = svcs[:4]
                info["desc"] = "서비스: " + ", ".join(svcs[:3]) + (f" 외 {len(svcs) - 3}개" if len(svcs) > 3 else "")
        if info["desc"] and info["desc"].lower() == key.rsplit(".", 1)[0]:
            info["desc"] = ""  # 파일 설명이 이름과 같으면 정보가 없는 것
        if not info["desc"]:
            info["desc"] = "설명 없음" + (" (서명·출처 확인 권장)" if info["cat"] == "사용자 폴더" else "")
        info["product"] = (vs.get("ProductName") if exe else "") or ""
        info["advice"], info["advice_text"] = advice_for(key, info, bool(kr))
        self._apply_note(key, info)
        with self.lock:
            if key != "svchost.exe":
                self.by_name[key] = {k: info.get(k, "") for k in ("desc", "company", "cat", "path", "advice", "advice_text", "product")}
        return info

    def _apply_note(self, key, info):
        """사용자 메모가 있으면 설명·권장을 메모로 바꿔 보여 준다."""
        n = getattr(self, "user_notes", {}).get(key)
        if not n:
            return info
        from finder import ADVICE_FROM_NOTE
        info["note"] = n.get("note", "")
        if n.get("note"):
            info["desc"] = "📝 " + n["note"]
        if n.get("verdict") in ADVICE_FROM_NOTE:
            info["advice"], info["advice_text"] = ADVICE_FROM_NOTE[n["verdict"]]
        return info

    def by_name_only(self, name):
        key = (name or "").lower()
        with self.lock:
            hit = self.by_name.get(key)
        if hit:
            return self._apply_note(key, dict(hit))
        if key in KNOWN:
            info = {"desc": KNOWN[key][0], "cat": KNOWN[key][1], "company": "", "path": ""}
            info["advice"], info["advice_text"] = advice_for(key, info)
            return self._apply_note(key, info)
        return self._apply_note(key, {"desc": "", "cat": "", "company": "", "path": "", "advice": "", "advice_text": ""})


PROCINFO = ProcInfo()


def get_memory_breakdown():
    """물리 RAM의 6대 포션(웹 브라우저군, 뱅킹보안, 사용자앱, Windows시스템, 커널풀, 가용메모리) 상세 분석"""
    import psutil
    from winutil import perf_info
    vm = psutil.virtual_memory()
    pi = perf_info()

    total_mb = int(vm.total / (1024 * 1024))
    available_mb = int(vm.available / (1024 * 1024))
    used_mb = max(0, total_mb - available_mb)

    # 커널 풀 (비페이징 + 페이징)
    paged_mb = int(pi.get("paged_pool_mb", 0) or 0)
    nonpaged_mb = int(pi.get("nonpaged_pool_mb", 0) or 0)
    kernel_mb = max(0, paged_mb + nonpaged_mb)

    banking_names = {
        "nosstarter.npe", "nprotect", "astx.exe", "astx64.exe", "touchen", "inisafe",
        "anysign", "crosscert", "deltasecrypt", "veraport", "ipinside", "wizvera"
    }
    browser_names = {
        "msedge.exe", "chrome.exe", "whale.exe", "firefox.exe", "msedgewebview2.exe",
        "brave.exe", "opera.exe"
    }
    system_names = {
        "system", "registry", "memory compression", "secure system", "smss.exe",
        "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
        "lsaiso.exe", "svchost.exe", "dwm.exe", "explorer.exe", "fontdrvhost.exe",
        "sihost.exe", "ctfmon.exe", "taskhostw.exe", "runtimebroker.exe", "dllhost.exe",
        "conhost.exe", "audiodg.exe", "spoolsv.exe", "searchindexer.exe", "searchhost.exe",
        "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe"
    }

    cats = {
        "browser": {"name": "🌐 웹 브라우저군", "mb": 0, "procs": 0, "color": "#3b82f6"},
        "banking": {"name": "🛡️ 뱅킹·보안 모듈", "mb": 0, "procs": 0, "color": "#f59e0b"},
        "apps": {"name": "📱 사용자 일반 앱", "mb": 0, "procs": 0, "color": "#8b5cf6"},
        "system": {"name": "⚙️ Windows 시스템", "mb": 0, "procs": 0, "color": "#10b981"},
        "kernel": {"name": "🧠 커널·드라이버 풀", "mb": kernel_mb, "procs": 1, "color": "#ec4899"},
        "available": {"name": "🍃 여유 (Available)", "mb": available_mb, "procs": 0, "color": "#64748b"},
    }

    proc_list = []
    seen_pids = set()
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            pid = p.info["pid"]
            if pid in (0, 4) or pid in seen_pids:
                continue
            seen_pids.add(pid)
            name = (p.info["name"] or "").lower()
            mi = p.info["memory_info"]
            rss_mb = int(getattr(mi, "rss", 0) / (1024 * 1024))
            if rss_mb <= 0:
                continue

            if any(k in name for k in banking_names):
                cat_key = "banking"
            elif any(k == name for k in browser_names):
                cat_key = "browser"
            elif any(k == name for k in system_names):
                cat_key = "system"
            else:
                cat_key = "apps"

            cats[cat_key]["mb"] += rss_mb
            cats[cat_key]["procs"] += 1
            proc_list.append({
                "pid": pid,
                "name": p.info["name"] or name,
                "cat": cat_key,
                "mem_mb": rss_mb,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    for k, v in cats.items():
        v["pct"] = round((v["mb"] / max(total_mb, 1)) * 100, 1)

    proc_list.sort(key=lambda x: x["mem_mb"], reverse=True)
    top15 = proc_list[:15]
    for p in top15:
        p["info"] = PROCINFO.by_name_only(p["name"])

    return {
        "total_mb": total_mb,
        "used_mb": used_mb,
        "available_mb": available_mb,
        "commit_pct": pi.get("commit_pct", 0),
        "commit_total_mb": pi.get("commit_total_mb", 0),
        "commit_limit_mb": pi.get("commit_limit_mb", 0),
        "paged_pool_mb": paged_mb,
        "nonpaged_pool_mb": nonpaged_mb,
        "portions": cats,
        "top_procs": top15,
    }


def optimize_memory():
    """Windows EmptyWorkingSet API를 호출하여 안전하게 비활성 메모리 회수"""
    import ctypes
    psapi = ctypes.windll.psapi
    kernel32 = ctypes.windll.kernel32
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_SET_QUOTA = 0x0100

    vm_before = psutil.virtual_memory()
    trimmed_count = 0
    for p in psutil.process_iter(['pid', 'name']):
        try:
            pid = p.info['pid']
            if pid in (0, 4):
                continue
            h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, False, pid)
            if h:
                if psapi.EmptyWorkingSet(h):
                    trimmed_count += 1
                kernel32.CloseHandle(h)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    vm_after = psutil.virtual_memory()
    saved_mb = max(0, int((vm_after.available - vm_before.available) / (1024 * 1024)))
    return {
        "ok": True,
        "count": trimmed_count,
        "saved_mb": saved_mb,
        "free_before_mb": int(vm_before.available / (1024 * 1024)),
        "free_after_mb": int(vm_after.available / (1024 * 1024)),
        "msg": f"안전하게 {saved_mb}MB의 메모리를 즉시 회수했습니다. (최적화 대상: {trimmed_count}개 프로세스)"
    }

