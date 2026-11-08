"""Windows 전용 도우미: 이벤트 로그 읽기(wevtapi), PowerShell 실행, 알림 팝업, 성능 정보."""
import base64
import ctypes
import json
import logging
import os
import subprocess
import threading
import winreg
import xml.etree.ElementTree as ET
from ctypes import wintypes
from datetime import datetime
from xml.sax.saxutils import escape

import config

log = logging.getLogger("pcmon.winutil")


CREATE_NO_WINDOW = 0x08000000
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# ---------------------------------------------------------------- 이벤트 로그
_wevt = ctypes.WinDLL("wevtapi.dll", use_last_error=True)
EVT_HANDLE = ctypes.c_void_p
_wevt.EvtQuery.argtypes = [EVT_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
_wevt.EvtQuery.restype = EVT_HANDLE
_wevt.EvtNext.argtypes = [EVT_HANDLE, wintypes.DWORD, ctypes.POINTER(EVT_HANDLE), wintypes.DWORD,
                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
_wevt.EvtNext.restype = wintypes.BOOL
_wevt.EvtRender.argtypes = [EVT_HANDLE, EVT_HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
_wevt.EvtRender.restype = wintypes.BOOL
_wevt.EvtClose.argtypes = [EVT_HANDLE]

EvtQueryChannelPath = 0x1
EvtQueryForwardDirection = 0x100
EvtQueryReverseDirection = 0x200
EvtRenderEventXml = 1


class EventLogAccessDenied(Exception):
    pass


def _render(h):
    used = wintypes.DWORD(0)
    count = wintypes.DWORD(0)
    size = 8192
    while True:
        buf = ctypes.create_unicode_buffer(size // 2)
        if _wevt.EvtRender(None, h, EvtRenderEventXml, size, buf, ctypes.byref(used), ctypes.byref(count)):
            return buf.value
        if ctypes.get_last_error() == 122:  # ERROR_INSUFFICIENT_BUFFER
            size = used.value + 2
            continue
        return None


def parse_event_xml(x):
    root = ET.fromstring(x)
    sys_ = root.find("e:System", NS)
    st = sys_.find("e:TimeCreated", NS).get("SystemTime")
    # 2026-11-01T10:08:17.5000000Z  -> epoch
    st = st.rstrip("Z")
    if "." in st:
        head, frac = st.split(".")
        st = head + "." + frac[:6]
        dt = datetime.strptime(st, "%Y-%m-%dT%H:%M:%S.%f")
    else:
        dt = datetime.strptime(st, "%Y-%m-%dT%H:%M:%S")
    from datetime import timezone
    ts = dt.replace(tzinfo=timezone.utc).timestamp()
    data = {}
    ed = root.find("e:EventData", NS)
    if ed is not None:
        for i, d in enumerate(ed.findall("e:Data", NS)):
            data[d.get("Name") or f"p{i}"] = (d.text or "")
    ud = root.find("e:UserData", NS)
    if ud is not None:
        for el in ud.iter():
            if el.text and el.text.strip() and len(el) == 0:
                data[el.tag.split("}")[-1]] = el.text.strip()
    prov = sys_.find("e:Provider", NS)
    return {
        "id": int(sys_.find("e:EventID", NS).text),
        "record": int(sys_.find("e:EventRecordID", NS).text),
        "level": int((sys_.find("e:Level", NS).text or "0")),
        "provider": prov.get("Name") if prov is not None else "",
        "ts": ts,
        "data": data,
    }


def query_events(channel, xpath, max_events=2000, reverse=False):
    """channel에서 xpath에 맞는 이벤트를 반환 (기본: 오래된 순, reverse=True: 최신 순)."""
    h = _wevt.EvtQuery(None, channel, xpath,
                       EvtQueryChannelPath | (EvtQueryReverseDirection if reverse else EvtQueryForwardDirection))
    if not h:
        err = ctypes.get_last_error()
        if err == 5:
            raise EventLogAccessDenied(channel)
        if err in (15007, 15002):  # 채널 없음/비활성
            return []
        raise OSError(err, f"EvtQuery 실패: {channel}")
    out = []
    try:
        arr = (EVT_HANDLE * 64)()
        n = wintypes.DWORD(0)
        while len(out) < max_events:
            if not _wevt.EvtNext(h, 64, arr, 1000, 0, ctypes.byref(n)):
                break  # 259 = 더 없음
            for i in range(n.value):
                try:
                    x = _render(arr[i])
                    if x:
                        out.append(parse_event_xml(x))
                except Exception:
                    pass
                finally:
                    _wevt.EvtClose(arr[i])
    finally:
        _wevt.EvtClose(h)
    return out


# ---------------------------------------------------------------- 성능 정보
class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("CommitTotal", ctypes.c_size_t), ("CommitLimit", ctypes.c_size_t),
                ("CommitPeak", ctypes.c_size_t), ("PhysicalTotal", ctypes.c_size_t),
                ("PhysicalAvailable", ctypes.c_size_t), ("SystemCache", ctypes.c_size_t),
                ("KernelTotal", ctypes.c_size_t), ("KernelPaged", ctypes.c_size_t),
                ("KernelNonpaged", ctypes.c_size_t), ("PageSize", ctypes.c_size_t),
                ("HandleCount", wintypes.DWORD), ("ProcessCount", wintypes.DWORD), ("ThreadCount", wintypes.DWORD)]


def perf_info():
    pi = PERFORMANCE_INFORMATION()
    pi.cb = ctypes.sizeof(pi)
    ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb)
    return {
        "commit_pct": 100.0 * pi.CommitTotal / pi.CommitLimit if pi.CommitLimit else 0,
        "handles": pi.HandleCount, "procs": pi.ProcessCount, "threads": pi.ThreadCount,
    }


class OSVERSIONINFOEXW(ctypes.Structure):
    _fields_ = [("dwOSVersionInfoSize", wintypes.DWORD), ("dwMajorVersion", wintypes.DWORD),
                ("dwMinorVersion", wintypes.DWORD), ("dwBuildNumber", wintypes.DWORD), ("dwPlatformId", wintypes.DWORD),
                ("szCSDVersion", wintypes.WCHAR * 128), ("wServicePackMajor", wintypes.WORD),
                ("wServicePackMinor", wintypes.WORD), ("wSuiteMask", wintypes.WORD), ("wProductType", ctypes.c_byte),
                ("wReserved", ctypes.c_byte)]


def os_info():
    """{'name','build','server','dc','system'} - PC인지 서버인지, SYSTEM 계정으로 도는지."""
    v = OSVERSIONINFOEXW()
    v.dwOSVersionInfoSize = ctypes.sizeof(v)
    try:
        ctypes.WinDLL("ntdll").RtlGetVersion(ctypes.byref(v))
    except Exception:
        pass
    name, disp = "Windows", ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            name = winreg.QueryValueEx(k, "ProductName")[0]
            try:
                disp = winreg.QueryValueEx(k, "DisplayVersion")[0]
            except OSError:
                pass
    except Exception:
        pass
    if v.wProductType == 1 and v.dwBuildNumber >= 22000:
        name = name.replace("Windows 10", "Windows 11")
    return {"name": (name + (" " + disp if disp else "")).strip(), "build": v.dwBuildNumber,
            "server": v.wProductType in (2, 3), "dc": v.wProductType == 2, "system": is_system()}


def is_system():
    return os.environ.get("USERNAME", "").endswith("$") or os.environ.get("USERPROFILE", "").lower().endswith("systemprofile")


def session_message(title, body):
    """사용자 작업 방해 금지를 위해 모달 Win32 MessageBox(WTSSendMessageW) 팝업을 전면 폐지하고 로그만 기록."""
    log.info("비간섭 알림 기록 (모달 창 억제됨): %s - %s", title, body.replace("\n", " ") if body else "")



def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------- PowerShell
def run_ps(script, timeout=60):
    """스크립트를 숨김 창으로 실행하고 stdout(UTF-8)을 반환."""
    full = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';" + script
    enc = base64.b64encode(full.encode("utf-16-le")).decode()
    try:
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-EncodedCommand", enc],
                           capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return ""  # PC가 매우 바쁠 때(백신 전체 검사 등) - 호출한 쪽이 나중에 다시 시도
    except OSError:
        return ""
    return r.stdout.decode("utf-8", errors="replace").strip()


def run_ps_json(script, timeout=60):
    out = run_ps(script, timeout)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def _b64(s):
    return base64.b64encode(s.encode("utf-8")).decode()


_aumid_checked = False


def ensure_aumid():
    r"""HKCU\Software\Classes\AppUserModelId\PCMonitor 등록 (알림 센터에 'PC BlackBox' 및 아이콘 표시)."""
    global _aumid_checked
    if _aumid_checked:
        return
    try:
        # 프로세스 레벨 AUMID 설정
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PCMonitor")
        except Exception:
            pass

        icon = os.path.join(config.RES_DIR, "pcmon.ico")
        if not os.path.isfile(icon):
            icon = os.path.join(config.BASE_DIR, "pcmon.ico")

        # 1. AppUserModelId 레지스트리 등록
        key_path = r"Software\Classes\AppUserModelId\PCMonitor"
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "PC BlackBox")
            if os.path.isfile(icon):
                winreg.SetValueEx(key, "IconUri", 0, winreg.REG_SZ, icon)
            winreg.SetValueEx(key, "IconBackgroundColor", 0, winreg.REG_SZ, "FF0078D7")

        # 2. pythonw.exe 및 python.exe FriendlyAppName 을 'PC BlackBox'로 통일 (OS 폴백 대비)
        for app in ("pythonw.exe", "python.exe"):
            try:
                with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, rf"Software\Classes\Applications\{app}", 0, winreg.KEY_SET_VALUE) as k:
                    winreg.SetValueEx(k, "FriendlyAppName", 0, winreg.REG_SZ, "PC BlackBox")
            except Exception:
                pass

        # 3. 시작 메뉴에 AUMID 바인딩된 바로가기 확보 (윈도우 셸 인덱싱)
        programs = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs")
        lnk_path = os.path.join(programs, "PC BlackBox.lnk")
        if os.path.isdir(programs) and not os.path.isfile(lnk_path):
            try:
                sc_script = (
                    f"$ws=New-Object -ComObject WScript.Shell;"
                    f"$s=$ws.CreateShortcut('{lnk_path}');"
                    f"$s.TargetPath='{os.path.join(config.BASE_DIR, 'launcher.bat')}';"
                    f"$s.WorkingDirectory='{config.BASE_DIR}';"
                    f"$s.Description='PC BlackBox';"
                    f"$s.IconLocation='{icon},0';"
                    f"$s.Save();"
                )
                run_ps(sc_script, timeout=10)
            except Exception:
                pass

        _aumid_checked = True
    except Exception as e:
        log.warning("AUMID 등록 실패: %s", e)


def toast(title, body):
    """Windows 알림 센터 팝업. 발신자 'PC 모니터' 표기. (모달 확인창 팝업 제거하여 단일 알림 보장)"""
    if is_system():
        log.info("SYSTEM 세션 감지: 데스크톱 토스트 대신 DB 기록: %s", title)
        return
    ensure_aumid()
    t, b = _b64(escape(title)), _b64(escape(body))
    # AUMID 'PCMonitor'로 ToastNotifier 생성 -> 윈도우 알림 센터에 'PC 모니터'로 표시
    script = (
        "$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));"
        "$b=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));"
        "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;"
        "[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]|Out-Null;"
        "$x=New-Object Windows.Data.Xml.Dom.XmlDocument;"
        "$x.LoadXml(\"<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>\");"
        "$n=[Windows.UI.Notifications.ToastNotification]::new($x);"
        "try { [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('PCMonitor').Show($n) }"
        "catch { try { [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier().Show($n) } catch {} }"
    ) % (t, b)
    def run():
        try:
            r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                                base64.b64encode(script.encode("utf-16-le")).decode()],
                               creationflags=CREATE_NO_WINDOW, capture_output=True, timeout=60)
            if r.returncode != 0 and r.stderr.strip():
                log.warning("토스트 출력 경고: %s", r.stderr.strip()[:100])
        except Exception as e:
            log.warning("토스트 실행 예외: %s", e)

    threading.Thread(target=run, daemon=True).start()




def signature_status(paths):
    """실행파일 경로 목록의 디지털 서명 상태 {path: 'Valid'|'NotSigned'|...}."""
    if not paths:
        return {}
    arr = ",".join("[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))" % _b64(p) for p in paths)
    script = ("$r=@{};foreach($p in @(%s)){try{$s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop;"
              "$r[$p]=@{s=[string]$s.Status;n=[string]$s.SignerCertificate.Subject}}catch{$r[$p]=@{s='Error';n=''}}};"
              "$r|ConvertTo-Json -Compress") % arr
    return run_ps_json(script, timeout=120) or {}
