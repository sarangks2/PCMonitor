"""시스템 트레이 아이콘 관리 (순수 Win32 ctypes 구현).

백그라운드로 실행 중일 때 작업 표시줄 오른쪽 알림 영역에 아이콘을 띄우고,
더블클릭/우클릭 메뉴를 통해 대시보드 화면을 열거나 백그라운드를 완전히 종료할 수 있다.
"""
import ctypes
from ctypes import wintypes
import logging
import os
import threading

log = logging.getLogger("pcmon.tray")

user32 = ctypes.windll.user32
shell32 = ctypes.windll.shell32
kernel32 = ctypes.windll.kernel32

LRESULT = ctypes.c_ssize_t
user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = LRESULT
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

WM_USER = 0x0400
WM_TRAY = WM_USER + 42
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205

NIM_ADD = 0
NIM_MODIFY = 1
NIM_DELETE = 2
NIF_MESSAGE = 0x01
NIF_ICON = 0x02
NIF_TIP = 0x04
NIF_INFO = 0x10
NIIF_INFO = 0x01

ID_MENU_OPEN = 1001
ID_MENU_EXIT = 1002


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HICON),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HICON),
    ]


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_byte * 8),
    ]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", GUID),
        ("hBalloonIcon", wintypes.HICON),
    ]


class TrayIcon:
    def __init__(self, icon_path, tooltip="PC BlackBox", on_open=None, on_exit=None):
        self.icon_path = icon_path
        self.tooltip = tooltip
        self.on_open = on_open
        self.on_exit = on_exit
        self.hwnd = None
        self.nid = None
        self.thread = None
        self.ready_event = threading.Event()
        self.class_name = f"PCMonTray_{os.getpid()}_{id(self)}"
        self._proc_delegate = None
        self.h_icon = None

    def start(self):
        """별도 스레드에서 윈도우 메시지 루프를 실행."""
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.ready_event.wait(timeout=5)

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAY:
            if lparam in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                if self.on_open:
                    threading.Thread(target=self.on_open, daemon=True).start()
                return 0
            elif lparam == WM_RBUTTONUP:
                self._show_menu(hwnd)
                return 0
        elif msg == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _show_menu(self, hwnd):
        menu = user32.CreatePopupMenu()
        user32.AppendMenuW(menu, 0, ID_MENU_OPEN, "📊 PC BlackBox 대시보드 열기")
        user32.AppendMenuW(menu, 0x00000800, 0, "")  # 구분선
        user32.AppendMenuW(menu, 0, ID_MENU_EXIT, "🛑 PC BlackBox 완전 종료 (백그라운드 중지)")

        user32.SetForegroundWindow(hwnd)
        pt = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        cmd = user32.TrackPopupMenu(menu, 0x0100 | 2, pt.x, pt.y, 0, hwnd, None)  # TPM_RETURNCMD | TPM_RIGHTBUTTON
        user32.DestroyMenu(menu)
        user32.PostMessageW(hwnd, 0, 0, 0)

        if cmd == ID_MENU_OPEN and self.on_open:
            threading.Thread(target=self.on_open, daemon=True).start()
        elif cmd == ID_MENU_EXIT:
            res = user32.MessageBoxW(
                hwnd,
                "PC BlackBox 백그라운드 감시를 완전히 종료할까요?\n\n종료하면 자원 기록, 장애 분석, 인터넷뱅킹 보안 관리가 모두 중단되며 작업 스케줄러 자동 실행도 중단됩니다.",
                "PC BlackBox 완전 종료",
                0x00000004 | 0x00000020 | 0x00040000,  # MB_YESNO | MB_ICONQUESTION | MB_TOPMOST
            )
            if res == 6:  # IDYES
                if self.on_exit:
                    threading.Thread(target=self.on_exit, daemon=True).start()

    def _run(self):
        hinst = kernel32.GetModuleHandleW(None)
        self._proc_delegate = WNDPROC(self._wnd_proc)

        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._proc_delegate
        wc.hInstance = hinst
        wc.lpszClassName = self.class_name
        user32.RegisterClassExW(ctypes.byref(wc))

        self.hwnd = user32.CreateWindowExW(
            0, self.class_name, "PCMonTrayWnd",
            0, 0, 0, 0, 0,
            None, None, hinst, None,
        )

        h_icon = 0
        if self.icon_path and os.path.exists(self.icon_path):
            h_icon = user32.LoadImageW(None, self.icon_path, 1, 0, 0, 0x00000010 | 0x00000040)
        if not h_icon:
            h_icon = user32.LoadIconW(None, 32512)
        self.h_icon = h_icon

        self.nid = NOTIFYICONDATAW()
        self.nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        self.nid.hWnd = self.hwnd
        self.nid.uID = 1
        self.nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        self.nid.uCallbackMessage = WM_TRAY
        self.nid.hIcon = h_icon
        self.nid.szTip = self.tooltip[:127]

        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(self.nid))
        self.ready_event.set()

        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        try:
            user32.UnregisterClassW(self.class_name, hinst)
        except Exception:
            pass

    def show_balloon(self, title, text):
        """트레이 풍선(알림) 표시. 윈도우 10/11 알림 센터 토스트로 발신자 'PC 모니터' 보장."""
        try:
            import winutil
            winutil.toast(title, text)
            return
        except Exception:
            pass
        if not self.hwnd or not self.nid:
            return
        b_nid = NOTIFYICONDATAW()
        b_nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        b_nid.hWnd = self.hwnd
        b_nid.uID = 1
        b_nid.uFlags = NIF_INFO
        b_nid.szInfoTitle = (title or "")[:63]
        b_nid.szInfo = (text or "")[:255]
        b_nid.dwInfoFlags = NIIF_INFO
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(b_nid))

    def update_tooltip(self, text):
        if not self.hwnd or not self.nid:
            return
        self.nid.uFlags = NIF_TIP
        self.nid.szTip = (text or "")[:127]
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self.nid))

    def stop(self):
        """트레이 아이콘 제거 및 윈도우 파괴."""
        if self.hwnd and self.nid:
            try:
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self.nid))
            except Exception:
                pass
            try:
                user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)
            except Exception:
                pass
            if self.thread and self.thread.is_alive():
                try:
                    self.thread.join(timeout=1.0)
                except Exception:
                    pass
            if self.h_icon:
                try:
                    user32.DestroyIcon(self.h_icon)
                except Exception:
                    pass
                self.h_icon = None
            try:
                user32.UnregisterClassW(self.class_name, kernel32.GetModuleHandleW(None))
            except Exception:
                pass
            self.hwnd = None
            self.nid = None
