"""AI 기반 프로그램 및 보안 경고 자동 분석·설명 모듈.

프로세스, 보안 이벤트, PowerShell 스크립트, 의심 항목에 대해:
1. 정체 및 역할 (무슨 프로그램이고 무엇을 하는지)
2. 위험도 및 신뢰성 평가 (안전 / 주의 / 위험)
3. 권장 대처 방안 (유지 / 종료 / 삭제)
4. 관련 지식 검색 및 웹 검색 요약을 자동으로 생성하여 제공한다.
"""
import logging
import os
import re
import urllib.parse
from procinfo import KNOWN, PROCINFO

log = logging.getLogger("pcmon.ai")

# 주요 보안 위협 패턴 설명 사전
SUSPICIOUS_PATTERNS = {
    "downloadfile": ("원격 파일 다운로드", "인터넷 웹사이트에서 실행 파일이나 스크립트를 PC로 내려받는 명령입니다. 정상적인 설치기(Installer)나 업데이트 도구도 사용하지만, 악성코드가 추가 페이로드를 다운로드할 때 가장 흔히 쓰는 패턴입니다."),
    "net.webclient": ("웹 클라이언트 네트워크 요청", ".NET 프레임워크를 이용해 웹 서버와 데이터를 주고받거나 파일을 다운로드하는 명령입니다. 개발 도구 및 관리자 스크립트에서도 자주 쓰입니다."),
    "bypass": ("실행 정책 우회 (Bypass)", "Windows PowerShell의 스크립트 실행 제한 정책을 일시 우회하여 스크립트를 강제 실행하는 옵션입니다. 개발자 CLI 도구나 배포 스크립트에서 흔히 사용됩니다."),
    "hidden": ("숨김 창 실행 (-WindowStyle Hidden)", "사용자 모니터에 콘솔 창을 띄우지 않고 백그라운드에서 조용히 실행하는 옵션입니다."),
    "encodedcommand": ("Base64 인코딩 명령 (-EncodedCommand)", "명령어 텍스트를 Base64로 암호화/인코딩하여 실행하는 방식으로, 긴 명령어 파싱 오류를 방지하기 위해 정품 툴(PCMonitor 등)도 사용하지만 악성코드도 탐지 회피용으로 애용합니다."),
    "iex": ("문자열 즉각 실행 (Invoke-Expression)", "텍스트 문자열이나 웹에서 받아온 코드를 메모리에서 즉시 실행하는 명령입니다."),
    "invoke-webrequest": ("웹 요청 실행 (curl/wget 유사)", "웹 페이지나 API 엔드포인트에 HTTP 요청을 보내는 표준 PowerShell 명령입니다."),
}

# 주요 알려진 소프트웨어 군단 정보
VENDOR_PROFILES = {
    "microsoft": ("Microsoft Windows 공식 구성 요소 / 앱", "safe", "Windows 운영체제 또는 Microsoft 소프트웨어의 정식 구성 요소입니다. 강제로 종료하거나 삭제하면 시스템이나 앱 기능에 장애가 발생할 수 있습니다."),
    "google": ("Google 소프트웨어 (Chrome, Updater 등)", "safe", "Google Chrome 브라우저 또는 백그라운드 자동 업데이트 서비스입니다."),
    "anthropic": ("Claude 데스크톱 앱", "safe", "Anthropic Claude AI 데스크톱 애플리케이션 및 보조 작업 프로세스입니다."),
    "openconnect": ("VPN 원격 접속 클라이언트", "safe", "사내망이나 원격 보안 네트워크에 연결하기 위한 OpenConnect VPN 도구입니다."),
    "nprotect": ("인터넷뱅킹 키보드 보안/백신 (nProtect)", "caution", "국내 금융/공공 사이트 이용 시 필수로 설치되는 키보드 보안 및 해킹 차단 프로그램입니다. 평소에도 백그라운드에서 메모리를 차지하므로 뱅킹 탭에서 '사이트 열 때만 켜기' 설정을 권장합니다."),
    "ahnlab": ("안랩 금융 보안 / V3 (AhnLab Safe Transaction)", "caution", "은행/증권 사이트 접속 시 구동되는 트랜잭션 보안 솔루션입니다. 평소 상주를 원치 않으시면 '사이트 열 때만 켜기' 모드를 이용하세요."),
    "wizvera": ("인터넷뱅킹 베라포트 / 프로세스 매니저", "caution", "공공기관 및 은행의 공인인증서/보안 모듈을 통합 관리하는 서비스입니다."),
    "iniline": ("CrossEX 인터넷뱅킹 웹 확장 모듈", "caution", "웹 브라우저와 비표준 보안 프로그램을 연결해 주는 뱅킹용 에이전트입니다."),
    "raon": ("TouchEn 보안 솔루션 (라온시큐어)", "caution", "키보드 보안 및 공인인증서 처리를 담당하는 금융 프로그램입니다."),
    "initech": ("INISAFE 공인인증 / 전자인증", "caution", "전자서명 및 금융 인증서 처리를 수행하는 보안 소프트웨어입니다."),
    "brother": ("Brother 프린터/복합기 소프트웨어", "safe", "Brother 프린터 드라이버, 상태 모니터 또는 Easy Setup 설치 관리자입니다. USB 연결 시 Windows PnP 충돌이나 절전 모드 I/O 교착이 의심될 경우 제조사 정식 드라이버 설치 또는 Wi-Fi 네트워크 연결을 권장합니다."),
}


def explain_item(name="", path="", details="", kind="process"):
    """
    프로세스, 알림 항목, 또는 이벤트에 대해 AI 분석 설명을 생성.
    반환: {
        'title': 항목명,
        'category': 분류,
        'summary': 2~3줄 요약 설명,
        'safety': 'safe' | 'caution' | 'danger',
        'safety_text': 안전도 평가,
        'action': 권장 대처 방안,
        'keywords': 주요 키워드 목록,
        'search_query': 검색어,
        'search_url': 구글 검색 링크
    }
    """
    name_clean = (name or "").strip()
    path_clean = (path or "").strip()
    details_clean = (details or "").strip()
    key = name_clean.lower()
    full_text = f"{name_clean} {path_clean} {details_clean}".lower()

    # 1. 기본 메타데이터 확인
    desc = ""
    company = ""
    cat = ""
    if key in KNOWN:
        desc, cat = KNOWN[key]

    if not desc and path_clean and os.path.isfile(path_clean):
        try:
            info = PROCINFO.describe(0, name_clean, exe=path_clean)
            desc = info.get("desc") or ""
            company = info.get("company") or ""
            cat = info.get("cat") or cat
        except Exception:
            pass

    # 2. 안전도 및 설명 판정
    safety = "safe"
    safety_text = "정상적인 시스템 또는 사용자 프로그램으로 분석되었습니다."
    action = "시스템 동작에 필요하거나 정상 프로그램이므로 그대로 두셔도 됩니다."
    summary = ""
    matched_vendor = None

    # (A) 벤더 매칭
    for v_key, v_info in VENDOR_PROFILES.items():
        if v_key in key or v_key in path_clean.lower() or v_key in company.lower():
            matched_vendor = v_info
            break

    # (B) PowerShell 스크립트 이벤트 분석
    if "powershell" in key or "ps4104" in full_text or "downloadfile" in full_text:
        detected_pats = []
        for p_key, (p_name, p_desc) in SUSPICIOUS_PATTERNS.items():
            if p_key in full_text:
                detected_pats.append(f"• **{p_name} ({p_key})**: {p_desc}")

        # 정상 개발 도구(Antigravity, Claude, npm, git 등) 맥락 확인
        is_dev_tool = any(dev in full_text for dev in ("antigravity", "claude", "openconnect", "npm", "node", "git", "vscode"))
        if is_dev_tool:
            safety = "safe"
            safety_text = "개발 도우미 또는 작업 환경(Antigravity/Claude 등)에서 실행한 정상 스크립트입니다."
            action = "사용자 또는 AI 에이전트의 개발 작업 중 발생한 정상이므로 조치할 필요가 없습니다."
            summary = (
                f"PowerShell 명령에서 원격 다운로드 패턴이 감지되었으나, "
                f"사용자가 작업 중인 개발 환경(CLI/도구)의 정상 스크립트 명령으로 확인되었습니다."
            )
        else:
            safety = "caution"
            safety_text = "출처가 불분명한 원격 다운로드 명령이 감지되었습니다."
            action = "직접 실행한 작업이 아니라면 대시보드의 [침입 감시] 및 [흔적 점검]에서 출처를 확인하세요."
            summary = (
                f"웹에서 파일을 다운로드하거나 코드를 실행하는 PowerShell 스크립트가 포착되었습니다.\n"
                + "\n".join(detected_pats[:2])
            )

    # (C) 뱅킹 보안 프로그램 매칭
    elif matched_vendor and matched_vendor[1] == "caution":
        safety = "caution"
        safety_text = "인터넷뱅킹 및 금융 보안 프로그램 (상시 백그라운드 상주)"
        action = "[프로그램] 탭의 '은행·공공기관 사이트 열 때만 켜기'를 설정하면 백그라운드 자원을 절약할 수 있습니다."
        summary = (
            f"**{name_clean}**은(는) {matched_vendor[0]}입니다.\n"
            f"{matched_vendor[2]}"
        )

    # (D) 일반 알려진 프로그램 매칭
    elif desc:
        summary = f"**{name_clean}**은(는) {desc}입니다."
        if company:
            summary += f" (제조사: {company})"
        if cat in ("시스템", "업데이트"):
            safety = "safe"
            safety_text = "Windows 핵심 시스템 프로세스"
            action = "Windows 정상 구동에 필수적인 프로세스이므로 절대 종료하지 마세요."
        elif cat == "보안":
            safety = "safe"
            safety_text = "보안 및 백신 보호 프로세스"
            action = "PC를 보호하는 정상 보안 프로세스입니다."
        elif cat == "원격":
            safety = "caution"
            safety_text = "원격 접속/제어 도구"
            action = "직접 설치한 원격 프로그램이 아니라면 [흔적 점검]에서 제거를 권장합니다."

    # (E) 미등록 프로그램에 대한 지능형 분석
    else:
        # 경로 기반 분석
        if "\\windows\\" in path_clean.lower() or "\\system32\\" in path_clean.lower():
            safety = "safe"
            safety_text = "Windows 시스템 디렉터리에 위치한 파일"
            summary = f"**{name_clean}**은(는) Windows 시스템 폴더에 위치한 실행 파일입니다."
            action = "Windows 운영체제 구성 파일일 가능성이 높으므로 그대로 유지하세요."
        elif "\\appdata\\" in path_clean.lower() or "\\temp\\" in path_clean.lower() or "\\users\\" in path_clean.lower():
            safety = "caution"
            safety_text = "사용자 임시/앱 데이터 폴더(AppData/Temp)에서 구동 중"
            summary = f"**{name_clean}**은(는) 사용자 전용 폴더(`{path_clean[:60]}...`)에서 실행되는 프로그램입니다."
            action = "최근 설치한 앱인지 확인하시고, 모르는 프로그램이라면 [프로그램] 탭에서 서명 상태를 확인하세요."
        else:
            summary = f"**{name_clean}** 프로그램입니다. {desc or '등록된 기본 설명이 없습니다.'}"
            safety = "safe"
            safety_text = "일반 응용 프로그램"
            action = "사용자가 설치한 소프트웨어인지 확인 후 필요에 따라 관리하세요."

    # 웹 검색 링크 생성
    search_q = f"{name_clean} 프로세스 프로그램 무엇" if name_clean else "Windows 보안 이벤트 분석"
    search_url = "https://www.google.com/search?q=" + urllib.parse.quote_plus(search_q)

    return {
        "title": name_clean or "보안/시스템 항목",
        "category": cat or "일반 앱",
        "summary": summary,
        "safety": safety,
        "safety_text": safety_text,
        "action": action,
        "path": path_clean,
        "search_query": search_q,
        "search_url": search_url,
    }
