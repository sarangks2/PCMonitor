"""PC BlackBox (PC 블랙박스) 설정값. 필요하면 여기 숫자만 바꾸면 된다."""
import os
import sys

APP_NAME = "PC BlackBox"
APP_NAME_KO = "PC 블랙박스"
VERSION = "1.5.0"
GITHUB_URL = "https://github.com/sarangks2/PCMonitor"   # 저장소 주소 (정보 화면에 표시)

if getattr(sys, "frozen", False):
    # exe로 실행: 기록은 exe 옆 data 폴더, dashboard.html 은 exe 안에 포함
    BASE_DIR = os.path.dirname(sys.executable)
    RES_DIR = getattr(sys, "_MEIPASS", BASE_DIR)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    RES_DIR = BASE_DIR
# 기록 위치: 환경변수 PCMON_DATA > 실행파일 옆 data 폴더(이미 있으면) > ProgramData\PCMonitor
_local = os.path.join(BASE_DIR, "data")
if os.environ.get("PCMON_DATA"):
    DATA_DIR = os.environ["PCMON_DATA"]
elif os.path.isdir(_local) or not getattr(sys, "frozen", False):
    DATA_DIR = _local
else:
    DATA_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "PCMonitor")
DB_PATH = os.path.join(DATA_DIR, "pcmon.db")
LOG_PATH = os.path.join(DATA_DIR, "pcmon.log")
TOKEN_PATH = os.path.join(DATA_DIR, "access.token")   # 대시보드 접근 열쇠 (설치한 사용자·관리자만 읽기 가능)

SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:") + "\\"
EXCLUDE_DRIVES = tuple(d.strip().upper() for d in os.environ.get("PCMON_EXCLUDE_DRIVES", "F:").split(",") if d.strip())
MIN_DRIVE_TOTAL_GB = 1.0  # 1GB 미만 특수 파티션(시스템 예약 100MB, 복구 파티션 등) 자동 제외

# 대시보드: 이 PC에서만 접속 가능 (외부 노출 안 함). 포트는 PCMON_PORT 로 변경 가능
HTTP_HOST = "127.0.0.1"
HTTP_PORT = int(os.environ.get("PCMON_PORT", "8765"))

# 수집 주기 (초)
SAMPLE_INTERVAL = 10          # CPU/메모리/디스크/네트워크 + 생존신호
PROC_SNAPSHOT_INTERVAL = 60   # 상위 프로세스 기록
EVENTLOG_INTERVAL = 60        # 이벤트 로그(보안/장애) 확인
PERSISTENCE_INTERVAL = 600    # 시작프로그램/서비스/예약작업 변경 확인
DEFENDER_INTERVAL = 1800      # Defender/방화벽 상태 확인

# 보관 기간 (일) - 이 기간이 지나면 자동 삭제
KEEP_RAW_DAYS = 3        # 10초 단위 원본, 프로세스 스냅샷
KEEP_5MIN_DAYS = 30      # 5분 요약
KEEP_EVENT_DAYS = 90     # 보안/장애 이벤트, 알림, 장애 기록
KEEP_FW_DAYS = 14        # 방화벽이 막은 접속 시도 (분 단위 요약)
TRACE_SCAN_HOURS = 24    # 침입 흔적 자동 점검 주기
DB_MAX_MB = 50           # 이 크기를 넘으면 오래된 것부터 강제 삭제
LOG_MAX_BYTES = 1_000_000  # 텍스트 로그 1MB x 2개까지만

# 경고 기준
CPU_ALERT_PCT = 90       # 이 값 이상이
CPU_ALERT_SECS = 120     # 이 시간 동안 지속되면 경고
MEM_ALERT_PCT = 90
MEM_ALERT_SECS = 60
COMMIT_ALERT_PCT = 95    # 가상 메모리 임계치 (90 -> 95%로 상향하여 정상 작업 중 과도한 알람 방지)
COMMIT_ALERT_SECS = 120  # 지속 시간 (60 -> 120초로 상향)
PROC_MEM_ALERT_MB = 3000     # 한 프로세스가 이만큼 넘게 쓰면 경고
DISK_FREE_ALERT_GB = 10      # C: 남은 공간
STALL_SECS = 60              # 수집 간격이 이보다 길게 끊기면 '응답 없음' 기록
DEFENDER_SIG_MAX_DAYS = 7    # 바이러스 정의가 이보다 오래되면 경고 (3 -> 7일로 완화)
FAILED_LOGON_ALERT = 5       # 1분 안에 로그인 실패가 이 횟수 이상이면 경고

ALERT_COOLDOWN_SECS = 1800        # 같은 알림은 30분에 한 번만 팝업
ALERT_GLOBAL_COOLDOWN_SECS = 120  # 전체 팝업 최소 간격: 2분 동안 최대 1번만 팝업
ALERT_LEVEL = "crit"              # 기본 팝업 수준: 'crit'(치명적 위험만 팝업), 'all'(주의 포함 모두), 'mute'(무음, DB에만 기록)
ALERT_MODE = "popup"              # 알림 방식: 'popup'(즉시 알람), 'list_only'(대시보드 리스트만 기록), 'digest'(모아서 한 번만 요약 알람)
ALERT_DIGEST_INTERVAL_SECS = 1800 # 모아서 알람 주기 (30분)


