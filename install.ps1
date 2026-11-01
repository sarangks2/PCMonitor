# PC 모니터 설치 (Windows 10/11, Windows Server 2016 이상 권장 / 8.1·2012 R2 최소)
#   쉬운 방법: Install.cmd 더블클릭 (관리자 권한 자동 요청)
#   직접 실행: 관리자 PowerShell 에서  powershell -ExecutionPolicy Bypass -File install.ps1 [-Mode Auto|User|System] [-InstallDir 경로]
#
#   -Mode User   : 설치한 사용자가 로그인하면 시작 (PC 기본값, 알림 팝업 표시)
#   -Mode System : PC가 켜지면 로그인 없이 SYSTEM 계정으로 시작 (서버 기본값, 알림은 메시지 창)
param(
    [ValidateSet('Auto', 'User', 'System')] [string]$Mode = 'Auto',
    [string]$InstallDir = ''
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Fail($msg) { Write-Host $msg -ForegroundColor Red; exit 1 }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Fail "관리자 권한으로 실행해 주세요 (Install.cmd 를 더블클릭하면 자동으로 요청합니다)" }
if ($PSVersionTable.PSVersion -lt [Version]'5.1') { Fail "PowerShell 5.1 이상이 필요합니다 (Windows Management Framework 5.1 설치)" }
$os = Get-CimInstance Win32_OperatingSystem
if ([int]$os.BuildNumber -lt 9600) { Fail "Windows 8.1 / Server 2012 R2 이상에서만 동작합니다 (현재: $($os.Caption))" }
$isServer = $os.ProductType -ne 1
if ($Mode -eq 'Auto') { $Mode = $(if ($isServer) { 'System' } else { 'User' }) }
Write-Host "대상: $($os.Caption) (빌드 $($os.BuildNumber)) · $(if($isServer){'서버'}else{'PC'}) · 실행 방식: $Mode" -ForegroundColor Cyan

# ---------------------------------------------------------------- 실행 파일 결정
$srcExe = Join-Path $here 'PCMonitor.exe'
if (Test-Path $srcExe) {
    if (-not [Environment]::Is64BitOperatingSystem) { Fail "PCMonitor.exe 는 64비트 Windows 전용입니다. 32비트에서는 Python 버전(monitor.py)을 사용하세요." }
    if (-not $InstallDir) {
        # 이미 이 폴더에서 기록 중이면(data 폴더 있음) 그 자리 유지, 아니면 Program Files 에 설치
        $InstallDir = $(if ((Test-Path (Join-Path $here 'data')) -or $here -like "$env:ProgramFiles*") { $here } else { Join-Path $env:ProgramFiles 'PCMonitor' })
    }
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    if ((Resolve-Path $InstallDir).Path -ne (Resolve-Path $here).Path) {
        Get-CimInstance Win32_Process -Filter "Name='PCMonitor.exe'" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep 1
        foreach ($f in 'PCMonitor.exe', 'install.ps1', 'uninstall.ps1', 'Install.cmd', 'Uninstall.cmd', 'README.md') {
            if (Test-Path (Join-Path $here $f)) { Copy-Item (Join-Path $here $f) $InstallDir -Force }
        }
    }
    $exe = Join-Path $InstallDir 'PCMonitor.exe'
    $runExe = $exe; $runArgs = '--background'
    $dataDir = $(if (Test-Path (Join-Path $InstallDir 'data')) { Join-Path $InstallDir 'data' } else { Join-Path $env:ProgramData 'PCMonitor' })
} else {
    $InstallDir = $here
    $pyw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
    if (-not $pyw) { Fail "PCMonitor.exe 도 Python(pythonw.exe)도 없습니다" }
    $py = $pyw -replace 'pythonw\.exe$', 'python.exe'
    & $py -c "import psutil" 2>$null
    if ($LASTEXITCODE -ne 0) { & $py -m pip install psutil }
    $exe = $null; $runExe = $pyw; $runArgs = "`"$here\monitor.py`" --background"
    $dataDir = Join-Path $here 'data'
}
Write-Host "설치 위치: $InstallDir"
Write-Host "기록 위치: $dataDir"

# ---------------------------------------------------------------- 1. 감사 정책
Write-Host "[1/5] 로그인/계정 감사 켜기 (침입 시도 기록용)"
foreach ($g in '{0CCE9215-69AE-11D9-BED3-505054503030}', '{0CCE9217-69AE-11D9-BED3-505054503030}',
               '{0CCE9235-69AE-11D9-BED3-505054503030}', '{0CCE9237-69AE-11D9-BED3-505054503030}') {
    auditpol /set /subcategory:$g /success:enable /failure:enable | Out-Null
}
Write-Host "      (도메인 그룹 정책이 감사 설정을 덮어쓰는 회사 PC/서버라면 GPO 에서도 켜야 합니다)" -ForegroundColor DarkGray

# ---------------------------------------------------------------- 2. 백신 정의 업데이트
Write-Host "[2/5] Windows 보안(Defender) 바이러스 정의 업데이트"
if (Get-Command Update-MpSignature -ErrorAction SilentlyContinue) {
    try { Update-MpSignature -ErrorAction Stop; Write-Host "      완료" }
    catch { Write-Host "      건너뜀: $($_.Exception.Message) (다른 백신 사용 중이거나 업데이트 진행 중)" -ForegroundColor Yellow }
} else { Write-Host "      Defender 없음 → 건너뜀 (다른 백신은 해당 백신에서 업데이트하세요)" -ForegroundColor Yellow }

# ---------------------------------------------------------------- 3. 기록 폴더 권한
Write-Host "[3/5] 기록 폴더 권한 설정 (설치한 사용자·관리자·SYSTEM 만)"
New-Item -ItemType Directory -Force $dataDir | Out-Null
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls $dataDir /inheritance:r /grant:r "*${me}:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null

# ---------------------------------------------------------------- 4. 자동 실행 작업
Write-Host "[4/5] 자동 실행 작업 등록 (PCMonitor)"
Stop-ScheduledTask -TaskName 'PCMonitor' -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'PCMonitor.exe' -or ($_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -match 'monitor\.py') } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
$action = New-ScheduledTaskAction -Execute $runExe -Argument $runArgs -WorkingDirectory $InstallDir
if ($Mode -eq 'System') {
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
} else {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
}
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'PCMonitor' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'PCMonitor'

# ---------------------------------------------------------------- 5. 바로가기
Write-Host "[5/5] 바로가기 (바탕화면 · 시작 메뉴)"
$ws = New-Object -ComObject WScript.Shell
$targets = @([Environment]::GetFolderPath('Desktop'), (Join-Path ([Environment]::GetFolderPath('Programs')) ''))
foreach ($dir in $targets) {
    Remove-Item (Join-Path $dir 'PC 모니터.url') -ErrorAction SilentlyContinue
    $lnk = $ws.CreateShortcut((Join-Path $dir 'PC 모니터.lnk'))
    if ($exe) { $lnk.TargetPath = $exe; $lnk.IconLocation = "$exe,0" }
    else { $lnk.TargetPath = $pyw; $lnk.Arguments = "`"$here\monitor.py`""; $lnk.IconLocation = "$here\pcmon.ico" }
    $lnk.WorkingDirectory = $InstallDir; $lnk.Description = 'PC 모니터 (앱 창으로 열기)'; $lnk.Save()
}

# ---------------------------------------------------------------- 확인
$port = $(if ($env:PCMON_PORT) { $env:PCMON_PORT } else { 8765 })
$ok = $false
for ($i = 0; $i -lt 20 -and -not $ok; $i++) {
    Start-Sleep 1
    try { $ok = (Invoke-RestMethod "http://127.0.0.1:$port/api/ping" -TimeoutSec 2).app -eq 'pcmon' } catch {}
}
if ($ok) {
    Write-Host "설치 완료. 바탕화면/시작 메뉴의 'PC 모니터' 로 여세요." -ForegroundColor Green
    # 관리자 권한이 아닌 일반 권한으로 앱 창 열기 (explorer 를 통해 실행)
    if ($exe) { Start-Process explorer.exe -ArgumentList "`"$exe`"" }
} else {
    Write-Host "작업은 등록됐지만 아직 응답이 없습니다. 잠시 후 'PC 모니터' 아이콘을 눌러 보세요. 로그: $dataDir\pcmon.log" -ForegroundColor Yellow
}
