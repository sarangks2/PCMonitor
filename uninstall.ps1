# PC 모니터 제거 - Uninstall.cmd 더블클릭 또는 관리자 PowerShell 에서 실행
# 기록(data)은 남겨 둡니다. 함께 지우려면: uninstall.ps1 -DeleteData
param([switch]$DeleteData)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Unregister-ScheduledTask -TaskName 'PCMonitor' -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'PCMonitor.exe' -or ($_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -match 'monitor\.py') } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Remove-Item 'HKCU:\Software\Classes\AppUserModelId\PCMonitor.App' -Recurse -ErrorAction SilentlyContinue  # 알림 앱 이름 등록
foreach ($dir in [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs')) {
    Remove-Item (Join-Path $dir 'PC 모니터.url'), (Join-Path $dir 'PC 모니터.lnk') -ErrorAction SilentlyContinue
}
if ($DeleteData) {
    Remove-Item -Recurse -Force (Join-Path $here 'data'), (Join-Path $env:ProgramData 'PCMonitor') -ErrorAction SilentlyContinue
}
Write-Host "제거 완료. (켜 둔 로그인 감사·방화벽 차단 기록 설정은 Windows 보안에 도움이 되므로 그대로 둡니다)"
