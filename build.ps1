# PC 모니터 배포 파일 만들기 → dist\PCMonitor.zip
#   powershell -ExecutionPolicy Bypass -File build.ps1
#
# exe 한 개(--onefile) 대신 폴더(--onedir)로 만든다.
# --onefile 은 실행할 때 자기 안의 파일을 임시 폴더에 풀어 실행하는데, 악성코드가 흔히 쓰는 방식과 비슷해
# 백신(V3 등)이 오진하는 일이 많다. 파일 버전 정보(회사·설명)도 넣어 출처를 알 수 있게 한다.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

$ver = (Select-String -Path config.py -Pattern '^VERSION = "([\d.]+)"').Matches[0].Groups[1].Value
$v = ($ver.Split('.') + @('0', '0', '0'))[0..3] -join ', '
Write-Host "버전 $ver 빌드" -ForegroundColor Cyan

python -m pip install --quiet psutil pyinstaller

New-Item -ItemType Directory -Force build | Out-Null
@"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($v), prodvers=($v), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable(u'041204B0', [
      StringStruct(u'CompanyName', u'sarangks2 (github.com/sarangks2/PCMonitor)'),
      StringStruct(u'FileDescription', u'PC Monitor - local PC/server health and security monitor'),
      StringStruct(u'FileVersion', u'$ver'),
      StringStruct(u'InternalName', u'PCMonitor'),
      StringStruct(u'LegalCopyright', u'sarangks2'),
      StringStruct(u'OriginalFilename', u'PCMonitor.exe'),
      StringStruct(u'ProductName', u'PC Monitor'),
      StringStruct(u'ProductVersion', u'$ver')])]),
    VarFileInfo([VarStruct(u'Translation', [1042, 1200])])
  ]
)
"@ | Out-File -Encoding utf8 build\version_info.txt

python -m PyInstaller --noconfirm --clean --onedir --noconsole --name PCMonitor --icon pcmon.ico `
    --version-file build\version_info.txt `
    --add-data "dashboard.html;." --add-data "pcmon.ico;." --add-data "i18n_en.json;." monitor.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller 실패" }

# 설치·제거 스크립트를 함께 넣어 zip 으로 묶기 (zip 안: PCMonitor\PCMonitor.exe, PCMonitor\_internal\..., 스크립트)
$out = Join-Path $here 'dist\PCMonitor'
foreach ($f in 'Install.cmd', 'install.ps1', 'Uninstall.cmd', 'uninstall.ps1', 'README.md') { Copy-Item $f $out -Force }
$zip = Join-Path $here 'dist\PCMonitor.zip'
Remove-Item $zip -ErrorAction SilentlyContinue
# Compress-Archive(PowerShell 5.1)는 경로를 '\' 로 저장해 일부 압축 프로그램에서 폴더가 깨지므로 파이썬으로 묶는다
python -c "import os,sys,zipfile; d=os.path.dirname(sys.argv[1]); z=zipfile.ZipFile(sys.argv[2],'w',zipfile.ZIP_DEFLATED); [z.write(os.path.join(r,f),os.path.relpath(os.path.join(r,f),d).replace(os.sep,'/')) for r,_,fs in os.walk(sys.argv[1]) for f in fs]; z.close()" $out $zip
if ($LASTEXITCODE -ne 0) { throw "zip 실패" }
Write-Host "완료: $zip" -ForegroundColor Green
foreach ($f in $zip, (Join-Path $out 'PCMonitor.exe')) {
    Write-Host ("  SHA-256 {0}: {1}" -f (Split-Path $f -Leaf), (Get-FileHash $f -Algorithm SHA256).Hash)
}
