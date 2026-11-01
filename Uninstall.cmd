@echo off
rem PC Monitor uninstaller - asks for administrator rights, then runs uninstall.ps1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -NoExit -File \"' + '%~dp0uninstall.ps1' + '\"')"
