@echo off
rem PC Monitor installer - asks for administrator rights, then runs install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -NoExit -File \"' + '%~dp0install.ps1' + '\"')"
