@echo off
chcp 65001 >nul
cd /d "%~dp0"
start "网络运维工具平台" "%~dp0netops-console-windows-x64.exe"
timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:8787"
