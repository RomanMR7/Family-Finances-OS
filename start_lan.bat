@echo off
chcp 65001 >nul
title Family Finances OS (Wi-Fi LAN Режим)
cd /d "%~dp0"

echo ================================================================
echo   Запуск Family Finances OS в режиме общего доступа (Wi-Fi LAN)
echo ================================================================
echo.

call start.bat --lan
