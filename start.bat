@echo off
chcp 65001 >nul
title Family Finances OS
cd /d "%~dp0"
set "PYTHON_CMD="

rem Accept only a real Python 3.10+ with the required encryption library.
call :try_python "%~dp0.venv\Scripts\python.exe"
call :try_python "%USERPROFILE%\.local\bin\python3.12.exe"
call :try_python "%USERPROFILE%\.local\bin\python3.11.exe"
for /f "delims=" %%P in ('where python3.12.exe 2^>nul') do call :try_python "%%P"
for /f "delims=" %%P in ('where python.exe 2^>nul') do call :try_python "%%P"
if defined PYTHON_CMD goto run
where py.exe >nul 2>&1
if errorlevel 1 goto fallback
py.exe -3 -c "import sys; assert sys.version_info >= (3,10); import cryptography" >nul 2>&1
if errorlevel 1 goto fallback
set "PYTHON_CMD=py.exe -3"
goto run

:fallback
for /d %%D in ("%APPDATA%\uv\python\cpython-*-windows-x86_64-none") do call :try_python "%%D\python.exe"
call :try_python "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if defined PYTHON_CMD goto run

echo [ОШИБКА] Нужен Python 3.10+ с установленными зависимостями.
echo Выполните: py -3 -m pip install -r requirements.txt
if /i not "%FFOS_NO_PAUSE%"=="1" pause
exit /b 1

:try_python
if defined PYTHON_CMD exit /b 0
if not exist "%~1" exit /b 0
if /i "%~1"=="%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" exit /b 0
"%~1" -c "import sys; assert sys.version_info >= (3,10); import cryptography" >nul 2>&1
if errorlevel 1 exit /b 0
set PYTHON_CMD="%~1"
exit /b 0

:run
echo [*] Запуск через: %PYTHON_CMD%
%PYTHON_CMD% run_app.py %*
set "APP_EXIT=%ERRORLEVEL%"
if "%APP_EXIT%"=="0" exit /b 0
echo [ОШИБКА] Приложение завершилось с кодом %APP_EXIT%.
if /i not "%FFOS_NO_PAUSE%"=="1" pause
exit /b %APP_EXIT%
