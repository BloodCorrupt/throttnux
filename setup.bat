@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo ========================================
echo  Throttnux - Windows Setup Script
echo ========================================

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Error: Python is not installed or not in PATH.
    pause
    exit /b 1
)

REM Create venv if not exists
if not exist "%SCRIPT_DIR%.venv" (
    echo [+] Creating virtual environment in .venv...
    python -m venv .venv
) else (
    echo [*] Virtual environment already exists.
)

REM Upgrade pip & install requirements
echo [+] Upgrading pip...
"%SCRIPT_DIR%.venv\Scripts\python.exe" -m pip install --upgrade pip

if exist "%SCRIPT_DIR%requirements.txt" (
    echo [+] Installing requirements from requirements.txt...
    "%SCRIPT_DIR%.venv\Scripts\pip.exe" install -r "%SCRIPT_DIR%requirements.txt"
)

echo [+] Installing throttnux package in editable mode...
"%SCRIPT_DIR%.venv\Scripts\pip.exe" install -e .

echo ========================================
echo [✓] Setup complete!
echo (Note: Throttnux runtime requires Linux/WSL with root privileges)
echo ========================================
