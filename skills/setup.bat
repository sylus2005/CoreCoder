@echo off
REM ============================================
REM CoreCoder Content Creator - Environment Setup
REM ============================================

echo.
echo ==========================================
echo   CoreCoder Content Creator - Setup
echo ==========================================
echo.

REM 1. Activate Python virtual environment
echo [1/3] Installing Python dependencies...
if exist "..\.venv\Scripts\activate" (
    call ..\.venv\Scripts\activate
    pip install -r requirements.txt
) else (
    echo WARNING: Python .venv not found, installing globally
    pip install -r requirements.txt
)
echo [OK] Python dependencies installed
echo.

REM 2. Install Node.js dependencies for format-markdown
echo [2/3] Installing Node.js dependencies...
cd content-creation-publisher\baoyu-format-markdown\scripts
call npm install
cd ..\..\..\..
echo [OK] Node.js dependencies installed
echo.

REM 3. Check environment
echo [3/3] Checking environment...
echo.
echo Python: & python --version
echo Node.js: & node --version
echo npm: & npm --version
echo.
echo Checking Chrome (required for CDP features)...
where chrome >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Chrome not found in PATH. CDP features need Chrome installed.
) else (
    echo [OK] Chrome found
)

echo.
echo ==========================================
echo   Setup Complete!
echo ==========================================
echo.
echo Skills directory: %~dp0
echo.
echo Required accounts:
echo   - WeChat Official Account (for post-to-wechat)
echo   - X/Twitter Premium+ (for post-to-x)
echo.
echo Quick start:
echo   See content-creation-publisher\快速使用指南.md
echo ==========================================

pause
