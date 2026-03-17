@echo off
REM ============================================================
REM  Check Point to Panorama Migration Tool - Launcher
REM ============================================================
title CP to Panorama Migration Tool

echo.
echo  ================================================
echo   Check Point ^> Panorama Migration Tool
echo  ================================================
echo.

REM -- Locate Python --
where py >nul 2>nul
if %ERRORLEVEL% == 0 (
    set PY=py
    goto found_python
)
where python >nul 2>nul
if %ERRORLEVEL% == 0 (
    set PY=python
    goto found_python
)
where python3 >nul 2>nul
if %ERRORLEVEL% == 0 (
    set PY=python3
    goto found_python
)
echo  [ERROR] Python not found. Please install Python 3.8+ from https://python.org
pause
exit /b 1

:found_python
echo  Python found: %PY%
echo.

REM -- Check/Install Flask --
echo  Checking Flask installation...
%PY% -c "import flask" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo  Flask not found. Installing from requirements.txt...
    %PY% -m pip install -r "%~dp0requirements.txt" --quiet
    if %ERRORLEVEL% NEQ 0 (
        echo  [ERROR] Failed to install Flask. Check your internet connection.
        pause
        exit /b 1
    )
    echo  Flask installed successfully.
) else (
    echo  Flask is already installed.
)

echo.
echo  Starting web server...
echo  Open your browser at: http://localhost:5000
echo.
echo  Press Ctrl+C to stop the server.
echo  ================================================
echo.

REM -- Run from the script's own directory --
cd /d "%~dp0"
%PY% app.py

echo.
echo  Server stopped.
pause
