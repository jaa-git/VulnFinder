@echo off
REM Build Bastion.exe using PyInstaller.
REM Output: dist\Bastion.exe (single-file, UAC-elevated console app).

setlocal
cd /d "%~dp0"

where pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [+] Installing PyInstaller...
    python -m pip install --upgrade pyinstaller || goto :err
)

echo [+] Installing requirements...
python -m pip install -r requirements.txt || goto :err

echo [+] Cleaning previous build...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [+] Building Bastion.exe ...
python -m PyInstaller --clean --noconfirm build.spec || goto :err

echo.
echo [OK] Built: %CD%\dist\Bastion.exe
echo      Copy to your VM and run as Administrator.
goto :eof

:err
echo.
echo [!!] Build failed. Scroll up for details.
exit /b 1
