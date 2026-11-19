@echo off
REM ============================================================
REM  Builds dist\EncryptX\EncryptX.exe (PyInstaller) and then the
REM  installer dist\EncryptX-Setup-<version>.exe (Inno Setup 6.3+).
REM ============================================================
cd /d "%~dp0"

echo [1/3] Installing requirements...
python -m pip install --upgrade -r requirements.txt pyinstaller || goto :error

echo [2/3] Building the program...
REM --onedir (not --onefile): starts much faster, which matters for the right-click menu.
python -m PyInstaller --noconfirm --clean --windowed --name EncryptX ^
    --paths src --icon assets\icon.ico --add-data "assets;assets" ^
    --exclude-module tkinter run.py || goto :error

echo [3/3] Building the installer...
set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist %ISCC% set ISCC="%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not exist %ISCC% (
    echo Inno Setup 6 was not found. Install it from https://jrsoftware.org/isdl.php
    echo then run:  ISCC installer\EncryptX.iss
    goto :error
)
%ISCC% installer\EncryptX.iss || goto :error

echo.
echo Done:  dist\EncryptX-Setup-*.exe
pause
exit /b 0

:error
echo.
echo Build failed. Read the messages above.
pause
exit /b 1
