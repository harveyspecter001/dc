@echo off
chcp 65001 >nul
cd /d "%~dp0build"
if not exist "dofus_process_sniffer.exe" (
  echo Falta el programa. Ejecuta primero COMPILAR_CON_MI_QT.bat
  pause
  exit /b 1
)
start "" "dofus_process_sniffer.exe"
