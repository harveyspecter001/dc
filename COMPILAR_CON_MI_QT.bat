@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

:: Ajusta solo si instalaste otra versión/carpeta de Qt
set "QT_KIT=C:\Qt\6.11.0\mingw_64"
set "CMAKE_EXE=C:\Qt\Tools\CMake_64\bin\cmake.exe"
set "MINGW_BIN=C:\Qt\Tools\mingw1310_64\bin"
set "NINJA_EXE=C:\Qt\Tools\Ninja\ninja.exe"

cd /d "%~dp0"
if not exist "%CMAKE_EXE%" (
  echo No encuentro CMake en "%CMAKE_EXE%". Cambia las rutas al inicio de este .bat.
  pause
  exit /b 1
)
if not exist "%QT_KIT%\bin\qmake.exe" (
  echo No encuentro Qt en "%QT_KIT%". Cambia QT_KIT al inicio de este .bat.
  pause
  exit /b 1
)

set "PATH=%MINGW_BIN%;C:\Qt\Tools\Ninja;%PATH%"

echo === Configurando (Ninja + MinGW de Qt)... ===
"%CMAKE_EXE%" -B build -S . -G Ninja ^
  "-DCMAKE_BUILD_TYPE=Release" ^
  "-DCMAKE_PREFIX_PATH=%QT_KIT%" ^
  "-DCMAKE_MAKE_PROGRAM=C:\Qt\Tools\Ninja\ninja.exe" ^
  "-DCMAKE_CXX_COMPILER=C:\Qt\Tools\mingw1310_64\bin\g++.exe"
if errorlevel 1 pause & exit /b 1

echo === Compilando... ===
"%CMAKE_EXE%" --build build --parallel
if errorlevel 1 pause & exit /b 1

echo === Copiando DLL de Qt junto al .exe ===
"%QT_KIT%\bin\windeployqt.exe" --release --compiler-runtime "build\dofus_process_sniffer.exe"
if errorlevel 1 pause & exit /b 1

echo.
echo LISTO.
echo Ejecutable: "%~dp0build\dofus_process_sniffer.exe"
echo.
explorer /select,"%CD%\build\dofus_process_sniffer.exe"
pause
