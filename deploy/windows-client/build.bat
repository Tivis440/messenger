@echo off
setlocal

if "%QT_DIR%"=="" set "QT_DIR=C:\Qt\6.7.2\msvc2019_64"
if "%SIGNAL_DIR%"=="" set "SIGNAL_DIR=C:\libs\signal-protocol-c"
if "%OPENSSL_DIR%"=="" set "OPENSSL_DIR=C:\libs\OpenSSL-Win64"

set "PATH=%QT_DIR%\bin;%PATH%"

if not exist build mkdir build
cd build

qmake ..\untitled\untitled.pro "SIGNAL_DIR=%SIGNAL_DIR%" "OPENSSL_DIR=%OPENSSL_DIR%"
nmake
windeployqt release\messenger.exe

echo Build output: build\release
