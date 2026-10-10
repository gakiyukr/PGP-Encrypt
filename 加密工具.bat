@echo off
rem Launcher: forward all arguments to PGPEncrypt.exe
rem Double-click with no arguments opens the GUI.
if "%~1"=="" (
  start "" "%~dp0PGPEncrypt.exe"
  exit /b 0
)
"%~dp0PGPEncrypt.exe" %*
exit /b %ERRORLEVEL%
