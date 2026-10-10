@echo off
rem Compile EncryptTool.cs into the single-file PGPEncrypt.exe
rem Uses the .NET Framework csc.exe that ships with Windows (no SDK needed).
setlocal
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
  echo csc.exe not found. .NET Framework 4.x is required.
  exit /b 1
)
"%CSC%" /nologo /target:winexe /platform:anycpu /out:"%~dp0PGPEncrypt.exe" /r:System.dll /r:System.Core.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "%~dp0EncryptTool.cs"
exit /b %ERRORLEVEL%
