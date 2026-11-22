@echo off
setlocal
rem Build wt_phys.sys (WDK) and wt_host.exe (MSVC x64).
rem Run from an "x64 Native Tools Command Prompt for VS".

if "%WindowsSdkDir%"=="" set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10\
set "WDKINC="
set "WDKLIB="
for /f "delims=" %%D in ('dir /b /ad /o-n "%WindowsSdkDir%Include\10.*"') do (
  if exist "%WindowsSdkDir%Include\%%D\km\ntddk.h" (
    set "WDKINC=%WindowsSdkDir%Include\%%D"
    set "WDKLIB=%WindowsSdkDir%Lib\%%D"
    goto :got
  )
)
echo WDK km headers not found under "%WindowsSdkDir%Include".
exit /b 1
:got
echo WDK %WDKINC%

cl /nologo /c /kernel /GS- /GR- /Gy- /O2 /W3 /D_AMD64_ /DAMD64 ^
  /I"%WDKINC%\km" /I"%WDKINC%\shared" /I"%WDKINC%\km\crt" ^
  driver\wt_phys.c /Fodriver\wt_phys.obj
if errorlevel 1 exit /b 1

link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB ^
  /OUT:wt_phys.sys driver\wt_phys.obj "%WDKLIB%\km\x64\ntoskrnl.lib" /IGNORE:4078
if errorlevel 1 exit /b 1

cl /nologo /O2 /W3 /EHsc /std:c++17 /DUNICODE /D_UNICODE host\wt_host.cpp ^
  /Fe:wt_host.exe /link user32.lib gdi32.lib advapi32.lib psapi.lib ntdll.lib
if errorlevel 1 exit /b 1

echo built wt_phys.sys and wt_host.exe
exit /b 0
