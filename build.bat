@echo off
echo ===================================================
echo   SuperHashTab - DLL and Setup Compiler
echo ===================================================
echo.
echo Compiling src\*.cs...
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:SuperHashTab.dll /optimize /r:System.Windows.Forms.dll,System.Drawing.dll,System.dll,System.Core.dll src\*.cs
if %errorlevel% equ 0 (
    echo [+] SuperHashTab.dll compiled successfully!
) else (
    echo [-] DLL compilation failed!
    exit /b %errorlevel%
)

echo.
echo Compiling installer\Setup.cs...
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:winexe /win32icon:SuperHashTab.ico /out:SuperHashTab_Setup.exe /optimize /r:System.Windows.Forms.dll,System.Drawing.dll,System.dll installer\Setup.cs /resource:SuperHashTab.dll,SuperHashTab.dll /resource:SuperHashTab.ico,SuperHashTab.ico /resource:settings.ini,settings.ini /resource:locales\de.json,locales.de.json /resource:locales\en.json,locales.en.json /resource:locales\es.json,locales.es.json /resource:locales\fr.json,locales.fr.json /resource:locales\it.json,locales.it.json /resource:locales\ja.json,locales.ja.json /resource:locales\ko.json,locales.ko.json /resource:locales\pt.json,locales.pt.json /resource:locales\ru.json,locales.ru.json /resource:locales\tr.json,locales.tr.json /resource:locales\zh.json,locales.zh.json
if %errorlevel% equ 0 (
    echo [+] SuperHashTab_Setup.exe compiled successfully!
) else (
    echo [-] Setup.exe compilation failed!
    exit /b %errorlevel%
)

echo.
echo ===================================================

