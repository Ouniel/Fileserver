@echo off
setlocal EnableDelayedExpansion

if "%~1"=="" (
    echo Usage: fcurl.bat ^<URL^>
    echo Example: fcurl.bat http://127.0.0.1:8080/test.txt
    exit /b 1
)

set URL=%~1

for /f "tokens=1,2,* delims=/" %%a in ("%URL%") do (
    set HOST_PORT=%%b
    set PATH_PART=%%c
)

set IS_DIR=0
echo %URL%|findstr /E /C:"/" >nul && set IS_DIR=1

if %IS_DIR%==0 (
    for %%f in ("%PATH_PART%") do set LAST_PART=%%~nxf
    echo !LAST_PART!|findstr "\." >nul
    if errorlevel 1 (
        set IS_DIR=1
        set PATH_PART=!PATH_PART!/
    )
)

if %IS_DIR%==1 (
    set SIGN_URL=http://%HOST_PORT%/list/%PATH_PART%
) else (
    set SIGN_URL=http://%HOST_PORT%/download/%PATH_PART%
)

for /f "tokens=*" %%i in ('sign.exe "%SIGN_URL%" ^| findstr /B "http://"') do (
    if %IS_DIR%==1 (
        curl "%%i"
    ) else (
        curl -OJ "%%i"
    )
    exit /b 0
)

echo Error: Failed to generate signed URL
exit /b 1
