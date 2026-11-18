@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem ===================================================================
rem  SecureVault launcher  --  double-click this file
rem
rem  First run builds the JAR, which takes a minute or two while Maven
rem  downloads JavaFX and Bouncy Castle. Every run after that starts
rem  straight from the JAR and is immediate.
rem
rem  Force a rebuild after changing the code:   run.bat rebuild
rem ===================================================================

set "JAR=target\securevault-3.0.0.jar"
set "REBUILD=%~1"

echo.
echo   SecureVault 3.0.0
echo   -----------------
echo.

rem ---- Check Java -----------------------------------------------------
where java >nul 2>&1
if errorlevel 1 (
    echo   [X] Java was not found on your PATH.
    echo.
    echo       Install a JDK 17 or newer, then run this file again.
    echo       Temurin builds: https://adoptium.net
    echo.
    pause
    exit /b 1
)

rem ---- Build if needed ------------------------------------------------
if /i "%REBUILD%"=="rebuild" (
    echo   Rebuild requested.
    if exist "%JAR%" del /q "%JAR%"
)

if not exist "%JAR%" (
    echo   No JAR found -- building. First build downloads dependencies.
    echo.
    where mvn >nul 2>&1
    if errorlevel 1 (
        echo   [X] Maven was not found on your PATH, so the JAR cannot be built.
        echo.
        echo       Install Maven from https://maven.apache.org/download.cgi
        echo       and add its bin folder to PATH, then run this file again.
        echo.
        pause
        exit /b 1
    )
    call mvn -q -DskipTests package
    if errorlevel 1 (
        echo.
        echo   [X] Build failed. Scroll up for the compiler output.
        echo.
        pause
        exit /b 1
    )
    echo   Build complete.
    echo.
)

rem ---- Launch ---------------------------------------------------------
echo   Starting SecureVault...
echo   Data folder: %USERPROFILE%\SecureStorageData
echo.

java -Xmx2g ^
     --add-opens java.base/java.lang=ALL-UNNAMED ^
     --add-opens java.base/java.io=ALL-UNNAMED ^
     --add-opens java.base/java.util=ALL-UNNAMED ^
     -jar "%JAR%"

set "EXITCODE=%ERRORLEVEL%"

if not "%EXITCODE%"=="0" (
    echo.
    echo   The app exited with code %EXITCODE%.
    echo   Trying the Maven JavaFX plugin instead, which loads JavaFX as
    echo   proper modules and works when the packaged JAR does not...
    echo.
    where mvn >nul 2>&1
    if not errorlevel 1 (
        call mvn -q javafx:run
        set "EXITCODE=!ERRORLEVEL!"
    )
)

if not "%EXITCODE%"=="0" (
    echo.
    echo   SecureVault did not start cleanly. The output above should say why.
    echo.
    pause
)

endlocal
