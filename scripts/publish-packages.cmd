@echo off
setlocal enabledelayedexpansion

REM Abblix OIDC Server - Package Publishing Script (Windows Batch)
REM This script publishes NuGet packages to both GitHub Packages and NuGet.org
REM with interactive confirmation steps

echo.
echo 📦 Abblix OIDC Server - Package Publishing Script
echo =================================================

REM Configuration
set "GITHUB_PACKAGES_SOURCE=https://nuget.pkg.github.com/Abblix/index.json"
set "NUGET_ORG_SOURCE=https://api.nuget.org/v3/index.json"
set "PACKAGES_DIR=%~1"
if "%PACKAGES_DIR%"=="" set "PACKAGES_DIR=nupkg"

REM Check if packages directory exists
if not exist "%PACKAGES_DIR%" (
    echo ❌ Error: Packages directory '%PACKAGES_DIR%' not found
    echo Usage: %0 [packages-directory]
    echo Example: %0 nupkg
    exit /b 1
)

REM Find .nupkg files
set "PACKAGE_COUNT=0"
for %%f in ("%PACKAGES_DIR%\*.nupkg") do (
    set /a PACKAGE_COUNT+=1
    set "PACKAGE_!PACKAGE_COUNT!=%%f"
)

if %PACKAGE_COUNT%==0 (
    echo ❌ Error: No .nupkg files found in '%PACKAGES_DIR%'
    exit /b 1
)

echo 📋 Found %PACKAGE_COUNT% packages:
for /l %%i in (1,1,%PACKAGE_COUNT%) do (
    for %%f in ("!PACKAGE_%%i!") do echo   - %%~nxf
)
echo.

REM Confirmation for GitHub Packages
echo 🎯 Publish to GitHub Packages?
echo    Source: %GITHUB_PACKAGES_SOURCE%
echo    Requires: GITHUB_TOKEN environment variable
echo.
set /p "GITHUB_CHOICE=Continue with GitHub Packages publishing? (y/N): "

if /i "%GITHUB_CHOICE%"=="y" (
    if "%GITHUB_TOKEN%"=="" (
        echo ❌ Error: GITHUB_TOKEN environment variable not set
        echo Please set GITHUB_TOKEN with packages:write permission
        exit /b 1
    )
    
    echo 📤 Publishing to GitHub Packages...
    for /l %%i in (1,1,%PACKAGE_COUNT%) do (
        for %%f in ("!PACKAGE_%%i!") do (
            echo Publishing %%~nxf...
            dotnet nuget push "%%f" --api-key "%GITHUB_TOKEN%" --source "%GITHUB_PACKAGES_SOURCE%" --skip-duplicate --no-symbols
            if errorlevel 1 (
                echo ⚠️  %%~nxf may already exist or failed to publish
            ) else (
                echo ✅ %%~nxf published successfully
            )
        )
    )
    echo ✅ GitHub Packages publishing completed
    echo.
) else (
    echo ⏭️  Skipping GitHub Packages publishing
    echo.
)

REM Confirmation for NuGet.org
echo 🎯 Publish to NuGet.org?
echo    Source: %NUGET_ORG_SOURCE%
echo    Requires: NUGET_API_KEY environment variable
echo.
set /p "NUGET_CHOICE=Continue with NuGet.org publishing? (y/N): "

if /i "%NUGET_CHOICE%"=="y" (
    if "%NUGET_API_KEY%"=="" (
        echo ❌ Error: NUGET_API_KEY environment variable not set
        echo Please set NUGET_API_KEY with your NuGet.org API key
        exit /b 1
    )
    
    echo 📤 Publishing to NuGet.org...
    for /l %%i in (1,1,%PACKAGE_COUNT%) do (
        for %%f in ("!PACKAGE_%%i!") do (
            echo Publishing %%~nxf...
            dotnet nuget push "%%f" --api-key "%NUGET_API_KEY%" --source "%NUGET_ORG_SOURCE%" --skip-duplicate --no-symbols
            if errorlevel 1 (
                echo ⚠️  %%~nxf may already exist or failed to publish
            ) else (
                echo ✅ %%~nxf published successfully
            )
        )
    )
    echo ✅ NuGet.org publishing completed
    echo.
) else (
    echo ⏭️  Skipping NuGet.org publishing
    echo.
)

echo 🎉 Publishing script completed!
echo.
echo 🔍 Verification steps:
echo 1. Check GitHub Packages: https://github.com/Abblix/Oidc.Server/packages
echo 2. Check NuGet.org: https://www.nuget.org/packages?q=Abblix
echo 3. Wait 5-15 minutes for package indexing to complete
echo.
echo 📋 Processed packages:
for /l %%i in (1,1,%PACKAGE_COUNT%) do (
    for %%f in ("!PACKAGE_%%i!") do echo   - %%~nxf
)

endlocal