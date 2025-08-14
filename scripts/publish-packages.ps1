# Abblix OIDC Server - Package Publishing Script (PowerShell)
# This script publishes NuGet packages to both GitHub Packages and NuGet.org
# with interactive confirmation steps

param(
    [string]$PackagesDir = "nupkg"
)

# Configuration
$GitHubPackagesSource = "https://nuget.pkg.github.com/Abblix/index.json"
$NuGetOrgSource = "https://api.nuget.org/v3/index.json"

Write-Host ""
Write-Host "📦 Abblix OIDC Server - Package Publishing Script" -ForegroundColor Blue
Write-Host "================================================="

# Check if packages directory exists
if (-not (Test-Path $PackagesDir)) {
    Write-Host "❌ Error: Packages directory '$PackagesDir' not found" -ForegroundColor Red
    Write-Host "Usage: .\publish-packages.ps1 [packages-directory]"
    Write-Host "Example: .\publish-packages.ps1 nupkg"
    exit 1
}

# Find .nupkg files
$Packages = Get-ChildItem -Path $PackagesDir -Filter "*.nupkg" -File

if ($Packages.Count -eq 0) {
    Write-Host "❌ Error: No .nupkg files found in '$PackagesDir'" -ForegroundColor Red
    exit 1
}

Write-Host "📋 Found $($Packages.Count) packages:" -ForegroundColor Green
foreach ($pkg in $Packages) {
    Write-Host "  - $($pkg.Name)"
}
Write-Host ""

# Confirmation for GitHub Packages
Write-Host "🎯 Publish to GitHub Packages?" -ForegroundColor Yellow
Write-Host "   Source: $GitHubPackagesSource"
Write-Host "   Requires: GITHUB_TOKEN environment variable"
Write-Host ""
$GitHubChoice = Read-Host "Continue with GitHub Packages publishing? (y/N)"

if ($GitHubChoice -eq "y" -or $GitHubChoice -eq "Y") {
    $GitHubToken = $env:GITHUB_TOKEN
    if (-not $GitHubToken) {
        Write-Host "❌ Error: GITHUB_TOKEN environment variable not set" -ForegroundColor Red
        Write-Host "Please set GITHUB_TOKEN with packages:write permission"
        exit 1
    }
    
    Write-Host "📤 Publishing to GitHub Packages..." -ForegroundColor Blue
    foreach ($pkg in $Packages) {
        Write-Host "Publishing $($pkg.Name)..."
        try {
            $result = dotnet nuget push $pkg.FullName --api-key $GitHubToken --source $GitHubPackagesSource --skip-duplicate --no-symbols 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ $($pkg.Name) published successfully" -ForegroundColor Green
            } else {
                Write-Host "⚠️  $($pkg.Name) may already exist or failed to publish" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "⚠️  $($pkg.Name) failed to publish: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    Write-Host "✅ GitHub Packages publishing completed" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "⏭️  Skipping GitHub Packages publishing" -ForegroundColor Yellow
    Write-Host ""
}

# Confirmation for NuGet.org
Write-Host "🎯 Publish to NuGet.org?" -ForegroundColor Yellow
Write-Host "   Source: $NuGetOrgSource"
Write-Host "   Requires: NUGET_API_KEY environment variable"
Write-Host ""
$NuGetChoice = Read-Host "Continue with NuGet.org publishing? (y/N)"

if ($NuGetChoice -eq "y" -or $NuGetChoice -eq "Y") {
    $NuGetApiKey = $env:NUGET_API_KEY
    if (-not $NuGetApiKey) {
        Write-Host "❌ Error: NUGET_API_KEY environment variable not set" -ForegroundColor Red
        Write-Host "Please set NUGET_API_KEY with your NuGet.org API key"
        exit 1
    }
    
    Write-Host "📤 Publishing to NuGet.org..." -ForegroundColor Blue
    foreach ($pkg in $Packages) {
        Write-Host "Publishing $($pkg.Name)..."
        try {
            $result = dotnet nuget push $pkg.FullName --api-key $NuGetApiKey --source $NuGetOrgSource --skip-duplicate --no-symbols 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ $($pkg.Name) published successfully" -ForegroundColor Green
            } else {
                Write-Host "⚠️  $($pkg.Name) may already exist or failed to publish" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "⚠️  $($pkg.Name) failed to publish: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    Write-Host "✅ NuGet.org publishing completed" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "⏭️  Skipping NuGet.org publishing" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "🎉 Publishing script completed!" -ForegroundColor Green
Write-Host ""
Write-Host "🔍 Verification steps:" -ForegroundColor Blue
Write-Host "1. Check GitHub Packages: https://github.com/Abblix/Oidc.Server/packages"
Write-Host "2. Check NuGet.org: https://www.nuget.org/packages?q=Abblix"
Write-Host "3. Wait 5-15 minutes for package indexing to complete"
Write-Host ""
Write-Host "📋 Processed packages:" -ForegroundColor Blue
foreach ($pkg in $Packages) {
    Write-Host "  - $($pkg.Name)"
}