#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Replace magic strings with TestConstants across test files.

.DESCRIPTION
    Systematically replaces hardcoded test values with TestConstants references
    to improve maintainability and consistency across the test suite.

.PARAMETER DryRun
    Preview changes without modifying files.

.PARAMETER Verbose
    Show detailed replacement information.

.EXAMPLE
    .\replace-magic-strings.ps1 -DryRun
    Preview changes without modifying files

.EXAMPLE
    .\replace-magic-strings.ps1 -Verbose
    Apply changes and show detailed output
#>

param(
    [switch]$DryRun,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Define replacement patterns
$replacements = @(
    @{
        Pattern = '"client_123"'
        Replacement = 'TestConstants.DefaultClientId'
        Description = 'Default client ID'
    },
    @{
        Pattern = '"test_client"'
        Replacement = 'TestConstants.DefaultClientId'
        Description = 'Default client ID (alternate)'
    },
    @{
        Pattern = '"test_secret"'
        Replacement = 'TestConstants.DefaultClientSecret'
        Description = 'Default client secret'
    },
    @{
        Pattern = '"https://example.com/callback"'
        Replacement = 'TestConstants.DefaultRedirectUri'
        Description = 'Default redirect URI'
    },
    @{
        Pattern = '"openid"'
        Replacement = 'TestConstants.DefaultScope'
        Description = 'Default OpenID scope'
        ContextCheck = { param($line)
            # Only replace in value assignments, not in scope lists like "openid profile"
            $line -notmatch '"openid\s+\w+"' -and $line -notmatch 'openid profile'
        }
    }
)

$requiredUsing = 'using Abblix.Oidc.Server.UnitTests.TestInfrastructure;'

# Find all test files
$testFiles = Get-ChildItem -Recurse -Filter '*.cs' -Exclude 'TestConstants.cs','ClientInfoBuilder.cs','TestSecretHasher.cs','LicenseFixture.cs' |
    Where-Object { $_.FullName -notmatch '\\obj\\' }

$stats = @{
    FilesProcessed = 0
    FilesModified = 0
    TotalReplacements = 0
    ReplacementsByType = @{}
}

Write-Host "Starting magic string replacement..." -ForegroundColor Cyan
Write-Host "Mode: $(if ($DryRun) { 'DRY RUN (no changes)' } else { 'LIVE (modifying files)' })" -ForegroundColor $(if ($DryRun) { 'Yellow' } else { 'Green' })
Write-Host ""

foreach ($file in $testFiles) {
    $stats.FilesProcessed++

    $content = Get-Content $file.FullName -Raw
    $originalContent = $content
    $fileModified = $false
    $fileReplacements = @{}

    # Check if file has any patterns to replace
    $hasPatterns = $false
    foreach ($replacement in $replacements) {
        if ($content -match [regex]::Escape($replacement.Pattern)) {
            $hasPatterns = $true
            break
        }
    }

    if (-not $hasPatterns) {
        continue
    }

    # Add using statement if needed
    if ($content -notmatch [regex]::Escape($requiredUsing)) {
        # Find the last using statement
        $lines = $content -split "`r?`n"
        $lastUsingIndex = -1

        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^using\s+') {
                $lastUsingIndex = $i
            }
            if ($lines[$i] -match '^namespace\s+') {
                break
            }
        }

        if ($lastUsingIndex -ge 0) {
            $lines = @($lines[0..$lastUsingIndex]) + $requiredUsing + @($lines[($lastUsingIndex+1)..($lines.Count-1)])
            $content = $lines -join "`n"
            $fileModified = $true

            if ($Verbose) {
                Write-Host "  Added using statement" -ForegroundColor Gray
            }
        }
    }

    # Apply replacements
    foreach ($replacement in $replacements) {
        $pattern = $replacement.Pattern
        $replacementText = $replacement.Replacement
        $contextCheck = $replacement.ContextCheck

        if ($contextCheck) {
            # Line-by-line replacement with context checking
            $lines = $content -split "`r?`n"
            $modified = $false

            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match [regex]::Escape($pattern)) {
                    if (& $contextCheck $lines[$i]) {
                        $lines[$i] = $lines[$i] -replace [regex]::Escape($pattern), $replacementText
                        $modified = $true

                        if (-not $fileReplacements.ContainsKey($replacement.Description)) {
                            $fileReplacements[$replacement.Description] = 0
                        }
                        $fileReplacements[$replacement.Description]++
                    }
                }
            }

            if ($modified) {
                $content = $lines -join "`n"
                $fileModified = $true
            }
        }
        else {
            # Simple global replacement
            $matches = [regex]::Matches($content, [regex]::Escape($pattern))
            if ($matches.Count -gt 0) {
                $content = $content -replace [regex]::Escape($pattern), $replacementText
                $fileModified = $true
                $fileReplacements[$replacement.Description] = $matches.Count
            }
        }
    }

    # Save changes if modified
    if ($fileModified) {
        $stats.FilesModified++

        $relativePath = $file.FullName.Substring((Get-Location).Path.Length + 1)
        Write-Host "Modified: $relativePath" -ForegroundColor Green

        foreach ($key in $fileReplacements.Keys) {
            $count = $fileReplacements[$key]
            Write-Host "  - $key ($count occurrence(s))" -ForegroundColor Gray

            if (-not $stats.ReplacementsByType.ContainsKey($key)) {
                $stats.ReplacementsByType[$key] = 0
            }
            $stats.ReplacementsByType[$key] += $count
            $stats.TotalReplacements += $count
        }

        if (-not $DryRun) {
            # Preserve original line endings
            if ($originalContent -match "`r`n") {
                $content = $content -replace "`n", "`r`n"
            }
            Set-Content -Path $file.FullName -Value $content -NoNewline
        }
    }
}

# Summary
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Files processed:  $($stats.FilesProcessed)"
Write-Host "Files modified:   $($stats.FilesModified)" -ForegroundColor $(if ($stats.FilesModified -gt 0) { 'Green' } else { 'White' })
Write-Host "Total replacements: $($stats.TotalReplacements)" -ForegroundColor $(if ($stats.TotalReplacements -gt 0) { 'Green' } else { 'White' })
Write-Host ""

if ($stats.ReplacementsByType.Count -gt 0) {
    Write-Host "Replacements by type:"
    foreach ($key in $stats.ReplacementsByType.Keys | Sort-Object) {
        $count = $stats.ReplacementsByType[$key]
        Write-Host "  - ${key}: $count" -ForegroundColor Gray
    }
}

if ($DryRun) {
    Write-Host ""
    Write-Host "DRY RUN: No files were modified. Run without -DryRun to apply changes." -ForegroundColor Yellow
}
else {
    Write-Host ""
    Write-Host "Changes applied successfully!" -ForegroundColor Green
    Write-Host "Run 'dotnet test --no-build' to verify tests still pass." -ForegroundColor Cyan
}
