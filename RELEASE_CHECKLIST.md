# NuGet Package Release Checklist

## Before Building Package

### Version & Copyright
- [ ] Update year in copyright (currently showing 2024, should be 2026 soon)
  - `.nuspec` file: `<copyright>Copyright (c) 2026 Abblix LLP. All rights reserved.</copyright>`
  - Check all project files for hardcoded copyright years

### Package Metadata
- [ ] Update version in `.nuspec`: `<version>X.Y.Z</version>`
- [ ] Update `<releaseNotes>` link to GitHub releases:
  - Link format: `https://github.com/Abblix/Oidc.Server/releases`
  - Previous CHANGELOG.md removed as duplicate - use GitHub releases instead
- [ ] Verify `<projectUrl>` is correct: `https://www.abblix.com/abblix-oidc-server`
- [ ] Verify repository URL: `https://github.com/Abblix/Oidc.Server`

### Dependencies
- [ ] Review all `<dependency>` entries for correct versions
- [ ] Check `targetFramework` for all dependency groups (net8.0, net9.0, net10.0)
- [ ] Verify no test or analyzer packages in dependencies (exclude="Build,Analyzers")

## Building Package

### Use nuget-pack.cmd Script
```powershell
# Kill processes first
Get-Process -Name dotnet,MSBuild,testhost,vstest -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 5

# Release version
powershell.exe -Command "& 'C:\Abblix\AuthenticationService\scripts\build\nuget-pack.cmd' 2.0.0"

# Beta version
powershell.exe -Command "& 'C:\Abblix\AuthenticationService\scripts\build\nuget-pack.cmd' 2.0.0 beta1"
```

**CRITICAL:**
- ✓ Always use `nuget-pack.cmd` script
- ✗ NEVER use `dotnet pack` directly
- ✓ Always kill dotnet/MSBuild processes before packing
- ✓ Use PowerShell call operator `&` (NOT cmd /c)

## After Building Package

### Package Health Checks

Issues visible on NuGet.org (see screenshots):

1. **Source Link: Missing Symbols** ❌
   - Package uploaded but source link symbols missing
   - TODO: Investigate why symbols not included
   - May need to configure SourceLink in project files

2. **Deterministic (dll/exe): Non deterministic** ❌
   - Build is not deterministic (different builds produce different binaries)
   - TODO: Enable deterministic builds in project files
   - Add: `<Deterministic>true</Deterministic>` and `<ContinuousIntegrationBuild>true</ContinuousIntegrationBuild>`

3. **Compiler Flags: Missing** ❌
   - Compiler flags not embedded in assembly
   - TODO: Enable embedded compiler flags
   - May be related to deterministic builds

### Package Verification
- [ ] Download package from NuGet.org
- [ ] Verify package size (should be around 2.9 KB for Abblix.Utils)
- [ ] Check digital signature (DigiCert SHA256 RSA4096 Timestamp Responder)
- [ ] Verify all frameworks included (net8.0, net9.0, net10.0)
- [ ] Test package installation in clean project

## Documentation

### Update Documentation
- [ ] Update README.md with new version info
- [ ] Update badges if .NET version support changes
- [ ] Add release notes to GitHub Releases page
- [ ] Update docs.abblix.com if API changes

### CHANGELOG vs GitHub Releases
- **Old approach:** CHANGELOG.md in repository (removed as duplicate)
- **Current approach:** Use https://github.com/Abblix/Oidc.Server/releases
  - All release information centralized
  - Automatic GitHub release notes generation
  - Better visibility for users

## Testing

### Smoke Tests
- [ ] Install package in test project
- [ ] Verify all public APIs work
- [ ] Run full test suite
- [ ] Test on all supported .NET versions (8.0, 9.0, 10.0)

## Known Issues to Fix

### High Priority
1. **Copyright Year** - Automate copyright year updates (currently stuck at 2024)
2. **Missing Symbols** - Fix SourceLink configuration
3. **Non-deterministic Build** - Enable deterministic builds

### Medium Priority
4. **Compiler Flags** - Embed compiler flags in assembly
5. **Package Health** - All three health checks should be green on NuGet.org

### Configuration Needed

Add to all `.csproj` files:

```xml
<PropertyGroup>
  <!-- Deterministic builds -->
  <Deterministic>true</Deterministic>
  <ContinuousIntegrationBuild>true</ContinuousIntegrationBuild>

  <!-- Source Link -->
  <PublishRepositoryUrl>true</PublishRepositoryUrl>
  <EmbedUntrackedSources>true</EmbedUntrackedSources>
  <IncludeSymbols>true</IncludeSymbols>
  <SymbolPackageFormat>snupkg</SymbolPackageFormat>

  <!-- Copyright with auto-year (requires MSBuild function) -->
  <Copyright>Copyright (c) $([System.DateTime]::Now.Year) Abblix LLP. All rights reserved.</Copyright>
</PropertyGroup>

<ItemGroup>
  <!-- Source Link package -->
  <PackageReference Include="Microsoft.SourceLink.GitHub" Version="8.0.0" PrivateAssets="All"/>
</ItemGroup>
```

## References

- NuGet Package Explorer: Check package contents before publishing
- GitHub Releases: https://github.com/Abblix/Oidc.Server/releases
- NuGet.org Package Health: https://www.nuget.org/packages/Abblix.Utils
- SourceLink Documentation: https://github.com/dotnet/sourcelink
- Deterministic Builds: https://github.com/clairernovotny/DeterministicBuilds
