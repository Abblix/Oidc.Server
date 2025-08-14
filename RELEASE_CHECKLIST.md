# Oidc.Server Release Checklist

## Pre-Release Preparation

### 🌿 Git Flow & Feature Integration
- [x] Identify all feature branches for this release
- [x] **Accept PRs and merge feature branches to develop using Git Flow**:
  - [x] PR #28: `feature/base32-improvements` (Base32 performance optimizations)
  - [x] PR #27: `feature/extend-auth-session` (AMR support, dependency updates)
- [x] Create release branch from updated `develop`
  ```bash
  git flow release start v1.6.0
  ```
- [x] Resolve any merge conflicts (none occurred)
- [x] Verify all features work together (integration testing)
- [x] Delete merged feature branches (done automatically by git flow)

### 🔍 Code Quality & Testing
- [x] All unit tests pass (`dotnet test`)
  - [x] `Abblix.Jwt.UnitTests` (1 test passed)
  - [x] `Abblix.Oidc.Server.UnitTests` (13 tests passed)
  - [x] `Abblix.Oidc.Server.Mvc.UnitTests` (13 tests passed) - **Fixed dependency version mismatch**
  - [x] `Abblix.Utils.UnitTests` (81 tests passed) - **Base32 improvements validated**
- [x] Integration tests pass (`Abblix.Oidc.Server.Tests`) (1 passed, 3 skipped - integration tests)
- [x] **Real-world integration testing with AuthenticationService**:
  - [x] Built NuGet packages v1.6.0-beta1 from release branch
  - [x] Updated AuthenticationService to use new packages (6 projects)
  - [x] All AuthenticationService tests pass (42/42) - **CRITICAL VALIDATION** ✅
- [ ] Code coverage meets minimum threshold (recommend >80%)
- [ ] Static code analysis passes (no critical issues)
- [ ] Security vulnerability scan completed  
- [ ] Performance benchmarks reviewed (if applicable)

### 📝 Documentation & Legal
- [ ] Update `README.md` with new features and changes
- [ ] Update `Nuget\README.md` for NuGet package description
- [ ] Review and update `LICENSE.md` if needed
- [ ] Update `SECURITY.md` if security practices have changed
- [ ] Ensure all code has proper XML documentation comments
- [ ] Update API documentation (if applicable)

### 📦 NuGet Dependencies Update
- [ ] ⚠️ **CAUTION**: **NEVER** use simple `dotnet add package` for projects with conditional references
- [ ] For projects with conditional framework-specific references (see Abblix.Oidc.Server, Abblix.Jwt):
  - [ ] **Manually update versions** in `.csproj` files for each framework condition
  - [ ] **Keep major versions aligned** per framework (e.g., all .NET 6-8 use 8.x, .NET 9 uses 9.x)
  - [ ] **Update patch versions safely** within same major (8.0.1 → 8.0.11)
  - [ ] **Test each framework separately** after updates
- [ ] Check for outdated packages:
  ```bash
  dotnet list package --outdated
  ```
- [ ] **Manual update process for conditional references:**
  ```xml
  <!-- Example: Update within major version boundaries -->
  <ItemGroup Condition="'$(TargetFramework)' == 'net9.0'">
    <PackageReference Include="Microsoft.Extensions.Caching.Memory" Version="9.0.12" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)' == 'net6.0' OR '$(TargetFramework)' == 'net7.0' OR '$(TargetFramework)' == 'net8.0'">
    <PackageReference Include="Microsoft.Extensions.Caching.Memory" Version="8.0.11" />
  </ItemGroup>
  ```
- [ ] For non-conditional references, safe to use standard update commands
- [ ] Test with updated dependencies (regression testing)
- [ ] Verify compatibility with all target frameworks (.NET 6.0, 7.0, 8.0, 9.0)
- [ ] Update package references in test projects

### 🔧 Version Management
- [ ] Decide on version number following [Semantic Versioning](https://semver.org/)
  - [ ] **MAJOR**: Breaking changes
  - [ ] **MINOR**: New features (backward compatible)
  - [ ] **PATCH**: Bug fixes (backward compatible)
- [ ] Update version numbers in all `.csproj` files:
  - [ ] `Abblix.Oidc.Server\Abblix.Oidc.Server.csproj`
    - [ ] `<AssemblyVersion>` → `{version}.0`
    - [ ] `<FileVersion>` → `{version}.0`
    - [ ] `<PackageVersion>` → `{version}`
  - [ ] `Abblix.Oidc.Server.Mvc\Abblix.Oidc.Server.Mvc.csproj`
    - [ ] `<AssemblyVersion>` → `{version}.0`
    - [ ] `<FileVersion>` → `{version}.0`  
    - [ ] `<PackageVersion>` → `{version}`
  - [ ] `Abblix.Jwt\Abblix.Jwt.csproj`
    - [ ] `<AssemblyVersion>` → `{version}.0`
    - [ ] `<FileVersion>` → `{version}.0`
    - [ ] `<PackageVersion>` → `{version}`
  - [ ] `Abblix.DependencyInjection\Abblix.DependencyInjection.csproj`
    - [ ] `<AssemblyVersion>` → `{version}.0`
    - [ ] `<FileVersion>` → `{version}.0`
    - [ ] `<PackageVersion>` → `{version}`
  - [ ] `Abblix.Utils\Abblix.Utils.csproj`
    - [ ] `<AssemblyVersion>` → `{version}.0`
    - [ ] `<FileVersion>` → `{version}.0`
    - [ ] `<PackageVersion>` → `{version}`
- [ ] Update inter-project dependency versions if needed
- [ ] Update `<PackageReleaseNotes>` in all project files with changelog
- [ ] Ensure version consistency across all projects
- [ ] Update copyright year if needed (`<Copyright>`)

### 🏗️ Pre-Automation Validation
- [ ] **Local build verification** (optional, GitHub Actions will also do this):
  - [ ] Clean solution (`dotnet clean`)
  - [ ] Restore packages (`dotnet restore`)
  - [ ] Build solution in Release mode (`dotnet build -c Release`)
  - [ ] Run tests (`dotnet test -c Release`)
- [ ] **Choose version bump type**:
  - [ ] **PATCH** (1.5.0 → 1.5.1): Bug fixes, dependency updates
  - [ ] **MINOR** (1.5.0 → 1.6.0): New features, backward compatible
  - [ ] **MAJOR** (1.5.0 → 2.0.0): Breaking changes
- [ ] **Decide release type**:
  - [ ] **Stable release**: Ready for production
  - [ ] **Pre-release**: Beta/RC version for testing

### 🤖 Automated Release via GitHub Actions
- [ ] **Navigate to GitHub Actions**:
  - [ ] Go to https://github.com/Abblix/Oidc.Server/actions
  - [ ] Select **"Enhanced Release Automation"** workflow
  - [ ] Click **"Run workflow"**
- [ ] **Configure workflow parameters**:
  - [ ] **Version bump type**: Select patch/minor/major
  - [ ] **Pre-release**: Check if this is a beta/RC version
  - [ ] Click **"Run workflow"** button
- [ ] **Monitor automated steps** (GitHub Actions handles):
  ✅ **Auto-versioning**: Creates git tag with new version  
  ✅ **Build & Test**: Compiles and tests all projects  
  ✅ **GettingStarted Integration**: Tests packages with sample projects  
  ✅ **GitHub Release**: Creates release with changelog and package files  
  ✅ **Auto-update GettingStarted**: Updates sample repo (stable releases only)
- [ ] **Verify automation success**:
  - [ ] Check that workflow completed successfully (green checkmarks)
  - [ ] Verify new git tag was created: `v{version}`
  - [ ] Confirm GitHub release was created with packages attached
  - [ ] If pre-release: verify marked correctly in GitHub
  - [ ] If stable: confirm GettingStarted repo was updated
- [ ] **If automation fails**:
  - [ ] Review GitHub Actions logs to identify the issue
  - [ ] Fix the problem in code (likely in main library or tests)
  - [ ] Commit fixes and re-run the workflow
  - [ ] May need to delete failed git tag before retrying

## Manual Publishing Process

### 📦 Download Release Packages
- [ ] **Download packages from GitHub Release**:
  - [ ] Go to https://github.com/Abblix/Oidc.Server/releases
  - [ ] Find the release created by automation: `v{version}`
  - [ ] Download all `.nupkg` files from release assets
  - [ ] Verify package versions match the release tag

### 📦 NuGet Publishing (Dual Platform)
- [ ] **Setup publishing environment**:
  ```bash
  # Ensure you have NuGet API key configured
  # Configure GitHub Packages source if not done
  dotnet nuget add source https://nuget.pkg.github.com/Abblix/index.json -n github -u USERNAME -p GITHUB_TOKEN
  ```
- [ ] **Publish to NuGet.org** in dependency order (using downloaded packages):
  ```bash
  # Navigate to folder with downloaded .nupkg files
  
  # 1. Base utilities (no dependencies)
  dotnet nuget push Abblix.Utils.{version}.nupkg -s https://api.nuget.org/v3/index.json
  
  # 2. Dependency injection (depends on Utils)  
  dotnet nuget push Abblix.DependencyInjection.{version}.nupkg -s https://api.nuget.org/v3/index.json
  
  # 3. JWT library (depends on Utils)
  dotnet nuget push Abblix.Jwt.{version}.nupkg -s https://api.nuget.org/v3/index.json
  
  # 4. Core OIDC Server (depends on JWT, DI, Utils)
  dotnet nuget push Abblix.OIDC.Server.{version}.nupkg -s https://api.nuget.org/v3/index.json
  
  # 5. MVC extensions (depends on OIDC Server)
  dotnet nuget push Abblix.OIDC.Server.MVC.{version}.nupkg -s https://api.nuget.org/v3/index.json
  ```
- [ ] **Publish to GitHub Packages** in same order:
  ```bash
  # Push to GitHub Packages (same order as NuGet.org)
  dotnet nuget push Abblix.Utils.{version}.nupkg -s github
  dotnet nuget push Abblix.DependencyInjection.{version}.nupkg -s github  
  dotnet nuget push Abblix.Jwt.{version}.nupkg -s github
  dotnet nuget push Abblix.OIDC.Server.{version}.nupkg -s github
  dotnet nuget push Abblix.OIDC.Server.MVC.{version}.nupkg -s github
  ```
- [ ] **Verify publishing success**:
  - [ ] **NuGet.org**: https://www.nuget.org/packages?q=Abblix
  - [ ] **GitHub Packages**: https://github.com/Abblix/Oidc.Server/packages
  - [ ] Test package installation from both sources in fresh project
  - [ ] Wait for package indexing to complete (can take 5-15 minutes)

### ✏️ Review Automated Release Notes  
- [ ] **GitHub Release was created automatically** with:
  ✅ Auto-generated changelog from git commits
  ✅ Package download links  
  ✅ Proper release/pre-release marking
  ✅ All `.nupkg` files attached
- [ ] **Review and enhance the release notes** (optional):
  - [ ] Navigate to https://github.com/Abblix/Oidc.Server/releases
  - [ ] Find the auto-created release: `v{version}`
  - [ ] Click **"Edit release"** if you want to improve the description
  - [ ] Add more detailed explanations, breaking changes, migration notes
  - [ ] Update if any important context is missing from auto-generated changelog

## Post-Release Activities

### 📢 Communication & Updates
- [ ] Update project website (abblix.com)
- [ ] Update documentation site (docs.abblix.com)
- [ ] Notify community/users through appropriate channels
- [ ] Update ChatGPT assistant knowledge (if major changes)
- [ ] Update sample projects and getting started guides
- [ ] Blog post announcement (if major release)

### 🔄 Dependency Updates
- [ ] Update AuthenticationService to use new version
- [ ] Update AdminApp dependencies if needed
- [ ] Update any example projects or demos
- [ ] Update Docker images/containers if applicable

### 🧪 Post-Release Verification
- [ ] Monitor for immediate issues or bug reports
- [ ] Verify download statistics on NuGet
- [ ] Check automated tests in dependent projects
- [ ] Monitor support channels for user questions
- [ ] Create hotfix branch if critical issues found

### 📋 Process Improvement
- [ ] Document any issues encountered during release
- [ ] Update release checklist based on learnings
- [ ] Schedule retrospective meeting with team
- [ ] Update CI/CD pipelines if needed

## Emergency Procedures

### 🚨 Rollback Process
If critical issues are discovered:
- [ ] **Immediate**: Unlist packages from NuGet.org (if severe security issue)
  ```bash
  dotnet nuget delete Abblix.OIDC.Server {version} -s https://api.nuget.org/v3/index.json
  # Repeat for other affected packages
  ```
- [ ] **GitHub**: Hide or delete problematic packages from GitHub Packages
- [ ] **Release**: Mark GitHub release as pre-release or delete if critical
- [ ] Create hotfix using Git Flow
- [ ] Communicate issue immediately to users via all channels

### 🔧 Hotfix Release (Git Flow)
- [ ] Create hotfix branch from main: 
  ```bash
  git flow hotfix start v{version}
  # or manually: git checkout -b hotfix/v{version} main
  ```
- [ ] Apply minimal necessary changes
- [ ] Update patch version only (e.g., 1.5.0 → 1.5.1)
- [ ] Run abbreviated test suite (critical tests only)
- [ ] Commit hotfix changes
- [ ] Finish Git Flow hotfix:
  ```bash  
  git flow hotfix finish v{version}
  # This merges to both main and develop, creates tag
  ```
- [ ] Push changes and tag
- [ ] Follow expedited publishing process
- [ ] Update release notes explaining the hotfix
- [ ] Document root cause and prevention measures

## Important Notes

### 🔧 Prerequisites
- [ ] **Git Flow** configured and initialized in repository
- [ ] **Git Flow signed tags** configured (one-time setup):
  ```bash
  git config gitflow.release.sign true
  ```
- [ ] **NuGet.org API Key** configured and valid 
- [ ] **GitHub Personal Access Token** with packages:write permissions
- [ ] **Build environment** clean with latest .NET SDK versions
- [ ] **Access permissions** for publishing to both NuGet.org and GitHub Packages

### ⚠️ Critical Reminders  
- **Feature Integration**: All feature branches must be merged into release branch before final testing
- **Version Consistency**: All 5 packages must have identical version numbers
- **Dependency Order**: Always publish in dependency order to avoid installation issues
- **Dual Publishing**: Verify packages are available on both NuGet.org and GitHub Packages
- **Git Flow Dual Merge**: The `git flow release finish` command automatically:
  - Merges release → master (production)
  - Creates signed tag on master (with `gitflow.release.sign true`)
  - Merges release → develop (future development)  
  - Deletes release branch
- **Automatic Signed Tags**: With `gitflow.release.sign true`, all release tags are automatically signed
- **GPG Verification**: Always verify signed tags with `git tag -v` after creation
- **GitHub Verification**: Your signed tags will show "Verified" badges on GitHub
- **Branch Protection**: If you have branch protection rules, use Option B (manual PR process)
- **Testing**: Re-run full test suite after merging all feature branches
- **Documentation**: Update release notes to mention all merged features
- **Merge Conflicts**: If conflicts occur during merge back to develop, resolve manually and commit

### 📋 Checklist Usage
- [ ] Complete all checkboxes in each section before proceeding to the next
- [ ] For major releases (breaking changes), consider beta/RC releases first
- [ ] Always test packages in isolated environment before publishing
- [ ] Keep detailed logs of release activities for audit purposes
- [ ] Have rollback plan ready before starting release process
- [ ] Document any deviations from this process for future improvements

### 🎯 Success Criteria
✅ **Release is complete when:**
- All feature branches merged and tested together
- All 5 packages published to both NuGet.org and GitHub Packages
- GitHub release created with comprehensive notes and artifacts  
- Git Flow properly completed (merged to main and develop)
- Post-release verification completed successfully

---
*This checklist is specifically tailored for the Abblix Oidc.Server Git Flow release process with dual NuGet publishing.*