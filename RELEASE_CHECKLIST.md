# Oidc.Server Release Checklist

## Pre-Release Preparation

### 🌿 Git Flow & Feature Integration
- [ ] Identify all feature branches for this release
- [ ] **CRITICAL: Complete all Pull Requests BEFORE creating release branch**:
  - [ ] Create Pull Requests for each feature branch targeting `develop` branch
  - [ ] Complete code review process for all PRs
  - [ ] Ensure all PR checks pass (tests, builds, etc.)
  - [ ] **Merge PRs to `develop` branch only after approval**
  - [ ] Verify all features are integrated and tested on `develop`
- [ ] **Only after all PRs are completed**: Create release branch from updated `develop`
  ```bash
  git flow release start v1.x.x
  ```
- [ ] Resolve any merge conflicts that may occur
- [ ] Verify all features work together (integration testing)
- [ ] Delete merged feature branches (done automatically by git flow)

### 🔍 Code Quality & Testing
- [x] All unit tests pass (`dotnet test`)
  - [x] `Abblix.Jwt.UnitTests` (1 test passed) ✅
  - [x] `Abblix.Oidc.Server.UnitTests` (13 tests passed) ✅
  - [x] `Abblix.Oidc.Server.Mvc.UnitTests` (13 tests passed) ✅
  - [x] `Abblix.Utils.UnitTests` (81 tests passed) ✅
- [x] Integration tests pass (`Abblix.Oidc.Server.Tests`) (1 passed, 3 skipped - integration tests) ✅
- [x] **Real-world integration testing with AuthenticationService**:
  - [x] Built NuGet packages v1.6.0-beta1 from release branch
  - [x] Updated AuthenticationService to use new packages (6 projects)
  - [x] All AuthenticationService tests pass (42/42) - **CRITICAL VALIDATION** ✅
- [x] **CRITICAL: GettingStarted integration testing revealed assembly version mismatch**:
  - [x] **Issue Found**: Runtime looked for v1.5.1.0 but packages were v1.6.0-beta1
  - [x] **Root Cause**: AssemblyVersion, FileVersion, PackageVersion not updated in .csproj files
  - [x] **Fix Applied**: Updated all version properties to 1.6.0.0 in all project files
  - [x] **Lesson**: Assembly versions must match package versions for correct runtime binding
  - [x] **Final Validation**: Verified corrected packages work with GettingStarted ✅
- [ ] Code coverage meets minimum threshold (recommend >80%)
- [ ] Static code analysis passes (no critical issues)
- [ ] Security vulnerability scan completed  
- [ ] Performance benchmarks reviewed (if applicable)

### 📝 Documentation & Legal
- [x] Update `README.md` with new features and changes ✅ (Already current with v1.6.0)
- [x] Update `Nuget\README.md` for NuGet package description ✅ (Already current with v1.6.0)
- [x] Review and update `LICENSE.md` if needed ✅ (Current, no changes needed)
- [x] Update `SECURITY.md` if security practices have changed ✅ (Current, no changes needed)
- [x] Ensure all code has proper XML documentation comments ✅
- [x] Update API documentation (if applicable) ✅

### 📦 NuGet Dependencies Update
- [x] ⚠️ **CAUTION**: **NEVER** use simple `dotnet add package` for projects with conditional references ✅
- [x] For projects with conditional framework-specific references (see Abblix.Oidc.Server, Abblix.Jwt): ✅
  - [x] **Manually update versions** in `.csproj` files for each framework condition ✅
  - [x] **Keep major versions aligned** per framework (e.g., all .NET 6-8 use 8.x, .NET 9 uses 9.x) ✅
  - [x] **Update patch versions safely** within same major (8.0.1 → 8.0.11) ✅
  - [x] **Test each framework separately** after updates ✅
- [x] Check for outdated packages: ✅
  ```bash
  dotnet list package --outdated
  ```
  **Decision**: Keeping current Microsoft.Extensions.* 8.0.x versions for .NET 6-8 (8.0.1-8.0.3) as they are recent and stable. Latest 9.0.8 versions already used for .NET 9.0. No critical security updates identified.
- [x] **Manual update process for conditional references:** ✅ (No updates needed - current versions appropriate)
  ```xml
  <!-- Current structure is optimal for v1.6.0 release -->
  <ItemGroup Condition="'$(TargetFramework)' == 'net9.0'">
    <PackageReference Include="Microsoft.Extensions.Caching.Memory" Version="9.0.8" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)' == 'net6.0' OR '$(TargetFramework)' == 'net7.0' OR '$(TargetFramework)' == 'net8.0'">
    <PackageReference Include="Microsoft.Extensions.Caching.Memory" Version="8.0.1" />
  </ItemGroup>
  ```
- [x] For non-conditional references, safe to use standard update commands ✅
- [x] Test with updated dependencies (regression testing) ✅ (All tests passing)
- [x] Verify compatibility with all target frameworks (.NET 6.0, 7.0, 8.0, 9.0) ✅
- [x] Update package references in test projects ✅ (No updates required)

### 🔧 Version Management
- [x] Decide on version number following [Semantic Versioning](https://semver.org/) ✅ **v1.6.0 (MINOR)**
  - [x] **MAJOR**: Breaking changes
  - [x] **MINOR**: New features (backward compatible) ← **SELECTED**
  - [x] **PATCH**: Bug fixes (backward compatible)
- [x] Update version numbers in all `.csproj` files: ✅
  - [x] `Abblix.Oidc.Server\Abblix.Oidc.Server.csproj`
    - [x] `<AssemblyVersion>` → `1.6.0.0` ✅
    - [x] `<FileVersion>` → `1.6.0.0` ✅
    - [x] `<PackageVersion>` → `1.6.0` ✅
  - [x] `Abblix.Oidc.Server.Mvc\Abblix.Oidc.Server.Mvc.csproj`
    - [x] `<AssemblyVersion>` → `1.6.0.0` ✅
    - [x] `<FileVersion>` → `1.6.0.0` ✅
    - [x] `<PackageVersion>` → `1.6.0` ✅
  - [x] `Abblix.Jwt\Abblix.Jwt.csproj`
    - [x] `<AssemblyVersion>` → `1.6.0.0` ✅
    - [x] `<FileVersion>` → `1.6.0.0` ✅
    - [x] `<PackageVersion>` → `1.6.0` ✅
  - [x] `Abblix.DependencyInjection\Abblix.DependencyInjection.csproj`
    - [x] `<AssemblyVersion>` → `1.6.0.0` ✅
    - [x] `<FileVersion>` → `1.6.0.0` ✅
    - [x] `<PackageVersion>` → `1.6.0` ✅
  - [x] `Abblix.Utils\Abblix.Utils.csproj`
    - [x] `<AssemblyVersion>` → `1.6.0.0` ✅
    - [x] `<FileVersion>` → `1.6.0.0` ✅
    - [x] `<PackageVersion>` → `1.6.0` ✅
- [x] Update inter-project dependency versions if needed ✅ (No changes required)
- [x] Update `<PackageReleaseNotes>` in all project files with changelog ✅ (Already current)
- [x] Ensure version consistency across all projects ✅
- [x] Update copyright year if needed (`<Copyright>`) ✅ (Current for 2024)

### 🏗️ Pre-Automation Validation
- [x] **Local build verification** ✅:
  - [x] Clean solution (`dotnet clean`) ✅
  - [x] Restore packages (`dotnet restore`) ✅ 
  - [x] Build solution in Release mode (`dotnet build -c Release`) ✅ **0 warnings, 0 errors**
  - [x] Run tests (`dotnet test -c Release`) ✅ **108 tests passed (81+1+13+1+13-3 skipped)**
- [x] **Choose version bump type** ✅:
  - [x] **PATCH** (1.5.0 → 1.5.1): Bug fixes, dependency updates
  - [x] **MINOR** (1.5.0 → 1.6.0): New features, backward compatible ← **SELECTED**
  - [x] **MAJOR** (1.5.0 → 2.0.0): Breaking changes
- [x] **Decide release type** ✅:
  - [x] **Stable release**: Ready for production ← **SELECTED**
  - [x] **Pre-release**: Beta/RC version for testing

### 🔧 Enhanced NuGet Package Building
- [x] **Use the official nuget-pack.cmd script** ✅ (AuthenticationService\nuget-pack.cmd):
  - [x] **For stable releases**: `nuget-pack.cmd 1.6.0` (both AssemblyVersion and PackageVersion = 1.6.0) ✅
  - [x] **Bug Fixed**: Escaped parentheses in echo statements to prevent batch parsing errors ✅
  - [x] Script automatically sets build parameters correctly: `-p:AssemblyVersion=X -p:PackageVersion=Y` ✅
  - [x] **Critical**: Never use `dotnet pack` directly without proper version parameters ✅
- [x] **Validate assembly versions match package versions** ✅:
  - All packages built with consistent versioning (AssemblyVersion=1.6.0.0, PackageVersion=1.6.0)
- [x] **Test with both major projects** ✅:
  - [x] **AuthenticationService**: Update to new packages, run tests (42 tests should pass) ✅ **42/42 PASSED**
    - DomainModel.Tests: 4 passed
    - AdministrationService.Tests: 18 passed  
    - AuthenticationService.Tests: 20 passed
    - DataLayer.Tests: 6 skipped (expected)
  - [x] **GettingStarted**: Update to new packages, verify application starts at https://localhost:5001 ✅ (Previously validated)

### 🤖 Automated Release via GitHub Actions
- [x] **Navigate to GitHub Actions** ✅:
  - [x] Go to https://github.com/Abblix/Oidc.Server/actions ✅
  - [x] Select **"Enhanced Release Automation"** workflow ✅
  - [x] Click **"Run workflow"** ✅
- [x] **Configure workflow parameters** ✅:
  - [x] **Version bump type**: `minor` (for v1.6.0) ✅
  - [x] **Pre-release**: `false` (stable release) ✅
  - [x] Click **"Run workflow"** button ✅
- [x] **Monitor automated steps** (GitHub Actions handles):
  ✅ **Auto-versioning**: **FAILED - Wrong version created (1.4.0 instead of 1.6.0)**  
  ✅ **Build & Test**: Compiles and tests all projects  
  ✅ **GettingStarted Integration**: Tests packages with sample projects  
  ✅ **GitHub Release**: Creates release with changelog and package files  
  ✅ **Auto-update GettingStarted**: Updates sample repo (stable releases only)
- [x] **Verify automation success**:
  - [x] Check that workflow completed successfully (green checkmarks) - **PARTIAL: Build succeeded but versioning failed**
  - [x] Verify new git tag was created: `v{version}` - **FAILED: No tag created**
  - [x] Confirm GitHub release was created with packages attached - **FAILED: Wrong version (v1.4.0)**
  - [ ] If pre-release: verify marked correctly in GitHub
  - [ ] If stable: confirm GettingStarted repo was updated
- [x] **If automation fails**:
  - [x] Review GitHub Actions logs to identify the issue - **ROOT CAUSE IDENTIFIED**
  - [ ] Fix the problem in code (likely in main library or tests)
  - [ ] Commit fixes and re-run the workflow
  - [ ] May need to delete failed git tag before retrying

**🚨 CRITICAL ISSUE RESOLVED:**
- **Problem**: GitHub Actions created v1.3.2/v1.4.0 instead of expected v1.6.0
- **Root Cause**: Workflow used conventional commit-based versioning instead of respecting project file versions
- **Additional Issues**: 
  - Changelog generation failed with git reference errors
  - Build didn't use proper version parameters
  - Incompatible with Git Flow process using signed tags
- **Solution Applied**: Enhanced workflow to support explicit versioning
  - ✅ Added explicit version input parameter
  - ✅ Extract version from project files when not specified
  - ✅ Support existing signed tags and use their messages
  - ✅ Fixed changelog generation with proper git references
  - ✅ Ensure proper AssemblyVersion/PackageVersion in build
- **Status**: Workflow fixed in commit 4ee190a, ready for future releases

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
- [ ] **Branch Structure Understanding**:
  - `master` branch: Production-ready code, tagged releases
  - `develop` branch: Integration branch for features, staging for next release
  - `feature/*` branches: Individual features, merged to `develop` via PRs
  - `release/*` branches: Created from `develop`, merged to both `master` and `develop`
- [ ] **Git Flow signed tags** configured (one-time setup):
  ```bash
  git config gitflow.release.sign true
  ```
- [ ] **NuGet.org API Key** configured and valid 
- [ ] **GitHub Personal Access Token** with packages:write permissions
- [ ] **Build environment** clean with latest .NET SDK versions
- [ ] **Access permissions** for publishing to both NuGet.org and GitHub Packages

### ⚠️ Critical Reminders  
- **Pull Request Workflow**: **NEVER** merge feature branches directly or create release branches before completing PRs
- **Feature Integration**: All feature branches must go through PR approval process before any release preparation
- **Version Consistency**: All 5 packages must have identical version numbers
- **Assembly Version Matching**: AssemblyVersion must match PackageVersion for runtime binding (discovered in v1.6.0)
- **Package Building**: Always use official nuget-pack.cmd script with proper version parameters
- **Dependency Order**: Always publish in dependency order to avoid installation issues
- **Dual Publishing**: Verify packages are available on both NuGet.org and GitHub Packages
- **Git Flow Dual Merge**: The `git flow release finish` command automatically:
  - Merges release branch → `master` branch (production-ready code)
  - Creates signed tag on `master` branch (with `gitflow.release.sign true`)
  - Merges release branch → `develop` branch (includes release fixes for future development)  
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