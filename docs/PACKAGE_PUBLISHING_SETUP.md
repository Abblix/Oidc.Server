# Package Publishing Setup

## GitHub Environment Configuration

To enable the manual approval gate for package publishing, you need to create a GitHub Environment:

### 1. Create Environment in GitHub

1. Go to your repository: https://github.com/Abblix/Oidc.Server
2. Navigate to **Settings** → **Environments**
3. Click **New environment**
4. Name: `package-publishing`
5. Configure **Environment protection rules**:
   - ✅ **Required reviewers**: Add yourself or trusted team members
   - ✅ **Prevent self-review**: Optional (recommended for teams)
   - ⏰ **Wait timer**: Optional (e.g., 5 minutes minimum wait)

### 2. Required Secrets

Ensure these secrets are configured in your repository:

#### Repository Secrets (Settings → Secrets → Actions)
- **`NUGET_API_KEY`**: Your NuGet.org API key with push permissions
- **`GITHUB_TOKEN`**: Automatically provided (has packages:write by default)

#### Getting NuGet.org API Key
1. Go to https://www.nuget.org/account/apikeys
2. Create new API key with **Push** permissions
3. Scope to **Abblix.*** packages (or specific package names)
4. Copy the key and add as `NUGET_API_KEY` secret

## How the Approval Process Works

### Workflow Behavior
1. **Automatic Steps**: Build, test, create release (no approval needed)
2. **Manual Approval**: Package publishing waits for approval
3. **Notification**: You'll receive GitHub notification when approval is needed
4. **Review & Approve**: Review packages list, then approve/reject
5. **Publishing**: After approval, packages are published to both sources

### Manual Publishing (Alternative)

You can also use the standalone script for local publishing:

```bash
# Set environment variables
export GITHUB_TOKEN="your_github_token"
export NUGET_API_KEY="your_nuget_api_key"

# Run the script
./scripts/publish-packages.sh nupkg

# Or specify different directory
./scripts/publish-packages.sh /path/to/packages
```

## Publishing Process

### From GitHub Actions (Recommended)
1. Run **Enhanced Release Automation** workflow
2. Wait for build/test/release steps to complete
3. **Approve package publishing** when prompted
4. Monitor publishing progress in workflow logs

### From Local Script
1. Download packages from GitHub release
2. Set environment variables (`GITHUB_TOKEN`, `NUGET_API_KEY`)
3. Run `./scripts/publish-packages.sh`
4. Confirm each publishing step interactively

## Verification

After publishing, verify packages are available:

- **GitHub Packages**: https://github.com/Abblix/Oidc.Server/packages
- **NuGet.org**: https://www.nuget.org/packages?q=Abblix
- **Package indexing**: Wait 5-15 minutes for full availability

## Safety Features

- ✅ **Manual approval gate** prevents accidental publishing
- ✅ **Skip duplicates** prevents overwriting existing versions
- ✅ **Per-package publishing** with individual error handling
- ✅ **Interactive confirmations** in standalone script
- ✅ **Comprehensive logging** for troubleshooting