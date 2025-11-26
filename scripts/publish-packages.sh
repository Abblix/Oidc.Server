#!/bin/bash

# Abblix OIDC Server - Package Publishing Script
# This script publishes NuGet packages to both GitHub Packages and NuGet.org
# with interactive confirmation steps

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GITHUB_PACKAGES_SOURCE="https://nuget.pkg.github.com/Abblix/index.json"
NUGET_ORG_SOURCE="https://api.nuget.org/v3/index.json"
PACKAGES_DIR="${1:-nupkg}"

echo -e "${BLUE}📦 Abblix OIDC Server - Package Publishing Script${NC}"
echo "================================================="

# Check if packages directory exists
if [[ ! -d "$PACKAGES_DIR" ]]; then
    echo -e "${RED}❌ Error: Packages directory '$PACKAGES_DIR' not found${NC}" >&2
    echo "Usage: $0 [packages-directory]" >&2
    echo "Example: $0 nupkg" >&2
    exit 1
fi

# Find .nupkg files
PACKAGES=($(find "$PACKAGES_DIR" -name "*.nupkg" -type f))

if [[ ${#PACKAGES[@]} -eq 0 ]]; then
    echo -e "${RED}❌ Error: No .nupkg files found in '$PACKAGES_DIR'${NC}" >&2
    exit 1
fi

echo -e "${GREEN}📋 Found ${#PACKAGES[@]} packages:${NC}"
for pkg in "${PACKAGES[@]}"; do
    echo "  - $(basename "$pkg")"
done
echo ""

# Confirmation for GitHub Packages
echo -e "${YELLOW}🎯 Publish to GitHub Packages?${NC}"
echo "   Source: $GITHUB_PACKAGES_SOURCE"
echo "   Requires: GITHUB_TOKEN environment variable"
echo ""
read -p "Continue with GitHub Packages publishing? (y/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [[ -z "$GITHUB_TOKEN" ]]; then
        echo -e "${RED}❌ Error: GITHUB_TOKEN environment variable not set${NC}" >&2
        echo "Please set GITHUB_TOKEN with packages:write permission" >&2
        exit 1
    fi
    
    echo -e "${BLUE}📤 Publishing to GitHub Packages...${NC}"
    for pkg in "${PACKAGES[@]}"; do
        echo "Publishing $(basename "$pkg")..."
        if dotnet nuget push "$pkg" \
            --api-key "$GITHUB_TOKEN" \
            --source "$GITHUB_PACKAGES_SOURCE" \
            --skip-duplicate \
            --no-symbols; then
            echo -e "${GREEN}✅ $(basename "$pkg") published successfully${NC}"
        else
            echo -e "${YELLOW}⚠️  $(basename "$pkg") may already exist or failed to publish${NC}"
        fi
    done
    echo -e "${GREEN}✅ GitHub Packages publishing completed${NC}"
    echo ""
else
    echo -e "${YELLOW}⏭️  Skipping GitHub Packages publishing${NC}"
    echo ""
fi

# Confirmation for NuGet.org
echo -e "${YELLOW}🎯 Publish to NuGet.org?${NC}"
echo "   Source: $NUGET_ORG_SOURCE"
echo "   Requires: NUGET_API_KEY environment variable"
echo ""
read -p "Continue with NuGet.org publishing? (y/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [[ -z "$NUGET_API_KEY" ]]; then
        echo -e "${RED}❌ Error: NUGET_API_KEY environment variable not set${NC}" >&2
        echo "Please set NUGET_API_KEY with your NuGet.org API key" >&2
        exit 1
    fi
    
    echo -e "${BLUE}📤 Publishing to NuGet.org...${NC}"
    for pkg in "${PACKAGES[@]}"; do
        echo "Publishing $(basename "$pkg")..."
        if dotnet nuget push "$pkg" \
            --api-key "$NUGET_API_KEY" \
            --source "$NUGET_ORG_SOURCE" \
            --skip-duplicate \
            --no-symbols; then
            echo -e "${GREEN}✅ $(basename "$pkg") published successfully${NC}"
        else
            echo -e "${YELLOW}⚠️  $(basename "$pkg") may already exist or failed to publish${NC}"
        fi
    done
    echo -e "${GREEN}✅ NuGet.org publishing completed${NC}"
    echo ""
else
    echo -e "${YELLOW}⏭️  Skipping NuGet.org publishing${NC}"
    echo ""
fi

echo -e "${GREEN}🎉 Publishing script completed!${NC}"
echo ""
echo -e "${BLUE}🔍 Verification steps:${NC}"
echo "1. Check GitHub Packages: https://github.com/Abblix/Oidc.Server/packages"
echo "2. Check NuGet.org: https://www.nuget.org/packages?q=Abblix"
echo "3. Wait 5-15 minutes for package indexing to complete"
echo ""
echo -e "${BLUE}📋 Processed packages:${NC}"
for pkg in "${PACKAGES[@]}"; do
    echo "  - $(basename "$pkg")"
done