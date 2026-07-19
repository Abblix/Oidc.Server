// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Unit tests for <see cref="InitialAccessTokenRevocationProvider"/> verifying
/// revocation checks against <see cref="OidcOptions.RevokedInitialAccessTokenSubjects"/>.
/// </summary>
public class InitialAccessTokenRevocationProviderTests
{
    private readonly OidcOptions _options;
    private readonly InitialAccessTokenRevocationProvider _provider;

    public InitialAccessTokenRevocationProviderTests()
    {
        _options = new OidcOptions();

        var optionsMonitor = new Mock<IOptionsMonitor<OidcOptions>>();
        optionsMonitor.Setup(m => m.CurrentValue).Returns(() => _options);

        _provider = new InitialAccessTokenRevocationProvider(optionsMonitor.Object);
    }

    [Fact]
    public async Task IsRevokedAsync_WithEmptySet_ShouldReturnFalse()
    {
        var result = await _provider.IsRevokedAsync("any-subject");

        Assert.False(result);
    }

    [Fact]
    public async Task IsRevokedAsync_WithRevokedSubject_ShouldReturnTrue()
    {
        _options.RevokedInitialAccessTokenSubjects = ["revoked-1", "revoked-2"];

        var result = await _provider.IsRevokedAsync("revoked-1");

        Assert.True(result);
    }

    [Fact]
    public async Task IsRevokedAsync_WithNonRevokedSubject_ShouldReturnFalse()
    {
        _options.RevokedInitialAccessTokenSubjects = ["revoked-1"];

        var result = await _provider.IsRevokedAsync("not-revoked");

        Assert.False(result);
    }

    [Fact]
    public async Task IsRevokedAsync_ShouldReflectOptionsChanges()
    {
        Assert.False(await _provider.IsRevokedAsync("partner-app"));

        _options.RevokedInitialAccessTokenSubjects = ["partner-app"];

        Assert.True(await _provider.IsRevokedAsync("partner-app"));
    }
}
