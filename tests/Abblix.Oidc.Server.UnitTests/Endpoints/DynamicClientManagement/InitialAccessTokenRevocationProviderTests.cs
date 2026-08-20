// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
