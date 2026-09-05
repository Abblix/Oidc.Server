// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="ScopeValidator"/> verifying scope validation
/// per RFC 7591 Section 2.
/// </summary>
public class ScopeValidatorTests
{
    private readonly Mock<IScopeManager> _scopeManager = new();
    private readonly ScopeValidator _validator;

    public ScopeValidatorTests()
    {
        _validator = new ScopeValidator(_scopeManager.Object);
    }

    private static ClientRegistrationValidationContext CreateContext(string[]? scope)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            Scope = scope,
        };
        return new ClientRegistrationValidationContext(request);
    }

    [Fact]
    public async Task ValidateAsync_WithNullScope_ShouldReturnNull()
    {
        var result = await _validator.ValidateAsync(CreateContext(null));
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WithEmptyScope_ShouldReturnNull()
    {
        var result = await _validator.ValidateAsync(CreateContext([]));
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WithKnownScopes_ShouldReturnNull()
    {
        ScopeDefinition? def = new(Scopes.OpenId);
        _scopeManager
            .Setup(m => m.TryGet("openid", out def))
            .Returns(true);

        ScopeDefinition? def2 = new(Scopes.Profile);
        _scopeManager
            .Setup(m => m.TryGet("profile", out def2))
            .Returns(true);

        var result = await _validator.ValidateAsync(CreateContext(["openid", "profile"]));
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WithUnknownScope_ShouldReturnError()
    {
        ScopeDefinition? def = new(Scopes.OpenId);
        _scopeManager
            .Setup(m => m.TryGet("openid", out def))
            .Returns(true);

        var result = await _validator.ValidateAsync(CreateContext(["openid", "unknown_scope"]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains("unknown_scope", result.ErrorDescription);
    }
}
