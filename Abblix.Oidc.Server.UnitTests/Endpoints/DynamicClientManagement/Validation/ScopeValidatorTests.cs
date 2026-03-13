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

using System;
using System.Diagnostics.CodeAnalysis;
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
            RedirectUris = [new Uri(TestConstants.DefaultRedirectUri)],
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
