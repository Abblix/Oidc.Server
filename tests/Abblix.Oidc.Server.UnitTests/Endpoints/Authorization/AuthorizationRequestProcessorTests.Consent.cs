// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

public partial class AuthorizationRequestProcessorTests
{
    /// <summary>
    /// Verifies consent_required error when consent is pending and prompt=none.
    /// Per OIDC, user cannot be prompted for consent when prompt=none.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPendingConsentAndPromptNone_ShouldReturnConsentRequired()
    {
        // Arrange
        var request = CreateRequest(prompt: Prompts.None);
        var session = CreateAuthSession();
        var consents = CreateConsents(pendingScopes: [new ScopeDefinition("email")]);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.ConsentRequired, error.Error);
    }

    /// <summary>
    /// Verifies ConsentRequired when scopes pending consent.
    /// User must grant permission for requested scopes.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPendingScopes_ShouldReturnConsentRequired()
    {
        // Arrange
        var request = CreateRequest();
        var session = CreateAuthSession();
        var pendingScopes = new[] { new ScopeDefinition("email"), new ScopeDefinition("profile") };
        var consents = CreateConsents(pendingScopes: pendingScopes);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var consentRequired = Assert.IsType<ConsentRequired>(result);
        Assert.Equal(pendingScopes, consentRequired.RequiredUserConsents.Scopes);
    }

    /// <summary>
    /// Verifies ConsentRequired when resources pending consent.
    /// User must grant permission for requested resources.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithPendingResources_ShouldReturnConsentRequired()
    {
        // Arrange
        var request = CreateRequest();
        var session = CreateAuthSession();
        var pendingResources = new[] { new ResourceDefinition(new Uri("https://api.example.com")) };
        var consents = CreateConsents(pendingResources: pendingResources);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var consentRequired = Assert.IsType<ConsentRequired>(result);
        Assert.Equal(pendingResources, consentRequired.RequiredUserConsents.Resources);
    }

    /// <summary>
    /// Anti-escalation backstop (#185): the IUserConsentsProvider contract permits a narrower grant
    /// than the request, never a broader one. A granted scope absent from the request is a host-side
    /// contract violation and must fail loud with an exception instead of issuing an escalated grant.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_GrantedScopeExceedsRequest_ShouldThrow()
    {
        // Arrange - request carries only openid; the consent provider returns an extra "admin"
        // scope that was never requested (e.g. browser tampering it failed to intersect away).
        var request = CreateRequest(responseType: [ResponseTypes.Code], scope: [Scopes.OpenId]);
        var session = CreateAuthSession();
        var consents = CreateConsents(
            grantedScopes: [new ScopeDefinition(Scopes.OpenId), new ScopeDefinition("admin")]);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);
        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(), request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        // Act + Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() => _processor.ProcessAsync(request));
    }

    /// <summary>
    /// Anti-escalation backstop (#185): a granted resource absent from the request is likewise a
    /// host-side contract violation and must fail loud.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_GrantedResourceNotRequested_ShouldThrow()
    {
        // Arrange - the request carries no resources; the provider grants one anyway.
        var request = CreateRequest(responseType: [ResponseTypes.Code]);
        var session = CreateAuthSession();
        var consents = CreateConsents(
            grantedResources: [new ResourceDefinition(new Uri("https://api.example/admin"))]);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);
        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(), request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("code");

        // Act + Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() => _processor.ProcessAsync(request));
    }
}
