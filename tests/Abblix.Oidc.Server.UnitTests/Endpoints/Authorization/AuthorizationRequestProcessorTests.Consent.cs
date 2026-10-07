// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
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
        var request = CreateRequest(prompt: [Prompts.None]);
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
    /// A request asking for consent leaves every scope pending, consent granted before included, and stamps the
    /// consent page it sends the end user to.
    /// </summary>
    [Theory]
    [InlineData(-60)]
    [InlineData(null)]
    public async Task ProcessAsync_PromptConsentNotGivenOnItsPage_AsksForEveryScope(int? givenSecondsBeforeNow)
    {
        var request = CreateRequest(prompt: [Prompts.Consent], scope: [Scopes.OpenId, Scopes.Email]);
        var session = CreateAuthSession();
        var granted = CreateConsents(grantedScopes: [.. request.Scope]) with
        {
            GivenAt = givenSecondsBeforeNow is { } seconds ? _timeProvider.GetUtcNow().AddSeconds(seconds) : null,
        };
        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(granted);

        var result = await _processor.ProcessAsync(request);

        var consentRequired = Assert.IsType<ConsentRequired>(result);
        Assert.Equal(request.Scope, consentRequired.RequiredUserConsents.Scopes);
        Assert.Equal(_timeProvider.GetUtcNow(), consentRequired.Model.Prompted![Prompts.Consent]);
    }

    /// <summary>
    /// Consent given on the request's consent page answers the prompt, so the request goes on with the host's
    /// consents: only what the host still holds pending is asked for.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_PromptConsentGivenOnItsPage_TakesTheHostsConsents()
    {
        var shownAt = _timeProvider.GetUtcNow();
        var request = CreateRequest(prompt: [Prompts.Consent], scope: [Scopes.OpenId, Scopes.Email], promptedAt: shownAt);
        var session = CreateAuthSession();
        var stillPending = new[] { new ScopeDefinition(Scopes.Email) };
        var consents = CreateConsents(pendingScopes: stillPending) with { GivenAt = shownAt.AddSeconds(5) };
        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        var result = await _processor.ProcessAsync(request);

        var consentRequired = Assert.IsType<ConsentRequired>(result);
        Assert.Equal(stillPending, consentRequired.RequiredUserConsents.Scopes);
    }

    private static readonly Uri RefusalResource = new("https://api.example.com");

    /// <summary>
    /// The error a request gets from consents the host reports, or null when it goes on to a code.
    /// </summary>
    private async Task<string?> ErrorOfAsync(ValidAuthorizationRequest request, UserConsents consents)
    {
        var session = CreateAuthSession();
        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);
        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(It.IsAny<AuthorizedGrant>(), It.IsAny<TimeSpan>()))
            .ReturnsAsync("code");

        return (await _processor.ProcessAsync(request) as AuthorizationError)?.Error;
    }

    private UserConsents Given(ConsentDefinition granted) => new()
    {
        Granted = granted,
        GivenAt = _timeProvider.GetUtcNow(),
    };

    /// <summary>
    /// A consent the end user gave that grants none of the scopes asked, with nothing left pending, is their refusal:
    /// access_denied at the redirect URI.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ConsentGivenGrantingNoScopeAsked_IsARefusal()
        => Assert.Equal(ErrorCodes.AccessDenied, await ErrorOfAsync(CreateRequest(), Given(new ConsentDefinition([], []))));

    /// <summary>
    /// Without a moment of giving, the same empty consent is no answer, and the request goes on.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_EmptyConsentNotGiven_IsNoRefusal()
        => Assert.Null(await ErrorOfAsync(CreateRequest(), new UserConsents { Granted = new ConsentDefinition([], []) }));

    [Fact]
    public async Task ProcessAsync_ConsentGivenGrantingNoResourceAsked_IsARefusal()
    {
        var request = CreateRequest(scope: [], resources: [new ResourceDefinition(RefusalResource)]);

        Assert.Equal(ErrorCodes.AccessDenied, await ErrorOfAsync(request, Given(new ConsentDefinition([], []))));
    }

    /// <summary>
    /// A consent granting a resource asked, though no scope, grants something, so it is no refusal.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ConsentGivenGrantingAResourceAsked_IsNoRefusal()
    {
        var resource = new ResourceDefinition(RefusalResource);
        var request = CreateRequest(scope: [], resources: [resource]);

        Assert.Null(await ErrorOfAsync(request, Given(new ConsentDefinition([], [resource]))));
    }

    /// <summary>
    /// A request asking for nothing a consent could grant is never refused by an empty consent, however the host
    /// reports it.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_RequestAskingForNothing_IsNoRefusal()
        => Assert.Null(await ErrorOfAsync(CreateRequest(scope: []), Given(new ConsentDefinition([], []))));

    /// <summary>
    /// A consent marked as given that leaves the authorization details list out grants none of the details asked,
    /// so it is a refusal rather than passing them through.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_DetailsAskedAndGivenConsentWithoutAList_IsARefusal()
    {
        var request = CreateRequest(scope: [], authorizationDetails: [new JsonObject { ["type"] = "payment_initiation" }]);

        Assert.Equal(ErrorCodes.AccessDenied, await ErrorOfAsync(request, Given(new ConsentDefinition([], []))));
    }

    /// <summary>
    /// A request asking for a scope and for authorization details is refused by a given consent granting neither.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ScopeAndDetailsAskedAndNothingGranted_IsARefusal()
    {
        var request = CreateRequest(authorizationDetails: [new JsonObject { ["type"] = "payment_initiation" }]);

        Assert.Equal(ErrorCodes.AccessDenied, await ErrorOfAsync(request, Given(new ConsentDefinition([], []))));
    }

    /// <summary>
    /// Authorization details the request never asked for grant nothing it asked for, so a consent granting only those
    /// is still a refusal.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ScopeAskedAndOnlyUnaskedDetailsGranted_IsARefusal()
    {
        var consents = Given(new ConsentDefinition([], [])
        {
            AuthorizationDetails = [new JsonObject { ["type"] = "payment_initiation" }],
        });

        Assert.Equal(ErrorCodes.AccessDenied, await ErrorOfAsync(CreateRequest(), consents));
    }

    [Fact]
    public async Task ProcessAsync_DetailsAskedAndAllRefused_IsARefusal()
    {
        var request = CreateRequest(scope: [], authorizationDetails: [new JsonObject { ["type"] = "payment_initiation" }]);
        var consents = Given(new ConsentDefinition([], []) { AuthorizationDetails = [] });

        Assert.Equal(ErrorCodes.AccessDenied, await ErrorOfAsync(request, consents));
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
