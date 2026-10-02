// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using System.Linq;
using System.Threading;
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
    /// The client is recorded against the session it signed in to, which is what the session's logout reads.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldRecordTheClientForItsSession()
    {
        // Arrange
        var request = CreateRequest();
        var session = CreateAuthSession();
        SetupSuccessfulAuthCodeFlow(request, session, CreateConsents());

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        _sessionClients.Verify(
            r => r.AddClientAsync(session.SessionId, request.ClientInfo.ClientId, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    /// <summary>
    /// The client is recorded before the code is issued, so a store that refuses the record fails the request
    /// before anything is handed out.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldRecordTheClientBeforeIssuingTheCode()
    {
        // Arrange
        var request = CreateRequest();
        var session = CreateAuthSession();
        SetupSuccessfulAuthCodeFlow(request, session, CreateConsents());

        var order = new List<string>();
        _sessionClients
            .Setup(r => r.AddClientAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback(() => order.Add("recorded"))
            .Returns(Task.CompletedTask);
        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                It.IsAny<AuthorizedGrant>(),
                request.ClientInfo.AuthorizationCodeExpiresIn))
            .Callback(() => order.Add("issued"))
            .ReturnsAsync("code");

        // Act
        await _processor.ProcessAsync(request);

        // Assert
        Assert.Equal(["recorded", "issued"], order);
    }

    /// <summary>
    /// The clients the response names are the ones recorded for the session.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldNameTheClientsRecordedForTheSession()
    {
        // Arrange
        var request = CreateRequest();
        var session = CreateAuthSession();
        SetupSuccessfulAuthCodeFlow(request, session, CreateConsents());
        _sessionClients
            .Setup(r => r.GetClientsAsync(session.SessionId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(["recorded-earlier", request.ClientInfo.ClientId]);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        var authenticated = Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Equal(["recorded-earlier", request.ClientInfo.ClientId], authenticated.AffectedClientIds);
    }

    /// <summary>
    /// A request stopped for consent issues nothing, so its client is not recorded against the session.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithConsentPending_ShouldNotRecordTheClient()
    {
        // Arrange
        var request = CreateRequest();
        var session = CreateAuthSession();
        var consents = CreateConsents(pendingScopes: [new ScopeDefinition(Scopes.OpenId)]);

        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());

        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(request, session))
            .ReturnsAsync(consents);

        // Act
        var result = await _processor.ProcessAsync(request);

        // Assert
        Assert.IsType<ConsentRequired>(result);
        _sessionClients.Verify(
            r => r.AddClientAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }
}
