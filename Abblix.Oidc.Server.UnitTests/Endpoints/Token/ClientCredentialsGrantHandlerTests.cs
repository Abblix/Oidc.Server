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
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="ClientCredentialsGrantHandler"/> verifying the client_credentials grant type
/// as defined in RFC 6749 section 4.4.
/// Tests cover the machine-to-machine (M2M) authentication flow where the client is the resource owner.
/// </summary>
public class ClientCredentialsGrantHandlerTests
{
    private const string ClientId = "service_client_123";

    /// <summary>
    /// Verifies that a client credentials request with requested scopes successfully returns a grant.
    /// This is the standard client credentials flow.
    /// </summary>
    [Fact]
    public async Task ValidRequest_WithScopes_ShouldReturnGrant()
    {
        // Arrange
        var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
        sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns("session_123");
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, TimeProvider.System);
        var clientInfo = new ClientInfo(ClientId);
        var requestedScopes = new[] { "api.read", "api.write" };
        var tokenRequest = new TokenRequest
        {
            Scope = requestedScopes
        };

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(ClientId, grant.Context.ClientId);
        Assert.Equal(requestedScopes, grant.Context.Scope);
        Assert.Equal(ClientId, grant.AuthSession.Subject);
        Assert.Equal("client_credentials", grant.AuthSession.IdentityProvider);
        Assert.NotNull(grant.AuthSession.SessionId);
        Assert.Contains(ClientId, grant.AuthSession.AffectedClientIds);
    }

    /// <summary>
    /// Verifies that a client credentials request without scopes successfully returns a grant with null scope.
    /// </summary>
    [Fact]
    public async Task ValidRequest_WithoutScopes_ShouldReturnGrant()
    {
        // Arrange
        var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
        sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns("session_123");
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, TimeProvider.System);
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest { Scope = null! };

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(ClientId, grant.Context.ClientId);
        Assert.Null(grant.Context.Scope);
    }

    /// <summary>
    /// Verifies that a client credentials request with empty scope array successfully returns a grant.
    /// </summary>
    [Fact]
    public async Task ValidRequest_WithEmptyScopes_ShouldReturnGrant()
    {
        // Arrange
        var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
        sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns("session_123");
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, TimeProvider.System);
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest
        {
            Scope = []
        };

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant);
        Assert.Equal(ClientId, grant.Context.ClientId);
        Assert.Empty(grant.Context.Scope);
    }

    /// <summary>
    /// Verifies that the authentication session uses the client ID as the subject.
    /// In client credentials flow, there is no user - the client itself is the subject.
    /// </summary>
    [Fact]
    public async Task AuthSession_ShouldUseClientIdAsSubject()
    {
        // Arrange
        var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
        sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns("session_123");
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, TimeProvider.System);
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest();

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(ClientId, grant.AuthSession.Subject);
    }

    /// <summary>
    /// Verifies that each request generates a unique session ID by using the session ID generator.
    /// </summary>
    [Fact]
    public async Task MultipleRequests_ShouldGenerateUniqueSessionIds()
    {
        // Arrange
        var callCount = 0;
        var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
        sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns(() => $"session_{++callCount}");
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, TimeProvider.System);
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest();

        // Act
        var result1 = await handler.AuthorizeAsync(tokenRequest, clientInfo);
        var result2 = await handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result1.TryGetSuccess(out var grant1));
        Assert.True(result2.TryGetSuccess(out var grant2));
        Assert.Equal("session_1", grant1.AuthSession.SessionId);
        Assert.Equal("session_2", grant2.AuthSession.SessionId);
        Assert.NotEqual(grant1.AuthSession.SessionId, grant2.AuthSession.SessionId);
    }

    /// <summary>
    /// Verifies that the authentication time is set correctly using the provided time provider.
    /// </summary>
    [Fact]
    public async Task AuthSession_ShouldUseProvidedAuthenticationTime()
    {
        // Arrange
        var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
        sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns("session_123");
        var fixedTime = new DateTimeOffset(2024, 11, 6, 12, 0, 0, TimeSpan.Zero);
        var timeProvider = new Mock<TimeProvider>();
        timeProvider.Setup(t => t.GetUtcNow()).Returns(fixedTime);
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, timeProvider.Object);
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest();

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(fixedTime, grant.AuthSession.AuthenticationTime);
    }

    /// <summary>
    /// Verifies that the identity provider is set to "client_credentials" for traceability.
    /// </summary>
    [Fact]
    public async Task AuthSession_ShouldSetIdentityProviderToClientCredentials()
    {
        // Arrange
        var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
        sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns("session_123");
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, TimeProvider.System);
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest();

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("client_credentials", grant.AuthSession.IdentityProvider);
    }

    /// <summary>
    /// Verifies that the affected client IDs collection contains the authenticating client.
    /// </summary>
    [Fact]
    public async Task AuthSession_ShouldTrackClientInAffectedClientIds()
    {
        // Arrange
        var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
        sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns("session_123");
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, TimeProvider.System);
        var clientInfo = new ClientInfo(ClientId);
        var tokenRequest = new TokenRequest();

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Contains(ClientId, grant.AuthSession.AffectedClientIds);
        Assert.Single(grant.AuthSession.AffectedClientIds);
    }

    /// <summary>
    /// Verifies that the handler reports the correct supported grant type.
    /// </summary>
    [Fact]
    public void GrantTypesSupported_ShouldReturnClientCredentials()
    {
        // Arrange
        var sessionIdGenerator = new Mock<ISessionIdGenerator>();
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, TimeProvider.System);

        // Act
        var grantTypes = handler.GrantTypesSupported.ToArray();

        // Assert
        Assert.Single(grantTypes);
        Assert.Equal(GrantTypes.ClientCredentials, grantTypes[0]);
    }

    /// <summary>
    /// Verifies that multiple scopes are correctly passed to the authorization context.
    /// </summary>
    [Fact]
    public async Task Request_WithMultipleScopes_ShouldIncludeAllScopes()
    {
        // Arrange
        var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
        sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns("session_123");
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, TimeProvider.System);
        var clientInfo = new ClientInfo(ClientId);
        var requestedScopes = new[] { "api.read", "api.write", "api.delete", "admin" };
        var tokenRequest = new TokenRequest
        {
            Scope = requestedScopes
        };

        // Act
        var result = await handler.AuthorizeAsync(tokenRequest, clientInfo);

        // Assert
        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(requestedScopes, grant.Context.Scope);
    }

    /// <summary>
    /// Verifies that different client IDs result in different grants with correct client identification.
    /// </summary>
    [Fact]
    public async Task DifferentClients_ShouldReturnDistinctGrants()
    {
        // Arrange
        var sessionIdGenerator = new Mock<ISessionIdGenerator>(MockBehavior.Strict);
        sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns("session_123");
        var handler = new ClientCredentialsGrantHandler(sessionIdGenerator.Object, TimeProvider.System);
        var clientInfo1 = new ClientInfo("client1");
        var clientInfo2 = new ClientInfo("client2");
        var tokenRequest = new TokenRequest { Scope = ["api.read"] };

        // Act
        var result1 = await handler.AuthorizeAsync(tokenRequest, clientInfo1);
        var result2 = await handler.AuthorizeAsync(tokenRequest, clientInfo2);

        // Assert
        Assert.True(result1.TryGetSuccess(out var grant1));
        Assert.True(result2.TryGetSuccess(out var grant2));
        Assert.Equal("client1", grant1.Context.ClientId);
        Assert.Equal("client2", grant2.Context.ClientId);
        Assert.Equal("client1", grant1.AuthSession.Subject);
        Assert.Equal("client2", grant2.AuthSession.Subject);
    }
}
