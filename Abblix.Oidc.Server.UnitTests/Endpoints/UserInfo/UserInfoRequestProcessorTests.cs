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
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.UserInfo;

/// <summary>
/// Unit tests for <see cref="UserInfoRequestProcessor"/> verifying user claims retrieval logic
/// per OIDC Core UserInfo Endpoint specification.
/// </summary>
[Collection("License")]
public class UserInfoRequestProcessorTests
{
    private const string Issuer = "https://auth.example.com";

    private readonly Mock<IIssuerProvider> _issuerProvider;
    private readonly Mock<IUserClaimsProvider> _userClaimsProvider;
    private readonly UserInfoRequestProcessor _processor;

    public UserInfoRequestProcessorTests(TestInfrastructure.LicenseFixture fixture)
    {
        _issuerProvider = new Mock<IIssuerProvider>(MockBehavior.Strict);
        _userClaimsProvider = new Mock<IUserClaimsProvider>(MockBehavior.Strict);
        _processor = new UserInfoRequestProcessor(_issuerProvider.Object, _userClaimsProvider.Object);
    }

    private static UserInfoRequest CreateUserInfoRequest() => new()
    {
        AccessToken = "access_token_value",
    };

    private static ValidUserInfoRequest CreateValidUserInfoRequest()
    {
        var request = CreateUserInfoRequest();

        var authSession = new Abblix.Oidc.Server.Features.UserAuthentication.AuthSession(
            "user_123",
            "session_123",
            DateTimeOffset.UtcNow,
            "local");

        var authContext = new Abblix.Oidc.Server.Common.AuthorizationContext(
            "client_123",
            ["openid", "profile", "email"],
            null);

        var clientInfo = new ClientInfo("client_123");

        return new ValidUserInfoRequest(request, authSession, authContext, clientInfo);
    }

    private static JsonObject CreateUserClaims()
    {
        return new JsonObject
        {
            ["sub"] = "user_123",
            ["name"] = "John Doe",
            ["email"] = "john@example.com",
            ["email_verified"] = true
        };
    }

    /// <summary>
    /// Verifies successful processing with user claims found.
    /// Tests happy path where user claims provider returns claims.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithUserClaimsFound_ShouldReturnSuccess()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();
        var userClaims = CreateUserClaims();
        var issuer = Issuer;

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                validRequest.AuthSession,
                validRequest.AuthContext.Scope,
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                validRequest.ClientInfo))
            .ReturnsAsync(userClaims);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(issuer);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.NotNull(response);
        Assert.Same(userClaims, response.User);
        Assert.Same(validRequest.ClientInfo, response.ClientInfo);
        Assert.Equal(issuer, response.Issuer);
    }

    /// <summary>
    /// Verifies processing with null user claims returns error.
    /// Per design: null claims indicates user not found or unauthorized.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithNullUserClaims_ShouldReturnError()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()))
            .ReturnsAsync((JsonObject?)null);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
        Assert.Contains("user claims", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies processor calls user claims provider with correct parameters.
    /// Tests that auth session, scope, requested claims, and client info are passed.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldCallUserClaimsProviderWithCorrectParameters()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();
        var userClaims = CreateUserClaims();
        var issuer = Issuer;

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                validRequest.AuthSession,
                validRequest.AuthContext.Scope,
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                validRequest.ClientInfo))
            .ReturnsAsync(userClaims);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(issuer);

        // Act
        await _processor.ProcessAsync(validRequest);

        // Assert
        _userClaimsProvider.Verify(
            p => p.GetUserClaimsAsync(
                validRequest.AuthSession,
                validRequest.AuthContext.Scope,
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                validRequest.ClientInfo),
            Times.Once);
    }

    /// <summary>
    /// Verifies processor calls issuer provider to get issuer.
    /// Tests that GetIssuer is called.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldCallIssuerProvider()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();
        var userClaims = CreateUserClaims();
        var issuer = Issuer;

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()))
            .ReturnsAsync(userClaims);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(issuer);

        // Act
        await _processor.ProcessAsync(validRequest);

        // Assert
        _issuerProvider.Verify(p => p.GetIssuer(), Times.Once);
    }

    /// <summary>
    /// Verifies processor returns user claims in response.
    /// Tests that claims from provider are included in response.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldReturnUserClaimsInResponse()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();
        var userClaims = CreateUserClaims();
        var issuer = Issuer;

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()))
            .ReturnsAsync(userClaims);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(issuer);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.Equal("user_123", response.User["sub"]?.GetValue<string>());
        Assert.Equal("John Doe", response.User["name"]?.GetValue<string>());
        Assert.Equal("john@example.com", response.User["email"]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies processor returns client info in response.
    /// Tests that ClientInfo is included in response.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldReturnClientInfoInResponse()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();
        var userClaims = CreateUserClaims();
        var issuer = Issuer;

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()))
            .ReturnsAsync(userClaims);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(issuer);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.Same(validRequest.ClientInfo, response.ClientInfo);
        Assert.Equal("client_123", response.ClientInfo.ClientId);
    }

    /// <summary>
    /// Verifies processor returns issuer in response.
    /// Per OIDC Core, issuer should be included in response.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldReturnIssuerInResponse()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();
        var userClaims = CreateUserClaims();
        var issuer = "https://auth.example.org";

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()))
            .ReturnsAsync(userClaims);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(issuer);

        // Act
        var result = await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.True(result.TryGetSuccess(out var response));
        Assert.Equal(issuer, response.Issuer);
    }

    /// <summary>
    /// Verifies processor passes scopes to user claims provider.
    /// Tests that scope array from auth context is used.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldPassScopesToUserClaimsProvider()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();
        var userClaims = CreateUserClaims();
        var issuer = Issuer;
        ICollection<string>? capturedScopes = null;

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()))
            .Callback<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession, ICollection<string>, ICollection<KeyValuePair<string, RequestedClaimDetails>>?, ClientInfo>(
                (_, scopes, _, _) => capturedScopes = scopes)
            .ReturnsAsync(userClaims);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(issuer);

        // Act
        await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.NotNull(capturedScopes);
        Assert.Equal(["openid", "profile", "email"], capturedScopes);
    }

    /// <summary>
    /// Verifies processor passes auth session to user claims provider.
    /// Tests that AuthSession with subject is used.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldPassAuthSessionToUserClaimsProvider()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();
        var userClaims = CreateUserClaims();
        var issuer = Issuer;
        Abblix.Oidc.Server.Features.UserAuthentication.AuthSession? capturedSession = null;

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()))
            .Callback<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession, ICollection<string>, ICollection<KeyValuePair<string, RequestedClaimDetails>>?, ClientInfo>(
                (session, _, _, _) => capturedSession = session)
            .ReturnsAsync(userClaims);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(issuer);

        // Act
        await _processor.ProcessAsync(validRequest);

        // Assert
        Assert.NotNull(capturedSession);
        Assert.Equal("user_123", capturedSession.Subject);
        Assert.Equal("session_123", capturedSession.SessionId);
    }

    /// <summary>
    /// Verifies processor does not call issuer provider when claims are null.
    /// Tests optimization: no need to get issuer if returning error.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WhenUserClaimsNull_ShouldNotCallIssuerProvider()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()))
            .ReturnsAsync((JsonObject?)null);

        // Act
        await _processor.ProcessAsync(validRequest);

        // Assert
        _issuerProvider.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies processor with different user claims returns different responses.
    /// Tests that each request returns its own claims.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_WithDifferentUserClaims_ShouldReturnDifferentResponses()
    {
        // Arrange
        var validRequest1 = CreateValidUserInfoRequest();
        var userClaims1 = new JsonObject { ["sub"] = "user_1", ["name"] = "User One" };

        var validRequest2 = CreateValidUserInfoRequest();
        var userClaims2 = new JsonObject { ["sub"] = "user_2", ["name"] = "User Two" };

        var issuer = Issuer;

        _userClaimsProvider
            .SetupSequence(p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()))
            .ReturnsAsync(userClaims1)
            .ReturnsAsync(userClaims2);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(issuer);

        // Act
        var result1 = await _processor.ProcessAsync(validRequest1);
        var result2 = await _processor.ProcessAsync(validRequest2);

        // Assert
        Assert.True(result1.TryGetSuccess(out var response1));
        Assert.True(result2.TryGetSuccess(out var response2));
        Assert.Equal("user_1", response1.User["sub"]?.GetValue<string>());
        Assert.Equal("user_2", response2.User["sub"]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies processor calls user claims provider exactly once.
    /// Tests efficient processing without redundant calls.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_ShouldCallUserClaimsProviderOnce()
    {
        // Arrange
        var validRequest = CreateValidUserInfoRequest();
        var userClaims = CreateUserClaims();
        var issuer = Issuer;

        _userClaimsProvider
            .Setup(p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()))
            .ReturnsAsync(userClaims);

        _issuerProvider
            .Setup(p => p.GetIssuer())
            .Returns(issuer);

        // Act
        await _processor.ProcessAsync(validRequest);

        // Assert
        _userClaimsProvider.Verify(
            p => p.GetUserClaimsAsync(
                It.IsAny<Abblix.Oidc.Server.Features.UserAuthentication.AuthSession>(),
                It.IsAny<ICollection<string>>(),
                It.IsAny<ICollection<KeyValuePair<string, RequestedClaimDetails>>?>(),
                It.IsAny<ClientInfo>()),
            Times.Once);
    }
}
