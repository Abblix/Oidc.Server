// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;
using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.RateLimiting;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// Unit tests for <see cref="ClientValidator"/> verifying client authentication
/// for token requests per OAuth 2.0 specification.
/// </summary>
public class ClientValidatorTests
{
    /// <summary>The client store the class under test is given; the authenticator it calls is a double.</summary>
    private static readonly IClientInfoProvider Clients = new Mock<IClientInfoProvider>().Object;

    private readonly Mock<IClientAuthenticator> _clientAuthenticator;
    private readonly Mock<IAuthServiceJwtReader> _jwtReader;
    private readonly ClientValidator _validator;

    public ClientValidatorTests()
    {
        _clientAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        _clientAuthenticator
            .Setup(a => a.FindPresentedCredentialsAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync([]);
        _jwtReader = new Mock<IAuthServiceJwtReader>(MockBehavior.Strict);
        _validator = new ClientValidator(_clientAuthenticator.Object, Clients, _jwtReader.Object);
    }

    private const string RefreshToken = "refresh-token";
    private const string PublicClientId = "public-client";

    private static TokenValidationContext RefreshContext(string grantType = GrantTypes.RefreshToken, string? clientId = null)
        => new(
            new TokenRequest { GrantType = grantType, RefreshToken = RefreshToken },
            new ClientRequest { ClientId = clientId });

    private void ArrangeRefreshTokenOf(string? clientId)
    {
        var token = new JsonWebToken();
        token.Header.Type = JwtTypes.RefreshToken;
        token.Payload.ClientId = clientId;

        // Read for the client it names whatever its lifetime, so an expired one reaches the grant, which answers it
        // invalid_grant
        _jwtReader
            .Setup(r => r.ReadAuthenticAsync(
                It.IsAny<TenantDefinition>(),
                null,
                RefreshToken,
                It.IsAny<TokenTypePolicy>(),
                It.Is<ValidationOptions>(options => (options & ValidationOptions.ValidateLifetime) == 0)))
            .ReturnsAsync(token);
    }

    /// <summary>
    /// OAuth 2.1 (draft-ietf-oauth-v2-1-17) sections 3.2.2 and 4.3.1: a refresh token request presenting no credential
    /// and no client_id is authenticated as a request naming the client its refresh token was issued to, so a public
    /// client is served without client_id, and through the same authenticators a request naming it goes through.
    /// Authenticated once, as that client: a first attempt without it would count as a failed one against the
    /// source's budget, which a working client never spends.
    /// </summary>
    [Fact]
    public async Task ARefreshTokenRequestWithoutClientId_IsAuthenticatedAsTheClientItsTokenNames()
    {
        var context = RefreshContext();
        ArrangeRefreshTokenOf(PublicClientId);
        var publicClient = new ClientInfo(PublicClientId);
        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(
                TestTenant.Matched, It.Is<ClientRequest>(r => r.ClientId == null), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(ClientAuthenticationFailures.NoCredential);
        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(
                TestTenant.Matched, It.Is<ClientRequest>(r => r.ClientId == PublicClientId), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(publicClient);

        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        Assert.Null(error);
        Assert.Same(publicClient, context.ClientInfo);
        _clientAuthenticator.Verify(
            a => a.TryAuthenticateClientAsync(
                It.IsAny<TenantDefinition>(), It.Is<ClientRequest>(r => r.ClientId == null), It.IsAny<IClientInfoProvider>()),
            Times.Never);
    }

    /// <summary>
    /// The refusal of a refresh token request that sent no Authorization header owes no Basic challenge, whatever
    /// method the client its token names is registered for: OAuth 2.1 section 3.2.4 owes the challenge to a request
    /// that used HTTP Basic.
    /// </summary>
    [Fact]
    public async Task ARefusalOfTheClientTheTokenNames_OwesNoChallengeWithoutTheHeader()
    {
        var context = RefreshContext();
        ArrangeRefreshTokenOf(PublicClientId);
        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(ClientAuthenticationFailures.NoCredential);

        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        Assert.Equal(ErrorCodes.InvalidClient, error?.Error);
        Assert.False(error?.BasicChallengeOwed);
    }

    /// <summary>
    /// A refresh token that cannot be read, or names no client, identifies none, so the request is refused as one
    /// authenticating no client, and the authenticators are not asked again.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ARefreshTokenNamingNoClient_LeavesTheRequestUnauthenticated(bool readable)
    {
        var context = RefreshContext();
        if (readable)
        {
            ArrangeRefreshTokenOf(null);
        }
        else
        {
            _jwtReader
                .Setup(r => r.ReadAuthenticAsync(
                    It.IsAny<TenantDefinition>(), null, RefreshToken, It.IsAny<TokenTypePolicy>(),
                    It.IsAny<ValidationOptions>()))
                .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "unreadable"));
        }

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(ClientAuthenticationFailures.NoCredential);

        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        Assert.Equal(ErrorCodes.InvalidClient, error?.Error);
        _clientAuthenticator.Verify(
            a => a.TryAuthenticateClientAsync(It.IsAny<TenantDefinition>(), It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()),
            Times.Once);
    }

    /// <summary>
    /// The refresh token is read only for a refresh token request presenting no credential at all: one naming a
    /// client_id, one presenting a credential that fails, and a request of another grant are answered for what they
    /// present.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.RefreshToken, PublicClientId, false)]
    [InlineData(GrantTypes.RefreshToken, null, true)]
    [InlineData(GrantTypes.AuthorizationCode, null, false)]
    public async Task ARequestOtherThanARefreshWithoutAnyCredential_DoesNotHaveItsRefreshTokenRead(
        string grantType, string? clientId, bool credentialFails)
    {
        var context = RefreshContext(grantType, clientId);
        if (credentialFails)
        {
            _clientAuthenticator
                .Setup(a => a.FindPresentedCredentialsAsync(
                    It.IsAny<TenantDefinition>(), It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
                .ReturnsAsync([nameof(ClientRequest.ClientSecret)]);
        }

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(credentialFails ? ClientAuthenticationFailures.InvalidCredential : ClientAuthenticationFailures.NoCredential);

        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        Assert.Equal(ErrorCodes.InvalidClient, error?.Error);
        _jwtReader.VerifyNoOtherCalls();
    }

    /// <summary>
    /// The credentials a request presents are sought before its refresh token is read, so a source the authenticator
    /// refuses as past its failure budget is refused before that read, a signature check, is spent on it.
    /// </summary>
    [Fact]
    public async Task ASourceRefusedWhenItsCredentialsAreSought_HasNoRefreshTokenRead()
    {
        var context = RefreshContext();
        _clientAuthenticator
            .Setup(a => a.FindPresentedCredentialsAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ThrowsAsync(new TooManyAuthenticationFailuresException(
                new TooManyRequestsError("Too many failed authentications", TimeSpan.FromMinutes(1), CallerRateLimiters.AuthenticationFailures)));

        await Assert.ThrowsAsync<TooManyAuthenticationFailuresException>(
            () => _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken));

        _jwtReader.VerifyNoOtherCalls();
    }

    private static TokenValidationContext CreateContext(ClientRequest? clientRequest = null)
    {
        var tokenRequest = new TokenRequest();
        return new TokenValidationContext(tokenRequest, clientRequest ?? new ClientRequest());
    }

    /// <summary>
    /// Verifies successful validation when client authentication succeeds.
    /// Per OAuth 2.0, client must be authenticated for token requests.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSuccessfulAuthentication_ShouldSucceed()
    {
        // Arrange
        var clientRequest = new ClientRequest { ClientId = TestConstants.DefaultClientId };
        var context = CreateContext(clientRequest);
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(clientInfo);

        // Act
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        Assert.Null(error);
        Assert.Same(clientInfo, context.ClientInfo);
    }

    /// <summary>
    /// Verifies error when client authentication fails.
    /// Per OAuth 2.0, unauthenticated clients must be rejected.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenAuthenticationFails_ShouldReturnError()
    {
        // Arrange
        var clientRequest = new ClientRequest { ClientId = "invalid_client" };
        var context = CreateContext(clientRequest);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential);

        // Act
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClient, error.Error);
        Assert.Contains("not authorized", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies client request is passed correctly to authenticator.
    /// Authenticator should receive the exact ClientRequest from context.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPassClientRequestToAuthenticator()
    {
        // Arrange
        var clientRequest = new ClientRequest { ClientId = TestConstants.DefaultClientId, ClientSecret = TestConstants.DefaultClientSecret };
        var context = CreateContext(clientRequest);
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, clientRequest, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, clientRequest, It.IsAny<IClientInfoProvider>()), Times.Once);
    }

    /// <summary>
    /// Verifies client info is correctly assigned to context.
    /// Context.ClientInfo should reference the authenticated client info.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnSuccess_ShouldSetClientInfoInContext()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId) { ClientName = "Test Client" };

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        Assert.Same(clientInfo, context.ClientInfo);
        Assert.Equal(TestConstants.DefaultClientId, context.ClientInfo.ClientId);
        Assert.Equal("Test Client", context.ClientInfo.ClientName);
    }

    /// <summary>
    /// Verifies authenticator is called only once per validation.
    /// Multiple calls to the same authenticator should be avoided.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallAuthenticatorOnce()
    {
        // Arrange
        var context = CreateContext();
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(clientInfo);

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        _clientAuthenticator.Verify(
            a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()),
            Times.Once);
    }

    /// <summary>
    /// Verifies error details on authentication failure.
    /// Error should contain proper code and description.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnAuthenticationFailure_ShouldReturnProperError()
    {
        // Arrange
        var context = CreateContext();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential);

        // Act
        var error = await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClient, error.Error);
        Assert.False(string.IsNullOrWhiteSpace(error.ErrorDescription));
    }

    /// <summary>
    /// Verifies validation with different client requests.
    /// Validator should work with various client request configurations.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithDifferentClientRequests_ShouldWork()
    {
        // Arrange
        var clientRequest1 = new ClientRequest { ClientId = "client1" };
        var clientRequest2 = new ClientRequest { ClientId = "client2", ClientSecret = TestConstants.DefaultClientSecret };
        var context1 = CreateContext(clientRequest1);
        var context2 = CreateContext(clientRequest2);
        var clientInfo1 = new ClientInfo("client1");
        var clientInfo2 = new ClientInfo("client2");

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, clientRequest1, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(clientInfo1);
        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, clientRequest2, It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(clientInfo2);

        // Act
        var error1 = await _validator.ValidateAsync(SingleIssuer.Tenant, context1, TestContext.Current.CancellationToken);
        var error2 = await _validator.ValidateAsync(SingleIssuer.Tenant, context2, TestContext.Current.CancellationToken);

        // Assert
        Assert.Null(error1);
        Assert.Null(error2);
        Assert.Same(clientInfo1, context1.ClientInfo);
        Assert.Same(clientInfo2, context2.ClientInfo);
    }

    /// <summary>
    /// Verifies context is not modified on authentication failure.
    /// Context.ClientInfo should remain unset when authentication fails.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnFailure_ShouldNotModifyContext()
    {
        // Arrange
        var context = CreateContext();

        _clientAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential);

        // Act
        await _validator.ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        // Assert - Context.ClientInfo getter will throw if not set, which is expected behavior
        // We just verify the error was returned
        _clientAuthenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>(), It.IsAny<IClientInfoProvider>()), Times.Once);
    }
}
