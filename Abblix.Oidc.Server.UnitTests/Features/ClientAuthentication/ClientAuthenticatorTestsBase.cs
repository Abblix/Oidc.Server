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
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Abstract base class for client authenticator tests that provides common test scenarios
/// and infrastructure. Derived classes only need to implement authenticator-specific
/// request preparation and authenticator instantiation logic.
/// </summary>
/// <typeparam name="TAuthenticator">The type of authenticator being tested.</typeparam>
public abstract class ClientAuthenticatorTestsBase<TAuthenticator>
    where TAuthenticator : IClientAuthenticator
{
    protected const string ClientId = "test_client_456";
    protected const string ClientSecret = "test_secret_abc123";

    /// <summary>
    /// Gets the authentication method supported by this authenticator.
    /// </summary>
    protected abstract string ExpectedAuthenticationMethod { get; }

    /// <summary>
    /// Creates an authenticator instance with mocked dependencies.
    /// </summary>
    /// <param name="clientInfoProvider">Mock for client information provider.</param>
    /// <param name="timeProvider">Optional time provider for time-dependent tests.</param>
    /// <returns>The authenticator instance.</returns>
    protected abstract TAuthenticator CreateAuthenticator(
        Mock<IClientInfoProvider> clientInfoProvider,
        TimeProvider? timeProvider = null);

    /// <summary>
    /// Prepares a valid request for authentication with the provided credentials.
    /// </summary>
    /// <param name="clientId">The client ID.</param>
    /// <param name="clientSecret">The client secret.</param>
    /// <returns>A ClientRequest configured for this authenticator type.</returns>
    protected abstract ClientRequest PrepareValidRequest(string clientId, string clientSecret);

    /// <summary>
    /// Prepares a request with missing primary credential (e.g., missing Authorization header,
    /// missing client_id, missing client_assertion_type).
    /// </summary>
    protected abstract ClientRequest PrepareMissingPrimaryCredentialRequest();

    /// <summary>
    /// Prepares a request with wrong credential format (e.g., wrong scheme, wrong assertion type).
    /// </summary>
    protected abstract ClientRequest PrepareWrongFormatRequest();

    /// <summary>
    /// Prepares a request with empty/whitespace client ID.
    /// </summary>
    protected abstract ClientRequest PrepareEmptyClientIdRequest();

    /// <summary>
    /// Prepares a request with empty/whitespace client secret.
    /// </summary>
    protected abstract ClientRequest PrepareEmptyClientSecretRequest();

    /// <summary>
    /// Prepares a request with whitespace-only client ID.
    /// </summary>
    protected abstract ClientRequest PrepareWhitespaceClientIdRequest();

    // ==================== COMMON TEST SCENARIOS ====================

    /// <summary>
    /// Verifies that valid credentials in the request successfully authenticate the client.
    /// </summary>
    [Fact]
    public async Task ValidAuthentication_ShouldAuthenticate()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);

        var clientInfo = CreateClientInfo(ClientSecret);
        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = PrepareValidRequest(ClientId, ClientSecret);

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that authentication fails when the primary credential is missing.
    /// </summary>
    [Fact]
    public async Task MissingPrimaryCredential_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);
        var request = PrepareMissingPrimaryCredentialRequest();

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the credential format is incorrect.
    /// </summary>
    [Fact]
    public async Task WrongCredentialFormat_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);
        var request = PrepareWrongFormatRequest();

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when an incorrect client secret is provided.
    /// </summary>
    [Fact]
    public async Task WrongClientSecret_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);

        const string wrongSecret = "wrong_secret_xyz";
        var clientInfo = CreateClientInfo(ClientSecret);

        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = PrepareValidRequest(ClientId, wrongSecret);

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client is not found in the system.
    /// </summary>
    [Fact]
    public async Task ClientNotFound_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);

        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync((ClientInfo?)null);

        var request = PrepareValidRequest(ClientId, ClientSecret);

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client is configured for a different authentication method.
    /// </summary>
    [Fact]
    public async Task WrongAuthenticationMethod_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);

        var clientInfo = CreateClientInfo(ClientSecret);
        clientInfo.TokenEndpointAuthMethod = GetWrongAuthenticationMethod();

        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = PrepareValidRequest(ClientId, ClientSecret);

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client has no secrets configured.
    /// </summary>
    [Fact]
    public async Task NoClientSecretsConfigured_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ExpectedAuthenticationMethod,
            ClientSecrets = []
        };

        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = PrepareValidRequest(ClientId, ClientSecret);

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client secret has expired.
    /// </summary>
    [Fact]
    public async Task ExpiredClientSecret_ShouldReturnNull()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var timeProvider = new Mock<TimeProvider>();
        timeProvider.Setup(t => t.GetUtcNow()).Returns(now);

        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider, timeProvider.Object);

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ExpectedAuthenticationMethod,
            ClientSecrets =
            [
                new ClientSecret
                {
                    Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)),
                    ExpiresAt = now.AddDays(-1)
                }
            ]
        };

        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = PrepareValidRequest(ClientId, ClientSecret);

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that special characters in credentials are handled correctly.
    /// </summary>
    [Fact]
    public async Task SpecialCharactersInCredentials_ShouldAuthenticate()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);

        const string specialClientId = "client-with-dash@example.com";
        const string specialSecret = "p@ss:word!#$%^&*()";

        var clientInfo = CreateClientInfo(specialSecret, specialClientId);
        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(specialClientId))
            .ReturnsAsync(clientInfo);

        var request = PrepareValidRequest(specialClientId, specialSecret);

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(specialClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that authentication succeeds when multiple secrets are configured and one is valid.
    /// </summary>
    [Fact]
    public async Task MultipleSecrets_OneValid_ShouldAuthenticate()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var timeProvider = new Mock<TimeProvider>();
        timeProvider.Setup(t => t.GetUtcNow()).Returns(now);

        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider, timeProvider.Object);

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ExpectedAuthenticationMethod,
            ClientSecrets =
            [
                new ClientSecret
                {
                    Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes("old_secret")),
                    ExpiresAt = now.AddDays(-1)
                },
                new ClientSecret
                {
                    Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)),
                    ExpiresAt = now.AddDays(30)
                }
            ]
        };

        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = PrepareValidRequest(ClientId, ClientSecret);

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that authentication fails when the client ID is empty.
    /// </summary>
    [Fact]
    public async Task EmptyClientId_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);
        var request = PrepareEmptyClientIdRequest();

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client secret is empty.
    /// </summary>
    [Fact]
    public async Task EmptyClientSecret_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);

        var clientInfo = CreateClientInfo(ClientSecret);
        clientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = PrepareEmptyClientSecretRequest();

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client ID contains only whitespace.
    /// </summary>
    [Fact]
    public async Task WhitespaceClientId_ShouldReturnNull()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);
        var request = PrepareWhitespaceClientIdRequest();

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that the authenticator reports the correct supported authentication method.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_ShouldReturnExpectedMethod()
    {
        // Arrange
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var authenticator = CreateAuthenticator(clientInfoProvider);

        // Act
        var methods = authenticator.ClientAuthenticationMethodsSupported.ToArray();

        // Assert
        Assert.Single(methods);
        Assert.Equal(ExpectedAuthenticationMethod, methods[0]);
    }

    // ==================== HELPER METHODS ====================

    /// <summary>
    /// Creates a test ClientInfo object with the specified secret.
    /// </summary>
    /// <param name="secret">The client secret to hash and store.</param>
    /// <param name="clientId">The client ID (defaults to test constant).</param>
    /// <returns>A configured ClientInfo object.</returns>
    protected ClientInfo CreateClientInfo(string secret, string? clientId = null)
    {
        return new ClientInfo(clientId ?? ClientId)
        {
            TokenEndpointAuthMethod = ExpectedAuthenticationMethod,
            ClientSecrets =
            [
                new ClientSecret
                {
                    Sha512Hash = TestSecretHasher.HashSecret(secret)
                }
            ]
        };
    }

    /// <summary>
    /// Returns an authentication method different from the one being tested.
    /// Used for testing wrong authentication method scenarios.
    /// </summary>
    private string GetWrongAuthenticationMethod()
    {
        return ExpectedAuthenticationMethod switch
        {
            ClientAuthenticationMethods.ClientSecretBasic => ClientAuthenticationMethods.ClientSecretPost,
            ClientAuthenticationMethods.ClientSecretPost => ClientAuthenticationMethods.ClientSecretBasic,
            ClientAuthenticationMethods.ClientSecretJwt => ClientAuthenticationMethods.ClientSecretBasic,
            _ => ClientAuthenticationMethods.None
        };
    }
}
