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
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="ClientSecretPostAuthenticator"/> verifying the client_secret_post authentication method
/// as defined in RFC 6749 section 2.3.1.
/// Tests cover credential extraction from request body, validation, and various error conditions.
/// </summary>
public class ClientSecretPostAuthenticatorTests
{
    private const string ClientId = "test_client_456";
    private const string ClientSecret = "test_secret_abc123";

    /// <summary>
    /// Verifies that valid client_id and client_secret in the request body successfully authenticate the client.
    /// This is the standard flow for client_secret_post authentication method.
    /// </summary>
    [Fact]
    public async Task ValidClientSecretPost_ShouldAuthenticate()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientSecret);
        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = ClientId,
            ClientSecret = ClientSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that authentication fails when client_id is missing from the request body.
    /// Both client_id and client_secret are required for this authentication method.
    /// </summary>
    [Fact]
    public async Task MissingClientId_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientSecret = ClientSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_secret is missing from the request body.
    /// Both client_id and client_secret are required for this authentication method.
    /// </summary>
    [Fact]
    public async Task MissingClientSecret_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientId = ClientId
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when both client_id and client_secret are missing.
    /// </summary>
    [Fact]
    public async Task MissingBothCredentials_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest();

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_id is empty string.
    /// Empty strings should be treated as missing values.
    /// </summary>
    [Fact]
    public async Task EmptyClientId_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientId = string.Empty,
            ClientSecret = ClientSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_secret is empty string.
    /// Empty strings should be treated as missing values.
    /// </summary>
    [Fact]
    public async Task EmptyClientSecret_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientId = ClientId,
            ClientSecret = string.Empty
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication handles whitespace-only client_id gracefully.
    /// Whitespace-only values should be treated as invalid.
    /// </summary>
    [Fact]
    public async Task WhitespaceClientId_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientId = "   ",
            ClientSecret = ClientSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication handles whitespace-only client_secret gracefully.
    /// Whitespace-only values should be treated as invalid.
    /// </summary>
    [Fact]
    public async Task WhitespaceClientSecret_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientSecret);
        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = ClientId,
            ClientSecret = "   "
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client secret is incorrect.
    /// The hash comparison should fail, resulting in null.
    /// </summary>
    [Fact]
    public async Task WrongClientSecret_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        const string wrongSecret = "wrong_secret_xyz";
        var clientInfo = CreateClientInfo(ClientSecret); // Different secret

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = ClientId,
            ClientSecret = wrongSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client is not found in the client registry.
    /// </summary>
    [Fact]
    public async Task ClientNotFound_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync((ClientInfo?)null);

        var request = new ClientRequest
        {
            ClientId = ClientId,
            ClientSecret = ClientSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client is configured to use a different authentication method.
    /// The authenticator only accepts clients configured for client_secret_post.
    /// </summary>
    [Fact]
    public async Task WrongAuthenticationMethod_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientSecret);
        clientInfo.TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic; // Wrong method

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = ClientId,
            ClientSecret = ClientSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client has no secrets configured.
    /// A client must have at least one valid secret for authentication.
    /// </summary>
    [Fact]
    public async Task NoClientSecretsConfigured_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            ClientSecrets = []
        };

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = ClientId,
            ClientSecret = ClientSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client secret has expired.
    /// The authenticator checks ExpiresAt and rejects expired secrets.
    /// </summary>
    [Fact]
    public async Task ExpiredClientSecret_ShouldReturnNull()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var timeProvider = new Mock<TimeProvider>();
        timeProvider.Setup(t => t.GetUtcNow()).Returns(now);
        var (authenticator, mocks) = CreateAuthenticator(timeProvider.Object);

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            ClientSecrets =
            [
                new ClientSecret
                {
                    Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)),
                    ExpiresAt = now.AddDays(-1) // Expired
                }
            ]
        };

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = ClientId,
            ClientSecret = ClientSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication handles special characters in client_id and client_secret.
    /// The POST body should support any characters without additional encoding.
    /// </summary>
    [Fact]
    public async Task SpecialCharactersInCredentials_ShouldAuthenticate()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        const string specialClientId = "client@example.com";
        const string specialSecret = "p@ss:word!#$%^&*()";

        var clientInfo = CreateClientInfo(specialSecret, specialClientId);
        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(specialClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = specialClientId,
            ClientSecret = specialSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(specialClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that authentication succeeds with a valid secret when multiple secrets are configured
    /// and some are expired. The authenticator should find the valid non-expired secret.
    /// </summary>
    [Fact]
    public async Task MultipleSecrets_OneValid_ShouldAuthenticate()
    {
        // Arrange
        var now = DateTimeOffset.UtcNow;
        var timeProvider = new Mock<TimeProvider>();
        timeProvider.Setup(t => t.GetUtcNow()).Returns(now);
        var (authenticator, mocks) = CreateAuthenticator(timeProvider.Object);

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            ClientSecrets =
            [
                new ClientSecret
                {
                    Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes("old_secret")),
                    ExpiresAt = now.AddDays(-1) // Expired
                },
                new ClientSecret
                {
                    Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)),
                    ExpiresAt = now.AddDays(30) // Valid
                }
            ]
        };

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = ClientId,
            ClientSecret = ClientSecret
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that the authenticator reports the correct supported authentication method.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_ShouldReturnClientSecretPost()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();

        // Act
        var methods = authenticator.ClientAuthenticationMethodsSupported.ToArray();

        // Assert
        Assert.Single(methods);
        Assert.Equal(ClientAuthenticationMethods.ClientSecretPost, methods[0]);
    }

    /// <summary>
    /// Creates a new instance of ClientSecretPostAuthenticator with mocked dependencies for testing.
    /// </summary>
    /// <param name="timeProvider">Optional time provider for controlling time in tests.</param>
    /// <returns>A tuple containing the authenticator instance and the mock objects.</returns>
    private (ClientSecretPostAuthenticator authenticator, Mocks mocks) CreateAuthenticator(
        TimeProvider? timeProvider = null)
    {
        LicenseTestHelper.StartTest();

        var logger = new Mock<ILogger<ClientSecretPostAuthenticator>>();
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var hashService = new HashService();

        var authenticator = new ClientSecretPostAuthenticator(
            logger.Object,
            clientInfoProvider.Object,
            timeProvider ?? TimeProvider.System,
            hashService);

        var mocks = new Mocks
        {
            Logger = logger,
            ClientInfoProvider = clientInfoProvider,
        };

        return (authenticator, mocks);
    }

    /// <summary>
    /// Creates a test ClientInfo object with the specified secret.
    /// </summary>
    /// <param name="secret">The client secret to hash and store.</param>
    /// <param name="clientId">The client ID (defaults to test constant).</param>
    /// <returns>A configured ClientInfo object.</returns>
    private ClientInfo CreateClientInfo(string secret, string? clientId = null)
    {
        return new ClientInfo(clientId ?? ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            ClientSecrets =
            [
                new ClientSecret
                {
                    Sha512Hash = SHA512.HashData(Encoding.ASCII.GetBytes(secret))
                }
            ]
        };
    }

    /// <summary>
    /// Container class for holding all mock objects used in tests.
    /// </summary>
    private sealed class Mocks
    {
        public Mock<ILogger<ClientSecretPostAuthenticator>> Logger { get; init; } = null!;
        public Mock<IClientInfoProvider> ClientInfoProvider { get; init; } = null!;
    }

}
