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
using System.Net.Http.Headers;
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
/// Unit tests for <see cref="ClientSecretBasicAuthenticator"/> verifying the client_secret_basic authentication method
/// as defined in RFC 7617.
/// Tests cover credential extraction from Authorization header with Basic scheme, Base64 decoding, validation,
/// and various error conditions.
/// </summary>
public class ClientSecretBasicAuthenticatorTests
{
    private const string ClientId = "test_client_456";
    private const string ClientSecret = "test_secret_abc123";

    /// <summary>
    /// Verifies that valid credentials in the Authorization header using Basic scheme successfully authenticate the client.
    /// The header should contain Base64-encoded "client_id:client_secret" as per RFC 7617.
    /// </summary>
    [Fact]
    public async Task ValidBasicAuthentication_ShouldAuthenticate()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientSecret);
        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var credentials = $"{ClientId}:{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that authentication fails when the Authorization header is missing.
    /// Basic authentication requires the Authorization header to be present.
    /// </summary>
    [Fact]
    public async Task MissingAuthorizationHeader_ShouldReturnNull()
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
    /// Verifies that authentication fails when the Authorization header uses wrong scheme.
    /// Only "Basic" scheme is supported by this authenticator.
    /// </summary>
    [Fact]
    public async Task WrongAuthorizationScheme_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();

        var credentials = $"{ClientId}:{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Bearer", base64Credentials)
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the Authorization header parameter is missing.
    /// The Basic scheme requires credentials parameter.
    /// </summary>
    [Fact]
    public async Task MissingCredentialsParameter_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic")
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when credentials don't contain colon separator.
    /// According to RFC 7617, the format must be "user-id:password".
    /// </summary>
    [Fact]
    public async Task CredentialsWithoutColon_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();

        var credentials = $"{ClientId}{ClientSecret}"; // No colon
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
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

        var credentials = $"{ClientId}:{wrongSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
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

        var credentials = $"{ClientId}:{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client is configured to use a different authentication method.
    /// The authenticator only accepts clients configured for client_secret_basic.
    /// </summary>
    [Fact]
    public async Task WrongAuthenticationMethod_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientSecret);
        clientInfo.TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost; // Wrong method

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var credentials = $"{ClientId}:{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
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
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            ClientSecrets = []
        };

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var credentials = $"{ClientId}:{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
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
        var timeProvider = new FakeTimeProvider(now);
        var (authenticator, mocks) = CreateAuthenticator(timeProvider);

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
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

        var credentials = $"{ClientId}:{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication handles special characters in client_id and client_secret.
    /// According to RFC 7617, the password (secret) part can contain colons.
    /// </summary>
    [Fact]
    public async Task SpecialCharactersInSecret_ShouldAuthenticate()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        const string specialClientId = "client-with-dash";
        const string specialSecret = "p@ss:word!#$%^&*()";

        var clientInfo = CreateClientInfo(specialSecret, specialClientId);
        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(specialClientId))
            .ReturnsAsync(clientInfo);

        var credentials = $"{specialClientId}:{specialSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
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
        var timeProvider = new FakeTimeProvider(now);
        var (authenticator, mocks) = CreateAuthenticator(timeProvider);

        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
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

        var credentials = $"{ClientId}:{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that authentication handles empty client_id gracefully.
    /// According to RFC 7617, credentials before first colon is the user-id (client_id).
    /// </summary>
    [Fact]
    public async Task EmptyClientId_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();

        var credentials = $":{ClientSecret}"; // Empty client_id
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication handles empty client_secret gracefully.
    /// According to RFC 7617, credentials after first colon is the password (client_secret).
    /// </summary>
    [Fact]
    public async Task EmptyClientSecret_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientSecret);
        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ClientId))
            .ReturnsAsync(clientInfo);

        var credentials = $"{ClientId}:"; // Empty secret
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
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

        var credentials = $"   :{ClientSecret}";
        var base64Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials));

        var request = new ClientRequest
        {
            AuthorizationHeader = new AuthenticationHeaderValue("Basic", base64Credentials)
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that the authenticator reports the correct supported authentication method.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_ShouldReturnClientSecretBasic()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();

        // Act
        var methods = authenticator.ClientAuthenticationMethodsSupported.ToArray();

        // Assert
        Assert.Single(methods);
        Assert.Equal(ClientAuthenticationMethods.ClientSecretBasic, methods[0]);
    }

    /// <summary>
    /// Creates a new instance of ClientSecretBasicAuthenticator with mocked dependencies for testing.
    /// </summary>
    /// <param name="timeProvider">Optional time provider for controlling time in tests.</param>
    /// <returns>A tuple containing the authenticator instance and the mock objects.</returns>
    private (ClientSecretBasicAuthenticator authenticator, Mocks mocks) CreateAuthenticator(
        TimeProvider? timeProvider = null)
    {
        LicenseTestHelper.StartTest();

        var logger = new Mock<ILogger<ClientSecretBasicAuthenticator>>();
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        var hashService = new HashService();

        var authenticator = new ClientSecretBasicAuthenticator(
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
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
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
        public Mock<ILogger<ClientSecretBasicAuthenticator>> Logger { get; init; } = null!;
        public Mock<IClientInfoProvider> ClientInfoProvider { get; init; } = null!;
    }

    /// <summary>
    /// Fake TimeProvider for testing time-dependent logic.
    /// </summary>
    private sealed class FakeTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _now;

        public FakeTimeProvider(DateTimeOffset now) => _now = now;

        public override DateTimeOffset GetUtcNow() => _now;
    }
}
