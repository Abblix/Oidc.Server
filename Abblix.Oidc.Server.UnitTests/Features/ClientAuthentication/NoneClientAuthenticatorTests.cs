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

using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="NoneClientAuthenticator"/> verifying the 'none' authentication method
/// for public clients as defined in OAuth 2.0 and OpenID Connect specifications.
/// Tests cover public client authentication without secrets, validation of client types,
/// and various error conditions.
/// </summary>
[Collection("License")]
public class NoneClientAuthenticatorTests
{
    private const string PublicClientId = "public_client_123";
    private const string ConfidentialClientId = "confidential_client_456";

    public NoneClientAuthenticatorTests(TestInfrastructure.LicenseFixture fixture)
    {
        // Fixture auto-configures license
    }

    /// <summary>
    /// Verifies that a valid public client with only client_id successfully authenticates.
    /// Public clients don't require client secrets and should authenticate with just their ID.
    /// </summary>
    [Fact]
    public async Task ValidPublicClient_ShouldAuthenticate()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreatePublicClientInfo(PublicClientId);
        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(PublicClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = PublicClientId
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(PublicClientId, result.ClientId);
        Assert.Equal(ClientType.Public, result.ClientType);
    }

    /// <summary>
    /// Verifies that authentication fails when client_id is missing.
    /// Even public clients must provide their client_id.
    /// </summary>
    [Fact]
    public async Task MissingClientId_ShouldReturnNull()
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
            ClientId = string.Empty
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_id is whitespace-only.
    /// Whitespace-only values should be treated as invalid.
    /// </summary>
    [Fact]
    public async Task WhitespaceClientId_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientId = "   "
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client is not found in the client registry.
    /// Even without secret validation, the client must be registered.
    /// </summary>
    [Fact]
    public async Task ClientNotFound_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(PublicClientId))
            .ReturnsAsync((ClientInfo?)null);

        var request = new ClientRequest
        {
            ClientId = PublicClientId
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client is configured as confidential.
    /// Only public clients are allowed to use the 'none' authentication method.
    /// </summary>
    [Fact]
    public async Task ConfidentialClient_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateConfidentialClientInfo(ConfidentialClientId);
        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(ConfidentialClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = ConfidentialClientId
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that public client authentication succeeds even when client_secret is provided in request.
    /// For public clients, the authenticator ignores any provided secret and relies only on client_id and type.
    /// </summary>
    [Fact]
    public async Task PublicClientWithSecretInRequest_ShouldAuthenticateIgnoringSecret()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreatePublicClientInfo(PublicClientId);
        mocks.ClientInfoProvider
            .Setup(p => p.TryFindClientAsync(PublicClientId))
            .ReturnsAsync(clientInfo);

        var request = new ClientRequest
        {
            ClientId = PublicClientId,
            ClientSecret = "ignored_secret"
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(PublicClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that the authenticator reports the correct supported authentication method.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_ShouldReturnNone()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();

        // Act
        var methods = authenticator.ClientAuthenticationMethodsSupported.ToArray();

        // Assert
        Assert.Single(methods);
        Assert.Equal(ClientAuthenticationMethods.None, methods[0]);
    }

    /// <summary>
    /// Creates a new instance of NoneClientAuthenticator with mocked dependencies for testing.
    /// </summary>
    /// <returns>A tuple containing the authenticator instance and the mock objects.</returns>
    private (NoneClientAuthenticator authenticator, Mocks mocks) CreateAuthenticator()
    {
        var logger = new Mock<ILogger<NoneClientAuthenticator>>();
        var clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);

        var authenticator = new NoneClientAuthenticator(
            logger.Object,
            clientInfoProvider.Object);

        var mocks = new Mocks
        {
            Logger = logger,
            ClientInfoProvider = clientInfoProvider,
        };

        return (authenticator, mocks);
    }

    /// <summary>
    /// Creates a test ClientInfo object for a public client.
    /// </summary>
    /// <param name="clientId">The client ID.</param>
    /// <returns>A configured ClientInfo object for a public client.</returns>
    private ClientInfo CreatePublicClientInfo(string clientId)
    {
        return new ClientInfo(clientId)
        {
            ClientType = ClientType.Public,
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None
        };
    }

    /// <summary>
    /// Creates a test ClientInfo object for a confidential client.
    /// </summary>
    /// <param name="clientId">The client ID.</param>
    /// <returns>A configured ClientInfo object for a confidential client.</returns>
    private ClientInfo CreateConfidentialClientInfo(string clientId)
    {
        return new ClientInfo(clientId)
        {
            ClientType = ClientType.Confidential,
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost
        };
    }

    /// <summary>
    /// Container class for holding all mock objects used in tests.
    /// </summary>
    private sealed class Mocks
    {
        public Mock<ILogger<NoneClientAuthenticator>> Logger { get; init; } = null!;
        public Mock<IClientInfoProvider> ClientInfoProvider { get; init; } = null!;
    }
}
