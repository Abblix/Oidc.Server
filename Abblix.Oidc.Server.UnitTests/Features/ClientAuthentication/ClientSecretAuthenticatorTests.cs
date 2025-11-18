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
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Hashing;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using HashAlg = Abblix.Oidc.Server.Features.Hashing.HashAlgorithm;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="ClientSecretAuthenticator"/> verifying client authentication
/// per OAuth 2.0 and OpenID Connect specifications.
/// </summary>
public class ClientSecretAuthenticatorTests
{
    private readonly Mock<IClientInfoProvider> _clientInfoProvider;
    private readonly Mock<TimeProvider> _clock;
    private readonly Mock<IHashService> _hashService;
    private readonly TestClientSecretAuthenticator _authenticator;

    public ClientSecretAuthenticatorTests()
    {
        var logger = new Mock<ILogger<ClientSecretAuthenticator>>();
        _clientInfoProvider = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        _clock = new Mock<TimeProvider>();
        _hashService = new Mock<IHashService>(MockBehavior.Strict);

        _authenticator = new TestClientSecretAuthenticator(
            logger.Object,
            _clientInfoProvider.Object,
            _clock.Object,
            _hashService.Object);
    }

    /// <summary>
    /// Test authenticator exposing protected method for testing.
    /// </summary>
    private class TestClientSecretAuthenticator(
        ILogger<ClientSecretAuthenticator> logger,
        IClientInfoProvider clientInfoProvider,
        TimeProvider clock,
        IHashService hashService)
        : ClientSecretAuthenticator(logger, clientInfoProvider, clock, hashService)
    {
        public Task<ClientInfo?> TestTryAuthenticateAsync(string? clientId, string? secret, string authMethod)
            => TryAuthenticateAsync(clientId, secret, authMethod);
    }

    private static byte[] ComputeSha256(string value)
    {
        return SHA256.HashData(Encoding.UTF8.GetBytes(value));
    }

    private static byte[] ComputeSha512(string value)
    {
        return SHA512.HashData(Encoding.UTF8.GetBytes(value));
    }

    /// <summary>
    /// Verifies authentication fails when client ID is null.
    /// Per OAuth 2.0, client_id is required for authentication.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithNullClientId_ShouldReturnNull()
    {
        // Arrange
        string? clientId = null;
        var secret = "test-secret";

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client ID is empty.
    /// Per OAuth 2.0, client_id must have a value.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithEmptyClientId_ShouldReturnNull()
    {
        // Arrange
        var clientId = string.Empty;
        var secret = "test-secret";

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client ID is whitespace.
    /// Whitespace-only values are treated as empty.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithWhitespaceClientId_ShouldReturnNull()
    {
        // Arrange
        var clientId = "   ";
        var secret = "test-secret";

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when secret is null.
    /// Per OAuth 2.0, client_secret is required for confidential clients.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithNullSecret_ShouldReturnNull()
    {
        // Arrange
        var clientId = "test-client";
        string? secret = null;

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when secret is empty.
    /// Empty secrets are not valid.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithEmptySecret_ShouldReturnNull()
    {
        // Arrange
        var clientId = "test-client";
        var secret = string.Empty;

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client not found.
    /// Per OAuth 2.0, unknown clients must be rejected.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithNonExistentClient_ShouldReturnNull()
    {
        // Arrange
        var clientId = "unknown-client";
        var secret = "test-secret";

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync((ClientInfo?)null);

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when client has no secrets configured.
    /// Clients must have at least one secret for secret-based authentication.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithClientWithoutSecrets_ShouldReturnNull()
    {
        // Arrange
        var clientId = "test-client";
        var secret = "test-secret";
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets = [],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails when authentication method doesn't match.
    /// Per OAuth 2.0, client must use its configured authentication method.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithWrongAuthMethod_ShouldReturnNull()
    {
        // Arrange
        var clientId = "test-client";
        var secret = "test-secret";
        var secretHash = ComputeSha256(secret);
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets = [new ClientSecret { Sha256Hash = secretHash }],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication succeeds with valid SHA256 secret.
    /// SHA256 is a standard hash algorithm for client secrets.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithValidSha256Secret_ShouldReturnClientInfo()
    {
        // Arrange
        var clientId = "test-client";
        var secret = "test-secret";
        var secretHash = ComputeSha256(secret);
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets = [new ClientSecret { Sha256Hash = secretHash }],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha512, secret))
            .Returns(ComputeSha512(secret));

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha256, secret))
            .Returns(secretHash);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(clientId, result.ClientId);
    }

    /// <summary>
    /// Verifies authentication succeeds with valid SHA512 secret.
    /// SHA512 provides stronger security than SHA256.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithValidSha512Secret_ShouldReturnClientInfo()
    {
        // Arrange
        var clientId = "test-client";
        var secret = "test-secret";
        var secretHash = ComputeSha512(secret);
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets = [new ClientSecret { Sha512Hash = secretHash }],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha512, secret))
            .Returns(secretHash);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(clientId, result.ClientId);
    }

    /// <summary>
    /// Verifies authentication fails with incorrect secret.
    /// Per OAuth 2.0, invalid secrets must be rejected.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithIncorrectSecret_ShouldReturnNull()
    {
        // Arrange
        var clientId = "test-client";
        var correctSecret = "correct-secret";
        var incorrectSecret = "wrong-secret";
        var secretHash = ComputeSha256(correctSecret);
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets = [new ClientSecret { Sha256Hash = secretHash }],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha512, incorrectSecret))
            .Returns(ComputeSha512(incorrectSecret));

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha256, incorrectSecret))
            .Returns(ComputeSha256(incorrectSecret));

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, incorrectSecret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication fails with expired secret.
    /// Per security best practices, expired secrets must not be accepted.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithExpiredSecret_ShouldReturnNull()
    {
        // Arrange
        var clientId = "test-client";
        var secret = "test-secret";
        var secretHash = ComputeSha256(secret);
        var expirationTime = DateTimeOffset.UtcNow.AddDays(-1);
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets =
            [
                new ClientSecret
                {
                    Sha256Hash = secretHash,
                    ExpiresAt = expirationTime
                }
            ],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha512, secret))
            .Returns(ComputeSha512(secret));

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha256, secret))
            .Returns(secretHash);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies authentication succeeds with non-expired secret.
    /// Secrets with future expiration should be accepted.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithNonExpiredSecret_ShouldReturnClientInfo()
    {
        // Arrange
        var clientId = "test-client";
        var secret = "test-secret";
        var secretHash = ComputeSha256(secret);
        var expirationTime = DateTimeOffset.UtcNow.AddDays(30);
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets =
            [
                new ClientSecret
                {
                    Sha256Hash = secretHash,
                    ExpiresAt = expirationTime
                }
            ],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha512, secret))
            .Returns(ComputeSha512(secret));

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha256, secret))
            .Returns(secretHash);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.NotNull(result);
    }

    /// <summary>
    /// Verifies authentication with multiple secrets uses most recent non-expired.
    /// Supports secret rotation without downtime.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithMultipleSecrets_ShouldUseLatestValid()
    {
        // Arrange
        var clientId = "test-client";
        var secret = "test-secret";
        var secretHash = ComputeSha256(secret);
        var oldExpiration = DateTimeOffset.UtcNow.AddDays(10);
        var newExpiration = DateTimeOffset.UtcNow.AddDays(30);
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets =
            [
                new ClientSecret { Sha256Hash = secretHash, ExpiresAt = oldExpiration },
                new ClientSecret { Sha256Hash = secretHash, ExpiresAt = newExpiration }
            ],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha512, secret))
            .Returns(ComputeSha512(secret));

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha256, secret))
            .Returns(secretHash);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.NotNull(result);
    }

    /// <summary>
    /// Verifies SHA512 secrets are checked before SHA256.
    /// SHA512 is preferred for stronger security.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_ChecksSha512BeforeSha256()
    {
        // Arrange
        var clientId = "test-client";
        var secret = "test-secret";
        var sha512Hash = ComputeSha512(secret);
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets =
            [
                new ClientSecret { Sha512Hash = sha512Hash }
            ],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha512, secret))
            .Returns(sha512Hash);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.NotNull(result);
        // Verify SHA256 was never called since SHA512 matched
        _hashService.Verify(h => h.Sha(HashAlg.Sha256, secret), Times.Never);
    }

    /// <summary>
    /// Verifies hash computation when client has both algorithms configured.
    /// Implementation checks both SHA512 and SHA256, then selects secret with latest expiration.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_ComputesHashLazily()
    {
        // Arrange
        var clientId = "test-client";
        var secret = "test-secret";
        var sha256Hash = ComputeSha256(secret);
        var sha512Hash = ComputeSha512(secret);

        // Client has BOTH hashes configured
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets =
            [
                new ClientSecret
                {
                    Sha256Hash = sha256Hash,
                    Sha512Hash = sha512Hash
                }
            ],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha512, secret))
            .Returns(sha512Hash);

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha256, secret))
            .Returns(sha256Hash);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        // Act
        await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        // Both hashes computed exactly once (implementation uses Concat+MaxBy)
        _hashService.Verify(h => h.Sha(HashAlg.Sha512, secret), Times.Once);
        _hashService.Verify(h => h.Sha(HashAlg.Sha256, secret), Times.Once);
    }

    /// <summary>
    /// Verifies authentication with secret having no expiration.
    /// Secrets without expiration should work indefinitely.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateAsync_WithNoExpiration_ShouldSucceed()
    {
        // Arrange
        var clientId = "test-client";
        var secret = "test-secret";
        var secretHash = ComputeSha256(secret);
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets =
            [
                new ClientSecret
                {
                    Sha256Hash = secretHash,
                    ExpiresAt = null // No expiration
                }
            ],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic
        };

        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(clientId))
            .ReturnsAsync(clientInfo);

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha512, secret))
            .Returns(ComputeSha512(secret));

        _hashService
            .Setup(h => h.Sha(HashAlg.Sha256, secret))
            .Returns(secretHash);

        _clock
            .Setup(c => c.GetUtcNow())
            .Returns(DateTimeOffset.UtcNow);

        // Act
        var result = await _authenticator.TestTryAuthenticateAsync(
            clientId, secret, ClientAuthenticationMethods.ClientSecretBasic);

        // Assert
        Assert.NotNull(result);
    }
}
