// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using JsonWebKey = Abblix.Jwt.JsonWebKey;


namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Formatters;

/// <summary>
/// Unit tests for <see cref="ClientJwtFormatter"/> verifying JWT formatting for client-issued tokens
/// per RFC 7519 (JWT), RFC 7515 (JWS), and RFC 7516 (JWE). Tests cover signing with service keys,
/// optional encryption with client keys, and integration with ClientInfo.
/// </summary>
public class ClientJwtFormatterTests
{
    private const string ClientId = TestConstants.DefaultClientId;
    private const string EncodedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

    private readonly Mock<IJsonWebTokenCreator> _jwtCreator;
    private readonly Mock<IClientKeysProvider> _clientKeysProvider;
    private readonly Mock<IAuthServiceKeysProvider> _serviceKeysProvider;
    private readonly ClientJwtFormatter _formatter;

    private readonly JsonWebKey _signingKeyRS256;
    private readonly JsonWebKey _clientEncryptionKey;
    private readonly ClientInfo _clientInfo;

    /// <summary>What the client registered for UserInfo, which is also what an ID token uses.</summary>
    private static ClientJwtEncryption UserInfoPolicy(ClientInfo client)
        => ClientJwtEncryption.ForUserInfo(client, new OidcOptions());

    /// <summary>What the client registered for identity tokens, which logout tokens share.</summary>
    private static ClientJwtEncryption LogoutTokenPolicy(ClientInfo client)
        => ClientJwtEncryption.ForIdentityToken(client, new OidcOptions());

    public ClientJwtFormatterTests()
    {
        _jwtCreator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        _clientKeysProvider = new Mock<IClientKeysProvider>(MockBehavior.Strict);
        _serviceKeysProvider = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);

        _formatter = new ClientJwtFormatter(
            _jwtCreator.Object,
            _clientKeysProvider.Object,
            _serviceKeysProvider.Object);

        _signingKeyRS256 = new RsaJsonWebKey { KeyId = "sig-rs256", Algorithm = SigningAlgorithms.RS256 };
        _clientEncryptionKey = new RsaJsonWebKey { KeyId = "client-enc", Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep };
        _clientInfo = new ClientInfo(ClientId);
    }

    /// <summary>
    /// Verifies that FormatAsync uses auth service signing key matching JWT algorithm.
    /// Per RFC 7515, auth service signs all tokens issued to clients.
    /// Critical for JWT integrity and client trust.
    /// </summary>
    [Fact]
    public async Task FormatAsync_ShouldUseServiceSigningKey()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123", Audiences = [ClientId] }
        };

        JsonWebKey? capturedSigningKey = null;

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, sig, _, _, _) => capturedSigningKey = sig)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token, _clientInfo, UserInfoPolicy(_clientInfo));

        // Assert
        Assert.Same(_signingKeyRS256, capturedSigningKey);
    }

    /// <summary>
    /// Verifies that FormatAsync uses client encryption key when available.
    /// Per RFC 7516, JWE encrypts a token for confidentiality when the client has published a key.
    /// Client keys are retrieved from IClientKeysProvider based on ClientInfo.
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithClientEncryptionKey_ShouldEncryptToken()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, Type = JsonWebTokenTypes.LogoutToken },
            Payload = { Subject = "user123", Audiences = [ClientId] }
        };

        JsonWebKey? capturedEncryptionKey = null;

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(new[] { _clientEncryptionKey }.ToAsyncEnumerable());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token, _clientInfo, LogoutTokenPolicy(_clientInfo));

        // Assert
        Assert.Same(_clientEncryptionKey, capturedEncryptionKey);
    }

    /// <summary>
    /// Verifies that FormatAsync creates unencrypted token when client has no encryption keys.
    /// Ensures formatter gracefully handles clients without encryption support.
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithoutClientEncryptionKey_ShouldCreateUnencryptedToken()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, Type = JsonWebTokenTypes.LogoutToken },
            Payload = { Subject = "user123", Audiences = [ClientId] }
        };

        JsonWebKey? capturedEncryptionKey = null;

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token, _clientInfo, LogoutTokenPolicy(_clientInfo));

        // Assert
        Assert.Null(capturedEncryptionKey);
    }

    /// <summary>
    /// Verifies that FormatAsync returns encoded JWT string from IJsonWebTokenCreator.
    /// Ensures complete token formatting flow produces expected result.
    /// </summary>
    [Fact]
    public async Task FormatAsync_ShouldReturnEncodedJwt()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123", Audiences = [ClientId] }
        };

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(EncodedJwt);

        // Act
        var result = await _formatter.FormatAsync(token, _clientInfo, UserInfoPolicy(_clientInfo));

        // Assert
        Assert.Equal(EncodedJwt, result);
    }

    /// <summary>
    /// The whole flow for a token this overload recognizes: signed with the service key the header's algorithm
    /// selects, then encrypted to the client's published key. Its neighbours each check one collaborator; this
    /// one requires all three to have been asked, exactly once.
    /// </summary>
    [Fact]
    public async Task FormatAsync_ForLogoutToken_ShouldProduceSignedAndEncryptedJwt()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, Type = JsonWebTokenTypes.LogoutToken },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Subject = "user123",
                Issuer = "https://auth.example.com",
                Audiences = [ClientId],
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
                AuthenticationTime = DateTimeOffset.UtcNow.AddMinutes(-1),
            }
        };

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(new[] { _clientEncryptionKey }.ToAsyncEnumerable());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, _clientEncryptionKey, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(EncodedJwt);

        // Act
        var result = await _formatter.FormatAsync(token, _clientInfo, LogoutTokenPolicy(_clientInfo));

        // Assert
        Assert.Equal(EncodedJwt, result);
        _serviceKeysProvider.Verify(p => p.GetSigningKeys(true), Times.Once);
        _clientKeysProvider.Verify(p => p.GetEncryptionKeys(_clientInfo), Times.Once);
        _jwtCreator.Verify(c => c.IssueAsync(token, _signingKeyRS256, _clientEncryptionKey, It.IsAny<string>(), It.IsAny<string>()), Times.Once);
    }

    /// <summary>
    /// Verifies JWT formatting for logout token per OpenID Connect Back-Channel Logout.
    /// Tests formatter correctly handles logout token type with client-specific configuration.
    /// </summary>
    [Fact]
    public async Task FormatAsync_ForLogoutToken_ShouldProduceSignedJwt()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, Type = JsonWebTokenTypes.LogoutToken },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Subject = "user123",
                Issuer = "https://auth.example.com",
                Audiences = [ClientId],
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            }
        };

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(EncodedJwt);

        // Act
        var result = await _formatter.FormatAsync(token, _clientInfo, LogoutTokenPolicy(_clientInfo));

        // Assert
        Assert.Equal(EncodedJwt, result);
    }

    /// <summary>
    /// Verifies that FormatAsync throws when no service signing keys available.
    /// Critical security check - prevents token issuance without valid signatures.
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithNoSigningKeys_ShouldThrow()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123", Audiences = [ClientId] }
        };

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, null!, null, It.IsAny<string>(), It.IsAny<string>()))
            .ThrowsAsync(new InvalidOperationException("Signing key is required"));

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _formatter.FormatAsync(token, _clientInfo, UserInfoPolicy(_clientInfo)));
    }
}
