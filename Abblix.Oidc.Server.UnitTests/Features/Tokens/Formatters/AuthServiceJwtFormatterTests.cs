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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Moq;
using Xunit;
using JsonWebKey = Abblix.Jwt.JsonWebKey;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Formatters;

/// <summary>
/// Unit tests for <see cref="AuthServiceJwtFormatter"/> verifying JWT formatting, signing, and encryption
/// for tokens issued by the authentication service per RFC 7519 (JWT), RFC 7515 (JWS), and RFC 7516 (JWE).
/// Tests cover signing key selection, optional encryption, and error handling.
/// </summary>
public class AuthServiceJwtFormatterTests
{
    private const string EncodedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

    private readonly Mock<IJsonWebTokenCreator> _jwtCreator;
    private readonly Mock<IAuthServiceKeysProvider> _keysProvider;
    private readonly AuthServiceJwtFormatter _formatter;

    private readonly JsonWebKey _signingKeyRS256;
    private readonly JsonWebKey _signingKeyRS384;
    private readonly JsonWebKey _encryptionKey;

    public AuthServiceJwtFormatterTests()
    {
        _jwtCreator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        _keysProvider = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);

        _formatter = new AuthServiceJwtFormatter(_jwtCreator.Object, _keysProvider.Object);

        _signingKeyRS256 = new RsaJsonWebKey { KeyId = "sig-rs256", Algorithm = SigningAlgorithms.RS256 };
        _signingKeyRS384 = new RsaJsonWebKey { KeyId = "sig-rs384", Algorithm = SigningAlgorithms.RS384 };
        _encryptionKey = new RsaJsonWebKey { KeyId = "enc-key", Algorithm = "RSA-OAEP" };
    }

    #region Signing Key Selection Tests

    /// <summary>
    /// Verifies that FormatAsync selects signing key matching JWT header algorithm.
    /// Per RFC 7515 Section 4.1.1, alg header parameter identifies signing algorithm.
    /// Critical for security - ensures correct key is used for token signatures.
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithRS256Algorithm_ShouldSelectMatchingSigningKey()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123" }
        };

        JsonWebKey? capturedSigningKey = null;
        JsonWebKey? capturedEncryptionKey = null;

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256, _signingKeyRS384 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?>((_, sig, enc) =>
            {
                capturedSigningKey = sig;
                capturedEncryptionKey = enc;
            })
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token);

        // Assert
        Assert.Same(_signingKeyRS256, capturedSigningKey);
    }

    /// <summary>
    /// Verifies that FormatAsync selects RS384 signing key when specified in JWT header.
    /// Ensures formatter correctly handles multiple available signing algorithms.
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithRS384Algorithm_ShouldSelectMatchingSigningKey()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS384 },
            Payload = { Subject = "user123" }
        };

        JsonWebKey? capturedSigningKey = null;

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256, _signingKeyRS384 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?>((_, sig, _) => capturedSigningKey = sig)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token);

        // Assert
        Assert.Same(_signingKeyRS384, capturedSigningKey);
    }

    /// <summary>
    /// Verifies that FormatAsync throws when no signing key matches JWT algorithm.
    /// Critical security requirement - prevents token issuance with unsupported/misconfigured algorithms.
    /// FirstByAlgorithmAsync returns null when no match found, causing IssueAsync to fail.
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithNoMatchingSigningKey_ShouldThrow()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS512 },
            Payload = { Subject = "user123" }
        };

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256, _signingKeyRS384 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        // IssueAsync will be called with null signing key, which should fail
        _jwtCreator
            .Setup(c => c.IssueAsync(token, null!, null))
            .ThrowsAsync(new InvalidOperationException("Signing key is required"));

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _formatter.FormatAsync(token));
    }

    /// <summary>
    /// Verifies that FormatAsync requests only public signing keys (activeOnly=true).
    /// Ensures only currently active signing keys are used for token generation.
    /// </summary>
    [Fact]
    public async Task FormatAsync_ShouldRequestActiveSigningKeys()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123" }
        };

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>()))
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token);

        // Assert
        _keysProvider.Verify(p => p.GetSigningKeys(true), Times.Once);
    }

    #endregion

    #region Encryption Tests

    /// <summary>
    /// Verifies that FormatAsync uses encryption key when available.
    /// Per RFC 7516, JWE provides confidentiality protection for JWTs.
    /// Important for sensitive tokens (refresh tokens, private claims).
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithEncryptionKeyAvailable_ShouldUseEncryption()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123" }
        };

        JsonWebKey? capturedEncryptionKey = null;

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(new[] { _encryptionKey }.ToAsyncEnumerable());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?>((_, _, enc) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token);

        // Assert
        Assert.Same(_encryptionKey, capturedEncryptionKey);
    }

    /// <summary>
    /// Verifies that FormatAsync creates token without encryption when no encryption keys available.
    /// Ensures formatter degrades gracefully when encryption is not configured.
    /// Tokens remain signed but unencrypted (JWS without JWE).
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithNoEncryptionKeys_ShouldCreateUnencryptedToken()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123" }
        };

        JsonWebKey? capturedEncryptionKey = null;

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?>((_, _, enc) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token);

        // Assert
        Assert.Null(capturedEncryptionKey);
    }

    /// <summary>
    /// Verifies that FormatAsync uses only the first available encryption key.
    /// Per implementation, encryption is optional and uses first key if available.
    /// Ensures consistent encryption key selection behavior.
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithMultipleEncryptionKeys_ShouldUseFirstKey()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123" }
        };

        var secondEncryptionKey = new RsaJsonWebKey { KeyId = "enc-key-2", Algorithm = "RSA-OAEP" };
        JsonWebKey? capturedEncryptionKey = null;

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(new[] { _encryptionKey, secondEncryptionKey }.ToAsyncEnumerable());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?>((_, _, enc) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token);

        // Assert
        Assert.Same(_encryptionKey, capturedEncryptionKey);
    }

    #endregion

    #region JWT Creation Tests

    /// <summary>
    /// Verifies that FormatAsync returns JWT string from IJsonWebTokenCreator.
    /// Ensures complete JWT creation flow produces expected encoded token.
    /// </summary>
    [Fact]
    public async Task FormatAsync_ShouldReturnEncodedJwtFromCreator()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123" }
        };

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null))
            .ReturnsAsync(EncodedJwt);

        // Act
        var result = await _formatter.FormatAsync(token);

        // Assert
        Assert.Equal(EncodedJwt, result);
    }

    /// <summary>
    /// Verifies that FormatAsync passes correct token to IJsonWebTokenCreator.
    /// Ensures token integrity throughout formatting process.
    /// </summary>
    [Fact]
    public async Task FormatAsync_ShouldPassTokenToCreator()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, Type = "at+jwt" },
            Payload =
            {
                Subject = "user123",
                Issuer = "https://auth.example.com",
                Audiences = ["api"]
            }
        };

        JsonWebToken? capturedToken = null;

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(It.IsAny<JsonWebToken>(), It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?>((t, _, _) => capturedToken = t)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token);

        // Assert
        Assert.Same(token, capturedToken);
    }

    /// <summary>
    /// Verifies that FormatAsync invokes IJsonWebTokenCreator exactly once.
    /// Ensures no duplicate token creation or unnecessary operations.
    /// </summary>
    [Fact]
    public async Task FormatAsync_ShouldInvokeCreatorOnce()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123" }
        };

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null))
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(token);

        // Assert
        _jwtCreator.Verify(c => c.IssueAsync(token, _signingKeyRS256, null), Times.Once);
    }

    #endregion

    #region Integration Tests

    /// <summary>
    /// Verifies complete JWT formatting flow with signing and encryption.
    /// Tests end-to-end token creation with both cryptographic operations.
    /// Represents typical production scenario for refresh tokens.
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithSigningAndEncryption_ShouldProduceCompleteJwt()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, Type = "JWT" },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Subject = "user123",
                Issuer = "https://auth.example.com",
                Audiences = ["https://api.example.com"],
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            }
        };

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256, _signingKeyRS384 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(new[] { _encryptionKey }.ToAsyncEnumerable());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, _encryptionKey))
            .ReturnsAsync(EncodedJwt);

        // Act
        var result = await _formatter.FormatAsync(token);

        // Assert
        Assert.Equal(EncodedJwt, result);
        _keysProvider.Verify(p => p.GetSigningKeys(true), Times.Once);
        _keysProvider.Verify(p => p.GetEncryptionKeys(false), Times.Once);
        _jwtCreator.Verify(c => c.IssueAsync(token, _signingKeyRS256, _encryptionKey), Times.Once);
    }

    /// <summary>
    /// Verifies JWT formatting flow for access token without encryption.
    /// Tests typical access token scenario (signed but not encrypted for performance).
    /// Per OAuth 2.0 best practices, access tokens often unencrypted for efficiency.
    /// </summary>
    [Fact]
    public async Task FormatAsync_ForAccessToken_ShouldProduceSignedJwt()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, Type = "at+jwt" },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Subject = "user123",
                Issuer = "https://auth.example.com",
                Audiences = ["https://api.example.com"],
                Scope = ["openid", "profile", "email"],
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15),
            }
        };

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null))
            .ReturnsAsync(EncodedJwt);

        // Act
        var result = await _formatter.FormatAsync(token);

        // Assert
        Assert.Equal(EncodedJwt, result);
        _jwtCreator.Verify(c => c.IssueAsync(token, _signingKeyRS256, null), Times.Once);
    }

    /// <summary>
    /// Verifies JWT formatting for Registration Access Token.
    /// Per RFC 7592 Section 3, Registration Access Tokens authenticate client configuration requests.
    /// Ensures formatter correctly handles all auth service token types.
    /// </summary>
    [Fact]
    public async Task FormatAsync_ForRegistrationAccessToken_ShouldProduceJwt()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, Type = "JWT" },
            Payload =
            {
                JwtId = Guid.NewGuid().ToString("N"),
                Subject = "client_abc123",
                Issuer = "https://auth.example.com",
                Audiences = ["https://auth.example.com/register"],
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            }
        };

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null))
            .ReturnsAsync(EncodedJwt);

        // Act
        var result = await _formatter.FormatAsync(token);

        // Assert
        Assert.Equal(EncodedJwt, result);
    }

    #endregion

    #region Error Handling Tests

    /// <summary>
    /// Verifies that FormatAsync throws when GetSigningKeys returns empty sequence.
    /// Critical security check - prevents token issuance when no signing keys configured.
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithNoSigningKeys_ShouldThrowInvalidOperationException()
    {
        // Arrange
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123" }
        };

        _keysProvider
            .Setup(p => p.GetSigningKeys(true))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _keysProvider
            .Setup(p => p.GetEncryptionKeys(false))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, null!, null))
            .ThrowsAsync(new InvalidOperationException("Signing key is required"));

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _formatter.FormatAsync(token));
    }

    #endregion
}
