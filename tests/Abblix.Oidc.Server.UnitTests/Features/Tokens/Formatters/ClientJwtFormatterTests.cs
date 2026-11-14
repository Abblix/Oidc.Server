// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
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
using Abblix.Oidc.Server.Features.MultiTenancy;


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
        _jwtCreator
            .Setup(c => c.EncryptedResponseAlgorithmsSupported)
            .Returns(
            [
                EncryptionAlgorithms.KeyManagement.Rsa1_5,
                EncryptionAlgorithms.KeyManagement.RsaOaep,
                EncryptionAlgorithms.KeyManagement.RsaOaep256,
                EncryptionAlgorithms.KeyManagement.EcdhEs,
            ]);
        _clientKeysProvider = new Mock<IClientKeysProvider>(MockBehavior.Strict);
        _serviceKeysProvider = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);

        _formatter = new ClientJwtFormatter(
            new ProfiledJwtIssuer(_jwtCreator.Object),
            new ClientEncryptionKeyResolver(
                new ProfiledJwtIssuer(_jwtCreator.Object), _clientKeysProvider.Object, TimeProvider.System),
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
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, sig, _, _, _) => capturedSigningKey = sig)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, UserInfoPolicy(_clientInfo));

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
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(new[] { _clientEncryptionKey }.ToAsyncEnumerable());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        _clientInfo.IdentityTokenEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep;

        // Act
        await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, LogoutTokenPolicy(_clientInfo));

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
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        // Act
        await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, LogoutTokenPolicy(_clientInfo));

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
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(EncodedJwt);

        // Act
        var result = await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, UserInfoPolicy(_clientInfo));

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
                IssuedAt = TimeProvider.System.GetUtcNow(),
                ExpiresAt = TimeProvider.System.GetUtcNow().AddMinutes(5),
                AuthenticationTime = TimeProvider.System.GetUtcNow().AddMinutes(-1),
            }
        };

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(new[] { _clientEncryptionKey }.ToAsyncEnumerable());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, _clientEncryptionKey, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(EncodedJwt);

        _clientInfo.IdentityTokenEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep;

        // Act
        var result = await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, LogoutTokenPolicy(_clientInfo));

        // Assert
        Assert.Equal(EncodedJwt, result);
        _serviceKeysProvider.Verify(p => p.GetSigningKeys(TestTenant.Matched, true), Times.Once);
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
                IssuedAt = TimeProvider.System.GetUtcNow(),
                ExpiresAt = TimeProvider.System.GetUtcNow().AddMinutes(5),
            }
        };

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(EncodedJwt);

        // Act
        var result = await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, LogoutTokenPolicy(_clientInfo));

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
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(AsyncEnumerable.Empty<JsonWebKey>());

        _jwtCreator
            .Setup(c => c.IssueAsync(token, null!, null, It.IsAny<string>(), It.IsAny<string>()))
            .ThrowsAsync(new InvalidOperationException("Signing key is required"));

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, UserInfoPolicy(_clientInfo)));
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.6.1: "For JWE, both clients and authorization servers shall not use the RSA1_5
    /// algorithm". For a client held to FAPI 1.0 Advanced whose published keys include one declaring RSA1_5, the
    /// server encrypts to another of its keys with that key's algorithm; a client held to no profile is encrypted to its
    /// first key as it always was.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, "oaep", EncryptionAlgorithms.KeyManagement.RsaOaep256)]
    [InlineData(null, "pkcs1", EncryptionAlgorithms.KeyManagement.Rsa1_5)]
    public async Task FormatAsync_UnderFapi1Advanced_NeverEncryptsWithRsa1_5(
        ClientSecurityProfile? profile, string expectedKeyId, string expectedAlgorithm)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.PS256 },
            Payload = { Subject = "user123", Audiences = [ClientId] },
        };
        var client = new ClientInfo(ClientId) { SecurityProfile = profile, UserInfoEncryptedResponseAlgorithm = expectedAlgorithm };
        var pkcs1 = new RsaJsonWebKey { KeyId = "pkcs1", Algorithm = EncryptionAlgorithms.KeyManagement.Rsa1_5 };
        var oaep = new RsaJsonWebKey { KeyId = "oaep", Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256 };
        var signing = new RsaJsonWebKey { KeyId = "sig", Algorithm = SigningAlgorithms.PS256 };
        JsonWebKey? usedKey = null;
        string? usedAlgorithm = null;

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { signing }.ToAsyncEnumerable());
        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(client))
            .Returns(new JsonWebKey[] { pkcs1, oaep }.ToAsyncEnumerable());
        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>(
                (_, _, key, algorithm, _) => (usedKey, usedAlgorithm) = (key, algorithm))
            .ReturnsAsync(EncodedJwt);

        await _formatter.FormatAsync(SingleIssuer.Tenant, token, client, UserInfoPolicy(client));

        Assert.Equal(expectedKeyId, usedKey?.KeyId);
        Assert.Equal(expectedAlgorithm, usedAlgorithm);
    }

    /// <summary>
    /// A client set may hold a key declaring a signing algorithm, or a key management algorithm the host did not
    /// register, ahead of its encryption key: the token is encrypted to the first key it can be encrypted to, under
    /// that key's algorithm.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256)]
    [InlineData(EncryptionAlgorithms.KeyManagement.EcdhEs)]
    [InlineData("A-NAME-NOTHING-REGISTERS")]
    public async Task FormatAsync_ClientSetLeadsWithAKeyNothingEncryptsTo_EncryptsToTheNextOne(string firstKeyAlgorithm)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.PS256 },
            Payload = { Subject = "user123", Audiences = [ClientId] },
        };
        var unusable = new RsaJsonWebKey { KeyId = "first", Algorithm = firstKeyAlgorithm };
        var oaep = new RsaJsonWebKey { KeyId = "oaep", Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256 };
        JsonWebKey? usedKey = null;
        string? usedAlgorithm = null;

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { new RsaJsonWebKey { KeyId = "sig", Algorithm = SigningAlgorithms.PS256 } }.ToAsyncEnumerable());
        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(new JsonWebKey[] { unusable, oaep }.ToAsyncEnumerable());
        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>(
                (_, _, key, algorithm, _) => (usedKey, usedAlgorithm) = (key, algorithm))
            .ReturnsAsync(EncodedJwt);

        _clientInfo.UserInfoEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256;

        await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, UserInfoPolicy(_clientInfo));

        Assert.Same(oaep, usedKey);
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep256, usedAlgorithm);
    }

    /// <summary>
    /// A key declaring no algorithm is judged by the algorithm it would be used under, the default RSA-OAEP-256 here,
    /// so an EC or a symmetric key ahead of the RSA key is passed over rather than failing the issuance.
    /// </summary>
    [Theory]
    [InlineData("ec")]
    [InlineData("oct")]
    public async Task FormatAsync_AKeyDeclaringNoAlgorithmTheDefaultDoesNotFit_IsPassedOver(string firstKey)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.PS256 },
            Payload = { Subject = "user123", Audiences = [ClientId] },
        };
        JsonWebKey unusable = firstKey == "ec"
            ? new EllipticCurveJsonWebKey { KeyId = "first", Curve = EllipticCurveTypes.P256 }
            : new OctetJsonWebKey { KeyId = "first" };
        var rsa = new RsaJsonWebKey { KeyId = "rsa" };
        JsonWebKey? usedKey = null;
        string? usedAlgorithm = null;

        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { new RsaJsonWebKey { KeyId = "sig", Algorithm = SigningAlgorithms.PS256 } }.ToAsyncEnumerable());
        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(new[] { unusable, rsa }.ToAsyncEnumerable());
        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>(
                (_, _, key, algorithm, _) => (usedKey, usedAlgorithm) = (key, algorithm))
            .ReturnsAsync(EncodedJwt);

        _clientInfo.UserInfoEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256;

        await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, UserInfoPolicy(_clientInfo));

        Assert.Same(rsa, usedKey);
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep256, usedAlgorithm);
    }

    /// <summary>
    /// OpenID Connect Dynamic Client Registration 1.0 section 2, id_token_encrypted_response_alg: "The default, if
    /// omitted, is that no encryption is performed." A client that registered no algorithm gets a signed token,
    /// whatever its key set holds, a key without use included.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(SigningAlgorithms.RS256)]
    public async Task FormatAsync_NoRegisteredAlgorithm_SignsOnlyWhateverTheKeys(string? keyAlgorithm)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123", Audiences = [ClientId] },
        };
        JsonWebKey? usedKey = new RsaJsonWebKey();
        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());
        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(new JsonWebKey[] { new RsaJsonWebKey { KeyId = "k", Algorithm = keyAlgorithm } }.ToAsyncEnumerable());
        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, key, _, _) => usedKey = key)
            .ReturnsAsync(EncodedJwt);

        var result = await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, LogoutTokenPolicy(_clientInfo));

        Assert.True(result.TryGetSuccess(out _));
        Assert.Null(usedKey);
    }

    /// <summary>
    /// id_token_encrypted_response_alg is the "JWE alg algorithm REQUIRED for encrypting the ID Token issued to this
    /// Client": the token is encrypted under it alone, to the first key declaring it or none whose material carries it
    /// out.
    /// </summary>
    [Fact]
    public async Task FormatAsync_EncryptsUnderTheRegisteredAlgorithm_ToTheFirstKeyThatCarriesIt()
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123", Audiences = [ClientId] },
        };
        var other = new RsaJsonWebKey { KeyId = "other", Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep };
        var ec = new EllipticCurveJsonWebKey { KeyId = "ec", Curve = EllipticCurveTypes.P256 };
        var rsa = new RsaJsonWebKey { KeyId = "rsa" };
        JsonWebKey? usedKey = null;
        string? usedAlgorithm = null;
        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());
        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns(new JsonWebKey[] { other, ec, rsa }.ToAsyncEnumerable());
        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>(
                (_, _, key, algorithm, _) => (usedKey, usedAlgorithm) = (key, algorithm))
            .ReturnsAsync(EncodedJwt);
        _clientInfo.IdentityTokenEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256;

        await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, LogoutTokenPolicy(_clientInfo));

        Assert.Same(rsa, usedKey);
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep256, usedAlgorithm);
    }

    /// <summary>
    /// A registered algorithm no published key can be used with, an empty key set included (a jwks_uri that could
    /// not be read), is the refusal, never a token sent signed only.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task FormatAsync_ARegisteredAlgorithmNoKeyCanBeUsedWith_IsRefused(bool keyDeclaringAnother)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Subject = "user123", Audiences = [ClientId] },
        };
        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { _signingKeyRS256 }.ToAsyncEnumerable());
        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(_clientInfo))
            .Returns((keyDeclaringAnother
                ? new JsonWebKey[] { new RsaJsonWebKey { KeyId = "other", Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep } }
                : []).ToAsyncEnumerable());
        _clientInfo.IdentityTokenEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256;

        var result = await _formatter.FormatAsync(SingleIssuer.Tenant, token, _clientInfo, LogoutTokenPolicy(_clientInfo));

        Assert.True(result.TryGetFailure(out var refusal));
        Assert.Equal(ErrorCodes.UnauthorizedClient, refusal.Error);
    }

    /// <summary>
    /// A client held to FAPI 1.0 Advanced whose only published encryption key declares RSA1_5 is not answered with a
    /// token encrypted against the profile, nor with one left unencrypted although it publishes a key: the token is not
    /// issued.
    /// </summary>
    [Fact]
    public async Task FormatAsync_UnderFapi1Advanced_WithOnlyAnRsa1_5Key_Refuses()
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.PS256 },
            Payload = { Subject = "user123", Audiences = [ClientId] },
        };
        var client = new ClientInfo(ClientId)
        {
            SecurityProfile = ClientSecurityProfile.Fapi1Advanced,
            UserInfoEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
        };
        _serviceKeysProvider
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { new RsaJsonWebKey { KeyId = "sig", Algorithm = SigningAlgorithms.PS256 } }.ToAsyncEnumerable());
        _clientKeysProvider
            .Setup(p => p.GetEncryptionKeys(client))
            .Returns(new JsonWebKey[]
            {
                new RsaJsonWebKey { KeyId = "pkcs1", Algorithm = EncryptionAlgorithms.KeyManagement.Rsa1_5 },
            }.ToAsyncEnumerable());

        var result = await _formatter.FormatAsync(SingleIssuer.Tenant, token, client, UserInfoPolicy(client));

        // A refusal the caller answers in its own protocol, not a server error
        Assert.True(result.TryGetFailure(out _));
    }
}
