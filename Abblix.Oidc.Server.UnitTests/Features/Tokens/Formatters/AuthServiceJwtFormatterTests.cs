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
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using JsonWebKey = Abblix.Jwt.JsonWebKey;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Formatters;

/// <summary>
/// Unit tests for <see cref="AuthServiceJwtFormatter"/> verifying JWT formatting, signing and encryption
/// for tokens the authorization server issues for itself, per RFC 7519 (JWT), RFC 7515 (JWS) and RFC 7516
/// (JWE). The tests exercise the explicit <see cref="ServiceJwtEncryption"/> policy overload — signed only,
/// encrypt with a key-derived or explicit key-management algorithm, signing- and encryption-key pinning by
/// <c>kid</c>, and the missing-key error — plus the retained implicit legacy path.
/// </summary>
public class AuthServiceJwtFormatterTests
{
    private const string EncodedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
    private const string ContentEnc = EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512;

    private readonly Mock<IJsonWebTokenCreator> _jwtCreator;
    private readonly Mock<IAuthServiceKeysProvider> _keysProvider;
    private readonly AuthServiceJwtFormatter _formatter;

    private readonly JsonWebKey _signingKeyRS256;
    private readonly JsonWebKey _signingKeyRS256Alt;
    private readonly JsonWebKey _signingKeyRS384;
    private readonly JsonWebKey _encryptionKey;

    public AuthServiceJwtFormatterTests()
    {
        _jwtCreator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        _keysProvider = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);

        var options = Options.Create(new OidcOptions());
        _formatter = new AuthServiceJwtFormatter(_jwtCreator.Object, _keysProvider.Object, options);

        _signingKeyRS256 = new RsaJsonWebKey { KeyId = "sig-rs256", Algorithm = SigningAlgorithms.RS256 };
        _signingKeyRS256Alt = new RsaJsonWebKey { KeyId = "sig-rs256-alt", Algorithm = SigningAlgorithms.RS256 };
        _signingKeyRS384 = new RsaJsonWebKey { KeyId = "sig-rs384", Algorithm = SigningAlgorithms.RS384 };
        _encryptionKey = new RsaJsonWebKey
        {
            KeyId = "enc-key",
            Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep,
        };
    }

    private static ServiceJwtEncryption SignedOnly => new(
        Encrypt: false, KeyManagementAlgorithm: null, KeyId: null, ContentEnc);

    private static ServiceJwtEncryption Encrypt(string? keyManagementAlgorithm = null, string? keyId = null) => new(
        Encrypt: true, keyManagementAlgorithm, keyId, ContentEnc);

    private void SetupSigningKeys(params JsonWebKey[] keys) =>
        _keysProvider.Setup(p => p.GetSigningKeys(true)).Returns(keys.ToAsyncEnumerable());

    private void SetupEncryptionKeys(params JsonWebKey[] keys) =>
        _keysProvider.Setup(p => p.GetEncryptionKeys(false)).Returns(keys.ToAsyncEnumerable());

    private static JsonWebToken TokenWith(string algorithm = SigningAlgorithms.RS256, string? keyId = null) => new()
    {
        Header = { Algorithm = algorithm, KeyId = keyId },
        Payload = { Subject = "user123" },
    };

    // Signing key selection

    /// <summary>
    /// Verifies that the signing key is chosen by the token header algorithm (RFC 7515 Section 4.1.1), so
    /// each service-token type is signed with the algorithm its issuing service placed in the header.
    /// </summary>
    [Fact]
    public async Task FormatAsync_SelectsSigningKeyByHeaderAlgorithm()
    {
        var token = TokenWith(SigningAlgorithms.RS384);
        SetupSigningKeys(_signingKeyRS256, _signingKeyRS384);

        JsonWebKey? capturedSigningKey = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), null, It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, sig, _, _, _) => capturedSigningKey = sig)
            .ReturnsAsync(EncodedJwt);

        await _formatter.FormatAsync(token, SignedOnly);

        Assert.Same(_signingKeyRS384, capturedSigningKey);
    }

    /// <summary>
    /// Verifies that a pinned signing <c>kid</c> selects that exact key among several sharing the algorithm,
    /// letting a host rotate or pin the signing key deterministically (RFC 7517 Section 4.4, RFC 7515 Section 4.1.4).
    /// </summary>
    [Fact]
    public async Task FormatAsync_WithPinnedSigningKeyId_SelectsThatKey()
    {
        var token = TokenWith(SigningAlgorithms.RS256, keyId: "sig-rs256-alt");
        SetupSigningKeys(_signingKeyRS256, _signingKeyRS256Alt);

        JsonWebKey? capturedSigningKey = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, It.IsAny<JsonWebKey>(), null, It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, sig, _, _, _) => capturedSigningKey = sig)
            .ReturnsAsync(EncodedJwt);

        await _formatter.FormatAsync(token, SignedOnly);

        Assert.Same(_signingKeyRS256Alt, capturedSigningKey);
    }

    // Signed only

    /// <summary>
    /// Verifies that a signed-only policy issues a JWS with no encryption key, and — mirroring the client
    /// formatter's JARM signed-only branch — does not even resolve the server's encryption keys. The strict
    /// mock has no <c>GetEncryptionKeys</c> setup, so any attempt to resolve them would fail the test.
    /// </summary>
    [Fact]
    public async Task FormatAsync_SignedOnly_IssuesJwsWithoutResolvingEncryptionKeys()
    {
        var token = TokenWith();
        SetupSigningKeys(_signingKeyRS256);

        JsonWebKey? capturedEncryptionKey = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null, It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        var result = await _formatter.FormatAsync(token, SignedOnly);

        Assert.Equal(EncodedJwt, result);
        Assert.Null(capturedEncryptionKey);
        _keysProvider.Verify(p => p.GetEncryptionKeys(It.IsAny<bool>()), Times.Never);
    }

    /// <summary>
    /// Verifies that turning encryption off (<c>Encrypt = false</c>) while the encryption algorithm and key id
    /// remain configured still yields a signed-only JWS and does not resolve the encryption keys: the flag alone
    /// disables encryption, so a host can flip it back on later without re-entering the settings.
    /// </summary>
    [Fact]
    public async Task FormatAsync_EncryptDisabledWithSettingsRetained_SignsOnly()
    {
        var token = TokenWith();
        SetupSigningKeys(_signingKeyRS256);

        var disabledButConfigured = new ServiceJwtEncryption(
            Encrypt: false,
            EncryptionAlgorithms.KeyManagement.RsaOaep256,
            KeyId: "enc-key",
            ContentEnc);

        JsonWebKey? capturedEncryptionKey = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null, It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        await _formatter.FormatAsync(token, disabledButConfigured);

        Assert.Null(capturedEncryptionKey);
        _keysProvider.Verify(p => p.GetEncryptionKeys(It.IsAny<bool>()), Times.Never);
    }

    // Encryption

    /// <summary>
    /// Verifies that when the policy leaves the key-management algorithm unset, it is derived from the
    /// selected encryption key's declared <c>alg</c> (RFC 7517 Section 4.4).
    /// </summary>
    [Fact]
    public async Task FormatAsync_Encrypt_DerivesKeyManagementAlgorithmFromKey()
    {
        var token = TokenWith();
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys(_encryptionKey); // declares RSA-OAEP

        string? capturedAlg = null;
        JsonWebKey? capturedEncryptionKey = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, It.IsAny<JsonWebKey?>(), It.IsAny<string>(), ContentEnc))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, alg, _) =>
            {
                capturedEncryptionKey = enc;
                capturedAlg = alg;
            })
            .ReturnsAsync(EncodedJwt);

        await _formatter.FormatAsync(token, Encrypt());

        Assert.Same(_encryptionKey, capturedEncryptionKey);
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep, capturedAlg);
    }

    /// <summary>
    /// Verifies that when neither the policy nor the key declares a key-management algorithm, it falls back
    /// to RSA-OAEP-256, the library's default JWE <c>alg</c>.
    /// </summary>
    [Fact]
    public async Task FormatAsync_Encrypt_FallsBackToRsaOaep256_WhenKeyDeclaresNoAlgorithm()
    {
        var token = TokenWith();
        var agnosticKey = new RsaJsonWebKey { KeyId = "enc-agnostic", Algorithm = null };
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys(agnosticKey);

        string? capturedAlg = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, agnosticKey, It.IsAny<string>(), ContentEnc))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, _, alg, _) => capturedAlg = alg)
            .ReturnsAsync(EncodedJwt);

        await _formatter.FormatAsync(token, Encrypt());

        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep256, capturedAlg);
    }

    /// <summary>
    /// Verifies that an explicit policy key-management algorithm selects an algorithm-agnostic encryption key
    /// (no declared <c>alg</c>, which matches any algorithm per RFC 7517 Section 4.4) and is set as the JWE
    /// <c>alg</c>. Under the symmetric selection model the policy algorithm drives key selection, so an agnostic
    /// key is the one a policy algorithm binds to.
    /// </summary>
    [Fact]
    public async Task FormatAsync_Encrypt_ExplicitPolicyAlgorithmSelectsAgnosticKeyAndSetsHeaderAlgorithm()
    {
        var token = TokenWith();
        var agnosticKey = new RsaJsonWebKey { KeyId = "enc-agnostic", Algorithm = null };
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys(agnosticKey);

        JsonWebKey? capturedEncryptionKey = null;
        string? capturedAlg = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, agnosticKey, It.IsAny<string>(), ContentEnc))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, alg, _) =>
            {
                capturedEncryptionKey = enc;
                capturedAlg = alg;
            })
            .ReturnsAsync(EncodedJwt);

        await _formatter.FormatAsync(token, Encrypt(EncryptionAlgorithms.KeyManagement.RsaOaep256));

        Assert.Same(agnosticKey, capturedEncryptionKey);
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep256, capturedAlg);
    }

    /// <summary>
    /// Verifies that a policy key-management algorithm matching no configured encryption key fails loudly
    /// rather than silently downgrading to a different key or algorithm: a required algorithm is an explicit
    /// intent, mirroring the pinned-key-id case and the signing side.
    /// </summary>
    [Fact]
    public async Task FormatAsync_Encrypt_WithUnmatchedPolicyAlgorithm_Throws()
    {
        var token = TokenWith();
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys(_encryptionKey); // declares RSA-OAEP only

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await _formatter.FormatAsync(token, Encrypt(EncryptionAlgorithms.KeyManagement.RsaOaep256)));
    }

    /// <summary>
    /// Verifies the produce-side symmetry with signing: among several encryption keys declaring different
    /// key-management algorithms, the policy's key-management algorithm SELECTS the matching key, not merely
    /// the first one (RFC 7517 Section 4.4). Mirrors signing-key selection by the token 'alg'.
    /// </summary>
    [Fact]
    public async Task FormatAsync_Encrypt_SelectsEncryptionKeyByPolicyAlgorithm()
    {
        var token = TokenWith();
        var rsaOaepKey = new RsaJsonWebKey
        {
            KeyId = "enc-oaep",
            Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep,
        };
        var rsaOaep256Key = new RsaJsonWebKey
        {
            KeyId = "enc-oaep256",
            Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
        };
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys(rsaOaepKey, rsaOaep256Key); // RSA-OAEP first, RSA-OAEP-256 second

        JsonWebKey? capturedEncryptionKey = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, It.IsAny<JsonWebKey?>(), It.IsAny<string>(), ContentEnc))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        await _formatter.FormatAsync(token, Encrypt(EncryptionAlgorithms.KeyManagement.RsaOaep256));

        Assert.Same(rsaOaep256Key, capturedEncryptionKey);
    }

    /// <summary>
    /// Verifies that a pinned encryption <c>kid</c> selects that exact encryption key among several.
    /// </summary>
    [Fact]
    public async Task FormatAsync_Encrypt_WithPinnedEncryptionKeyId_SelectsThatKey()
    {
        var token = TokenWith();
        var otherEncryptionKey = new RsaJsonWebKey
        {
            KeyId = "enc-key-2",
            Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
        };
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys(_encryptionKey, otherEncryptionKey);

        JsonWebKey? capturedEncryptionKey = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, It.IsAny<JsonWebKey?>(), It.IsAny<string>(), ContentEnc))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        await _formatter.FormatAsync(token, Encrypt(keyId: "enc-key-2"));

        Assert.Same(otherEncryptionKey, capturedEncryptionKey);
    }

    /// <summary>
    /// Verifies that the policy's content-encryption algorithm flows through to the JWE <c>enc</c>.
    /// </summary>
    [Fact]
    public async Task FormatAsync_Encrypt_PassesPolicyContentEncryptionAlgorithm()
    {
        var token = TokenWith();
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys(_encryptionKey);

        var policy = new ServiceJwtEncryption(
            Encrypt: true,
            KeyManagementAlgorithm: null,
            KeyId: null,
            EncryptionAlgorithms.ContentEncryption.Aes128Gcm);

        string? capturedEnc = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, _encryptionKey, It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, _, _, enc) => capturedEnc = enc)
            .ReturnsAsync(EncodedJwt);

        await _formatter.FormatAsync(token, policy);

        Assert.Equal(EncryptionAlgorithms.ContentEncryption.Aes128Gcm, capturedEnc);
    }

    /// <summary>
    /// Verifies that a policy asking for encryption while no encryption key is configured falls back to a
    /// signed-only JWS rather than failing, matching the behavior of prior versions a host keeps by leaving
    /// encryption on without configuring a key.
    /// </summary>
    [Fact]
    public async Task FormatAsync_Encrypt_WithNoEncryptionKey_SignsOnly()
    {
        var token = TokenWith();
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys();

        JsonWebKey? capturedEncryptionKey = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, null, It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

        var result = await _formatter.FormatAsync(token, Encrypt());

        Assert.Equal(EncodedJwt, result);
        Assert.Null(capturedEncryptionKey);
    }

    /// <summary>
    /// Verifies that a pinned encryption <c>kid</c> that matches no configured key fails loudly rather than
    /// silently downgrading: pinning a key is an explicit intent, so a missing pinned key is a misconfiguration.
    /// </summary>
    [Fact]
    public async Task FormatAsync_Encrypt_WithUnknownPinnedEncryptionKeyId_Throws()
    {
        var token = TokenWith();
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys(_encryptionKey);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await _formatter.FormatAsync(token, Encrypt(keyId: "missing-kid")));
    }

    // Retained implicit legacy path

    /// <summary>
    /// Verifies that the retained, obsolete parameterless overload still encrypts implicitly whenever any
    /// service encryption key exists, preserving backward compatibility for callers not yet migrated.
    /// </summary>
    [Fact]
    public async Task Legacy_FormatAsync_WithEncryptionKey_EncryptsImplicitly()
    {
        var token = TokenWith();
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys(_encryptionKey);

        JsonWebKey? capturedEncryptionKey = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

#pragma warning disable CS0618 // exercising the retained obsolete overload on purpose
        await _formatter.FormatAsync(token);
#pragma warning restore CS0618

        Assert.Same(_encryptionKey, capturedEncryptionKey);
    }

    /// <summary>
    /// Verifies that the obsolete parameterless overload produces a signed-only token when no service
    /// encryption key is configured.
    /// </summary>
    [Fact]
    public async Task Legacy_FormatAsync_WithNoEncryptionKey_SignsOnly()
    {
        var token = TokenWith();
        SetupSigningKeys(_signingKeyRS256);
        SetupEncryptionKeys();

        JsonWebKey? capturedEncryptionKey = null;
        _jwtCreator
            .Setup(c => c.IssueAsync(token, _signingKeyRS256, It.IsAny<JsonWebKey?>(), It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(EncodedJwt);

#pragma warning disable CS0618 // exercising the retained obsolete overload on purpose
        await _formatter.FormatAsync(token);
#pragma warning restore CS0618

        Assert.Null(capturedEncryptionKey);
    }
}
