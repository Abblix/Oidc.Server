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
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.ResponseObject;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;
using JsonWebKey = Abblix.Jwt.JsonWebKey;

namespace Abblix.Oidc.Server.UnitTests.Features.Jarm;

/// <summary>
/// Unit tests for <see cref="ResponseJwtBuilder"/> verifying JARM (JWT Secured Authorization Response
/// Mode) JWT construction: the mandated <c>iss</c>/<c>aud</c>/<c>exp</c> claims (JARM §2.1), signing with the
/// client's registered algorithm (default RS256, JARM §3), optional signed-then-encrypted output, and the
/// resolution of the JARM response mode to its plaintext delivery counterpart (JARM §2.3).
/// </summary>
public class ResponseJwtBuilderTests
{
    private const string ClientId = TestConstants.DefaultClientId;
    private static readonly string Issuer = TestConstants.DefaultIssuer.OriginalString;
    private const string EncodedJwt = "header.payload.signature";

    private readonly Mock<IClientInfoProvider> _clientInfoProvider = new(MockBehavior.Strict);
    private readonly Mock<IJsonWebTokenCreator> _jwtCreator = new(MockBehavior.Strict);
    private readonly Mock<IClientKeysProvider> _clientKeys = new(MockBehavior.Strict);
    private readonly Mock<IAuthServiceKeysProvider> _serviceKeys = new(MockBehavior.Strict);
    private readonly Mock<IIssuerProvider> _issuerProvider = new(MockBehavior.Strict);
    private readonly Mock<TimeProvider> _timeProvider = new(MockBehavior.Strict);

    private readonly ResponseJwtBuilder _builder;
    private readonly ClientInfo _client = new(ClientId);

    private readonly JsonWebKey _signingKeyRs256 = new RsaJsonWebKey { KeyId = "sig-rs256", Algorithm = SigningAlgorithms.RS256 };
    private readonly JsonWebKey _clientEncryptionKey = new RsaJsonWebKey { KeyId = "client-enc", Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256 };
    private readonly DateTimeOffset _now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    public ResponseJwtBuilderTests()
    {
        _clientInfoProvider.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync(_client);
        _issuerProvider.Setup(p => p.GetIssuer()).Returns(Issuer);
        _timeProvider.Setup(t => t.GetUtcNow()).Returns(_now);
        _serviceKeys.Setup(p => p.GetSigningKeys(true)).Returns(new[] { _signingKeyRs256 }.ToAsyncEnumerable());

        _builder = new ResponseJwtBuilder(
            _clientInfoProvider.Object,
            _jwtCreator.Object,
            _clientKeys.Object,
            _serviceKeys.Object,
            _issuerProvider.Object,
            _timeProvider.Object);
    }

    /// <summary>
    /// Mutable holder for the arguments the encoder passes to <see cref="IJsonWebTokenCreator.IssueAsync"/>.
    /// The callback writes into it during the call, so the test reads it <em>after</em> awaiting BuildAsync.
    /// </summary>
    private sealed class IssuedToken
    {
        public JsonWebToken Token { get; set; } = null!;
        public JsonWebKey? EncryptionKey { get; set; }
        public string KeyAlgorithm { get; set; } = null!;
        public string ContentAlgorithm { get; set; } = null!;
    }

    private IssuedToken CaptureIssue()
    {
        var captured = new IssuedToken();

        _jwtCreator
            .Setup(c => c.IssueAsync(
                It.IsAny<JsonWebToken>(), It.IsAny<JsonWebKey?>(), It.IsAny<JsonWebKey?>(),
                It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey?, JsonWebKey?, string, string>((t, _, enc, ka, ca) =>
            {
                captured.Token = t;
                captured.EncryptionKey = enc;
                captured.KeyAlgorithm = ka;
                captured.ContentAlgorithm = ca;
            })
            .ReturnsAsync(EncodedJwt);

        return captured;
    }

    [Fact]
    public async Task BuildAsync_SignedOnly_PopulatesJarmClaimsAndSignsWithDefaultRs256()
    {
        var capture = CaptureIssue();

        var result = await _builder.BuildAsync(
            ClientId, [("code", "auth-code"), ("state", "client-state")]);

        Assert.Equal(EncodedJwt, result);

        // JARM §2.1 mandated claims.
        Assert.Equal(Issuer, capture.Token.Payload.Issuer);
        Assert.Equal([ClientId], capture.Token.Payload.Audiences);
        Assert.Equal(_now + TimeSpan.FromMinutes(10), capture.Token.Payload.ExpiresAt);

        // Response parameters carried as claims.
        Assert.Equal("auth-code", capture.Token.Payload["code"]!.GetValue<string>());
        Assert.Equal("client-state", capture.Token.Payload["state"]!.GetValue<string>());

        // Signed with the client's algorithm (default RS256, JARM §3).
        Assert.Equal(SigningAlgorithms.RS256, capture.Token.Header.Algorithm);
    }

    [Fact]
    public async Task BuildAsync_WithoutEncryptionAlgorithm_DoesNotEncrypt()
    {
        var capture = CaptureIssue();

        await _builder.BuildAsync(ClientId, [("code", "auth-code")]);

        // Signed-only: no encryption key is resolved or passed.
        Assert.Null(capture.EncryptionKey);
        _clientKeys.Verify(p => p.GetEncryptionKeys(It.IsAny<ClientInfo>()), Times.Never);
    }

    [Fact]
    public async Task BuildAsync_WithEncryptionAlgorithm_SignsThenEncryptsWithClientKey()
    {
        var capture = CaptureIssue();
        _clientKeys
            .Setup(p => p.GetEncryptionKeys(It.IsAny<ClientInfo>()))
            .Returns(new[] { _clientEncryptionKey }.ToAsyncEnumerable());

        _client.AuthorizationEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256;
        _client.AuthorizationEncryptedResponseEncryption = EncryptionAlgorithms.ContentEncryption.Aes256Gcm;

        await _builder.BuildAsync(ClientId, [("code", "auth-code")]);

        Assert.Same(_clientEncryptionKey, capture.EncryptionKey);
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep256, capture.KeyAlgorithm);
        Assert.Equal(EncryptionAlgorithms.ContentEncryption.Aes256Gcm, capture.ContentAlgorithm);
    }

    [Fact]
    public async Task BuildAsync_WithEncryptionAlgorithmButNoEnc_DefaultsToA128CbcHs256()
    {
        var capture = CaptureIssue();
        _clientKeys
            .Setup(p => p.GetEncryptionKeys(It.IsAny<ClientInfo>()))
            .Returns(new[] { _clientEncryptionKey }.ToAsyncEnumerable());

        _client.AuthorizationEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256;
        // AuthorizationEncryptedResponseEncryption omitted → JARM §3 default

        await _builder.BuildAsync(ClientId, [("code", "auth-code")]);

        Assert.Equal(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256, capture.ContentAlgorithm);
    }

    [Fact]
    public async Task BuildAsync_HonoursClientConfiguredSigningAlgorithm()
    {
        var signingKeyRS384 = new RsaJsonWebKey { KeyId = "sig-rs384", Algorithm = SigningAlgorithms.RS384 };
        _serviceKeys
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new[] { _signingKeyRs256, signingKeyRS384 }.ToAsyncEnumerable());

        var capture = CaptureIssue();
        _client.AuthorizationSignedResponseAlgorithm = SigningAlgorithms.RS384;

        await _builder.BuildAsync(ClientId, [("code", "auth-code")]);

        Assert.Equal(SigningAlgorithms.RS384, capture.Token.Header.Algorithm);
    }

    /// <summary>
    /// The JARM response mode is mapped to its plaintext delivery mode by
    /// <see cref="ResponseModeExtensions.ToDeliveryMode"/>: the fixed variants map to their base mode, and the
    /// <c>jwt</c> shortcut resolves to fragment for token-bearing flows and query otherwise (JARM §2.3.4).
    /// </summary>
    [Theory]
    [InlineData(ResponseModes.QueryJwt, false, ResponseModes.Query)]
    [InlineData(ResponseModes.FragmentJwt, false, ResponseModes.Fragment)]
    [InlineData(ResponseModes.FormPostJwt, false, ResponseModes.FormPost)]
    [InlineData(ResponseModes.Jwt, false, ResponseModes.Query)]
    [InlineData(ResponseModes.Jwt, true, ResponseModes.Fragment)]
    public void ToDeliveryMode_MapsToPlaintextMode(string responseMode, bool carriesTokens, string expectedDeliveryMode)
    {
        Assert.Equal(expectedDeliveryMode, responseMode.ToDeliveryMode(carriesTokens));
    }
}
