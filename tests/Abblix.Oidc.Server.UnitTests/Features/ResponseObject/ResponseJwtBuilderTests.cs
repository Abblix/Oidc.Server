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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ResponseObject;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using JsonWebKey = Abblix.Jwt.JsonWebKey;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Features.ResponseObject;

/// <summary>
/// Unit tests for <see cref="ResponseJwtBuilder"/> verifying JARM (JWT Secured Authorization Response
/// Mode) JWT construction: the mandated <c>iss</c>/<c>aud</c>/<c>exp</c> claims (JARM section 2.1), signing with the
/// client's registered algorithm (default RS256, JARM section 3), optional signed-then-encrypted output, and the
/// resolution of the JARM response mode to its plaintext delivery counterpart (JARM section 2.3).
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
    private readonly FakeTimeProvider _timeProvider;

    private readonly ResponseJwtBuilder _builder;
    private readonly ClientInfo _client = new(ClientId);

    private readonly JsonWebKey _signingKeyRs256 = new RsaJsonWebKey { KeyId = "sig-rs256", Algorithm = SigningAlgorithms.RS256 };
    private readonly JsonWebKey _clientEncryptionKey = new RsaJsonWebKey { KeyId = "client-enc", Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256 };
    private readonly DateTimeOffset _now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);

    public ResponseJwtBuilderTests()
    {
        _clientInfoProvider.Setup(p => p.TryFindClientAsync(TestTenant.Matched, ClientId)).ReturnsAsync(_client);
        _timeProvider = new FakeTimeProvider(_now);
        _serviceKeys.Setup(p => p.GetSigningKeys(TestTenant.Matched, true)).Returns(new[] { _signingKeyRs256 }.ToAsyncEnumerable());
        _jwtCreator
            .Setup(c => c.EncryptedResponseAlgorithmsSupported)
            .Returns([EncryptionAlgorithms.KeyManagement.RsaOaep, EncryptionAlgorithms.KeyManagement.RsaOaep256]);

        // The builder now delegates signing/encryption to a real ClientJwtFormatter built over the same mocks,
        // so the assertions on IJsonWebTokenCreator.IssueAsync continue to exercise the end-to-end JARM behavior.
        var clientJwtFormatter = new ClientJwtFormatter(
            new ProfiledJwtIssuer(_jwtCreator.Object),
            new ClientEncryptionKeyResolver(
                new ProfiledJwtIssuer(_jwtCreator.Object), _clientKeys.Object, TimeProvider.System),
            _serviceKeys.Object);

        _builder = new ResponseJwtBuilder(
            _clientInfoProvider.Object,
            clientJwtFormatter,
            _timeProvider,
            Options.Create(new OidcOptions()));
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
            SingleIssuer.Tenant,
            ClientId, [(ResponseParameters.Code, "auth-code"), (ResponseParameters.State, "client-state")]);

        Assert.Equal(EncodedJwt, result);

        // JARM section 2.1 mandated claims.
        Assert.Equal(Issuer, capture.Token.Payload.Issuer);
        Assert.Equal([ClientId], capture.Token.Payload.Audiences);
        Assert.Equal(_now + TimeSpan.FromMinutes(10), capture.Token.Payload.ExpiresAt);

        // Response parameters carried as claims.
        Assert.Equal("auth-code", capture.Token.Payload[ResponseParameters.Code]!.GetValue<string>());
        Assert.Equal("client-state", capture.Token.Payload[ResponseParameters.State]!.GetValue<string>());

        // Signed with the client's algorithm (default RS256, JARM section 3).
        Assert.Equal(SigningAlgorithms.RS256, capture.Token.Header.Algorithm);
    }

    [Fact]
    public async Task BuildAsync_WithoutEncryptionAlgorithm_DoesNotEncrypt()
    {
        var capture = CaptureIssue();

        await _builder.BuildAsync(SingleIssuer.Tenant, ClientId, [(ResponseParameters.Code, "auth-code")]);

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

        await _builder.BuildAsync(SingleIssuer.Tenant, ClientId, [(ResponseParameters.Code, "auth-code")]);

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
        // AuthorizationEncryptedResponseEncryption omitted → JARM section 3 default

        await _builder.BuildAsync(SingleIssuer.Tenant, ClientId, [(ResponseParameters.Code, "auth-code")]);

        Assert.Equal(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256, capture.ContentAlgorithm);
    }

    /// <summary>
    /// A client that asked for its responses encrypted and publishes no key one can be encrypted to (here an EC key
    /// declaring no algorithm, which the RSA-OAEP-256 it registered does not fit) gets the formatter's refusal back
    /// rather than an exception, for the caller to answer.
    /// </summary>
    [Fact]
    public async Task BuildAsync_ForAClientWhoseKeysNothingCanBeEncryptedTo_ReturnsTheRefusal()
    {
        _clientKeys
            .Setup(p => p.GetEncryptionKeys(It.IsAny<ClientInfo>()))
            .Returns(new JsonWebKey[]
            {
                new EllipticCurveJsonWebKey { KeyId = "ec", Curve = EllipticCurveTypes.P256 },
            }.ToAsyncEnumerable());
        _client.AuthorizationEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256;

        var result = await _builder.BuildAsync(SingleIssuer.Tenant, ClientId, [(ResponseParameters.Code, "auth-code")]);

        Assert.True(result.TryGetFailure(out var refusal));
        Assert.Equal(ErrorCodes.InvalidClient, refusal.Error);
    }

    /// <summary>
    /// The JARM fallback is a setting, so a deployment whose clients all understand a stronger algorithm can
    /// raise it.
    /// </summary>
    /// <remarks>
    /// <see cref="BuildAsync_WithEncryptionAlgorithmButNoEnc_DefaultsToA128CbcHs256"/> pins the value the
    /// specification names, which a client registering only
    /// <c>authorization_encrypted_response_alg</c> is entitled to. This one pins that the value is reachable
    /// at all: without it the setting could be read from nowhere and every test would still pass, because the
    /// default it happens to carry is the same constant the code used to hold.
    /// </remarks>
    [Fact]
    public async Task BuildAsync_WithEncryptionAlgorithmButNoEnc_HonoursTheConfiguredFallback()
    {
        var capture = CaptureIssue();
        _clientKeys
            .Setup(p => p.GetEncryptionKeys(It.IsAny<ClientInfo>()))
            .Returns(new[] { _clientEncryptionKey }.ToAsyncEnumerable());

        _client.AuthorizationEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256;

        var options = Options.Create(new OidcOptions
        {
            DefaultAuthorizationResponseEncryptionAlgorithm = EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
        });

        var builder = new ResponseJwtBuilder(
            _clientInfoProvider.Object,
            new ClientJwtFormatter(
                new ProfiledJwtIssuer(_jwtCreator.Object),
                new ClientEncryptionKeyResolver(
                    new ProfiledJwtIssuer(_jwtCreator.Object), _clientKeys.Object, TimeProvider.System),
                _serviceKeys.Object),
            _timeProvider,
            options);

        await builder.BuildAsync(SingleIssuer.Tenant, ClientId, [(ResponseParameters.Code, "auth-code")]);

        Assert.Equal(EncryptionAlgorithms.ContentEncryption.Aes256Gcm, capture.ContentAlgorithm);
    }

    /// <summary>
    /// JARM section 3: authorization_encrypted_response_alg is "The JWE [RFC7516] alg algorithm REQUIRED for
    /// encrypting authorization responses". The response is encrypted under the registered algorithm only: a key
    /// declaring another one is passed over for one declaring it or none, and a set holding no such key refuses.
    /// </summary>
    [Fact]
    public async Task BuildAsync_EncryptsUnderTheRegisteredAlgorithm_PassingOverAKeyDeclaringAnother()
    {
        var capture = CaptureIssue();
        var other = new RsaJsonWebKey { KeyId = "other", Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256 };
        var plain = new RsaJsonWebKey { KeyId = "plain" };
        _clientKeys
            .Setup(p => p.GetEncryptionKeys(It.IsAny<ClientInfo>()))
            .Returns(new JsonWebKey[] { other, plain }.ToAsyncEnumerable());
        _client.AuthorizationEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep;

        var result = await _builder.BuildAsync(SingleIssuer.Tenant, ClientId, [(ResponseParameters.Code, "auth-code")]);

        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep, capture.KeyAlgorithm);
        Assert.Same(plain, capture.EncryptionKey);
    }

    /// <summary>
    /// A registered algorithm no published key can be used with - a key declaring another one, or no key at all, as
    /// when the jwks_uri could not be read - is the refusal, never a response sent signed only.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task BuildAsync_ARegisteredAlgorithmNoKeyCanBeUsedWith_IsRefused(bool keyDeclaringAnother)
    {
        _clientKeys
            .Setup(p => p.GetEncryptionKeys(It.IsAny<ClientInfo>()))
            .Returns((keyDeclaringAnother
                ? new JsonWebKey[]
                {
                    new RsaJsonWebKey { KeyId = "other", Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256 },
                }
                : []).ToAsyncEnumerable());
        _client.AuthorizationEncryptedResponseAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep;

        var result = await _builder.BuildAsync(SingleIssuer.Tenant, ClientId, [(ResponseParameters.Code, "auth-code")]);

        Assert.True(result.TryGetFailure(out var refusal));
        Assert.Equal(ErrorCodes.InvalidClient, refusal.Error);
    }

    /// <summary>
    /// JARM section 3: "The default, if omitted, is that no encryption is performed." A client that registered no
    /// algorithm gets its response signed only, whatever keys it publishes.
    /// </summary>
    [Fact]
    public async Task BuildAsync_NoRegisteredAlgorithm_SignsOnlyWhateverTheKeys()
    {
        var capture = CaptureIssue();
        _clientKeys
            .Setup(p => p.GetEncryptionKeys(It.IsAny<ClientInfo>()))
            .Returns(new JsonWebKey[] { new RsaJsonWebKey { KeyId = "plain" } }.ToAsyncEnumerable());

        var result = await _builder.BuildAsync(SingleIssuer.Tenant, ClientId, [(ResponseParameters.Code, "auth-code")]);

        Assert.True(result.TryGetSuccess(out _));
        Assert.Null(capture.EncryptionKey);
    }

    [Fact]
    public async Task BuildAsync_HonoursClientConfiguredSigningAlgorithm()
    {
        var signingKeyRs384 = new RsaJsonWebKey { KeyId = "sig-rs384", Algorithm = SigningAlgorithms.RS384 };

        _serviceKeys
            .Setup(p => p.GetSigningKeys(TestTenant.Matched, true))
            .Returns(new[] { _signingKeyRs256, signingKeyRs384 }.ToAsyncEnumerable());

        var capture = CaptureIssue();
        _client.AuthorizationSignedResponseAlgorithm = SigningAlgorithms.RS384;

        await _builder.BuildAsync(SingleIssuer.Tenant, ClientId, [(ResponseParameters.Code, "auth-code")]);

        Assert.Equal(SigningAlgorithms.RS384, capture.Token.Header.Algorithm);
    }

    /// <summary>
    /// The JARM response mode is mapped to its plaintext delivery mode by
    /// <see cref="ResponseModeExtensions.ToDeliveryMode"/>: the fixed variants map to their base mode, and the
    /// <c>jwt</c> shortcut resolves to fragment for token-bearing flows and query otherwise (JARM section 2.3.4).
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
