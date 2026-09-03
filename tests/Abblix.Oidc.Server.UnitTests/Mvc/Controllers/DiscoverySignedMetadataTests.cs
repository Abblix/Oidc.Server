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
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Mvc.Features.EndpointResolving;
using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;
using JsonWebKey = Abblix.Jwt.JsonWebKey;

namespace Abblix.Oidc.Server.UnitTests.Mvc.Controllers;

/// <summary>
/// Unit tests for <see cref="ConfigurationResponseFormatter"/> verifying RFC 8414 section 2.1
/// <c>signed_metadata</c> emission: opt-in gating, pure-JWS production (never JWE), the
/// mandatory <c>iss</c> claim, and the requirement that the signed payload restate the
/// metadata without containing <c>signed_metadata</c> itself.
/// </summary>
public class DiscoverySignedMetadataTests
{
    private static readonly string Issuer = TestConstants.DefaultIssuer.OriginalString;
    private const string SignedJws = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.sig";

    private readonly Mock<IOptionsSnapshot<OidcOptions>> _optionsMock = new();
    private readonly Mock<IEndpointResolver> _endpointResolverMock = new();
    private readonly Mock<IJsonWebTokenCreator> _jwtCreatorMock = new(MockBehavior.Strict);
    private readonly Mock<IAuthServiceKeysProvider> _keysProviderMock = new(MockBehavior.Strict);
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 5, 19, 10, 0, 0, TimeSpan.Zero));
    private readonly OidcOptions _oidcOptions;
    private readonly ConfigurationResponseFormatter _formatter;
    private readonly JsonWebKey _signingKey = new RsaJsonWebKey { KeyId = "sig", Algorithm = SigningAlgorithms.RS256 };

    public DiscoverySignedMetadataTests()
    {
        _oidcOptions = new OidcOptions
        {
            Discovery = new DiscoveryOptions { AllowEndpointPathsDiscovery = true },
            EnabledEndpoints = OidcEndpoints.Token,
        };
        _optionsMock.Setup(x => x.Value).Returns(_oidcOptions);

        _endpointResolverMock
            .Setup(x => x.Resolve("Token", "Token"))
            .Returns(new Uri("https://example.com/token"));

        _formatter = new ConfigurationResponseFormatter(
            _optionsMock.Object,
            _endpointResolverMock.Object,
            new SignedMetadataProvider(_jwtCreatorMock.Object, _keysProviderMock.Object, _clock));
    }

    /// <summary>
    /// The smallest handler output the formatter will accept: the four members OpenID Connect Discovery 1.0
    /// section 3 marks REQUIRED, and nothing else. These tests are about the signed_metadata field, so every
    /// other field is left absent on purpose.
    /// </summary>
    private static EndpointResponse MinimalResponse() => new()
    {
        Issuer = Issuer,
        ResponseTypesSupported = ["code"],
        IdTokenSigningAlgValuesSupported = ["RS256"],
        SubjectTypesSupported = ["public"],
    };

    /// <summary>
    /// When the opt-in flag is off, the discovery document carries no <c>signed_metadata</c>
    /// and the signing pipeline is never touched (safe-by-default).
    /// </summary>
    [Fact]
    public async Task SignedMetadataDisabled_OmitsFieldAndDoesNotSign()
    {
        _oidcOptions.Discovery.SignedMetadata = false;

        var result = await _formatter.FormatResponseAsync(MinimalResponse());

        Assert.NotNull(result.Value);
        Assert.Null(result.Value.SignedMetadata);
        _jwtCreatorMock.Verify(
            c => c.IssueAsync(It.IsAny<JsonWebToken>(), It.IsAny<JsonWebKey?>(), It.IsAny<JsonWebKey?>(),
                It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// When enabled, the field carries the JWS produced by the creator, and the token is
    /// issued as a pure JWS - no encryption key is passed even though a deployment may have
    /// encryption keys, so the result stays verifiable against <c>jwks_uri</c>.
    /// </summary>
    [Fact]
    public async Task SignedMetadataEnabled_EmitsPureJws()
    {
        _oidcOptions.Discovery.SignedMetadata = true;
        _keysProviderMock.Setup(p => p.GetSigningKeys(true)).Returns(new[] { _signingKey }.ToAsyncEnumerable());

        JsonWebKey? capturedEncryptionKey = null;
        _jwtCreatorMock
            .Setup(c => c.IssueAsync(It.IsAny<JsonWebToken>(), It.IsAny<JsonWebKey?>(), It.IsAny<JsonWebKey?>(),
                It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey?, JsonWebKey?, string, string>(
                (_, _, enc, _, _) => capturedEncryptionKey = enc)
            .ReturnsAsync(SignedJws);

        var result = await _formatter.FormatResponseAsync(MinimalResponse());

        Assert.Equal(SignedJws, result.Value!.SignedMetadata);
        Assert.Null(capturedEncryptionKey);
    }

    /// <summary>
    /// The signed payload must restate the metadata (resolved endpoints included), carry the
    /// mandatory <c>iss</c> claim (RFC 8414 section 2.1) and an <c>iat</c>, and must NOT contain
    /// <c>signed_metadata</c> itself.
    /// </summary>
    [Fact]
    public async Task SignedMetadataEnabled_PayloadRestatesMetadataWithIssAndNoSelfReference()
    {
        _oidcOptions.Discovery.SignedMetadata = true;
        _keysProviderMock.Setup(p => p.GetSigningKeys(true)).Returns(new[] { _signingKey }.ToAsyncEnumerable());

        JsonWebToken? capturedToken = null;
        _jwtCreatorMock
            .Setup(c => c.IssueAsync(It.IsAny<JsonWebToken>(), It.IsAny<JsonWebKey?>(), It.IsAny<JsonWebKey?>(),
                It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey?, JsonWebKey?, string, string>((t, _, _, _, _) => capturedToken = t)
            .ReturnsAsync(SignedJws);

        await _formatter.FormatResponseAsync(MinimalResponse());

        Assert.NotNull(capturedToken);
        var payload = capturedToken!.Payload.Json;

        Assert.Equal(Issuer, (string?)payload["iss"]);
        Assert.Equal(Issuer, (string?)payload["issuer"]);
        Assert.Equal("https://example.com/token", (string?)payload["token_endpoint"]);
        Assert.True(payload.ContainsKey("iat"));
        Assert.False(payload.ContainsKey("signed_metadata"));
        // Null-omission parity with the wire JSON: an unset optional field must be absent,
        // not serialized as null, otherwise "signed values take precedence" asserts the null.
        Assert.False(payload.ContainsKey("acr_values_supported"));
    }

    /// <summary>
    /// Enabling the feature without configured signing keys is a misconfiguration that must
    /// fail loudly rather than emit an unsigned or absent field.
    /// </summary>
    [Fact]
    public async Task SignedMetadataEnabled_NoSigningKeys_Throws()
    {
        _oidcOptions.Discovery.SignedMetadata = true;
        _keysProviderMock.Setup(p => p.GetSigningKeys(true)).Returns(AsyncEnumerable.Empty<JsonWebKey>());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _formatter.FormatResponseAsync(MinimalResponse()));
    }

    /// <summary>
    /// A signing key that declares no <c>alg</c> is signed with the standard algorithm for its kind, rather
    /// than with none.
    /// </summary>
    /// <remarks>
    /// RFC 7517 section 4.4 makes <c>alg</c> OPTIONAL, and a key imported from an RSA certificate carries
    /// none - the ordinary case for a deployment that signs with a certificate. Taking the algorithm off the
    /// key left the header empty, the signer then resolved nothing for the key's type, and the discovery
    /// endpoint answered with an error instead of a document. Every other case in this class hands over a key
    /// that names RS256, which is why the one shape that actually ships was the one never exercised.
    /// </remarks>
    [Fact]
    public async Task SignedMetadataEnabled_KeyWithoutAlgorithm_SignsWithTheStandardOneForItsKind()
    {
        _oidcOptions.Discovery.SignedMetadata = true;
        _keysProviderMock
            .Setup(p => p.GetSigningKeys(true))
            .Returns(new JsonWebKey[] { new RsaJsonWebKey { KeyId = "sig" } }.ToAsyncEnumerable());

        JsonWebToken? capturedToken = null;
        _jwtCreatorMock
            .Setup(c => c.IssueAsync(It.IsAny<JsonWebToken>(), It.IsAny<JsonWebKey?>(), It.IsAny<JsonWebKey?>(),
                It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey?, JsonWebKey?, string, string>((t, _, _, _, _) => capturedToken = t)
            .ReturnsAsync(SignedJws);

        await _formatter.FormatResponseAsync(MinimalResponse());

        Assert.Equal(SigningAlgorithms.RS256, capturedToken!.Header.Algorithm);
    }
}
