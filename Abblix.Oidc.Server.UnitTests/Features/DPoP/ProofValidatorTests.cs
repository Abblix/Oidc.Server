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
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.DPoP;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DPoP;

/// <summary>
/// Tests for <see cref="ProofValidator"/> covering RFC 9449 §4.2 / §4.3 structural,
/// algorithmic and claim-binding validation. Replay-cache and DPoP-Nonce checks are out
/// of scope here and land in the next slice.
/// </summary>
public class ProofValidatorTests
{
    private const string DefaultHttpMethod = "POST";
    private static readonly Uri DefaultRequestUri = new("https://auth.example.com/token");

    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 5, 7, 12, 0, 0, TimeSpan.Zero));
    private readonly IProofValidator _sut;

    public ProofValidatorTests()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton<TimeProvider>(_time);
        services.AddSingleton<IProofValidator, ProofValidator>();
        var sp = services.BuildServiceProvider();
        _sut = sp.GetRequiredService<IProofValidator>();
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ValidateAsync_ValidProofWithoutAccessToken_ReturnsSuccess()
    {
        var builder = new DPoPProofBuilder(_time.GetUtcNow());
        var proof = builder.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetSuccess(out var ok));
        Assert.Equal(builder.PublicJwk.ComputeJwkThumbprintBase64Url(), ok.Jkt);
        Assert.Equal(builder.Jti, ok.Jti);
        Assert.Equal(_time.GetUtcNow(), ok.IssuedAt);
    }

    [Fact]
    public async Task ValidateAsync_ValidProofWithMatchingAth_ReturnsSuccess()
    {
        const string accessToken = "test-access-token-value";
        var expectedAth = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));

        var builder = new DPoPProofBuilder(_time.GetUtcNow()) { Ath = expectedAth };
        var proof = builder.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, accessToken, Ct);

        Assert.True(result.TryGetSuccess(out _));
    }

    [Fact]
    public async Task ValidateAsync_HtuWithDefaultPortInRequest_PassesAfterCanonicalisation()
    {
        // Proof carries htu without port; request URI includes the default :443.
        // Both must canonicalise to the same form.
        var builder = new DPoPProofBuilder(_time.GetUtcNow());
        var proof = builder.Build();
        var requestUriWithExplicitDefaultPort = new Uri("https://auth.example.com:443/token");

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, requestUriWithExplicitDefaultPort, cancellationToken: Ct);

        Assert.True(result.TryGetSuccess(out _));
    }

    [Theory]
    [InlineData("openid+jwt")]
    [InlineData("JWT")]
    [InlineData("application/dpop+jwt")] // Even spec-prefix-stripping convention does not save it; this validator is strict.
    public async Task ValidateAsync_TypNotDpopJwt_ReturnsInvalidTyp(string typ)
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Typ = typ }.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("invalid_typ", error.Reason);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    public async Task ValidateAsync_AlgNotInWhitelist_ReturnsInvalidAlg(string alg)
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Alg = alg }.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("invalid_alg", error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_HeaderMissingJwk_ReturnsMissingJwk()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { IncludeJwk = false }.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("missing_jwk", error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_JwkContainsPrivateKeyMaterial_ReturnsInvalidJwk()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { IncludePrivateInJwk = true }.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("invalid_jwk", error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_SignatureCorrupted_ReturnsSignatureInvalid()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { CorruptSignature = true }.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("signature_invalid", error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_HtmDoesNotMatchRequest_ReturnsHtmMismatch()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Htm = "GET" }.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("htm_mismatch", error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_HtuDoesNotMatchRequest_ReturnsHtuMismatch()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow())
        {
            Htu = "https://auth.example.com/different-endpoint",
        }.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("htu_mismatch", error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_IatBeforeToleranceWindow_ReturnsIatOutOfWindow()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow().AddMinutes(-5)).Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("iat_out_of_window", error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_IatAfterToleranceWindow_ReturnsIatOutOfWindow()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow().AddMinutes(5)).Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("iat_out_of_window", error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_AccessTokenPresentButAthAbsent_ReturnsAthMissing()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()).Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, "some-access-token", Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("ath_missing", error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_AthDoesNotMatchAccessToken_ReturnsAthMismatch()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Ath = "wrong-hash" }.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, "some-access-token", Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("ath_mismatch", error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_JtiMissing_ReturnsJtiMissing()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Jti = null }.Build();

        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("jti_missing", error.Reason);
    }

    [Theory]
    [InlineData("not.a.jwt.with.too.many.parts")]
    [InlineData("only.two")]
    [InlineData("")]
    public async Task ValidateAsync_MalformedJwt_ReturnsMalformedJwt(string proof)
    {
        var result = await _sut.ValidateAsync(proof, DefaultHttpMethod, DefaultRequestUri, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal("malformed_jwt", error.Reason);
    }
}

/// <summary>
/// Builds a signed DPoP proof JWS for tests, with sensible defaults that produce a valid
/// proof for <c>POST https://auth.example.com/token</c>. Each instance generates a fresh
/// EC P-256 keypair; the public-only JWK is exposed via <see cref="PublicJwk"/> so tests
/// can compute the expected <c>jkt</c>.
/// </summary>
internal sealed class DPoPProofBuilder
{
    private readonly ECDsa _ecdsa;
    private readonly DateTimeOffset _now;

    public EllipticCurveJsonWebKey PublicJwk { get; }

    public string Typ { get; init; } = "dpop+jwt";
    public string Alg { get; init; } = "ES256";
    public bool IncludeJwk { get; init; } = true;
    public bool IncludePrivateInJwk { get; init; } = false;
    public string? Htm { get; init; } = "POST";
    public string? Htu { get; init; } = "https://auth.example.com/token";
    public string? Jti { get; init; } = "test-jti-" + Guid.NewGuid();
    public DateTimeOffset? Iat { get; init; }
    public string? Ath { get; init; }
    public bool CorruptSignature { get; init; }

    public DPoPProofBuilder(DateTimeOffset now)
    {
        _now = now;
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicParams = _ecdsa.ExportParameters(includePrivateParameters: false);
        PublicJwk = new EllipticCurveJsonWebKey
        {
            Algorithm = SigningAlgorithms.ES256,
            Usage = PublicKeyUsages.Signature,
        }.Apply(publicParams);
    }

    public string Build()
    {
        var header = new JsonObject
        {
            ["typ"] = Typ,
            ["alg"] = Alg,
        };
        if (IncludeJwk)
        {
            JsonWebKey jwkForHeader = IncludePrivateInJwk
                ? new EllipticCurveJsonWebKey { Algorithm = SigningAlgorithms.ES256 }
                    .Apply(_ecdsa.ExportParameters(includePrivateParameters: true))
                : PublicJwk;
            header["jwk"] = JsonSerializer.SerializeToNode(jwkForHeader);
        }

        var payload = new JsonObject();
        if (Htm is not null) payload["htm"] = Htm;
        if (Htu is not null) payload["htu"] = Htu;
        if (Jti is not null) payload["jti"] = Jti;
        payload["iat"] = (Iat ?? _now).ToUnixTimeSeconds();
        if (Ath is not null) payload["ath"] = Ath;

        var headerB64 = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadB64 = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var signingInput = $"{headerB64}.{payloadB64}";

        var signature = _ecdsa.SignData(
            Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (CorruptSignature && signature.Length > 0)
        {
            signature[0] ^= 0xFF;
        }
        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }
}
