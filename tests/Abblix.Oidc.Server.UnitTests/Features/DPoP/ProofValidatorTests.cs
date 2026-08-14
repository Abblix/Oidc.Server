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
using System.Threading;
using System.Threading.Tasks;

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

using Moq;

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

    private readonly Mock<Abblix.Oidc.Server.Common.Interfaces.IRequestInfoProvider> _requestInfo
        = new(MockBehavior.Strict);

    public ProofValidatorTests()
    {
        _requestInfo.SetupGet(p => p.RequestMethod).Returns(DefaultHttpMethod);
        _requestInfo.SetupGet(p => p.RequestUri).Returns(DefaultRequestUri.ToString());

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddDistributedMemoryCache();
        services.Configure<Abblix.Oidc.Server.Common.Configuration.OidcOptions>(_ => { });
        services.AddSingleton<TimeProvider>(_time);
        services.AddSingleton(_requestInfo.Object);
        // Through the library's own wiring rather than a hand-picked implementation, so this
        // suite exercises the replay cache a deployment actually gets, decorator included.
        services.AddReplayPrevention();
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

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetSuccess(out var ok));
        Assert.Equal(builder.PublicJwk.ComputeJwkThumbprintBase64Url(), ok.ProofKeyThumbprint);
        Assert.Equal(builder.Jti, ok.JwtId);
        Assert.Equal(_time.GetUtcNow(), ok.IssuedAt);
    }

    [Fact]
    public async Task ValidateAsync_ValidProofWithMatchingAth_ReturnsSuccess()
    {
        const string accessToken = "test-access-token-value";
        var expectedAth = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));

        var builder = new DPoPProofBuilder(_time.GetUtcNow()) { Ath = expectedAth };
        var proof = builder.Build();

        var result = await _sut.ValidateAsync(proof, accessToken, Ct);

        Assert.True(result.TryGetSuccess(out _));
    }

    [Fact]
    public async Task ValidateAsync_HtuWithDefaultPortInRequest_PassesAfterCanonicalisation()
    {
        // Proof carries htu without port; request URI includes the default :443.
        // Both must canonicalise to the same form.
        _requestInfo.SetupGet(p => p.RequestUri).Returns("https://auth.example.com:443/token");
        var builder = new DPoPProofBuilder(_time.GetUtcNow());
        var proof = builder.Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// RFC 9449 §7.1: a request must carry at most one DPoP header. ASP.NET Core's string
    /// FromHeader binder joins repeated header values with a comma - the proof string
    /// arrives at the validator looking like "&lt;jwt1&gt;,&lt;jwt2&gt;". Because JWS
    /// compact serialization (RFC 7515 §3.1) uses only base64url + '.', a comma is
    /// unambiguous evidence of HTTP-level concatenation. The validator must reject before
    /// the downstream JsonWebTokenValidator sees a string with 5 dot-separated parts,
    /// which would route to the JWE branch and crash with "ResolveTokenDecryptionKeys is
    /// expected to be not null". Caught 2026-05-14 against OIDF FAPI 2.0 DPoP-negative
    /// "AddMultipleDpopHeaderForResourceEndpointRequest" sub-test (the multi-DPoP-header
    /// scenario produced exactly this 500-instead-of-401 outcome at /connect/userinfo).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_MultipleDpopHeaderValues_ReturnsMalformed()
    {
        var first = new DPoPProofBuilder(_time.GetUtcNow()).Build();
        var second = new DPoPProofBuilder(_time.GetUtcNow()).Build();
        var concatenated = $"{first},{second}";

        var result = await _sut.ValidateAsync(concatenated, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.MalformedJwt, error.Reason);
        Assert.NotNull(error.Detail);
        Assert.Contains("RFC 9449", error.Detail);
    }

    [Theory]
    [InlineData("openid+jwt")]
    [InlineData("JWT")]
    public async Task ValidateAsync_TypNotDpopJwt_ReturnsInvalidTyp(string typ)
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Typ = typ }.Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.InvalidTokenType, error.Reason);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    public async Task ValidateAsync_AlgNotInWhitelist_ReturnsInvalidAlg(string alg)
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Alg = alg }.Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.InvalidAlgorithm, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_HeaderMissingJwk_ReturnsInvalidJwk()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { IncludeJwk = false }.Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.InvalidJwk, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_JwkContainsPrivateKeyMaterial_ReturnsInvalidJwk()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { IncludePrivateInJwk = true }.Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.InvalidJwk, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_SignatureCorrupted_ReturnsSignatureInvalid()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { CorruptSignature = true }.Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.SignatureInvalid, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_HtmDoesNotMatchRequest_ReturnsHtmMismatch()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Htm = "GET" }.Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.HttpMethodMismatch, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_HtuDoesNotMatchRequest_ReturnsHtuMismatch()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow())
        {
            Htu = "https://auth.example.com/different-endpoint",
        }.Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.HttpUriMismatch, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_IatBeforeToleranceWindow_ReturnsIatOutOfWindow()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow().AddMinutes(-5)).Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.IssuedAtOutOfWindow, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_IatAfterToleranceWindow_ReturnsIatOutOfWindow()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow().AddMinutes(5)).Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.IssuedAtOutOfWindow, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_AccessTokenPresentButAthAbsent_ReturnsAthMissing()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()).Build();

        var result = await _sut.ValidateAsync(proof, "some-access-token", Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.AccessTokenHashMissing, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_AthDoesNotMatchAccessToken_ReturnsAthMismatch()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Ath = "wrong-hash" }.Build();

        var result = await _sut.ValidateAsync(proof, "some-access-token", Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.AccessTokenHashMismatch, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_JtiMissing_ReturnsJtiMissing()
    {
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Jti = null }.Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.JwtIdMissing, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_JtiTooShort_ReturnsJtiMissing()
    {
        // RFC 9449 §11.1 RECOMMENDS at least 96 bits of effective entropy in the jti
        // claim - anything shorter is rejected to harden the replay defence.
        var proof = new DPoPProofBuilder(_time.GetUtcNow()) { Jti = "short" }.Build();

        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.JwtIdMissing, error.Reason);
    }

    [Fact]
    public async Task ValidateAsync_SameJtiPresentedTwice_SecondReturnsReplayDetected()
    {
        // Same builder produces the same jti on every Build() - two consecutive validates
        // exercise the replay-cache integration: first registers the jti, second hits.
        var builder = new DPoPProofBuilder(_time.GetUtcNow());
        var proof = builder.Build();

        var first = await _sut.ValidateAsync(proof, cancellationToken: Ct);
        Assert.True(first.TryGetSuccess(out _));

        var second = await _sut.ValidateAsync(proof, cancellationToken: Ct);
        Assert.True(second.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.ReplayDetected, error.Reason);
    }

    [Theory]
    [InlineData("not.a.jwt.with.too.many.parts")]
    [InlineData("only.two")]
    [InlineData("")]
    public async Task ValidateAsync_MalformedJwt_ReturnsMalformedJwt(string proof)
    {
        var result = await _sut.ValidateAsync(proof, cancellationToken: Ct);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ProofErrorReasons.MalformedJwt, error.Reason);
    }
}