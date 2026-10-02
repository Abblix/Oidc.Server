// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

using System.Buffers.Text;

namespace Abblix.Jwt.UnitTests;

public partial class JsonWebTokenValidationTests
{
    // ─────────────────────────────────────────────────────────────────────────────
    // Hardening coverage - token-shape confusion (segment count) and alg-stripping /
    // payload tampering. RFC 7515 section 7.1 fixes JWS compact serialization at exactly three
    // dot-separated parts and RFC 7516 section 9 fixes JWE at five; any other count must be
    // rejected as malformed, never mis-routed into a validation path (the JWS-as-JWE
    // type-confusion class). RFC 8725 section 2.1/section 3.1 warn that an attacker will strip 'alg'
    // to none or rewrite the payload of a captured token - the validator must reject both.
    // ─────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// RFC 7515 section 7.1 / RFC 7516 section 9: a compact token has exactly 3 (JWS) or 5 (JWE) parts. A 4-,
    /// 6-, or 7-segment string matches neither shape, so the part-count dispatch must fail it as
    /// <see cref="JwtError.MalformedToken"/> rather than fall through to any validation path.
    /// </summary>
    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(7)]
    public async Task MalformedJwt_WithUnsupportedSegmentCount_FailsAsMalformed(int segments)
    {
        var jwt = string.Join('.', Enumerable.Repeat("AAAA", segments));

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
    }

    /// <summary>
    /// The real-token variant of the segment-count guard: a genuine, correctly-signed JWS with one
    /// extra segment appended (<c>header.payload.signature.injected</c>) is a 4-part string. The
    /// validator must reject it as <see cref="JwtError.MalformedToken"/> on the part-count dispatch,
    /// never strip the trailing junk and trust the valid three-part prefix.
    /// </summary>
    [Fact]
    public async Task SignedJws_WithAppendedSegment_RejectedAsMalformed()
    {
        var signedJwt = await IssueToken(CreateValidToken(), SigningKey);
        var tampered = signedJwt + ".injected";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(tampered, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
    }

    /// <summary>
    /// The 5-segment type-confusion variant: a genuine 3-part JWS padded with two extra segments
    /// becomes a 5-part string, which the part-count dispatch routes to the JWE decryption path. The
    /// signed JWS content must NOT be trusted - the JWE decrypt fails (a JWS 'alg' is not a JWE
    /// key-management alg and no matching key exists), so the token is rejected rather than accepted
    /// as its inner JWS.
    /// </summary>
    [Fact]
    public async Task SignedJws_PaddedToFiveSegments_RoutedToJweAndRejected()
    {
        var signedJwt = await IssueToken(CreateValidToken(), SigningKey);
        var tampered = signedJwt + ".injected.tag";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey, encryptionKey);

        var result = await validator.ValidateAsync(tampered, parameters);

        Assert.True(result.TryGetFailure(out _),
            "A signed JWS padded to 5 segments must be rejected on the JWE path, not accepted as its inner JWS.");
    }

    /// <summary>
    /// RFC 8725 section 3.1 (alg-stripping): a header that declares no 'alg' - whether it carries other
    /// parameters (<c>{"typ":"JWT"}</c>) or is the empty object (<c>{}</c>) - must be rejected as
    /// <see cref="JwtError.InvalidAlgorithm"/>, never treated as an implicit unsigned token. RFC 7515
    /// section 4.1.1 makes 'alg' REQUIRED.
    /// </summary>
    [Theory]
    [InlineData("""{"typ":"JWT"}""")]
    [InlineData("{}")]
    public async Task Jws_WithNoAlgInHeader_RejectedAsInvalidAlgorithm(string headerJson)
    {
        var header = EncodeBase64Url(headerJson);
        var payload = EncodeBase64Url($$"""{"iss":"{{IssuerUri}}","aud":"{{TestAudience}}","sub":"test-user"}""");
        var jwt = $"{header}.{payload}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
    }

    /// <summary>
    /// RFC 8725 section 3.1 (alg-stripping on a captured token): take a genuinely RS256-signed token, rewrite
    /// its header 'alg' to 'none' and drop the signature. Under the default options (RequireSignedTokens)
    /// the downgraded token must be rejected as <see cref="JwtError.InvalidAlgorithm"/> - the captured
    /// payload is not trusted just because the attacker relabeled it unsigned.
    /// </summary>
    [Fact]
    public async Task SignedJws_AlgStrippedToNone_RejectedWhenSigningRequired()
    {
        var signedJwt = await IssueToken(CreateValidToken(), SigningKey);
        var parts = signedJwt.Split('.');

        // Rewrite the header to alg=none, keep the original (signed) payload, drop the signature.
        var strippedHeader = EncodeBase64Url(NoneAlgHeaderJson);
        var downgraded = $"{strippedHeader}.{parts[1]}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(downgraded, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
    }

    /// <summary>
    /// RFC 8725 section 2.1 (payload tampering): take a genuinely signed token, rewrite a payload claim (a
    /// privilege-escalation attempt on 'sub'), re-encode the payload but keep the ORIGINAL signature.
    /// The signature no longer covers the mutated payload, so validation must fail as
    /// <see cref="JwtError.InvalidSignature"/>. Header and 'alg' are untouched, isolating the payload
    /// integrity check - and the rewrite is done at the JSON level so the payload stays parseable and
    /// the token reaches the signature stage rather than short-circuiting as malformed.
    /// </summary>
    [Fact]
    public async Task SignedJws_WithTamperedPayload_RejectedAsInvalidSignature()
    {
        var signedJwt = await IssueToken(CreateValidToken(), SigningKey);
        var parts = signedJwt.Split('.');

        var originalPayload = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[1]));
        var tamperedPayload = originalPayload.Replace("test-user", "attacker");
        Assert.NotEqual(originalPayload, tamperedPayload); // guard: the claim we rewrite is actually present
        var tampered = $"{parts[0]}.{EncodeBase64Url(tamperedPayload)}.{parts[2]}";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(tampered, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidSignature, error.Error);
    }
}
