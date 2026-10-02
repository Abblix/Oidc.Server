// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

public partial class JsonWebTokenValidationTests
{
    // ─────────────────────────────────────────────────────────────────────────────
    // RFC 8725 section 3.11 - pin the JWT 'typ' header (RFC 7515 section 4.1.9) via
    // ValidationParameters.ExpectedTokenTypes so token-type confusion (replaying a
    // logout_token as an id_token, etc.) is rejected inside the validator instead of
    // relying on every caller to post-check token.Header.Type.
    // ─────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sanity baseline: when <see cref="ValidationParameters.ExpectedTokenTypes"/> is null,
    /// the validator skips <c>typ</c> enforcement entirely - preserves historical behavior
    /// for callers that have not opted in to the RFC 8725 section 3.11 hook.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_NullByDefault_SkipsTypValidation()
    {
        var token = CreateValidToken();
        token.Header.Type = "logout+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey);

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// When the JWT's <c>typ</c> matches the configured expected value, validation passes.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_TypMatches_Validates()
    {
        var token = CreateValidToken();
        token.Header.Type = "at+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// When the JWT's <c>typ</c> does not match any configured expected value, the validator
    /// rejects with <see cref="JwtError.InvalidTokenType"/> - the very token-type confusion
    /// rejection RFC 8725 section 3.11 prescribes.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_TypMismatch_RejectsAsInvalidTokenType()
    {
        var token = CreateValidToken();
        token.Header.Type = "logout+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidTokenType, error.Error);
        Assert.Contains("logout+jwt", error.ErrorDescription);
        Assert.Contains("at+jwt", error.ErrorDescription);
    }

    /// <summary>
    /// When <see cref="ValidationParameters.ExpectedTokenTypes"/> is configured but the JWT
    /// has no <c>typ</c> header at all, validation rejects: the caller asked for typ pinning
    /// and the token does not declare its class.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_TypMissing_RejectsAsInvalidTokenType()
    {
        var token = CreateValidToken();
        token.Header.Type = null;
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidTokenType, error.Error);
        Assert.Contains("missing", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// RFC 7515 section 4.1.9: a <c>typ</c> value without a slash is treated as if
    /// <c>application/</c> were prepended. The validator strips that prefix before lookup so
    /// callers can register the bare canonical form (<c>at+jwt</c>) and tokens whose
    /// producer wrote out the long form (<c>application/at+jwt</c>) still validate.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_ApplicationPrefixStripped_Matches()
    {
        var token = CreateValidToken();
        token.Header.Type = "application/at+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// A <c>typ</c> is a media type, and RFC 2045 section 5.1 makes the type and subtype
    /// case-insensitive ("Matching of media type and subtype is ALWAYS case-insensitive"),
    /// which RFC 7515 section 4.1.9 adopts by reference. So <c>At+JWT</c> names the same token
    /// class as <c>at+jwt</c> and must be accepted.
    /// </summary>
    /// <remarks>
    /// This test asserted the opposite until 2026-07-20, citing RFC 7515 section 5.3 - which is
    /// the section that ends "Only the 'typ' and 'cty' member values defined in this
    /// specification do not use these comparison rules", exempting <c>typ</c> rather than
    /// governing it. The assertion was holding the wrong behavior in place.
    /// </remarks>
    [Fact]
    public async Task ExpectedTokenTypes_TypMatchesCaseInsensitively()
    {
        var token = CreateValidToken();
        token.Header.Type = "At+JWT";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// The <c>application/</c> prefix is stripped from the expectation as well as from the token,
    /// so a caller may register either form. RFC 7515 section 4.1.9 recommends producers omit the
    /// prefix but requires recipients to treat a prefix-less value as if it were prepended, which
    /// makes the two forms the same name and leaves the caller free to write either.
    /// </summary>
    /// <remarks>
    /// Stripping used to be applied to the token's own <c>typ</c> only, which made the long form
    /// unusable as an expectation in both directions: it matched neither <c>at+jwt</c> nor
    /// <c>application/at+jwt</c>, since both reach the lookup already stripped.
    /// </remarks>
    [Theory]
    [InlineData("at+jwt", "application/at+jwt")]
    [InlineData("application/at+jwt", "at+jwt")]
    [InlineData("application/at+jwt", "application/at+jwt")]
    [InlineData("Application/AT+JWT", "at+jwt")]
    public async Task ExpectedTokenTypes_ApplicationPrefixStrippedOnBothSides(string typ, string expected)
    {
        var token = CreateValidToken();
        token.Header.Type = typ;
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { expected },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Case folding must not blur the classes apart from each other: a logout token still fails
    /// an id_token expectation. The names this library pins differ in more than casing, so the
    /// RFC 2045 rule costs nothing in separation.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_DifferentClassStillRejected()
    {
        var token = CreateValidToken();
        token.Header.Type = "Logout+JWT";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidTokenType, error.Error);
    }

    /// <summary>
    /// When the configured set has multiple values, any one of them is acceptable. Lets a
    /// caller accept several token types through the same validator invocation - for
    /// example, a transitional period where both <c>at+jwt</c> and a legacy custom
    /// <c>access+jwt</c> are honoured.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_MultipleValues_AnyMatchPasses()
    {
        var token = CreateValidToken();
        token.Header.Type = "access+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal) { "at+jwt", "access+jwt" },
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Empty set is treated identically to null - no enforcement. Defensive default for
    /// callers that build the set programmatically and may hit edge cases producing zero
    /// expected types.
    /// </summary>
    [Fact]
    public async Task ExpectedTokenTypes_EmptySet_SkipsTypValidation()
    {
        var token = CreateValidToken();
        token.Header.Type = "logout+jwt";
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with
        {
            ExpectedTokenTypes = new HashSet<string>(StringComparer.Ordinal),
        };

        var result = await validator.ValidateAsync(jwt, parameters);

        Assert.True(result.TryGetSuccess(out _));
    }
}
