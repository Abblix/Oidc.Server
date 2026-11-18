// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

// The token types a validation accepts (RFC 8725 section 3.11), stated by every validation through
// ValidationParameters.TokenTypes.
public partial class JsonWebTokenValidationTests
{
    private async Task<Result<JsonWebToken, JwtValidationError>> ValidateTypedAsync(string? typ, TokenTypePolicy policy)
    {
        var token = CreateValidToken();
        token.Header.Type = typ;
        var jwt = await IssueToken(token, SigningKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        return await validator.ValidateAsync(jwt, CreateValidationParameters(SigningKey) with { TokenTypes = policy });
    }

    private static void AssertRefusedAsInvalidTokenType(Result<JsonWebToken, JwtValidationError> result)
    {
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidTokenType, error.Error);
    }

    /// <summary>
    /// A validation that names no token types is the host's mistake, refused before the token is read.
    /// </summary>
    [Fact]
    public async Task TokenTypes_NotStated_Throws()
    {
        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = CreateValidationParameters(SigningKey) with { TokenTypes = null! };

        await Assert.ThrowsAsync<ArgumentException>(() => validator.ValidateAsync("not.even.read", parameters));
    }

    [Theory]
    [InlineData("at+jwt")]
    [InlineData("application/at+jwt")]
    [InlineData("Application/AT+JWT")]
    public async Task Exactly_AnyAcceptedSpellingOfTheType_Validates(string typ)
    {
        Assert.True((await ValidateTypedAsync(typ, TokenTypePolicy.Exactly("at+jwt"))).TryGetSuccess(out _));
    }

    // The accepted type may itself be stated with the prefix, and the short form a token carries still matches it
    [Theory]
    [InlineData("at+jwt")]
    [InlineData("AT+JWT")]
    public async Task Exactly_ATypeStatedWithThePrefix_AcceptsTheShortForm(string typ)
    {
        var policy = TokenTypePolicy.Exactly("application/at+jwt");
        Assert.True((await ValidateTypedAsync(typ, policy)).TryGetSuccess(out _));
    }

    // Folding the prefix and the case must not widen the match beyond the one type
    [Theory]
    [InlineData("logout+jwt")]
    [InlineData("at+jwt-but-not-really")]
    [InlineData("application/jwt")]
    [InlineData("text/at+jwt")]
    public async Task Exactly_AnotherType_IsRefused(string typ)
    {
        AssertRefusedAsInvalidTokenType(await ValidateTypedAsync(typ, TokenTypePolicy.Exactly("at+jwt")));
    }

    [Fact]
    public async Task Exactly_NoType_IsRefused()
    {
        AssertRefusedAsInvalidTokenType(await ValidateTypedAsync(null, TokenTypePolicy.Exactly("at+jwt")));
    }

    [Fact]
    public async Task Exactly_AnyOfSeveralTypes_Validates()
    {
        var policy = TokenTypePolicy.Exactly("at+jwt", "vnd.example.rt+jwt");

        Assert.True((await ValidateTypedAsync("vnd.example.rt+jwt", policy)).TryGetSuccess(out _));
    }

    [Fact]
    public void Exactly_NoTypes_Throws()
    {
        Assert.Throws<ArgumentException>(() => TokenTypePolicy.Exactly());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("logout+jwt")]
    public async Task OrUntyped_NoTypeOrTheType_Validates(string? typ)
    {
        Assert.True((await ValidateTypedAsync(typ, TokenTypePolicy.OrUntyped("logout+jwt"))).TryGetSuccess(out _));
    }

    [Fact]
    public async Task OrUntyped_AnotherType_IsRefused()
    {
        AssertRefusedAsInvalidTokenType(await ValidateTypedAsync("at+jwt", TokenTypePolicy.OrUntyped("logout+jwt")));
    }

    /// <summary>
    /// With no types, only a token without a type is accepted, as an ID token is.
    /// </summary>
    [Fact]
    public async Task OrUntypedWithNoTypes_AcceptsOnlyAnUntypedToken()
    {
        Assert.True((await ValidateTypedAsync(null, TokenTypePolicy.OrUntyped())).TryGetSuccess(out _));
        AssertRefusedAsInvalidTokenType(await ValidateTypedAsync("at+jwt", TokenTypePolicy.OrUntyped()));
    }

    /// <summary>
    /// A caller that judges the type itself receives the token whatever it declares.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("logout+jwt")]
    public async Task CheckedByCaller_AnyType_Validates(string? typ)
    {
        Assert.True((await ValidateTypedAsync(typ, TokenTypePolicy.CheckedByCaller)).TryGetSuccess(out _));
    }
}
