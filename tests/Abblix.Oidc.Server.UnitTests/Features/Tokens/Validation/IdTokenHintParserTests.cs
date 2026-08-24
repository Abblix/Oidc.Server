// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Validation;

/// <summary>
/// What makes an <c>id_token_hint</c> believable, shared by the two endpoints that accept one.
/// </summary>
/// <remarks>
/// What each endpoint then does with the result differs and is covered where that happens: the authorization
/// side requires the requesting client in the audience, the end-session side reads the client out of it.
/// </remarks>
public class IdTokenHintParserTests
{
    private const string Hint = "hint.jwt";

    private static readonly DateTimeOffset Expiry = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator = new(MockBehavior.Strict);
    private readonly IdTokenHintParser _parser;

    public IdTokenHintParserTests()
    {
        _parser = new IdTokenHintParser(_jwtValidator.Object);
    }

    private void SetupToken(JsonWebToken token)
    {
        Result<JsonWebToken, JwtValidationError> success = token;
        _jwtValidator
            .Setup(v => v.ValidateAsync(Hint, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(success);
    }

    private static JsonWebToken IdToken(string? type = null) => Build(type);

    private static JsonWebToken Build(string? type)
    {
        var token = new JsonWebToken { Payload = { Subject = "user_42", ExpiresAt = Expiry } };
        if (type is not null)
            token.Header.Type = type;

        return token;
    }

    [Fact]
    public async Task AnIdToken_IsReturned()
    {
        SetupToken(IdToken());

        var result = await _parser.ParseAsync(Hint);

        Assert.True(result.TryGetSuccess(out var idToken));
        Assert.Equal("user_42", idToken.Payload.Subject);
    }

    /// <summary>
    /// A token the shared validator refuses - a bad signature, an unknown issuer, a missing expiry - comes
    /// back as a reason rather than as a token.
    /// </summary>
    [Fact]
    public async Task ATokenThatDoesNotValidate_IsRefused()
    {
        Result<JsonWebToken, JwtValidationError> failure =
            new JwtValidationError(JwtError.InvalidToken, "bad signature");

        _jwtValidator
            .Setup(v => v.ValidateAsync(Hint, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(failure);

        var result = await _parser.ParseAsync(Hint);

        Assert.True(result.TryGetFailure(out var reason));
        Assert.Contains("invalid token", reason, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Another own-issued token of this server is refused by its type.
    /// </summary>
    /// <remarks>
    /// RFC 8725 Section 3.12 on keeping the validation rules of different kinds of JWT mutually exclusive:
    /// these are signed with the same key and can carry the same audience, so the type is what parts them
    /// from an ID token.
    /// </remarks>
    [Theory]
    [InlineData(JsonWebTokenTypes.AccessToken)]
    [InlineData(JsonWebTokenTypes.RequestObject)]
    [InlineData(JsonWebTokenTypes.LogoutToken)]
    [InlineData(JsonWebTokenTypes.TokenIntrospection)]
    public async Task AnotherKindOfOwnIssuedToken_IsRefused(string type)
    {
        SetupToken(IdToken(type));

        var result = await _parser.ParseAsync(Hint);

        Assert.True(result.TryGetFailure(out var reason));
        Assert.Contains("not an ID Token", reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The generic type an ID token carries, and no type at all, both pass.
    /// </summary>
    /// <remarks>
    /// Stated because the theory above would hold equally over a parser that refused everything: what makes
    /// it a discriminator is that these two get through.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData(JsonWebTokenTypes.Jwt)]
    public async Task TheTypeAnIdTokenCarries_IsAccepted(string? type)
    {
        SetupToken(IdToken(type));

        var result = await _parser.ParseAsync(Hint);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// The options handed to the shared validator switch off the lifetime and the audience, and require an
    /// expiration time to be present.
    /// </summary>
    /// <remarks>
    /// Asserted rather than left to the behaviours they produce, because two of the three cannot be observed
    /// from here: whether an expired hint is accepted and whether an audience naming somebody else is
    /// tolerated are decided inside the validator this test mocks. What this pins is the instruction.
    /// <para>
    /// The lifetime is off because a hint names an end user rather than a live credential. The audience is
    /// off because this server need not be in it - OpenID Connect Core 1.0 Section 3.1.2.1 says so outright -
    /// and who must be is the caller's question. The expiry is required because Section 2 makes it REQUIRED
    /// in an ID Token, and its presence is what parts one from a signed UserInfo response.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheHintIsValidatedWithoutItsLifetimeOrAudienceAndWithARequiredExpiry()
    {
        ValidationOptions? asked = null;
        Result<JsonWebToken, JwtValidationError> success = IdToken();

        _jwtValidator
            .Setup(v => v.ValidateAsync(Hint, It.IsAny<ValidationOptions>()))
            .Callback((string _, ValidationOptions options) => asked = options)
            .ReturnsAsync(success);

        await _parser.ParseAsync(Hint);

        Assert.NotNull(asked);
        Assert.False(asked.Value.HasFlag(ValidationOptions.ValidateLifetime));
        Assert.False(asked.Value.HasFlag(ValidationOptions.ValidateAudience));
        Assert.True(asked.Value.HasFlag(ValidationOptions.RequireExpirationTime));

        // And the checks that do not depend on the lifetime are still asked for.
        Assert.True(asked.Value.HasFlag(ValidationOptions.RequireValidIssuer));
        Assert.True(asked.Value.HasFlag(ValidationOptions.RequireValidSignedTokens));
    }
}
