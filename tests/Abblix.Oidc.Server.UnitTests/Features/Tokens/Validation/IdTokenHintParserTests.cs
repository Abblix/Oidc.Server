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

    private static JsonWebToken IdToken(string? type = null, bool withExpiry = true)
    {
        var token = new JsonWebToken { Payload = { Subject = "user_42" } };
        if (withExpiry)
            token.Payload.ExpiresAt = Expiry;

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
    /// A token with no expiration time is refused, which is what stops a signed UserInfo response.
    /// </summary>
    /// <remarks>
    /// That one carries no type either, is signed with the same key and addressed to the same client, so the
    /// header gate cannot reach it. What parts the two is a claim: OpenID Connect Core 1.0 Section 2 makes
    /// <c>exp</c> REQUIRED in an ID Token, while Section 5.3.2 requires a signed UserInfo response to carry
    /// <c>iss</c> and <c>aud</c> and nothing more. RFC 8725 Section 3.12 lists a claim as an equal way to
    /// keep the rules of two kinds of JWT mutually exclusive.
    /// </remarks>
    [Fact]
    public async Task ATokenWithNoExpirationTime_IsRefused()
    {
        SetupToken(IdToken(withExpiry: false));

        var result = await _parser.ParseAsync(Hint);

        Assert.True(result.TryGetFailure(out var reason));
        Assert.Contains("not an ID Token", reason, StringComparison.Ordinal);
        Assert.Contains("expiration time", reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// A token that is both the wrong kind and missing an expiry is refused for being the wrong kind.
    /// </summary>
    /// <remarks>
    /// The order is the point, and it is not cosmetic. This server mints one own-issued kind that carries no
    /// <c>exp</c> by default - a registration access token, which RFC 7592 Section 5 says SHOULD NOT expire -
    /// so asking for the expiry first answers its sender with "add an exp claim", which is advice the
    /// specification forbids this server to take, about a token that could never be a hint anyway. Requiring
    /// the expiry through <see cref="ValidationOptions.RequireExpirationTime"/> would put it first, inside
    /// the validator call, which is why the parser asks for it itself.
    /// </remarks>
    [Fact]
    public async Task ATokenBothOfTheWrongKindAndWithoutAnExpiry_IsRefusedForItsKind()
    {
        SetupToken(IdToken(JwtTypes.RegistrationAccessToken, withExpiry: false));

        var result = await _parser.ParseAsync(Hint);

        Assert.True(result.TryGetFailure(out var reason));
        Assert.DoesNotContain("expiration time", reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The options handed to the shared validator switch off the lifetime and the audience, and leave the
    /// expiry to this parser.
    /// </summary>
    /// <remarks>
    /// Asserted rather than left to the behaviours they produce, because neither can be observed from here:
    /// whether an expired hint is accepted and whether an audience naming somebody else is tolerated are
    /// both decided inside the validator this test mocks. What this pins is the instruction.
    /// <para>
    /// The lifetime is off because a hint names an end user rather than a live credential. The audience is
    /// off because this server need not be in it - OpenID Connect Core 1.0 Section 3.1.2.1 says so outright -
    /// and who must be is the caller's question. <see cref="ValidationOptions.RequireExpirationTime"/> is
    /// left out so the expiry is asked after the type rather than before it, which
    /// <see cref="ATokenBothOfTheWrongKindAndWithoutAnExpiry_IsRefusedForItsKind"/> is what pins.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheHintIsValidatedWithoutItsLifetimeOrAudienceOrARequiredExpiry()
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
        Assert.False(asked.Value.HasFlag(ValidationOptions.RequireExpirationTime));

        // And the checks that do not depend on the lifetime are still asked for.
        Assert.True(asked.Value.HasFlag(ValidationOptions.RequireValidIssuer));
        Assert.True(asked.Value.HasFlag(ValidationOptions.RequireValidSignedTokens));
    }
}
