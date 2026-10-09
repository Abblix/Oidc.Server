// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Constants;

/// <summary>
/// Which of this server's own tokens the shared sets of accepted types let through the real JWT validator, for the
/// places that read a token of this server back.
/// </summary>
public class JwtTypesTests
{
    private static readonly IServiceProvider Jwt = BuildJwtServices();

    private static readonly OctetJsonWebKey Key = new()
    {
        Algorithm = SigningAlgorithms.HS256,
        KeyValue = RandomNumberGenerator.GetBytes(32),
    };

    private static IServiceProvider BuildJwtServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// An ID token this server issues carries no type, and one issued by an earlier version carries the generic
    /// <c>JWT</c>; a session that began before an upgrade still ends with its own ID token as the hint.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(JsonWebTokenTypes.Jwt)]
    public async Task AnIdToken_IsAcceptedAsOne(string? type)
    {
        var result = await ValidateAsync(type, JwtTypes.IdTokens);

        Assert.True(result.TryGetSuccess(out _), $"An ID token typed '{type}' was refused: {result}");
    }

    /// <summary>
    /// Every other token this server issues carries a type of its own, and each is refused, so none of them is
    /// taken back as an ID token (RFC 8725 Section 3.11).
    /// </summary>
    [Theory]
    [InlineData(JsonWebTokenTypes.AccessToken)]
    [InlineData(JwtTypes.RefreshToken)]
    [InlineData(JwtTypes.RegistrationAccessToken)]
    [InlineData(JwtTypes.InitialAccessToken)]
    [InlineData(JsonWebTokenTypes.LogoutToken)]
    [InlineData(JsonWebTokenTypes.TokenIntrospection)]
    public async Task AnotherTokenOfThisServer_IsRefusedAsAnIdToken(string type)
    {
        var result = await ValidateAsync(type, JwtTypes.IdTokens);

        Assert.True(result.TryGetFailure(out var error), $"A token typed '{type}' passed as an ID token.");
        Assert.Equal(JwtError.InvalidTokenType, error.Error);
    }

    /// <summary>
    /// The introspection and revocation endpoints read back access and refresh tokens, which RFC 7662 and RFC 7009
    /// cover, and the registration and initial access tokens this server issues too.
    /// </summary>
    [Theory]
    [InlineData(JsonWebTokenTypes.AccessToken)]
    [InlineData(JwtTypes.RefreshToken)]
    [InlineData(JwtTypes.RegistrationAccessToken)]
    [InlineData(JwtTypes.InitialAccessToken)]
    public async Task AnIntrospectableToken_IsAccepted(string type)
    {
        var result = await ValidateAsync(type, JwtTypes.IntrospectableTokens);

        Assert.True(result.TryGetSuccess(out _), $"A token typed '{type}' was refused: {result}");
    }

    /// <summary>
    /// An ID token, which carries no type, and the other tokens this server signs are refused there.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(JsonWebTokenTypes.Jwt)]
    [InlineData(JsonWebTokenTypes.LogoutToken)]
    [InlineData(JsonWebTokenTypes.TokenIntrospection)]
    public async Task AnyOtherToken_IsNotIntrospectable(string? type)
    {
        var result = await ValidateAsync(type, JwtTypes.IntrospectableTokens);

        Assert.True(result.TryGetFailure(out var error), $"A token typed '{type}' was accepted.");
        Assert.Equal(JwtError.InvalidTokenType, error.Error);
    }

    private static async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
        string? type,
        TokenTypePolicy accepted)
    {
        var issuedAt = TimeProvider.System.GetUtcNow();
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.HS256 },
            Payload =
            {
                Issuer = TestConstants.DefaultIssuer.OriginalString,
                Subject = "user_42",
                IssuedAt = issuedAt,
                ExpiresAt = issuedAt + TimeSpan.FromMinutes(5),
            },
        };
        if (type is not null)
            token.Header.Type = type;

        var jws = await Jwt.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, Key);

        return await Jwt.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(jws, new ValidationParameters
        {
            TokenTypes = accepted,
            Options = ValidationOptions.RequireValidSignedTokens,
            ResolveIssuerSigningKeys = _ => ((JsonWebKey)Key).ToAsync(),
        });
    }
}
