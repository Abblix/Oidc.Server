// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Verifies <see cref="RegistrationAccessTokenValidator"/> answers with the jti of a registration access token
/// valid for the client, which the endpoint then matches against its registration (RFC 7592 section 5), and
/// refuses a token that names another client or carries no jti to match.
/// </summary>
public class RegistrationAccessTokenValidatorTests
{
    private const string ClientId = "client-1";
    private static readonly string Issuer = TestConstants.DefaultIssuer.OriginalString;

    private static RegistrationAccessTokenValidator CreateValidator(JsonWebToken token)
    {
        var jwtValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        return new RegistrationAccessTokenValidator(jwtValidator.Object);
    }

    private static JsonWebToken CreateToken(string? jti, string? subject = null, string? audience = null) => new()
    {
        Header = new JsonWebTokenHeader(new JsonObject
        {
            [JwtClaimTypes.Type] = JwtTypes.RegistrationAccessToken,
        }),
        Payload = new JsonWebTokenPayload(new JsonObject
        {
            [JwtClaimTypes.JwtId] = jti,
            [JwtClaimTypes.Subject] = subject ?? ClientId,
            [JwtClaimTypes.Audience] = audience ?? Issuer,
        }),
    };

    private static AuthenticationHeaderValue Bearer => new(TokenTypes.Bearer, "the.jwt.token");

    [Fact]
    public async Task AValidToken_AnswersWithItsJti()
    {
        var validator = CreateValidator(CreateToken("jti-current"));

        var result = await validator.ValidateAsync(Bearer, ClientId);

        Assert.True(result.TryGetSuccess(out var tokenId));
        Assert.Equal("jti-current", tokenId);
    }

    /// <summary>
    /// A token without a jti binds to no registration, so it manages none.
    /// </summary>
    [Fact]
    public async Task ATokenWithoutAJti_IsRejected()
    {
        var validator = CreateValidator(CreateToken(jti: null));

        var result = await validator.ValidateAsync(Bearer, ClientId);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
    }

    /// <summary>
    /// The token is bound to the registration it names, and presenting it against another is refused. The
    /// binding rests on the subject: the audience names this server and reads the same on every registration
    /// access token, so it cannot say which registration this one is about. Nothing tested this before, so the
    /// binding could have been dropped without a red run.
    /// </summary>
    [Fact]
    public async Task ATokenIssuedForAnotherClient_IsRejected()
    {
        var validator = CreateValidator(CreateToken("jti-current"));

        var result = await validator.ValidateAsync(Bearer, "client-2");

        Assert.True(result.TryGetFailure(out _));
    }

}
