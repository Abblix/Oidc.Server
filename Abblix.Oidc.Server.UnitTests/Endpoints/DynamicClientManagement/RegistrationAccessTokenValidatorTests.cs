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

using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Verifies the RFC 7592 §5 registration-access-token binding in
/// <see cref="RegistrationAccessTokenValidator"/>: a token is accepted only when its jti matches
/// the value recorded on the client, so a rotated token invalidates its predecessors, while a null
/// expectation keeps statically configured / pre-existing clients working unchanged.
/// </summary>
public class RegistrationAccessTokenValidatorTests
{
    private const string ClientId = "client-1";

    private static RegistrationAccessTokenValidator CreateValidator(JsonWebToken token)
    {
        var jwtValidator = new Mock<IAuthServiceJwtValidator>(MockBehavior.Strict);
        jwtValidator
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(token);

        return new RegistrationAccessTokenValidator(jwtValidator.Object);
    }

    private static JsonWebToken CreateToken(string jti) => new()
    {
        Header = new JsonWebTokenHeader(new JsonObject
        {
            [JwtClaimTypes.Type] = JwtTypes.RegistrationAccessToken,
        }),
        Payload = new JsonWebTokenPayload(new JsonObject
        {
            [JwtClaimTypes.JwtId] = jti,
            [JwtClaimTypes.Subject] = ClientId,
            [JwtClaimTypes.Audience] = ClientId,
        }),
    };

    private static AuthenticationHeaderValue Bearer => new(TokenTypes.Bearer, "the.jwt.token");

    [Fact]
    public async Task MatchingJti_IsAccepted()
    {
        var validator = CreateValidator(CreateToken("jti-current"));

        var error = await validator.ValidateAsync(Bearer, ClientId, "jti-current");

        Assert.Null(error);
    }

    [Fact]
    public async Task MismatchedJti_IsRejected()
    {
        // A token issued before the last rotation carries a stale jti; binding rejects it.
        var validator = CreateValidator(CreateToken("jti-old"));

        var error = await validator.ValidateAsync(Bearer, ClientId, "jti-current");

        Assert.NotNull(error);
    }

    [Fact]
    public async Task NullExpectation_SkipsBinding()
    {
        // Statically configured or pre-existing client with no recorded jti: binding not enforced.
        var validator = CreateValidator(CreateToken("any-jti"));

        var error = await validator.ValidateAsync(Bearer, ClientId, expectedTokenId: null);

        Assert.Null(error);
    }
}
