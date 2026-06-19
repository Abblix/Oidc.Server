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

using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.TokenExchange;

/// <summary>
/// Unit tests for <see cref="JwtSubjectTokenResolver"/> -- the RFC 8693 subject_token resolver
/// for JWT-formatted tokens (access_token / id_token / jwt URIs).
/// </summary>
public class JwtSubjectTokenResolverTests
{
    private const string TokenWire = "header.payload.signature";

    // RFC 8693 subject tokens are not minted for this AS, so the resolver must validate them with
    // the audience constraint dropped (signature + issuer + lifetime only). Strict mocks assert
    // this exact option set -- a regression that re-enables audience validation fails to match.
    private const ValidationOptions SubjectTokenValidation =
        ValidationOptions.Default & ~ValidationOptions.RequireValidAudience;

    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator = new(MockBehavior.Strict);
    private readonly FakeTimeProvider _timeProvider = new();
    private readonly JwtSubjectTokenResolver _resolver;

    public JwtSubjectTokenResolverTests()
    {
        _resolver = new JwtSubjectTokenResolver(_jwtValidator.Object);
    }

    [Fact]
    public async Task ValidJwt_ReturnsContextWithSubjectIssuerScope()
    {
        var jwt = NewJwt(subject: "user-1", issuer: "https://idp.example.com");
        jwt.Payload.Scope = ["openid", "profile"];
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, SubjectTokenValidation))
            .ReturnsAsync(jwt);

        var result = await _resolver.ResolveAsync(TokenWire, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal("user-1", ctx.Subject);
        Assert.Equal("https://idp.example.com", ctx.Issuer);
        Assert.Equal(["openid", "profile"], ctx.Scope!);
        Assert.Null(ctx.AuthorizationDetails);
    }

    [Fact]
    public async Task AuthorizationDetailsClaim_DeepClonedIntoContext()
    {
        const string adWire = """[{"type":"payment_initiation","actions":["initiate"]}]""";
        var jwt = NewJwt(subject: "user-1", issuer: null);
        jwt.Payload.Json[IanaClaimTypes.AuthorizationDetails] = (JsonArray)JsonNode.Parse(adWire)!;
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, SubjectTokenValidation))
            .ReturnsAsync(jwt);

        var result = await _resolver.ResolveAsync(TokenWire, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.NotNull(ctx.AuthorizationDetails);
        Assert.Equal(adWire, ctx.AuthorizationDetails!.ToJsonString());
        // The clone must be detached from the JWT payload -- mutating one must not affect the other.
        Assert.NotSame(jwt.Payload.Json[IanaClaimTypes.AuthorizationDetails], ctx.AuthorizationDetails);
    }

    [Fact]
    public async Task JwtValidationFailure_Rejected()
    {
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, SubjectTokenValidation))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "expired"));

        var result = await _resolver.ResolveAsync(TokenWire, CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("invalid", error.ErrorDescription, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MissingSubClaim_Rejected()
    {
        var jwt = NewJwt(subject: null, issuer: null);
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, SubjectTokenValidation))
            .ReturnsAsync(jwt);

        var result = await _resolver.ResolveAsync(TokenWire, CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("sub", error.ErrorDescription);
    }

    [Fact]
    public async Task IdTokenShape_OriginalClientId_DerivedFromSingleAudience()
    {
        // An id_token carries no client_id claim. The client it was minted for is the sole
        // audience, and the resolver must surface that so the handler confused-deputy guard can
        // fire. Otherwise any client could exchange any user id_token.
        var jwt = NewJwt(subject: "user-1", issuer: null, audiences: ["client-A"]);
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, SubjectTokenValidation))
            .ReturnsAsync(jwt);

        var result = await _resolver.ResolveAsync(TokenWire, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal("client-A", ctx.OriginalClientId);
    }

    [Fact]
    public async Task ClientIdClaim_TakesPrecedenceOverAzpAndAudience()
    {
        // Access tokens carry client_id directly and may also list resource-server audiences
        // (RFC 8707). client_id is the authoritative origin and must win over both.
        var jwt = NewJwt(subject: "user-1", issuer: null, audiences: ["https://api.example.com"]);
        jwt.Payload.ClientId = "client-A";
        jwt.Payload.AuthorizedParty = "client-Z";
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, SubjectTokenValidation))
            .ReturnsAsync(jwt);

        var result = await _resolver.ResolveAsync(TokenWire, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal("client-A", ctx.OriginalClientId);
    }

    [Fact]
    public async Task Azp_UsedWhenClientIdAbsentAndMultipleAudiences()
    {
        // Multi-audience id_token: OIDC Core mandates azp, and the single-audience shortcut does
        // not apply. azp names the client the token was issued to.
        var jwt = NewJwt(subject: "user-1", issuer: null, audiences: ["client-A", "client-B"]);
        jwt.Payload.AuthorizedParty = "client-A";
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, SubjectTokenValidation))
            .ReturnsAsync(jwt);

        var result = await _resolver.ResolveAsync(TokenWire, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal("client-A", ctx.OriginalClientId);
    }

    [Fact]
    public async Task NoClientIdNoAzpMultipleAudiences_OriginalClientIdNull()
    {
        // Genuinely ambiguous: no client_id, no azp, more than one audience. The resolver leaves
        // origin undetermined rather than guessing; the cross-client guard then cannot narrow it.
        var jwt = NewJwt(subject: "user-1", issuer: null, audiences: ["a", "b"]);
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, SubjectTokenValidation))
            .ReturnsAsync(jwt);

        var result = await _resolver.ResolveAsync(TokenWire, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Null(ctx.OriginalClientId);
    }

    private JsonWebToken NewJwt(string? subject, string? issuer, string[]? audiences = null)
    {
        var now = _timeProvider.GetUtcNow();
        var jwt = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { IssuedAt = now, ExpiresAt = now.AddHours(1) },
        };
        if (issuer is not null) jwt.Payload.Issuer = issuer;
        if (subject is not null) jwt.Payload.Subject = subject;
        if (audiences is not null) jwt.Payload.Audiences = audiences;
        return jwt;
    }
}
