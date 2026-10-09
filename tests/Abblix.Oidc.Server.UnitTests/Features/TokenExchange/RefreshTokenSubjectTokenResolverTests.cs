// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.TokenExchange;

/// <summary>
/// Unit tests for <see cref="RefreshTokenSubjectTokenResolver"/> -- the RFC 8693 subject_token
/// resolver for refresh_token URI (own-issued JWT of typ=rt+jwt, recovers original AuthorizedGrant).
/// </summary>
public class RefreshTokenSubjectTokenResolverTests
{
    private const string TokenWire = "refresh.jwt.signature";
    private const string OriginalClientId = "client-1";

    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator = new(MockBehavior.Strict);
    private readonly Mock<IRefreshTokenService> _refreshTokenService = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> _clientInfoProvider = new(MockBehavior.Strict);
    private readonly FakeTimeProvider _timeProvider = new();
    private readonly RefreshTokenSubjectTokenResolver _resolver;

    public RefreshTokenSubjectTokenResolverTests()
    {
        // The refresh token names its original client; the resolver looks that client up (its sector opens a
        // pairwise subject) before recovering the grant. The permissive fixture lets the lookup pass licensing.
        _clientInfoProvider
            .Setup(p => p.TryFindClientAsync(OriginalClientId))
            .ReturnsAsync(new ClientInfo(OriginalClientId));

        _resolver = new RefreshTokenSubjectTokenResolver(
            _jwtValidator.Object, _refreshTokenService.Object, _clientInfoProvider.Object);
    }

    [Fact]
    public async Task ValidRefreshToken_ResolvesViaServiceLookup()
    {
        var jwt = NewRefreshJwt();
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, It.IsAny<TokenTypePolicy>(), ValidationOptions.Default))
            .ReturnsAsync(jwt);

        var grant = new AuthorizedGrant(
            new AuthSession("user-9", "session-1", _timeProvider.GetUtcNow(), "https://idp.example.com"),
            new AuthorizationContext("client-1", ["openid"], null));

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(grant);

        var result = await _resolver.ResolveAsync(TokenWire, TokenExchangeTokenTypes.RefreshToken, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal("user-9", ctx.Subject);
        Assert.Equal("https://idp.example.com", ctx.Issuer);
        Assert.Equal(["openid"], ctx.Scope!);
    }

    /// <summary>
    /// The refresh token's own family travels into the exchange, so a token exchanged from it dies with that
    /// family. A token carrying none answers none rather than an empty name, which would be a family of its own
    /// for everything downstream.
    /// </summary>
    [Theory]
    [InlineData("grant_of_this_lineage")]
    [InlineData(null)]
    public async Task FamilyOfTheRefreshToken_ReachesTheContext(string? grantId)
    {
        var jwt = NewRefreshJwt();
        jwt.Payload.GrantId = grantId;
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, It.IsAny<TokenTypePolicy>(), ValidationOptions.Default))
            .ReturnsAsync(jwt);

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(new AuthorizedGrant(
                new AuthSession("user-9", "session-1", _timeProvider.GetUtcNow(), "self"),
                new AuthorizationContext("client-1", ["openid"], null)));

        var result = await _resolver.ResolveAsync(TokenWire, TokenExchangeTokenTypes.RefreshToken, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal(grantId, ctx.GrantId);
    }

    /// <summary>
    /// The refresh token's expiry reaches the context, because a token exchanged within its family must not
    /// outlive it.
    /// </summary>
    [Fact]
    public async Task ExpiryOfTheRefreshToken_ReachesTheContext()
    {
        var jwt = NewRefreshJwt();
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, It.IsAny<TokenTypePolicy>(), ValidationOptions.Default))
            .ReturnsAsync(jwt);

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(new AuthorizedGrant(
                new AuthSession("user-9", "session-1", _timeProvider.GetUtcNow(), "self"),
                new AuthorizationContext("client-1", ["openid"], null)));

        var result = await _resolver.ResolveAsync(TokenWire, TokenExchangeTokenTypes.RefreshToken, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.NotNull(jwt.Payload.ExpiresAt);
        Assert.Equal(jwt.Payload.ExpiresAt, ctx.ExpiresAt);
    }

    [Fact]
    public async Task GrantWithAuthorizationDetails_DeepClonedIntoContext()
    {
        var jwt = NewRefreshJwt();
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, It.IsAny<TokenTypePolicy>(), ValidationOptions.Default))
            .ReturnsAsync(jwt);

        const string adWire = """[{"type":"payment_initiation"}]""";
        var adNode = (JsonArray)JsonNode.Parse(adWire)!;
        var grant = new AuthorizedGrant(
            new AuthSession("user-9", "session-1", _timeProvider.GetUtcNow(), "self"),
            new AuthorizationContext("client-1", ["openid"], null) { AuthorizationDetails = adNode });

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(grant);

        var result = await _resolver.ResolveAsync(TokenWire, TokenExchangeTokenTypes.RefreshToken, CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal(adWire, ctx.AuthorizationDetails!.ToJsonString());
        Assert.NotSame(adNode, ctx.AuthorizationDetails);
    }

    [Fact]
    public async Task JwtValidationFailure_Rejected()
    {
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, It.IsAny<TokenTypePolicy>(), ValidationOptions.Default))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "expired"));

        var result = await _resolver.ResolveAsync(TokenWire, TokenExchangeTokenTypes.RefreshToken, CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("invalid", error.ErrorDescription, System.StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A token presented as a refresh token is validated as exactly that type, and the refusal of another one
    /// ends the exchange.
    /// </summary>
    [Fact]
    public async Task WrongTypHeader_Rejected()
    {
        _jwtValidator
            .Setup(v => v.ValidateAsync(
                TokenWire, TokenTypesArg.Is(TokenTypePolicy.Exactly(JwtTypes.RefreshToken)), ValidationOptions.Default))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidTokenType, "an access token"));

        var result = await _resolver.ResolveAsync(TokenWire, TokenExchangeTokenTypes.RefreshToken, CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    [Fact]
    public async Task RefreshTokenServiceFailure_Rejected()
    {
        var jwt = NewRefreshJwt();
        _jwtValidator
            .Setup(v => v.ValidateAsync(TokenWire, It.IsAny<TokenTypePolicy>(), ValidationOptions.Default))
            .ReturnsAsync(jwt);

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidGrant, "token revoked"));

        var result = await _resolver.ResolveAsync(TokenWire, TokenExchangeTokenTypes.RefreshToken, CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("does not refer", error.ErrorDescription);
    }

    private JsonWebToken NewRefreshJwt()
    {
        var now = _timeProvider.GetUtcNow();
        return new JsonWebToken
        {
            Header = { Type = JwtTypes.RefreshToken, Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                ClientId = OriginalClientId,
                Issuer = "https://issuer.example.com",
                IssuedAt = now,
                ExpiresAt = now.AddDays(30),
            },
        };
    }
}
