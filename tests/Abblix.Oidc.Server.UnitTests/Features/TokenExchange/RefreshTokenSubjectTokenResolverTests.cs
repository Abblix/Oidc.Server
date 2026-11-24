// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using System;
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
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Features.TokenExchange;

/// <summary>
/// Unit tests for <see cref="RefreshTokenSubjectTokenResolver"/> -- the RFC 8693 subject_token
/// resolver for refresh_token URI (own-issued JWT of typ=rt+jwt, recovers original AuthorizedGrant).
/// </summary>
public class RefreshTokenSubjectTokenResolverTests
{
    /// <summary>
    /// The client requesting the exchange: a client trusted to present tokens issued to others, as a broker exchanging them is, so the cases below reach
    /// what follows the token's ownership.
    /// </summary>
    private static readonly ClientInfo Requester = new("requester") { AllowCrossClientSubjectTokenExchange = true };

    private const string TokenWire = "refresh.jwt.signature";
    private const string OriginalClientId = "client-1";

    private readonly Mock<IAuthServiceJwtReader> _jwtValidator = new(MockBehavior.Strict);
    private readonly Mock<IRefreshTokenService> _refreshTokenService = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> _clientInfoProvider = new(MockBehavior.Strict);
    private readonly Mock<IRevocationCutoffChecker> _cutoffChecker = new(MockBehavior.Strict);
    private readonly FakeTimeProvider _timeProvider = new();
    private readonly RefreshTokenSubjectTokenResolver _resolver;

    public RefreshTokenSubjectTokenResolverTests()
    {
        // The refresh token names its original client; the resolver looks that client up (its sector opens a
        // pairwise subject) before recovering the grant. The permissive fixture lets the lookup pass licensing.
        _clientInfoProvider
            .Setup(p => p.FindClientAsync(TestTenant.Matched, OriginalClientId))
            .ReturnsAsync(new ClientInfo(OriginalClientId) { OfflineAccess = OfflineAccess.ConsentRequired });

        _cutoffChecker
            .Setup(c => c.IsSessionRefusedAsync(TestTenant.Matched, It.IsAny<AuthSession>()))
            .ReturnsAsync(false);

        _jwtValidator
            .Setup(v => v.ReadRecordsAsync(It.IsAny<TenantDefinition>(), It.IsAny<JsonWebToken>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync((TenantDefinition _, JsonWebToken token, ValidationOptions _) => token);

        _resolver = new RefreshTokenSubjectTokenResolver(
            _jwtValidator.Object, _refreshTokenService.Object, _clientInfoProvider.Object, _cutoffChecker.Object);
    }

    /// <summary>
    /// A client not trusted to present tokens issued to others is refused another client's refresh token before what
    /// is recorded about it is read, since reading the records of a superseded one revokes its owner's grant.
    /// </summary>
    [Fact]
    public async Task AnotherClientsRefreshToken_IsRefusedBeforeItsRecordsAreRead()
    {
        var presenter = new ClientInfo("requester");
        var jwt = NewRefreshJwt();
        _jwtValidator
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, presenter, TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(jwt);

        var result = await _resolver.ResolveAsync(
            SingleIssuer.Tenant, presenter, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        _jwtValidator.Verify(
            v => v.ReadRecordsAsync(It.IsAny<TenantDefinition>(), It.IsAny<JsonWebToken>(), It.IsAny<ValidationOptions>()),
            Times.Never);
    }

    /// <summary>
    /// A refresh token whose records refuse it - revoked, superseded or cut off - is not exchanged.
    /// </summary>
    [Fact]
    public async Task ARefreshTokenItsRecordsRefuse_IsAnInvalidSubjectToken()
    {
        var owner = new ClientInfo(OriginalClientId);
        var jwt = NewRefreshJwt();
        _jwtValidator
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, owner, TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(jwt);
        _jwtValidator
            .Setup(v => v.ReadRecordsAsync(TestTenant.Matched, jwt, ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(new JwtValidationError(JwtError.TokenAlreadyUsed, "Token was already used"));

        var result = await _resolver.ResolveAsync(
            SingleIssuer.Tenant, owner, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// A public client's refresh token bound to no DPoP key must rotate (RFC 9700 section 2.2.2), and an exchange
    /// issues no refresh token to rotate it into, so it is refused as a subject token, with invalid_request
    /// (RFC 8693 section 2.2.2). A bound token of a public client, and a confidential client's token, are exchanged.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.None, false, false)]
    [InlineData(ClientAuthenticationMethods.None, true, true)]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, false, true)]
    public async Task ARefreshTokenThatMustRotate_IsNotExchanged(
        string ownerAuthMethod,
        bool boundToADPoPKey,
        bool exchanged)
    {
        _clientInfoProvider
            .Setup(p => p.FindClientAsync(TestTenant.Matched, OriginalClientId))
            .ReturnsAsync(new ClientInfo(OriginalClientId)
            {
                OfflineAccess = OfflineAccess.ConsentRequired,
                TokenEndpointAuthMethod = ownerAuthMethod,
            });
        var jwt = NewRefreshJwt();
        if (boundToADPoPKey)
            jwt.Payload.Confirmation = new JsonWebTokenConfirmation { JwkThumbprint = "the-dpop-key-thumbprint" };
        _jwtValidator
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, Requester, TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(jwt);
        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(TestTenant.Matched, jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(new AuthorizedGrant(
                new AuthSession("user-9", "session-1", _timeProvider.GetUtcNow(), "self"),
                new AuthorizationContext(OriginalClientId, [Scopes.OpenId], null)));

        var result = await _resolver.ResolveAsync(
            SingleIssuer.Tenant, Requester, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.Equal(exchanged, result.TryGetSuccess(out var context));
        if (!exchanged)
            Assert.Equal(ErrorCodes.InvalidRequest, result.GetFailure().Error);

        // A bound token's key reaches the context, so the exchange must prove it (RFC 9449 section 5)
        if (exchanged)
            Assert.Equal(boundToADPoPKey ? "the-dpop-key-thumbprint" : null, context!.ProofKeyThumbprint);
    }

    [Fact]
    public async Task ValidRefreshToken_ResolvesViaServiceLookup()
    {
        var jwt = NewRefreshJwt();
        _jwtValidator
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, Requester, TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(jwt);

        var signedInAt = _timeProvider.GetUtcNow().AddHours(-2);
        var grant = new AuthorizedGrant(
            new AuthSession("user-9", "session-1", signedInAt, "https://idp.example.com")
            {
                AuthContextClassRef = "urn:example:acr:1",
                AuthenticationMethodReferences = ["pwd", "otp"],
            },
            new AuthorizationContext("client-1", [Scopes.OpenId], null));

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(TestTenant.Matched, jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(grant);

        var result = await _resolver.ResolveAsync(SingleIssuer.Tenant, Requester, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal("user-9", ctx.Subject);
        Assert.Equal("https://idp.example.com", ctx.IdentityProvider);
        Assert.Equal(jwt.Payload.Issuer, ctx.Issuer);
        Assert.Equal([Scopes.OpenId], ctx.Scope!);
        Assert.Equal("session-1", ctx.SessionId);
        Assert.Equal(signedInAt, ctx.AuthenticationTime);
        Assert.Equal("urn:example:acr:1", ctx.AuthContextClassRef);
        Assert.Equal(["pwd", "otp"], ctx.AuthenticationMethodReferences!);
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
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, It.IsAny<ClientInfo?>(), TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(jwt);

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(TestTenant.Matched, jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(new AuthorizedGrant(
                new AuthSession("user-9", "session-1", _timeProvider.GetUtcNow(), "self"),
                new AuthorizationContext("client-1", [Scopes.OpenId], null)));

        var result = await _resolver.ResolveAsync(SingleIssuer.Tenant, Requester, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

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
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, It.IsAny<ClientInfo?>(), TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(jwt);

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(TestTenant.Matched, jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(new AuthorizedGrant(
                new AuthSession("user-9", "session-1", _timeProvider.GetUtcNow(), "self"),
                new AuthorizationContext("client-1", [Scopes.OpenId], null)));

        var result = await _resolver.ResolveAsync(SingleIssuer.Tenant, Requester, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.NotNull(jwt.Payload.ExpiresAt);
        Assert.Equal(jwt.Payload.ExpiresAt, ctx.ExpiresAt);
    }

    [Fact]
    public async Task GrantWithAuthorizationDetails_DeepClonedIntoContext()
    {
        var jwt = NewRefreshJwt();
        _jwtValidator
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, It.IsAny<ClientInfo?>(), TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(jwt);

        const string adWire = """[{"type":"payment_initiation"}]""";
        var adNode = (JsonArray)JsonNode.Parse(adWire)!;
        var grant = new AuthorizedGrant(
            new AuthSession("user-9", "session-1", _timeProvider.GetUtcNow(), "self"),
            new AuthorizationContext("client-1", [Scopes.OpenId], null) { AuthorizationDetails = adNode });

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(TestTenant.Matched, jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(grant);

        var result = await _resolver.ResolveAsync(SingleIssuer.Tenant, Requester, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.True(result.TryGetSuccess(out var ctx));
        Assert.Equal(adWire, ctx.AuthorizationDetails!.ToJsonString());
        Assert.NotSame(adNode, ctx.AuthorizationDetails);
    }

    /// <summary>
    /// A refresh token exists only for offline access, so one whose client is not allowed it, as when the host
    /// withdrew the permission, ends the exchange before its grant is looked up, as it ends the refresh grant.
    /// </summary>
    [Fact]
    public async Task ClientNotAllowedOfflineAccess_Rejected()
    {
        _jwtValidator
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, It.IsAny<ClientInfo?>(), TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(NewRefreshJwt());
        _clientInfoProvider
            .Setup(p => p.FindClientAsync(TestTenant.Matched, OriginalClientId))
            .ReturnsAsync(new ClientInfo(OriginalClientId) { OfflineAccess = OfflineAccess.Disabled });

        var result = await _resolver.ResolveAsync(SingleIssuer.Tenant, Requester, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        _refreshTokenService.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task JwtValidationFailure_Rejected()
    {
        _jwtValidator
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, It.IsAny<ClientInfo?>(), TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "expired"));

        var result = await _resolver.ResolveAsync(SingleIssuer.Tenant, Requester, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

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
            .Setup(v => v.ReadAuthenticAsync(
                TestTenant.Matched, It.IsAny<ClientInfo?>(), TokenWire, TokenTypesArg.Is(TokenTypePolicy.Exactly(JwtTypes.RefreshToken)), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidTokenType, "an access token"));

        var result = await _resolver.ResolveAsync(SingleIssuer.Tenant, Requester, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    [Fact]
    public async Task RefreshTokenServiceFailure_Rejected()
    {
        var jwt = NewRefreshJwt();
        _jwtValidator
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, It.IsAny<ClientInfo?>(), TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(jwt);

        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(TestTenant.Matched, jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidGrant, "token revoked"));

        var result = await _resolver.ResolveAsync(SingleIssuer.Tenant, Requester, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("does not refer", error.ErrorDescription);
    }

    /// <summary>
    /// Through the server's own reading of a refresh token, one that names no tenant, as every refresh token before 3.0,
    /// is an invalid subject token and buys nothing: its grant is never looked up.
    /// </summary>
    [Fact]
    public async Task ARefreshTokenNamingNoTenant_IsAnInvalidSubjectToken()
    {
        var inner = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        inner
            .Setup(v => v.ValidateAsync(TokenWire, It.IsAny<ValidationParameters>()))
            .ReturnsAsync(NewRefreshJwt());
        var resolver = new RefreshTokenSubjectTokenResolver(
            new AuthServiceJwtValidator(
                new ProfiledJwtValidator(inner.Object),
                SingleIssuer.LicensedCatalog,
                Mock.Of<Abblix.Oidc.Server.Common.Interfaces.IAuthServiceKeysProvider>(),
                NothingRecorded.StatusCheck,
                TestOidcOptions.Defaults(),
            Mock.Of<Abblix.Oidc.Server.Features.ClientInformation.IClientInfoProvider>()),
            _refreshTokenService.Object,
            _clientInfoProvider.Object,
            _cutoffChecker.Object);

        var result = await resolver.ResolveAsync(
            SingleIssuer.Tenant,
            Requester,
            TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// A refresh token the refresh grant would refuse because its session was revoked is not exchanged instead: the
    /// resolver asks the session the same question.
    /// </summary>
    [Fact]
    public async Task ARefreshTokenOfARevokedSession_IsRefused()
    {
        var jwt = NewRefreshJwt();
        _jwtValidator
            .Setup(v => v.ReadAuthenticAsync(TestTenant.Matched, Requester, TokenWire, It.IsAny<TokenTypePolicy>(), ServiceTokenValidation.AnyAudience))
            .ReturnsAsync(jwt);
        var session = new AuthSession("user-9", "session-1", _timeProvider.GetUtcNow(), "self");
        _refreshTokenService
            .Setup(s => s.AuthorizeByRefreshTokenAsync(TestTenant.Matched, jwt, It.IsAny<ClientInfo>()))
            .ReturnsAsync(new AuthorizedGrant(session, new AuthorizationContext("client-1", [Scopes.OpenId], null)));
        _cutoffChecker
            .Setup(c => c.IsSessionRefusedAsync(TestTenant.Matched, session))
            .ReturnsAsync(true);

        var result = await _resolver.ResolveAsync(
            SingleIssuer.Tenant, Requester, TokenWire, new Uri(TokenExchangeTokenTypes.RefreshToken), CancellationToken.None);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
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
