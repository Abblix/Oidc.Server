// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

public partial class TokenRequestProcessorTests
{
    /// <summary>
    /// The clients the rows describe, each named for what it states, so a row reads as the client it is.
    /// </summary>
    public static TheoryData<string> Clients =>
    [
        NotStated, CodeOnly, CodeAndRefresh, CodeAndExchange,
        CodeAndExchangeOfAccessTokens, CodeAndExchangeForbidden,
    ];

    private const string NotStated = "grant types not stated";
    private const string CodeOnly = "authorization code only";
    private const string CodeAndRefresh = "authorization code and refresh token";
    private const string CodeAndExchange = "authorization code and token exchange of any token type";
    private const string CodeAndExchangeOfAccessTokens = "authorization code and token exchange of access tokens";
    private const string CodeAndExchangeForbidden = "authorization code and token exchange of no token type";

    private static readonly string[] CodeAndRefreshGrants = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken];
    private static readonly string[] CodeAndExchangeGrants = [GrantTypes.AuthorizationCode, GrantTypes.TokenExchange];

    private static ClientInfo ClientNamed(string name)
    {
        var client = new ClientInfo(TestConstants.DefaultClientId) { OfflineAccess = OfflineAccess.ConsentRequired };
        switch (name)
        {
            case NotStated:
                return client;

            case CodeOnly:
                return client with { AllowedGrantTypes = [GrantTypes.AuthorizationCode] };

            case CodeAndRefresh:
                return client with { AllowedGrantTypes = CodeAndRefreshGrants };

            case CodeAndExchange:
                return client with { AllowedGrantTypes = CodeAndExchangeGrants };

            case CodeAndExchangeOfAccessTokens:
                return client with
                {
                    AllowedGrantTypes = CodeAndExchangeGrants,
                    TokenExchangeAllowedSubjectTokenTypes = [new Uri(TokenExchangeTokenTypes.AccessToken)],
                };

            case CodeAndExchangeForbidden:
                return client with
                {
                    AllowedGrantTypes = CodeAndExchangeGrants,
                    TokenExchangeAllowedSubjectTokenTypes = [],
                };

            default:
                throw new ArgumentOutOfRangeException(nameof(name), name, "An unknown client.");
        }
    }

    /// <summary>
    /// A code exchange granted offline_access hands the client a refresh token exactly when the token endpoint would
    /// take that refresh token from the client: through the refresh token grant, or through a token exchange naming
    /// it as the subject token (RFC 8693 section 3) where the client's token types admit it. RFC 7591 section 2 has
    /// grant_types name the grant types the client can use at the token endpoint, defaulting to authorization_code
    /// alone, so a refresh token issued past them is one the token endpoint then refuses. The answer of the token
    /// endpoint is read from the validator it runs and the exchange grant's own handler, so the issuance cannot drift
    /// from either.
    /// </summary>
    [Theory]
    [MemberData(nameof(Clients))]
    public async Task ACodeExchange_IssuesARefreshToken_ExactlyWhenTheTokenEndpointTakesItFromTheClient(string name)
    {
        var clientInfo = ClientNamed(name);

        var redeemable = await GrantAccepts(clientInfo, GrantTypes.RefreshToken) ||
                         await GrantAccepts(clientInfo, GrantTypes.TokenExchange) &&
                         await ExchangeTakesRefreshTokenFrom(clientInfo);
        var refreshTokenIssued = await CodeExchangeIssuesRefreshToken(clientInfo);

        Assert.Equal(redeemable, refreshTokenIssued);
        Assert.Equal(name is CodeAndRefresh or CodeAndExchange, refreshTokenIssued);
    }

    /// <summary>
    /// Whether the token exchange grant handler takes a refresh token as this client's subject token as far as
    /// resolving it, which is past every check of the client the handler makes before it looks at the token.
    /// </summary>
    private static async Task<bool> ExchangeTakesRefreshTokenFrom(ClientInfo clientInfo)
    {
        var resolved = false;
        var resolver = new Mock<ISubjectTokenResolver>(MockBehavior.Strict);
        resolver
            .Setup(r => r.ResolveAsync(
                It.IsAny<TenantDefinition>(), clientInfo, It.IsAny<string>(), It.IsAny<Uri>(),
                It.IsAny<CancellationToken>()))
            .Callback(() => resolved = true)
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidGrant, "Not resolved in this test."));

        var services = new ServiceCollection();
        services.AddKeyedSingleton(TokenExchangeTokenTypes.RefreshToken, resolver.Object);
        await using var provider = services.BuildServiceProvider();

        var handler = new TokenExchangeGrantHandler(
            provider, new Mock<ISessionIdGenerator>(MockBehavior.Strict).Object, TimeProvider.System);
        await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            new TokenRequest
            {
                GrantType = GrantTypes.TokenExchange,
                SubjectToken = "refresh_token_jwt",
                SubjectTokenType = new Uri(TokenExchangeTokenTypes.RefreshToken),
            },
            clientInfo,
            TestContext.Current.CancellationToken);

        return resolved;
    }

    /// <summary>
    /// Whether the token endpoint lets this client use the grant, as the validator answers it.
    /// </summary>
    private static async Task<bool> GrantAccepts(ClientInfo clientInfo, string grantType)
    {
        var grantHandler = new Mock<IAuthorizationGrantHandler>(MockBehavior.Strict);
        grantHandler
            .Setup(h => h.AuthorizeAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<TokenRequest>(), clientInfo, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)CreateAuthorizedGrant([Scopes.OfflineAccess]));

        var context = new TokenValidationContext(
            new TokenRequest { GrantType = grantType },
            new ClientRequest())
        {
            ClientInfo = clientInfo,
        };

        var error = await new AuthorizationGrantValidator(grantHandler.Object)
            .ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        return error switch
        {
            null => true,
            { Error: ErrorCodes.UnauthorizedClient } => false,
            _ => throw new InvalidOperationException($"The {grantType} grant failed for another reason: {error.Error}."),
        };
    }

    /// <summary>
    /// Whether a code exchange granted offline_access hands this client a refresh token.
    /// </summary>
    private async Task<bool> CodeExchangeIssuesRefreshToken(ClientInfo clientInfo)
    {
        var scopes = new[] { Scopes.OfflineAccess };
        var request = new ValidTokenRequest(CreateTokenRequest(), CreateAuthorizedGrant(scopes), clientInfo, [], []);
        var authContext = new AuthorizationContext(TestConstants.DefaultClientId, scopes, null);

        _contextEvaluator
            .Setup(e => e.EvaluateAuthorizationContext(It.IsAny<TenantDefinition>(), request))
            .Returns(authContext);
        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                TestTenant.Matched, It.IsAny<AuthSession>(), It.IsAny<AuthorizationContext>(), clientInfo,
                It.IsAny<string?>(), It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(CreateAccessToken());
        _refreshTokenService
            .Setup(s => s.CreateRefreshTokenAsync(
                TestTenant.Matched, It.IsAny<AuthSession>(), It.IsAny<AuthorizationContext>(), clientInfo, null,
                NewGrantId))
            .ReturnsAsync(CreateRefreshToken());

        var result = await _processor.ProcessAsync(SingleIssuer.Tenant, request);

        Assert.True(result.TryGetSuccess(out var issued));
        return issued.RefreshToken is not null;
    }
}
