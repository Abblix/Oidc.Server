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
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

public partial class TokenRequestProcessorTests
{
    /// <summary>
    /// The grant types each row's client states, by name, so a row reads as the client it describes.
    /// </summary>
    public static TheoryData<string> GrantTypeStatements => [nameof(NotStated), nameof(CodeOnly), nameof(CodeAndRefresh)];

    private static readonly string[]? NotStated = null;
    private static readonly string[] CodeOnly = [GrantTypes.AuthorizationCode];
    private static readonly string[] CodeAndRefresh = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken];

    private static string[]? GrantTypesOf(string statement) => statement switch
    {
        nameof(NotStated) => NotStated,
        nameof(CodeOnly) => CodeOnly,
        nameof(CodeAndRefresh) => CodeAndRefresh,
        _ => throw new ArgumentOutOfRangeException(nameof(statement), statement, "An unknown grant type statement."),
    };

    /// <summary>
    /// A code exchange granted offline_access hands the client a refresh token exactly when the refresh grant would
    /// accept that client: RFC 7591 section 2 has grant_types name the grant types the client can use at the token
    /// endpoint, defaulting to authorization_code alone, so a refresh token issued past that list is one the token
    /// endpoint then refuses with unauthorized_client. Both answers come from the same client, through the
    /// validator the token endpoint runs and the processor that issues, so the two cannot drift apart.
    /// </summary>
    [Theory]
    [MemberData(nameof(GrantTypeStatements))]
    public async Task ACodeExchange_IssuesARefreshToken_ExactlyWhenTheRefreshGrantAcceptsTheClient(string statement)
    {
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId)
        {
            OfflineAccess = OfflineAccess.ConsentRequired,
            AllowedGrantTypes = GrantTypesOf(statement),
        };

        var refreshGrantAccepted = await RefreshGrantAccepts(clientInfo);
        var refreshTokenIssued = await CodeExchangeIssuesRefreshToken(clientInfo);

        Assert.Equal(refreshGrantAccepted, refreshTokenIssued);
        Assert.Equal(statement == nameof(CodeAndRefresh), refreshTokenIssued);
    }

    /// <summary>
    /// Whether the token endpoint lets this client present a refresh token, as the validator answers it.
    /// </summary>
    private static async Task<bool> RefreshGrantAccepts(ClientInfo clientInfo)
    {
        var grantHandler = new Mock<IAuthorizationGrantHandler>(MockBehavior.Strict);
        grantHandler
            .Setup(h => h.AuthorizeAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<TokenRequest>(), clientInfo, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Result<AuthorizedGrant, OidcError>)CreateAuthorizedGrant([Scopes.OfflineAccess]));

        var context = new TokenValidationContext(
            new TokenRequest { GrantType = GrantTypes.RefreshToken, RefreshToken = "refresh_token_jwt" },
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
            _ => throw new InvalidOperationException($"The refresh grant failed for another reason: {error.Error}."),
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
                TestTenant.Matched, It.IsAny<AuthSession>(), authContext, clientInfo, It.IsAny<string?>(),
                It.IsAny<DateTimeOffset?>()))
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
