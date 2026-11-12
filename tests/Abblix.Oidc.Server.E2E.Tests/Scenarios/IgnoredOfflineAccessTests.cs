// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using CodeResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// An offline_access the server ignores is as if never asked for (OpenID Connect Core 1.0 section 11), so a request
/// naming it alone named no scope and is served the client's default, with the resource that default belongs to -
/// sent by value and pushed alike, since a pushed request is validated, stored and read back before the code is issued.
/// </summary>
/// <remarks>
/// The client receives offline access only when the request asks for consent, which this one does not, and its
/// default scope is one only <see cref="TestConstants.ApiResource"/> declares, so the resources settled for the
/// request and the scope it is served have to agree for it to pass at all.
/// </remarks>
public class IgnoredOfflineAccessTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OfflineAccessAloneAndIgnored_IsServedTheClientsDefault(bool pushed)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();

        var parameters = CodeFlowParameters(TestConstants.DefaultScopeCodeClientId, challenge);
        parameters[AuthorizationRequest.Parameters.Scope] = Scopes.OfflineAccess;
        parameters[AuthorizationRequest.Parameters.Resource] = TestConstants.ApiResource;
        List<KeyValuePair<string, string>> request = [.. parameters];

        if (pushed)
        {
            var pushResponse = await PushAuthorizationRequestAsync(client, discovery,
            [
                .. request,
                new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
            ]);
            request =
            [
                new(AuthorizationRequest.Parameters.ClientId, TestConstants.DefaultScopeCodeClientId),
                new(AuthorizationRequest.Parameters.RequestUri,
                    pushResponse[PushedAuthorizationResponse.Parameters.RequestUri]!.GetValue<string>()),
            ];
        }

        var code = await AuthorizeAndExtractFromCallbackAsync(client, discovery, request, CodeResponse.Parameters.Code);
        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = TestConstants.DefaultScopeCodeClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var payload = DecodeJwtPayload(tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>());
        Assert.Equal(TestConstants.ApiScope, payload[IanaClaimTypes.Scope]?.GetValue<string>());
        Assert.False(tokens.ContainsKey(TokenResponse.Parameters.RefreshToken));
    }
}
