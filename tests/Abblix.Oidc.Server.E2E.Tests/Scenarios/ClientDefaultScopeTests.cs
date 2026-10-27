// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A client credentials request naming no scope is served with the client's default scope, or refused with
/// <c>invalid_scope</c> for a client required to name one: the two answers RFC 6749 section 3.3 allows a server.
/// </summary>
public class ClientDefaultScopeTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task ARequestNamingNoScope_IsIssuedATokenWithTheClientsDefault()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, Form(TestConstants.DefaultScopeClientId));

        var payload = DecodeJwtPayload(tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        Assert.Equal(Scopes.Profile, payload[IanaClaimTypes.Scope]?.GetValue<string>());
    }

    [Fact]
    public async Task ARequestNamingNoScope_OfAClientRequiredToNameOne_IsRefused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await FormPostHelpers.PostFormAsync(
            client, discovery.TokenEndpoint, Form(TestConstants.ScopeRequiredClientId));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidScope, body[ResponseParameters.Error]?.GetValue<string>());
    }

    private static Dictionary<string, string> Form(string clientId) => new()
    {
        [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
        [AuthorizationRequest.Parameters.ClientId] = clientId,
        [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
    };
}
