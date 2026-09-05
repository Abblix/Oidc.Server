// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 6749 §5.2 client-authentication failures at the token endpoint: when the client attempted
/// to authenticate via the Authorization header, the server MUST respond with 401 and a
/// WWW-Authenticate challenge matching the scheme the client used.
/// </summary>
public class TokenEndpointClientAuthTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task Token_request_with_wrong_basic_credentials_returns_401_with_basic_challenge()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(
            TokenTypes.Basic,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{TestConstants.ConfidentialClientId}:wrong-secret")));
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = "irrelevant-code",
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
        });

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // RFC 6749 §5.2: Authorization-header authentication failure -> 401 (not 400) with a
        // WWW-Authenticate challenge matching the scheme the client used (Basic).
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == TokenTypes.Basic);

        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidClient, body[ResponseParameters.Error]!.GetValue<string>());
    }
}
