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

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 6749 section 5.2 client-authentication failures at the token endpoint: when the client attempted
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

        // RFC 6749 section 5.2: Authorization-header authentication failure -> 401 (not 400) with a
        // WWW-Authenticate challenge matching the scheme the client used (Basic).
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == TokenTypes.Basic);

        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidClient, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// A public client (token_endpoint_auth_method none, which OpenID Connect Core 1.0 section 9 gives "a Public
    /// Client with no Client Secret or other authentication mechanism") presenting a client_secret uses a method it is
    /// not registered for, answered invalid_client (RFC 6749 section 5.2, "unsupported authentication method"). The
    /// same request without the secret gets past client authentication to the grant, whose code it fails.
    /// </summary>
    [Theory]
    [InlineData("wrong-secret", ErrorCodes.InvalidClient)]
    [InlineData(null, ErrorCodes.InvalidGrant)]
    public async Task Public_client_presenting_a_client_secret_is_not_authenticated(string? secret, string expected)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = "irrelevant-code",
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            [ClientRequest.Parameters.ClientId] = TestConstants.DPoPPublicClientId,
        };
        if (secret is not null)
            form[ClientRequest.Parameters.ClientSecret] = secret;

        using var response = await client.PostAsync(
            discovery.TokenEndpoint, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(
            JsonNode.Parse(raw)![ErrorResponse.Parameters.Error]!.GetValue<string>() == expected,
            $"{(int)response.StatusCode}: {raw}");
    }
}
