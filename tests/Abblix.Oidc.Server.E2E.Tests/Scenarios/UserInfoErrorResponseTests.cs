// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// What the UserInfo endpoint answers a request it refuses, held to OpenID Connect Core 1.0 section 5.3.3, which
/// returns "an Error Response as defined in Section 3 of OAuth 2.0 Bearer Token Usage". Driven through both hosts.
/// </summary>
public class UserInfoErrorResponseTests(TestFactory factory) : TestBase(factory)
{
    private async Task<(HttpClient Client, Uri Endpoint)> EndpointAsync()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        return (client, discovery.UserInfoEndpoint!);
    }

    private static async Task<HttpResponseMessage> GetAsync(
        HttpClient client, Uri endpoint, AuthenticationHeaderValue? authorization)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Authorization = authorization;
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// RFC 6750 section 3.1: "If the request lacks any authentication information (e.g., the client was unaware that
    /// authentication is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." A scheme the endpoint does not speak gets the
    /// very challenges a request without credentials gets.
    /// </summary>
    [Fact]
    public async Task An_unsupported_scheme_is_challenged_as_a_request_without_credentials()
    {
        var (client, endpoint) = await EndpointAsync();

        var withoutCredentials = await GetAsync(client, endpoint, authorization: null);
        var withUnsupportedScheme = await GetAsync(
            client, endpoint, new AuthenticationHeaderValue(TokenTypes.Basic, "dXNlcjpwYXNz"));

        Assert.Equal(HttpStatusCode.Unauthorized, withUnsupportedScheme.StatusCode);
        Assert.Equal(
            withoutCredentials.Headers.WwwAuthenticate.Select(challenge => challenge.ToString()),
            withUnsupportedScheme.Headers.WwwAuthenticate.Select(challenge => challenge.ToString()));
    }

    /// <summary>
    /// RFC 6750 section 2.1 gives the credentials as <c>"Bearer" 1*SP b64token</c>; a header naming the scheme
    /// without a token is a malformed request, which section 3.1 names invalid_request and answers with 400.
    /// </summary>
    [Fact]
    public async Task A_bearer_header_without_a_token_is_an_invalid_request()
    {
        var (client, endpoint) = await EndpointAsync();

        var response = await GetAsync(client, endpoint, new AuthenticationHeaderValue(TokenTypes.Bearer));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(
            ErrorCodes.InvalidRequest,
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
}
