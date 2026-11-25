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
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 5.1: "resource servers MUST ignore access tokens in a URI query
/// parameter". The userinfo endpoint reads the access token from the Authorization header or the form-encoded body
/// (sections 5.1.1 and 5.1.2) and never from the query, so a token there neither authenticates the request nor counts
/// as a second method beside another. Driven through both hosts.
/// </summary>
public class UserInfoAccessTokenSourceTests(TestFactory factory) : TestBase(factory)
{
    private async Task<(HttpClient Client, Uri Endpoint, string AccessToken)> ObtainAccessTokenAsync()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        return (client, discovery.UserInfoEndpoint!, tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>());
    }

    private static Uri WithTokenInQuery(Uri endpoint, string accessToken)
        => new($"{endpoint}?{UserInfoRequest.Parameters.AccessToken}={Uri.EscapeDataString(accessToken)}");

    private static FormUrlEncodedContent TokenInForm(string accessToken)
        => new(new Dictionary<string, string> { [UserInfoRequest.Parameters.AccessToken] = accessToken });

    /// <summary>
    /// A token in the query alone is ignored, so the request carries no token, which RFC 6750 section 3.1 answers with
    /// 401 and a bare Bearer challenge, no error code.
    /// </summary>
    [Fact]
    public async Task A_token_in_the_query_alone_is_answered_as_no_token()
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        var response = await client.GetAsync(WithTokenInQuery(endpoint, accessToken), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var challenge = Assert.Single(response.Headers.WwwAuthenticate, value => value.Scheme == TokenTypes.Bearer);
        Assert.DoesNotContain("error=", challenge.Parameter ?? string.Empty);
    }

    [Fact]
    public async Task A_token_in_the_form_alone_is_answered()
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        var response = await client.PostAsync(endpoint, TokenInForm(accessToken), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// A token in the query beside one in the body or the header is ignored, so the request presents one token and is
    /// answered, whatever the query copy holds, an empty one included.
    /// </summary>
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task A_token_in_the_query_beside_another_source_is_ignored(bool otherSourceIsForm, bool queryCopyEmpty)
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();
        var inQuery = queryCopyEmpty
            ? new Uri($"{endpoint}?{UserInfoRequest.Parameters.AccessToken}=")
            : WithTokenInQuery(endpoint, accessToken);

        using var request = otherSourceIsForm
            ? new HttpRequestMessage(HttpMethod.Post, inQuery) { Content = TokenInForm(accessToken) }
            : new HttpRequestMessage(HttpMethod.Get, inQuery)
            {
                Headers = { Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken) },
            };

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// RFC 6750 section 3.1: the token in the Authorization header and again in the body "uses more than one method
    /// for including an access token", which is an invalid_request answered with 400, whichever scheme the header
    /// names.
    /// </summary>
    [Theory]
    [InlineData(TokenTypes.Bearer)]
    [InlineData(TokenTypes.Basic)]
    public async Task A_token_in_the_header_and_in_the_form_is_an_invalid_request(string scheme)
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = TokenInForm(accessToken) };
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, accessToken);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequest, await ErrorResponseReader.ErrorCodeOf(response));
    }
}
