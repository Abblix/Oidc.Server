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
/// The userinfo request binds the access_token parameter of the query and of the form-encoded body each to its own
/// member (RFC 6750 sections 2.3 and 2.2), so a security profile can refuse the query alone. Driven through both hosts:
/// a source that also filled the other member would read as the token sent twice and be refused.
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

    [Fact]
    public async Task A_token_in_the_query_alone_is_answered()
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        var response = await client.GetAsync(WithTokenInQuery(endpoint, accessToken), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// RFC 6750 section 2.3: "Server success (2XX status) responses to these requests SHOULD contain a Cache-Control
    /// header with the "private" option." The no-store every response of the endpoint carries stays beside it.
    /// </summary>
    [Fact]
    public async Task A_success_to_a_token_in_the_query_is_private_to_the_client()
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        var response = await client.GetAsync(WithTokenInQuery(endpoint, accessToken), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Read as the server sent it, before the client merges repeated lines into one value
        var sent = Assert.Single(response.Headers.NonValidated[Microsoft.Net.Http.Headers.HeaderNames.CacheControl]);
        var cacheControl = CacheControlHeaderValue.Parse(sent);
        Assert.True(cacheControl.Private);
        Assert.True(cacheControl.NoStore);
    }

    [Fact]
    public async Task A_token_in_the_form_alone_is_answered()
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        var response = await client.PostAsync(endpoint, TokenInForm(accessToken), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// RFC 6750 section 3.1: a request that "uses more than one method for including an access token" is an
    /// invalid_request.
    /// </summary>
    [Fact]
    public async Task A_token_in_both_the_query_and_the_form_is_refused()
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        var response = await client.PostAsync(
            WithTokenInQuery(endpoint, accessToken), TokenInForm(accessToken), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(
            ErrorCodes.InvalidRequest,
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// RFC 6749 section 3.1: "Request and response parameters MUST NOT be included more than once." A copy in the
    /// query counts against the copy in the body even when it is empty, which no member reading one source sees.
    /// </summary>
    [Fact]
    public async Task An_empty_query_copy_beside_a_token_in_the_form_is_refused_as_a_repetition()
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        var response = await client.PostAsync(
            new Uri($"{endpoint}?{UserInfoRequest.Parameters.AccessToken}="),
            TokenInForm(accessToken),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(
            ErrorCodes.InvalidRequest,
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// RFC 6750 section 3.1: the token in the Authorization header and again as a parameter "uses more than one
    /// method for including an access token", which is an invalid_request answered with 400, whichever part of the
    /// request carries the parameter.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_token_in_the_header_and_as_a_parameter_is_an_invalid_request(bool parameterInForm)
    {
        var (client, endpoint, accessToken) = await ObtainAccessTokenAsync();

        using var request = parameterInForm
            ? new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = TokenInForm(accessToken) }
            : new HttpRequestMessage(HttpMethod.Get, WithTokenInQuery(endpoint, accessToken));
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(
            ErrorCodes.InvalidRequest,
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
}
